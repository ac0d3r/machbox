package vm

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ac0d3r/machbox/internal/agent"
	"github.com/ac0d3r/machbox/internal/assets"
	boxvm "github.com/ac0d3r/machbox/pkg/vm"
	"github.com/ac0d3r/machbox/pkg/vm/config"

	"github.com/sirupsen/logrus"
)

const bootTimeout = 15 * time.Minute

// ErrSIPEnabled is returned when the guest still has System Integrity
// Protection enabled.
var ErrSIPEnabled = errors.New(
	"guest SIP (System Integrity Protection) is still enabled; " +
		"boot the guest into Recovery Mode, open Utilities → Terminal, run " +
		"`csrutil disable`, then reboot the guest and import again")

// setup boots the cloned VBVM with the guest DMG attached and a GUI, then
// dials the guest agent until a matching version reports in (or SIP/timeout).
func setup(ctx context.Context, dir string) (*agent.GuestInfo, error) {
	// Main thread is pinned in main(); do not UnlockOSThread.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	vbvmcfg, err := config.DecodeVBVMPath(dir)
	if err != nil {
		return nil, fmt.Errorf("decode baseline bundle: %w", err)
	}

	vmcfg, err := config.NewMacVMConf(vbvmcfg, &config.VMOptions{
		DisplayWidth:  config.DefaultDisplayWidth,
		DisplayHeight: config.DefaultDisplayHeight,
		Disks:         []config.StorageDisk{{Path: assets.GuestDMGPath(), ReadOnly: true}},
		Network:       config.Network{Enable: true, Mode: config.NetworkNAT},
	})
	if err != nil {
		return nil, fmt.Errorf("create vm configuration: %w", err)
	}

	inst, err := boxvm.New(ctx, vmcfg)
	if err != nil {
		return nil, fmt.Errorf("create vm instance: %w", err)
	}
	if err := inst.Start(); err != nil {
		return nil, fmt.Errorf("start vm: %w", err)
	}
	logrus.Info("VM started successfully")

	type outcome struct {
		info *agent.GuestInfo
		err  error
	}
	done := make(chan outcome, 1)

	waitCtx, waitCancel := context.WithTimeout(ctx, bootTimeout)
	defer waitCancel()

	go func() {
		// Let StartGraphicApplication settle before the first Connect.
		select {
		case <-waitCtx.Done():
			done <- outcome{err: waitCtx.Err()}
			return
		case <-time.After(2 * time.Second):
		}

		info, err := waitGuest(waitCtx, inst)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				err = fmt.Errorf(
					"timed out after %s waiting for guest agent API %q; "+
						"install machbox-guest.pkg from the MachboxGuest volume in the GUI",
					bootTimeout, agent.ProtocolVersion)
			}
			logrus.Errorf("setup checks failed: %v — close the VM window to abort", err)
			done <- outcome{err: err}
			return
		}
		if err := finalizeBaseline(dir); err != nil {
			done <- outcome{err: err}
			return
		}
		logrus.Info("setup checks passed — close the VM window to finish import")
		done <- outcome{info: info}
	}()

	logrus.Infof("showing GUI (%dx%d); install machbox-guest.pkg from MachboxGuest if needed",
		config.DefaultDisplayWidth, config.DefaultDisplayHeight)
	logrus.Infof("waiting for guest agent protocol %q…", agent.ProtocolVersion)
	graphicErr := inst.ShowGraphic(config.DefaultDisplayWidth, config.DefaultDisplayHeight)
	cancel()

	if err := inst.Shutdown(); err != nil {
		logrus.Warnf("failed to stop baseline vm: %v", err)
	}
	// Wait for the VM to fully release disk files before Import's cleanup
	// RemoveAll runs; otherwise an aborted import can leave ~/.machbox/vms/<uuid>.
	select {
	case <-inst.AlreadyShutdown():
	case <-time.After(30 * time.Second):
		logrus.Warn("timed out waiting for baseline VM to stop")
	}

	r := <-done
	if graphicErr != nil && r.err == nil {
		return nil, fmt.Errorf("show graphic: %w", graphicErr)
	}
	if r.info == nil && r.err == nil {
		return nil, context.Canceled
	}
	return r.info, r.err
}

func waitGuest(ctx context.Context, inst *boxvm.VMInstance) (*agent.GuestInfo, error) {
	dial := func(ctx context.Context) (net.Conn, error) {
		return inst.ConnectVsock(ctx, agent.DefaultVsockPort)
	}

	for {
		client, info, err := agent.Dial(ctx, dial)
		if err != nil {
			logrus.Debugf("guest agent not ready: %v", err)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Second):
			}
			continue
		}
		_ = client.Close()

		if info.OSName == "" {
			info.OSName = "macOS"
		}
		if err := agent.CompatibleProtocol(info.AgentVersion); err != nil {
			logrus.Warnf("guest not ready: %v — install/reinstall machbox-guest.pkg", err)
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Second):
			}
			continue
		}
		agent.LogGuest(info)
		if !info.SIPDisabled {
			return nil, ErrSIPEnabled
		}
		return &info, nil
	}
}

func finalizeBaseline(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("inspect baseline directory: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() && strings.HasPrefix(entry.Name(), "runs_") {
			if err := os.RemoveAll(filepath.Join(dir, entry.Name())); err != nil {
				return fmt.Errorf("remove stale snapshot %s: %w", entry.Name(), err)
			}
		}
	}
	return nil
}
