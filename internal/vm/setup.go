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

type setupPurpose int

const (
	purposeImport setupPurpose = iota
	purposeUpdateAgent
)

// setup boots the VBVM with the guest DMG attached and a GUI, then dials the
// guest agent until a matching protocol reports in (or timeout). SIP may be
// in either state; plugins that need it disabled say so in their requirements.
func setup(ctx context.Context, dir string, purpose setupPurpose) (*agent.GuestInfo, error) {
	// Main thread is pinned in main(); do not UnlockOSThread.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	bundle, err := loadBundle(dir)
	if err != nil {
		return nil, fmt.Errorf("load baseline bundle: %w", err)
	}

	guestDMG, err := assets.GuestDMG()
	if err != nil {
		return nil, err
	}

	vmcfg, err := config.NewMacVMConf(bundle, &config.VMOptions{
		DisplayWidth:  config.DefaultDisplayWidth,
		DisplayHeight: config.DefaultDisplayHeight,
		Disks:         []config.StorageDisk{{Path: guestDMG, ReadOnly: true}},
		Network:       config.Network{Enable: true, Mode: config.NetworkNAT},
	})
	if err != nil {
		return nil, fmt.Errorf("create vm configuration: %w", err)
	}

	inst, err := boxvm.New(vmcfg)
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

	finishVerb := "finish import"
	pkgHint := "install machbox-guest.pkg from the MachboxGuest volume in the GUI"
	if purpose == purposeUpdateAgent {
		finishVerb = "finish agent update"
		pkgHint = "reinstall machbox-guest.pkg from the MachboxGuest volume in the GUI"
	}

	go func() {
		// Let StartGraphicApplication settle before the first Connect.
		select {
		case <-waitCtx.Done():
			done <- outcome{err: waitCtx.Err()}
			return
		case <-time.After(2 * time.Second):
		}

		info, err := waitGuest(waitCtx, inst, purpose)
		if err != nil {
			if errors.Is(err, context.DeadlineExceeded) {
				err = fmt.Errorf(
					"timed out after %s waiting for guest agent API %q; %s",
					bootTimeout, agent.AgentVersion, pkgHint)
			}
			logrus.Errorf("setup checks failed: %v — close the VM window to abort", err)
			done <- outcome{err: err}
			return
		}
		if err := finalizeBaseline(dir); err != nil {
			done <- outcome{err: err}
			return
		}
		logrus.Infof("setup checks passed — close the VM window to %s", finishVerb)
		done <- outcome{info: info}
	}()

	logrus.Infof("showing GUI (%dx%d); %s",
		config.DefaultDisplayWidth, config.DefaultDisplayHeight, pkgHint)
	logrus.Infof("waiting for guest agent version %q…", agent.AgentVersion)
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

func waitGuest(ctx context.Context, inst *boxvm.VMInstance, purpose setupPurpose) (*agent.GuestInfo, error) {
	dial := func(ctx context.Context) (net.Conn, error) {
		return inst.ConnectVsock(ctx, agent.DefaultVsockPort)
	}

	// update-agent must observe the agent go down (pkg reinstall / kickstart)
	// before accepting a handshake, otherwise an already-running old agent
	// would pass immediately without the user reinstalling.
	requireRestart := purpose == purposeUpdateAgent
	sawDown := !requireRestart
	loggedWaitingReinstall := false
	lastIncompatible := ""

	c := agent.NewClient(dial)
	for {
		info, err := c.Info(ctx)
		if err != nil {
			if requireRestart && !sawDown {
				logrus.Debugf("guest agent unreachable (waiting for reinstall cycle): %v", err)
			} else {
				logrus.Debugf("guest agent not ready: %v", err)
			}
			sawDown = true
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Second):
			}
			continue
		}
		if info.OSName == "" {
			info.OSName = "macOS"
		}
		if err := agent.CompatibleAgent(info.AgentVersion); err != nil {
			sawDown = true
			if msg := err.Error(); msg != lastIncompatible {
				logrus.Warnf("guest not ready: %v — install/reinstall machbox-guest.pkg", err)
				lastIncompatible = msg
			} else {
				logrus.Debugf("guest not ready: %v", err)
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Second):
			}
			continue
		}
		if !sawDown {
			if !loggedWaitingReinstall {
				logrus.Info("guest agent is still running; reinstall machbox-guest.pkg from MachboxGuest to continue")
				loggedWaitingReinstall = true
			}
			select {
			case <-ctx.Done():
				return nil, ctx.Err()
			case <-time.After(time.Second):
			}
			continue
		}
		agent.LogGuest(info)
		return &info, nil
	}
}

// finalizeBaseline drops runs_* snapshot directories that older versions
// created inside the baseline bundle (runs now live in assets.RunsDir).
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
