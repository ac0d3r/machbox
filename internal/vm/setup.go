package vm

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/ac0d3r/machbox/internal/assets"
	"github.com/ac0d3r/machbox/internal/version"
	boxvm "github.com/ac0d3r/machbox/pkg/vm"
	"github.com/ac0d3r/machbox/pkg/vm/config"
	"github.com/ac0d3r/machbox/pkg/vsock"
	"github.com/ac0d3r/machbox/pkg/vsock/protocol"

	"github.com/sirupsen/logrus"
)

const bootTimeout = 15 * time.Minute

// ErrSIPEnabled is returned when the guest still has System Integrity
// Protection enabled.
var ErrSIPEnabled = errors.New(
	"guest SIP (System Integrity Protection) is still enabled; " +
		"boot the guest into Recovery Mode, open Utilities → Terminal, run " +
		"`csrutil disable`, then reboot the guest and import again")

// setup boots the cloned VBVM with the guest DMG attached and a GUI (same
// lifecycle as safetyRunVM: Start → vsock → ShowGraphic on the main thread).
// The guest handshake must run inside the vsock accept handler — returning
// early closes the connection (see VsockServer.untrackConn).
//
// An outdated agent already on the source VBVM may connect first with an empty
// or mismatched version; those attempts are ignored until a matching agent
// connects (or SIP fails / timeout).
func setup(ctx context.Context, dir string) (*protocol.GuestInfo, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()

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
		info *protocol.GuestInfo
		err  error
	}
	done := make(chan outcome, 1)
	var once sync.Once
	complete := func(info *protocol.GuestInfo, err error) {
		once.Do(func() {
			done <- outcome{info: info, err: err}
			if err != nil {
				logrus.Errorf("setup checks failed: %v — close the VM window to abort", err)
				return
			}
			logrus.Info("setup checks passed — close the VM window to finish import")
		})
	}

	waitCtx, waitCancel := context.WithTimeout(ctx, bootTimeout)
	defer waitCancel()
	go func() {
		<-waitCtx.Done()
		err := waitCtx.Err()
		if errors.Is(err, context.DeadlineExceeded) {
			err = fmt.Errorf(
				"timed out after %s waiting for guest agent %q; "+
					"install machbox-guest.pkg from the MachboxGuest volume in the GUI",
				bootTimeout, version.Version)
		}
		complete(nil, err)
	}()

	logrus.Infof("waiting for guest agent %q…", version.Version)
	if err := inst.StartVsockServer(func(nc net.Conn) {
		// Handshake must finish before this handler returns; otherwise
		// VsockServer closes the connection and the guest sees broken pipe.
		info, err := acceptGuest(dir, nc)
		if err != nil {
			if errors.Is(err, ErrSIPEnabled) {
				complete(nil, err)
				return
			}
			logrus.Warnf("guest not ready: %v — install/reinstall machbox-guest.pkg from MachboxGuest", err)
			return
		}
		complete(info, nil)
	}); err != nil {
		_ = inst.Shutdown()
		return nil, fmt.Errorf("start vsock server: %w", err)
	}

	logrus.Infof("showing GUI (%dx%d); install machbox-guest.pkg from MachboxGuest if needed",
		config.DefaultDisplayWidth, config.DefaultDisplayHeight)
	graphicErr := inst.ShowGraphic(config.DefaultDisplayWidth, config.DefaultDisplayHeight)
	cancel()

	if err := inst.Shutdown(); err != nil {
		logrus.Warnf("failed to stop baseline vm: %v", err)
	}

	r := <-done
	if graphicErr != nil && r.err == nil {
		return nil, fmt.Errorf("show graphic: %w", graphicErr)
	}
	return r.info, r.err
}

func acceptGuest(dir string, nc net.Conn) (*protocol.GuestInfo, error) {
	hc := vsock.HostConnWrap(nc)
	defer hc.Close()

	info, err := hc.GuestHandshake()
	if err != nil {
		return nil, fmt.Errorf("guest handshake: %w", err)
	}

	logrus.Infof("guest connected: %s %s (%s), agent %q",
		info.OSName, info.OSVersion, info.BuildVersion, info.AgentVersion)

	if info.OSName == "" {
		info.OSName = "macOS"
	}
	if !info.SIPDisabled {
		return nil, ErrSIPEnabled
	}
	if info.AgentVersion != version.Version {
		return nil, fmt.Errorf(
			"agent version %q != expected %q",
			info.AgentVersion, version.Version)
	}

	if err := finalizeBaseline(dir); err != nil {
		return nil, err
	}
	return &info, nil
}

// finalizeBaseline drops transient per-run snapshot dirs left from prior boots.
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
