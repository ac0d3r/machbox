package vm

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"time"

	"github.com/ac0d3r/machbox/internal/agent"
	boxvm "github.com/ac0d3r/machbox/pkg/vm"
	"github.com/ac0d3r/machbox/pkg/vm/config"
	"github.com/ac0d3r/machbox/pkg/vm/gateway"

	"github.com/sirupsen/logrus"
)

// BootOptions configures a run's VM.
type BootOptions struct {
	Network config.Network
	// Capture, if not empty, is where the Internet network writes its pcap.
	Capture string
	// GUI shows the VM window. Boot must then be called on the main thread.
	GUI bool
}

// GuestFunc works with a booted guest. ctx is cancelled when the VM stops.
type GuestFunc func(ctx context.Context, c *agent.Client, info agent.GuestInfo) error

// Boot starts the run's snapshot, waits for a compatible guest agent and
// calls fn. The VM is stopped once fn returns or ctx is cancelled.
func (r *Run) Boot(ctx context.Context, opts BootOptions, fn GuestFunc) error {
	// Main thread is pinned in main(); do not UnlockOSThread.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	network := opts.Network
	if network.Enable && network.Mode == config.NetworkInternet {
		gw, err := gateway.Start(opts.Capture)
		if err != nil {
			return fmt.Errorf("start network gateway: %w", err)
		}
		// Boot only returns after the VM has stopped (or the stop timed out).
		defer func() {
			if err := gw.Close(); err != nil {
				logrus.Warnf("close network gateway: %v", err)
			}
		}()
		network.File = gw.VMFile()
	}

	vmcfg, err := r.VMConfig(config.VMOptions{
		DisplayWidth:  config.DefaultDisplayWidth,
		DisplayHeight: config.DefaultDisplayHeight,
		Network:       network,
	})
	if err != nil {
		return fmt.Errorf("create vm configuration: %w", err)
	}
	inst, err := boxvm.New(ctx, vmcfg)
	if err != nil {
		return fmt.Errorf("create vm instance: %w", err)
	}
	if err := inst.Start(); err != nil {
		return fmt.Errorf("start vm: %w", err)
	}
	logrus.Info("VM started")

	// Stop the VM on cancellation, and cancel fn if the VM stops first.
	var stoppedEarly atomic.Bool
	go func() {
		select {
		case <-ctx.Done():
			_ = inst.Shutdown()
		case <-inst.AlreadyShutdown():
			stoppedEarly.Store(true)
			cancel()
		}
	}()

	errCh := make(chan error, 1)
	go func() {
		errCh <- r.withGuest(ctx, inst, fn)
		if !opts.GUI {
			cancel()
			return
		}
		// Keep the guest up for inspection; closing the window stops it.
		logrus.Info("finished — close the VM window to exit")
	}()

	var graphicErr error
	if opts.GUI {
		graphicErr = inst.ShowGraphic(config.DefaultDisplayWidth, config.DefaultDisplayHeight)
		cancel()
	}

	runErr := <-errCh
	_ = inst.Shutdown()
	select {
	case <-inst.AlreadyShutdown():
	case <-time.After(30 * time.Second):
		logrus.Warn("timed out waiting for the VM to stop")
	}
	logrus.Info("VM stopped")

	if graphicErr != nil && (runErr == nil || errors.Is(runErr, context.Canceled)) {
		return fmt.Errorf("show graphic: %w", graphicErr)
	}
	if stoppedEarly.Load() && errors.Is(runErr, context.Canceled) {
		return fmt.Errorf("VM stopped unexpectedly: %w", runErr)
	}
	return runErr
}

func (r *Run) withGuest(ctx context.Context, inst *boxvm.VMInstance, fn GuestFunc) error {
	waitCtx, waitCancel := context.WithTimeout(ctx, bootTimeout)
	defer waitCancel()

	dial := func(ctx context.Context) (net.Conn, error) {
		return inst.ConnectVsock(ctx, agent.DefaultVsockPort)
	}
	client, info, err := agent.WaitReady(waitCtx, dial, time.Second)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
			return fmt.Errorf("timed out after %s waiting for the guest agent", bootTimeout)
		}
		return fmt.Errorf("wait for guest agent: %w", err)
	}

	if err := agent.CompatibleAgent(info.AgentVersion); err != nil {
		return fmt.Errorf("%w; run: machbox vm update-agent %s", err, r.Baseline.UUID)
	}
	return fn(ctx, client, info)
}
