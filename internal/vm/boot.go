package vm

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/ac0d3r/machbox/internal/agent"
	boxvm "github.com/ac0d3r/machbox/pkg/vm"
	"github.com/ac0d3r/machbox/pkg/vm/config"
	"github.com/ac0d3r/machbox/pkg/vm/gateway"
	"github.com/ac0d3r/machbox/pkg/vsock"

	"github.com/sirupsen/logrus"
)

// BootOptions configures a run's VM.
type BootOptions struct {
	Network config.Network
	// Capture, if not empty, is where the gateway writes its pcap.
	Capture string
	// Egress is the gateway's policy; "" is gateway.EgressNone.
	Egress gateway.Egress
	// GUI shows the VM window. Boot must then be called on the main thread.
	GUI bool
}

// GuestFunc works with a booted guest. ctx is cancelled when the VM stops.
type GuestFunc func(ctx context.Context, c *agent.Client, info agent.GuestInfo) error

// Boot starts the run's snapshot, waits for a compatible guest agent and
// calls fn. The VM is stopped once fn returns or ctx is cancelled. The host
// does not idle-sleep meanwhile.
func (r *Run) Boot(ctx context.Context, opts BootOptions, fn GuestFunc) error {
	// Main thread is pinned in main(); do not UnlockOSThread.
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	network, stopNetwork, err := startNetwork(opts)
	if err != nil {
		return err
	}
	// Boot only returns after the VM has stopped (or the stop timed out).
	defer stopNetwork()

	vmcfg, err := r.VMConfig(config.VMOptions{
		DisplayWidth:  config.DefaultDisplayWidth,
		DisplayHeight: config.DefaultDisplayHeight,
		Network:       network,
	})
	if err != nil {
		return fmt.Errorf("create vm configuration: %w", err)
	}
	inst, err := boxvm.New(vmcfg)
	if err != nil {
		return fmt.Errorf("create vm instance: %w", err)
	}
	if err := inst.Start(); err != nil {
		return fmt.Errorf("start vm: %w", err)
	}
	logrus.Info("VM started")
	defer keepAwake()()

	// Cancel fn if the VM stops first.
	var stoppedEarly atomic.Bool
	go func() {
		select {
		case <-ctx.Done():
		case <-inst.AlreadyShutdown():
			stoppedEarly.Store(true)
			cancel()
		}
	}()

	var runErr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer stopVM(inst)
		runErr = r.withGuest(ctx, inst, fn)
	}()

	var graphicErr error
	if opts.GUI {
		// Returns when the window is closed or the VM stops.
		graphicErr = inst.ShowGraphic(config.DefaultDisplayWidth, config.DefaultDisplayHeight)
		cancel()
	}
	<-done
	logrus.Info("VM stopped")

	if graphicErr != nil && (runErr == nil || errors.Is(runErr, context.Canceled)) {
		return fmt.Errorf("show graphic: %w", graphicErr)
	}
	if stoppedEarly.Load() && errors.Is(runErr, context.Canceled) {
		return fmt.Errorf("VM stopped unexpectedly: %w", runErr)
	}
	return runErr
}

// stopVM stops the VM at once and waits for it: a run's snapshot is
// discarded, so the guest need not shut down cleanly.
func stopVM(inst *boxvm.VMInstance) {
	_ = inst.Shutdown()
	select {
	case <-inst.AlreadyShutdown():
	case <-time.After(30 * time.Second):
		logrus.Warn("timed out waiting for the VM to stop")
	}
}

// keepAwake keeps the host from idle-sleeping, which would pause the
// guest, until the returned func is called or machbox exits.
func keepAwake() func() {
	cmd := exec.Command("/usr/bin/caffeinate", "-i", "-w", strconv.Itoa(os.Getpid())) // #nosec G204 -- fixed command, our pid
	if err := cmd.Start(); err != nil {
		logrus.Warnf("keep the host awake: %v", err)
		return func() {}
	}
	return func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}
}

// startNetwork starts the host gateway when n needs one and returns the
// network for the VM configuration. stop closes the gateway, flushing the
// capture; call it once the VM has stopped.
func startNetwork(opts BootOptions) (_ config.Network, stop func(), err error) {
	n := opts.Network
	if !n.Gateway() {
		return n, func() {}, nil
	}
	gw, err := gateway.Start(gateway.Options{
		Capture: opts.Capture,
		Egress:  opts.Egress,
	})
	if err != nil {
		return n, nil, fmt.Errorf("start network gateway: %w", err)
	}
	n.File = gw.VMFile()
	return n, func() {
		if err := gw.Close(); err != nil {
			logrus.Warnf("close network gateway: %v", err)
		}
	}, nil
}

// agentDialer dials the guest agent with the flow control its listener uses.
func agentDialer(inst *boxvm.VMInstance) agent.DialFunc {
	return func(ctx context.Context) (net.Conn, error) {
		c, err := inst.ConnectVsock(ctx, agent.DefaultVsockPort)
		if err != nil {
			return nil, err
		}
		return vsock.FlowControl(c), nil
	}
}

func (r *Run) withGuest(ctx context.Context, inst *boxvm.VMInstance, fn GuestFunc) error {
	waitCtx, waitCancel := context.WithTimeout(ctx, bootTimeout)
	defer waitCancel()

	dial := agentDialer(inst)
	client, info, err := agent.WaitReady(waitCtx, dial, time.Second)
	if err != nil {
		if errors.Is(err, context.DeadlineExceeded) && ctx.Err() == nil {
			return fmt.Errorf("timed out after %s waiting for the guest agent", bootTimeout)
		}
		return fmt.Errorf("wait for guest agent: %w", err)
	}

	if err := agent.CompatibleAgent(info.AgentVersion); err != nil {
		return fmt.Errorf("%w; update it: machbox vm setup %s", err, r.Baseline.Name)
	}
	// Only SIP is read live; the rest is the baseline's record.
	agent.LogGuest(info, agent.WithSIP(r.Baseline.Features, info.SIPDisabled))
	return fn(ctx, client, info)
}
