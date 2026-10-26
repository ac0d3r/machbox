package vm

import (
	"context"
	"fmt"
	"sync"

	vz "github.com/Code-Hex/vz/v4"
	"github.com/sirupsen/logrus"
)

type VMInstance struct {
	ctx context.Context
	vm  *vz.VirtualMachine

	vsockMu sync.Mutex // serializes host→guest Connect

	stateWatchOnce sync.Once
	shutdownOnce   sync.Once
	shutdownCh     chan struct{}
}

func New(ctx context.Context, cfg *vz.VirtualMachineConfiguration) (*VMInstance, error) {
	if cfg == nil {
		return nil, fmt.Errorf("virtual machine configuration is nil")
	}

	vm, err := vz.NewVirtualMachine(cfg)
	if err != nil {
		return nil, fmt.Errorf("create virtual machine: %w", err)
	}

	return &VMInstance{
		ctx:        ctx,
		vm:         vm,
		shutdownCh: make(chan struct{}),
	}, nil
}

func (i *VMInstance) startStateWatcher() {
	i.stateWatchOnce.Do(func() {
		go i.handleStateChanges()
	})
}

func (i *VMInstance) handleStateChanges() {
	ch := make(chan vz.VirtualMachineState, 4)
	stop, err := i.vm.StateChangedNotify(ch)
	if err != nil {
		logrus.Warnf("watch VM state: %v", err)
		return
	}
	defer stop()

	for {
		// Notifications may be dropped or stale, so State() is authoritative;
		// checking it first also covers a stop before registration.
		if i.vm.State() == vz.VirtualMachineStateStopped {
			logrus.Debug("VM stopped")
			i.setShutdownState()
			return
		}

		select {
		case state := <-ch:
			if state == vz.VirtualMachineStateRunning {
				logrus.Debug("VM started")
			}
		case <-i.ctx.Done():
			logrus.Debug("VM state watcher cancelled by context")
			if i.vm.State() == vz.VirtualMachineStateStopped {
				i.setShutdownState()
			}
			return
		}
	}
}

func (i *VMInstance) Start(opts ...vz.VirtualMachineStartOption) error {
	if err := i.vm.Start(opts...); err != nil {
		return fmt.Errorf("start VM: %w", err)
	}
	i.startStateWatcher()
	return nil
}

func (i *VMInstance) ShowGraphic(width, height int64) error {
	if width <= 0 || height <= 0 {
		return fmt.Errorf("invalid graphic size: width=%d height=%d", width, height)
	}
	if err := i.vm.StartGraphicApplication(
		float64(width),
		float64(height),
		vz.WithWindowTitle("machbox"),
		vz.WithController(true),
	); err != nil {
		return fmt.Errorf("start graphic application: %w", err)
	}
	return nil
}

func (i *VMInstance) setShutdownState() {
	i.shutdownOnce.Do(func() {
		close(i.shutdownCh)
	})
}

func (i *VMInstance) Shutdown() error {
	if i.vm.State() == vz.VirtualMachineStateStopped {
		i.setShutdownState()
		return nil
	}
	logrus.Debug("Stopping VM")
	return i.vm.Stop()
}

func (i *VMInstance) AlreadyShutdown() <-chan struct{} {
	return i.shutdownCh
}
