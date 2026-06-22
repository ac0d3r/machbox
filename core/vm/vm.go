package vm

import (
	"context"
	"fmt"
	"net"
	"sync"

	vz "github.com/Code-Hex/vz/v3"
	"github.com/sirupsen/logrus"
)

type VMInstance struct {
	ctx context.Context

	vm    *vz.VirtualMachine
	vssrv *VsockServer

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

	instance := &VMInstance{
		ctx:        ctx,
		vm:         vm,
		shutdownCh: make(chan struct{}),
	}

	// Initialize socket manager if a virtio socket device is configured.
	if devices := vm.SocketDevices(); len(devices) > 0 {
		instance.vssrv = NewVsockServer(devices[0])
	}

	return instance, nil
}

func (i *VMInstance) startStateWatcher() {
	i.stateWatchOnce.Do(func() {
		go i.handleStateChanges()
	})
}

// handleStateChanges watches the VM state and triggers shutdown when stopped.
func (i *VMInstance) handleStateChanges() {
	ch := i.vm.StateChangedNotify()

	for {
		select {
		case state, ok := <-ch:
			if !ok {
				logrus.Debug("VM state notification channel closed")
				return
			}

			switch state {
			case vz.VirtualMachineStateRunning:
				logrus.Debug("VM started")
			case vz.VirtualMachineStateStopped:
				logrus.Debug("VM stopped")
				i.setShutdownState()
				return
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

// Start starts the VM and launches the state watcher.
func (i *VMInstance) Start(opts ...vz.VirtualMachineStartOption) error {
	if err := i.vm.Start(opts...); err != nil {
		return fmt.Errorf("start VM: %w", err)
	}
	i.startStateWatcher()
	return nil
}

// ShowGraphic starts the VM's graphical application window.
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
	if i.vssrv != nil {
		i.vssrv.Close()
	}

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

func (i *VMInstance) StartVsockServer(handler func(net.Conn)) error {
	if i.vssrv == nil {
		return fmt.Errorf("no virtio socket device available")
	}
	return i.vssrv.AcceptLoop(i.ctx, DefaultVsockPort, handler)
}
