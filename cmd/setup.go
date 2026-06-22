package cmd

import (
	"context"
	"fmt"
	"net"

	"github.com/ac0d3r/machbox/core/assets"
	"github.com/ac0d3r/machbox/core/vm"
	"github.com/ac0d3r/machbox/core/vm/config"
	"github.com/ac0d3r/machbox/core/vsock"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func newSetuptCommand() *cobra.Command {
	opts := &vmOptions{}

	cmd := &cobra.Command{
		Use:   "setup",
		Short: "Setup a VBVM sandbox virtual machine environment",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := context.Background()

			logrus.Infof("decoding VBVM path: %s", opts.vbvmPath)
			vbvmcfg, err := config.DecodeVBVMPath(opts.vbvmPath)
			if err != nil {
				return fmt.Errorf("failed to decode vbvm path: %w", err)
			}

			if err := opts.parseDisplay(); err != nil {
				return err
			}

			vmcfg, err := config.NewMacVMConf(
				vbvmcfg,
				&config.VMOptions{
					DisplayWidth:  opts.width,
					DisplayHeight: opts.height,
					Disks:         []config.StorageDisk{{Path: assets.GuestDMGPath(), ReadOnly: true}},
					Network: config.Network{Enable: true,
						Mode: config.NetworkNAT}, // // On setup mode must enable network
				},
			)
			if err != nil {
				return fmt.Errorf("failed to create VM configuration: %w", err)
			}

			opts.headless = false // On setup mode must enable GUI
			return safetyRunVM(ctx, opts, vmcfg, vmSetup)
		},
	}

	bindVMFlags(cmd, opts)
	return cmd
}

func vmSetup(vmi *vm.VMInstance) {
	err := vmi.StartVsockServer(func(nc net.Conn) {
		hostconn := vsock.HostConnWrap(nc)
		defer hostconn.Close()

		if _, err := hostconn.GuestHandshake(); err != nil {
			logrus.Errorf("guest handshake failed: %v", err)
			return
		}
	})

	if err != nil {
		logrus.Errorf("failed to start setup vsock listener: %v", err)
	}
}
