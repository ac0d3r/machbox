package cmd

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/ac0d3r/machbox/internal/db"
	"github.com/ac0d3r/machbox/internal/vm"
	"github.com/ac0d3r/machbox/pkg/vm/config"

	"github.com/spf13/cobra"
)

func newStartCommand() *cobra.Command {
	var (
		baseline string
		network  string
		shareRW  []string
		shareRO  []string
		noShare  bool
		opts     vm.StartOptions
	)
	cmd := &cobra.Command{
		Use:   "start [flags] <instance>",
		Short: "Start a persistent VM instance, creating it from a baseline the first time",
		Long: "Boots <instance>, a clone of a baseline that keeps its disk across shutdowns. " +
			"With --vm and no such instance, clones the baseline into a new one first. " +
			"Runs until the guest shuts down, the window is closed, or Ctrl-C, which shuts the guest down cleanly; " +
			"the host does not idle-sleep meanwhile.\n\n" +
			"Shared directories appear in the guest under " + vm.SharedFolder + "/<name>. " +
			"--network and the share flags are saved: the next start without them uses the same; " +
			"share flags replace the saved shares, --no-share removes them.\n\n" +
			"machbox run never uses instances, so what is signed in to in one stays out of plugin runs. " +
			"Removing the baseline removes its instances.",
		Example: "  machbox start cc --vm sonoma --network gateway-public --share ~/src/foo   # create and start\n" +
			"  machbox start cc --gui                                                     # start again, same network and shares, with the window",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: withVMDB(func(cmd *cobra.Command, args []string) error {
			name := args[0]
			// Flags are checked before anything is created.
			var err error
			if opts.Network, err = config.ParseNetwork(network); err != nil {
				return err
			}
			if noShare && len(shareRW)+len(shareRO) > 0 {
				return errors.New("--no-share cannot be combined with --share or --share-ro")
			}
			if opts.Shares, err = parseShares(shareRW, shareRO); err != nil {
				return err
			}
			in, err := vm.FindInstance(name)
			switch {
			case err == nil && baseline != "":
				return fmt.Errorf("instance %s already exists; start it without --vm", name)
			case errors.Is(err, vm.ErrInstanceNotFound) && baseline == "":
				return fmt.Errorf("no instance named %s; create it with --vm <baseline>", name)
			case errors.Is(err, vm.ErrInstanceNotFound):
				var rec *db.VM
				if rec, err = vm.Resolve(baseline); err == nil {
					in, err = vm.CreateInstance(rec, name, opts.Network)
				}
			}
			if err != nil {
				return err
			}
			if !cmd.Flags().Changed("network") {
				if opts.Network, err = config.ParseNetwork(in.Meta.Network); err != nil {
					return err
				}
			}
			if !noShare && len(opts.Shares) == 0 && len(in.Meta.Shares) > 0 {
				opts.Shares = in.Meta.Shares
				if err := vm.CheckShares(opts.Shares); err != nil {
					return fmt.Errorf("saved shares of %s: %w; change them with --share or --no-share", in.Name, err)
				}
			}

			// The first signal shuts the guest down, a second forces it off.
			// SIGHUP too: closing the terminal must not cut the guest's power.
			ctx, cancel := context.WithCancel(cmd.Context())
			defer cancel()
			sigs := make(chan os.Signal, 1)
			signal.Notify(sigs, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
			defer signal.Stop(sigs)
			force := make(chan struct{})
			opts.Force = force
			go func() {
				select {
				case <-sigs:
				case <-ctx.Done():
					return
				}
				cancel()
				<-sigs
				close(force)
			}()
			return in.Start(ctx, opts)
		}),
	}
	cmd.Flags().StringVarP(&baseline, "vm", "m", "", "baseline UUID or unique name to create the instance from")
	cmd.Flags().StringVar(&network, "network", "",
		fmt.Sprintf("guest network: none, %s (default: the instance's last, else none)",
			strings.Join(config.NetworkModes, ", ")))
	cmd.Flags().StringArrayVar(&shareRW, "share", nil,
		"share a host directory read-write, repeatable; replaces the saved shares")
	cmd.Flags().StringArrayVar(&shareRO, "share-ro", nil,
		"share a host directory read-only, repeatable; replaces the saved shares")
	cmd.Flags().BoolVar(&noShare, "no-share", false, "start without shares, and forget the saved ones")
	cmd.Flags().BoolVar(&opts.GUI, "gui", false, "show the VM window")
	return cmd
}

// parseShares returns the shares for --share and --share-ro, as absolute
// paths, checked as Start checks them.
func parseShares(rw, ro []string) ([]vm.InstanceShare, error) {
	shares := make([]vm.InstanceShare, 0, len(rw)+len(ro))
	for _, list := range []struct {
		paths    []string
		readOnly bool
	}{{rw, false}, {ro, true}} {
		for _, p := range list.paths {
			abs, err := filepath.Abs(p)
			if err != nil {
				return nil, fmt.Errorf("share %s: %w", p, err)
			}
			shares = append(shares, vm.InstanceShare{Path: abs, ReadOnly: list.readOnly})
		}
	}
	return shares, vm.CheckShares(shares)
}
