package cmd

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/ac0d3r/machbox/internal/db"
	"github.com/ac0d3r/machbox/internal/vm"

	"github.com/spf13/cobra"
)

func newVMCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vm",
		Short: "Manage macOS VM baselines",
	}
	cmd.AddCommand(
		newVMImportCommand(),
		newVMListCommand(),
		newVMRenameCommand(),
		newVMDuplicateCommand(),
		newVMSetupCommand(),
		newVMRemoveCommand(),
	)
	return cmd
}

func withVMDB(run func(*cobra.Command, []string) error) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		if err := db.InitDB(); err != nil {
			return err
		}
		defer func() { _ = db.CloseDB() }()
		return run(cmd, args)
	}
}

func newVMImportCommand() *cobra.Command {
	return &cobra.Command{
		Use:          "import <path.vbvm> <name>",
		Short:        "Import a VirtualBuddy VM as a ready baseline",
		Args:         cobra.ExactArgs(2),
		SilenceUsage: true,
		RunE: withVMDB(func(cmd *cobra.Command, args []string) error {
			rec, err := vm.Import(cmd.Context(), vm.ImportOptions{
				VbvmPath: args[0],
				Name:     args[1],
			})
			if err != nil {
				return err
			}
			return printBaselines(cmd.OutOrStdout(), *rec)
		}),
	}
}

func newVMListCommand() *cobra.Command {
	return &cobra.Command{
		Use:          "list",
		Short:        "List imported baselines",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: withVMDB(func(cmd *cobra.Command, args []string) error {
			vms, err := vm.List()
			if err != nil {
				return err
			}
			return printBaselines(cmd.OutOrStdout(), vms...)
		}),
	}
}

func newVMRenameCommand() *cobra.Command {
	var name string
	cmd := &cobra.Command{
		Use:          "rename <uuid-or-name>",
		Short:        "Rename a baseline",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: withVMDB(func(cmd *cobra.Command, args []string) error {
			rec, err := vm.Rename(args[0], name)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\n", rec.UUID, rec.Name)
			return nil
		}),
	}
	cmd.Flags().StringVar(&name, "name", "", "new baseline name")
	_ = cmd.MarkFlagRequired("name")
	return cmd
}

func newVMDuplicateCommand() *cobra.Command {
	return &cobra.Command{
		Use:          "duplicate <uuid-or-name> <new-name>",
		Short:        "Copy a baseline, to configure the copy independently",
		Args:         cobra.ExactArgs(2),
		SilenceUsage: true,
		RunE: withVMDB(func(cmd *cobra.Command, args []string) error {
			rec, err := vm.Duplicate(args[0], args[1])
			if err != nil {
				return err
			}
			return printBaselines(cmd.OutOrStdout(), *rec)
		}),
	}
}

func newVMSetupCommand() *cobra.Command {
	return &cobra.Command{
		Use:     "setup <uuid-or-name>",
		Aliases: []string{"update-agent"},
		Short:   "Update the guest agent or change the tools of an imported baseline",
		Long: "Boots the baseline with the current MachboxGuest disk attached. " +
			"In the VM window, open MachboxGuest and run Machbox Setup, " +
			"then close the window when checks pass.",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: withVMDB(func(cmd *cobra.Command, args []string) error {
			rec, err := vm.Reconfigure(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			return printBaselines(cmd.OutOrStdout(), *rec)
		}),
	}
}

func newVMRemoveCommand() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:          "remove <uuid-or-name>",
		Short:        "Remove an imported baseline",
		Aliases:      []string{"rm"},
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: withVMDB(func(cmd *cobra.Command, args []string) error {
			rec, err := vm.Resolve(args[0])
			if err != nil {
				return err
			}
			if !yes {
				ok, err := confirm(cmd, fmt.Sprintf("Remove baseline %s (%s) and its disk?", rec.Name, rec.UUID))
				if err != nil {
					return err
				}
				if !ok {
					return ErrAborted
				}
			}
			rec, err = vm.Remove(rec.UUID)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\n", rec.UUID, rec.Name)
			return nil
		}),
	}
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "remove without asking")
	return cmd
}

// printBaselines prints baselines as a table, the format of vm list.
func printBaselines(out io.Writer, vms ...db.VM) error {
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "UUID\tNAME\tOS\tAGENT\tFEATURES\tCREATED")
	for i := range vms {
		v := &vms[i]
		features := "-"
		if len(v.Features) > 0 {
			features = strings.Join(v.Features, ",")
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\n",
			v.UUID, v.Name, formatOS(v.OSName, v.OSVersion, v.OSBuild),
			v.AgentVersion, features, v.CreatedAt.Format(time.RFC3339))
	}
	return w.Flush()
}

func formatOS(name, version, build string) string {
	switch {
	case name != "" && version != "" && build != "":
		return fmt.Sprintf("%s %s (%s)", name, version, build)
	case name != "" && version != "":
		return name + " " + version
	default:
		return name
	}
}
