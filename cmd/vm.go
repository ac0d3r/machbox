package cmd

import (
	"fmt"
	"text/tabwriter"
	"time"

	"github.com/ac0d3r/machbox/internal/db"
	"github.com/ac0d3r/machbox/internal/vm"

	"github.com/spf13/cobra"
)

func newVMCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vm",
		Short: "Manage sandbox VM baselines",
	}
	cmd.AddCommand(
		newVMImportCommand(),
		newVMListCommand(),
		newVMRenameCommand(),
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
			fmt.Fprintln(cmd.OutOrStdout(), rec.UUID)
			return nil
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
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 4, 2, ' ', 0)
			fmt.Fprintln(w, "UUID\tNAME\tOS\tAGENT\tCREATED")
			for i := range vms {
				v := &vms[i]
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
					v.UUID, v.Name, formatOS(v.OSName, v.OSVersion, v.OSBuild),
					v.AgentVersion, v.CreatedAt.Format(time.RFC3339))
			}
			return w.Flush()
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

func newVMRemoveCommand() *cobra.Command {
	return &cobra.Command{
		Use:          "remove <uuid-or-name>",
		Short:        "Remove an imported baseline",
		Aliases:      []string{"rm"},
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: withVMDB(func(cmd *cobra.Command, args []string) error {
			rec, err := vm.Remove(args[0])
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\n", rec.UUID, rec.Name)
			return nil
		}),
	}
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
