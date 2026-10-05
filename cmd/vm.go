package cmd

import (
	"fmt"
	"io"
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
		newVMDoctorCommand(),
		newVMRenameCommand(),
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
	var name string
	cmd := &cobra.Command{
		Use:          "import <path.vbvm>",
		Short:        "Import a VirtualBuddy VM as a ready baseline",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: withVMDB(func(cmd *cobra.Command, args []string) error {
			rec, err := vm.Import(cmd.Context(), vm.ImportOptions{
				VbvmPath: args[0],
				Name:     name,
			})
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), rec.UUID)
			return nil
		}),
	}
	cmd.Flags().StringVar(&name, "name", "", "baseline name")
	_ = cmd.MarkFlagRequired("name")
	return cmd
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
			fmt.Fprintln(w, "UUID\tNAME\tOS\tVERSION\tBUILD\tAGENT\tCREATED")
			for i := range vms {
				v := &vms[i]
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
					v.UUID, v.Name, v.OSName, v.OSVersion, v.OSBuild,
					v.AgentVersion, v.CreatedAt.Format(time.RFC3339))
			}
			return w.Flush()
		}),
	}
}

func newVMDoctorCommand() *cobra.Command {
	return &cobra.Command{
		Use:          "doctor <uuid-or-name>",
		Short:        "Inspect a baseline",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: withVMDB(func(cmd *cobra.Command, args []string) error {
			res, err := vm.Doctor(args[0])
			if err != nil {
				return err
			}
			printDoctor(cmd.OutOrStdout(), res)
			if !res.Healthy() {
				return fmt.Errorf("baseline %s is not healthy", res.VM.UUID)
			}
			return nil
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

func printDoctor(w io.Writer, res *vm.DoctorResult) {
	v := res.VM
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "UUID:\t%s\n", v.UUID)
	fmt.Fprintf(tw, "Name:\t%s\n", v.Name)
	fmt.Fprintf(tw, "OS:\t%s %s (%s)\n", v.OSName, v.OSVersion, v.OSBuild)
	fmt.Fprintf(tw, "Agent:\t%s\n", v.AgentVersion)
	fmt.Fprintf(tw, "Path:\t%s\n", res.Path)
	fmt.Fprintf(tw, "Created:\t%s\n", v.CreatedAt.Format(time.RFC3339))
	fmt.Fprintf(tw, "Updated:\t%s\n", v.UpdatedAt.Format(time.RFC3339))
	_ = tw.Flush()

	if res.Healthy() {
		fmt.Fprintln(w, "Status:\tok")
		return
	}
	fmt.Fprintln(w, "Problems:")
	for _, p := range res.Problems {
		fmt.Fprintf(w, "  - %s\n", p)
	}
}
