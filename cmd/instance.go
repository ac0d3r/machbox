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

func newInstanceCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "instance",
		Short: "Manage persistent VM instances (see machbox start)",
	}
	cmd.AddCommand(newInstanceListCommand(), newInstanceRemoveCommand())
	return cmd
}

func newInstanceListCommand() *cobra.Command {
	return &cobra.Command{
		Use:          "list",
		Aliases:      []string{"ls"},
		Short:        "List instances",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: withVMDB(func(cmd *cobra.Command, args []string) error {
			ins, err := vm.ListInstances()
			if err != nil {
				return err
			}
			return printInstances(cmd.OutOrStdout(), ins)
		}),
	}
}

func newInstanceRemoveCommand() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:          "remove <instance>",
		Aliases:      []string{"rm"},
		Short:        "Remove a stopped instance and its disk",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: withVMDB(func(cmd *cobra.Command, args []string) error {
			in, err := vm.FindInstance(args[0])
			if err != nil {
				return err
			}
			if in.Running() {
				return fmt.Errorf("instance %s is running; shut it down first", in.Name)
			}
			if !yes {
				ok, err := confirm(cmd, fmt.Sprintf("Remove instance %s and its disk, with everything done in it?", in.Name))
				if err != nil {
					return err
				}
				if !ok {
					return ErrAborted
				}
			}
			return vm.RemoveInstance(in)
		}),
	}
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "remove without asking")
	return cmd
}

func printInstances(out io.Writer, ins []vm.Instance) error {
	names := map[string]string{}
	if vms, err := db.ListVMs(); err == nil {
		for i := range vms {
			names[vms[i].UUID] = vms[i].Name
		}
	}
	w := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
	fmt.Fprintln(w, "NAME\tBASELINE\tNETWORK\tSHARES\tSTATE\tCREATED\tSTARTED")
	for i := range ins {
		in := &ins[i]
		baseline := names[in.BaselineUUID]
		if baseline == "" {
			baseline = in.BaselineUUID
		}
		state := "stopped"
		if in.Running() {
			state = "running"
		}
		shares := make([]string, len(in.Meta.Shares))
		for j, s := range in.Meta.Shares {
			shares[j] = s.Path
			if s.ReadOnly {
				shares[j] += " (ro)"
			}
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\t%s\t%s\n", in.Name, baseline, orDash(in.Meta.Network),
			orDash(strings.Join(shares, ", ")), state, formatTime(in.Meta.CreatedAt), formatTime(in.Meta.StartedAt))
	}
	return w.Flush()
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.Format(time.RFC3339)
}
