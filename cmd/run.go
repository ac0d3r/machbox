package cmd

import (
	"errors"
	"fmt"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"

	"github.com/ac0d3r/machbox/internal/job"
	"github.com/ac0d3r/machbox/internal/plugin"
	"github.com/ac0d3r/machbox/pkg/vm/config"

	"github.com/spf13/cobra"
)

func newRunCommand() *cobra.Command {
	var (
		opts    job.Options
		network string
		echo    bool
	)
	cmd := &cobra.Command{
		Use:   "run [flags] <plugin-dir> [<workflow> [inputs...]]",
		Short: "Run a plugin workflow in a disposable VM",
		Long: "Runs a workflow of the plugin in <plugin-dir> (a directory with plugin.yml) " +
			"in a fresh snapshot of a baseline. Flags go before <plugin-dir>; everything " +
			"after <workflow> sets the workflow's inputs (--<input> <value> or positional). " +
			"Without <workflow>, lists the plugin's workflows; with --help after it, its inputs.\n\n" +
			"Step logs, outputs and job.json are kept in ~/.machbox/jobs/<id>/, printed when the job ends.",
		Example:      "  machbox run --vm sonoma ./plugins/malware analyze ./sample.zip --timeout 5m",
		Args:         cobra.MinimumNArgs(1),
		SilenceUsage: true,
		RunE: withVMDB(func(cmd *cobra.Command, args []string) error {
			p, err := plugin.Load(args[0])
			if err != nil {
				return err
			}
			if len(args) == 1 {
				printWorkflows(cmd, p)
				return nil
			}
			wf, err := p.Workflow(args[1])
			if err != nil {
				return err
			}

			prefix := fmt.Sprintf("machbox run [flags] %s %s", args[0], args[1])
			inputs, err := wf.ParseArgs(args[2:])
			if errors.Is(err, plugin.ErrHelp) {
				wf.Usage(cmd.OutOrStdout(), prefix)
				return nil
			}
			if err != nil {
				var usage strings.Builder
				wf.Usage(&usage, prefix)
				return fmt.Errorf("%w\n\n%s", err, usage.String())
			}

			if opts.Boot.Network, err = parseNetwork(network); err != nil {
				return err
			}
			if echo {
				opts.Echo = cmd.ErrOrStderr()
			}

			ctx, stop := signal.NotifyContext(cmd.Context(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			j, err := job.Run(ctx, p, wf, inputs, opts)
			if j != nil {
				fmt.Fprintln(cmd.OutOrStdout(), j.Dir)
			}
			return err
		}),
	}
	cmd.Flags().SetInterspersed(false)
	cmd.Flags().StringVarP(&opts.Baseline, "vm", "m", "",
		"baseline UUID or unique name (default: the only one meeting the plugin's requirements)")
	cmd.Flags().StringVar(&network, "network", "none",
		fmt.Sprintf("guest network: none, %s", strings.Join(config.NetworkModes, ", ")))
	cmd.Flags().BoolVar(&opts.Boot.GUI, "gui", false, "show the VM window")
	cmd.Flags().BoolVar(&echo, "show-output", false, "also print step output (always kept in the job's logs)")
	return cmd
}

func printWorkflows(cmd *cobra.Command, p *plugin.Plugin) {
	names := make([]string, 0, len(p.Workflows))
	for name := range p.Workflows {
		names = append(names, name)
	}
	slices.Sort(names)
	fmt.Fprintf(cmd.OutOrStdout(), "Workflows of %s %s:\n", p.Name, p.Version)
	for _, name := range names {
		fmt.Fprintf(cmd.OutOrStdout(), "  %s\n", name)
	}
}

func parseNetwork(mode string) (config.Network, error) {
	if strings.EqualFold(mode, "none") || mode == "" {
		return config.Network{}, nil
	}
	for _, m := range config.NetworkModes {
		if strings.EqualFold(mode, m) {
			return config.Network{Enable: true, Mode: m}, nil
		}
	}
	return config.Network{}, fmt.Errorf("unknown --network %q (none, %s)", mode, strings.Join(config.NetworkModes, ", "))
}
