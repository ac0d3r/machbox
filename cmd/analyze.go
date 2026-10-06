package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/ac0d3r/machbox/internal/analyze"

	"github.com/spf13/cobra"
)

func newAnalyzeCommand() *cobra.Command {
	opts := &vmOptions{}
	var (
		vmID     string
		password string
		timeout  int
	)

	cmd := &cobra.Command{
		Use:                   "analyze [flags] <sample> [--] [sample-args...]",
		Short:                 "Run malware analysis inside an imported sandbox baseline",
		DisableFlagsInUseLine: true,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) < 1 {
				return fmt.Errorf("missing sample file path")
			}
			if _, err := os.Stat(args[0]); err != nil {
				return fmt.Errorf("sample not found: %w", err)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := opts.parseDisplay(); err != nil {
				return err
			}

			sampleArgs := args[1:]
			if len(sampleArgs) > 0 && sampleArgs[0] == "--" {
				sampleArgs = sampleArgs[1:]
			}

			return analyze.Run(cmd.Context(), analyze.Options{
				VM:            vmID,
				SamplePath:    filepath.Clean(args[0]),
				SampleArgs:    sampleArgs,
				Password:      password,
				Timeout:       timeout,
				DisplayWidth:  opts.width,
				DisplayHeight: opts.height,
				Headless:      opts.headless,
				Network:       opts.parseNetwork(),
			})
		},
	}

	bindVMFlags(cmd, opts)
	cmd.Flags().StringVarP(&vmID, "vm", "m", "", "baseline UUID or unique name")
	cmd.Flags().StringVar(&password, "password", "", "password for encrypted archives")
	cmd.Flags().IntVar(&timeout, "timeout", 60, "")
	cmd.Flags().SetInterspersed(false)
	return cmd
}
