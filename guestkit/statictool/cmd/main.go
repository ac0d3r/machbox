package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"statictool"
)

type rootOptions struct {
	output     string
	password   string
	extractDir string
}

func NewRootCommand() *cobra.Command {
	opts := &rootOptions{}
	var samplePath string

	cmd := &cobra.Command{
		Use:                   "statictool [flags] <sample>",
		DisableFlagsInUseLine: true,
		SilenceErrors:         true,
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
			samplePath = args[0]

			report, err := statictool.NewAnalyzer(
				statictool.AnalyzeOptions{
					ArchivePassword: opts.password,
					ExtractDir:      opts.extractDir,
				}).Analyze(samplePath)
			if err != nil {
				return fmt.Errorf("analyze failed: %w", err)
			}

			data, err := json.Marshal(report)
			if err != nil {
				return fmt.Errorf("json encode failed: %w", err)
			}

			writer := os.Stdout
			if opts.output != "" {
				f, err := os.Create(opts.output)
				if err != nil {
					return fmt.Errorf("create output file failed: %w", err)
				}
				defer f.Close()
				writer = f
			}

			_, err = writer.Write(data)
			return err
		},
	}

	cmd.Flags().StringVarP(&opts.output, "output", "o", "", "write JSON output to file")
	cmd.Flags().StringVar(&opts.password, "password", "", "password for encrypted archives")
	cmd.Flags().StringVar(&opts.extractDir, "extract-dir", "", "extract archive to this directory")

	return cmd
}

func main() {
	if err := NewRootCommand().Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
