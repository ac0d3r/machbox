package cmd

import (
	"github.com/ac0d3r/machbox/internal/assets"
	"github.com/ac0d3r/machbox/internal/logger"

	"github.com/spf13/cobra"
)

type logOptions struct {
	level  string
	output string
	JSON   bool
}

type rootOptions struct {
	log logOptions
}

func NewRootCommand(version string) *cobra.Command {
	opts := &rootOptions{}

	cmd := &cobra.Command{
		Use:           "machbox",
		Short:         "macOS VM sandbox",
		Version:       version,
		SilenceErrors: true,
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},

		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if err := logger.Init(&logger.Config{
				Level:  opts.log.level,
				Output: opts.log.output,
				Format: opts.log.JSON}); err != nil {
				return err
			}
			return assets.Init()
		},
	}

	cmd.SetVersionTemplate("{{.Name}} version {{.Version}}\n")

	cmd.PersistentFlags().StringVar(&opts.log.level, "log-level",
		"info", "log level: debug, info, warn, error")
	cmd.PersistentFlags().StringVar(&opts.log.output, "log-output",
		"", "log file path, empty for stdout")
	cmd.PersistentFlags().BoolVar(&opts.log.JSON, "log-json",
		false, "enable JSON log output")

	cmd.AddCommand(
		newVMCommand(),
		newRunCommand(),
	)

	return cmd
}

// Execute creates the root command and runs it.
func Execute(version string) error {
	return NewRootCommand(version).Execute()
}
