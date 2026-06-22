package cmd

import (
	"github.com/ac0d3r/machbox/report"

	"github.com/spf13/cobra"
)

func newReportViewCommand() *cobra.Command {
	var addr string

	cmd := &cobra.Command{
		Use:   "report-view",
		Short: "Start the web UI server to browse analysis reports",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return report.InitDB()
		},
		PostRunE: func(cmd *cobra.Command, args []string) error {
			return report.CloseDB()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return report.StartWebServer(addr)
		},
	}

	cmd.Flags().StringVarP(&addr, "addr", "a", "127.0.0.1:8080", "server listen address")
	return cmd
}
