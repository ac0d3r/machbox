package cmd

import (
	"fmt"

	"github.com/ac0d3r/machbox/internal/assets"
	"github.com/ac0d3r/machbox/internal/job"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
)

func newJobCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "job",
		Short: "Manage job directories (see machbox run)",
	}
	cmd.AddCommand(newJobPruneCommand())
	return cmd
}

func newJobPruneCommand() *cobra.Command {
	var yes bool
	cmd := &cobra.Command{
		Use:          "prune",
		Short:        "Remove finished jobs: their records, logs and outputs",
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			ids, err := job.Finished()
			if err != nil {
				return err
			}
			if len(ids) == 0 {
				logrus.Info("no finished jobs")
				return nil
			}
			if !yes {
				ok, err := confirm(cmd, fmt.Sprintf("Remove %d finished job(s) under %s, outputs included?", len(ids), assets.JobsDir()))
				if err != nil {
					return err
				}
				if !ok {
					return ErrAborted
				}
			}
			removed := 0
			for _, id := range ids {
				if err := job.Remove(id); err != nil {
					logrus.Warnf("%v", err)
					continue
				}
				removed++
			}
			logrus.Infof("removed %d job(s)", removed)
			return nil
		},
	}
	cmd.Flags().BoolVarP(&yes, "yes", "y", false, "remove without asking")
	return cmd
}
