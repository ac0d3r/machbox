package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/ac0d3r/machbox/internal/assets"
	"github.com/ac0d3r/machbox/internal/plugin"
	"github.com/ac0d3r/machbox/internal/plugin/store"

	"github.com/spf13/cobra"
)

func pluginStore() *store.Store { return &store.Store{Dir: assets.PluginsDir()} }

// loadPlugin loads the plugin directory arg or, if there is none, the
// installed plugin arg names (owner/repo or a plugin name).
func loadPlugin(arg string) (*plugin.Plugin, error) {
	if _, err := os.Stat(arg); err != nil && !strings.HasPrefix(arg, ".") && !filepath.IsAbs(arg) {
		in, err := pluginStore().Get(arg)
		if err != nil {
			return nil, err
		}
		return in.Plugin, nil
	}
	return plugin.Load(arg)
}

func newPluginCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "plugin",
		Short: "Manage installed plugins (~/.machbox/plugins/<owner>/<repo>)",
	}
	cmd.AddCommand(
		newPluginInstallCommand(),
		newPluginListCommand(),
		newPluginUpdateCommand(),
		newPluginRemoveCommand(),
	)
	return cmd
}

func newPluginInstallCommand() *cobra.Command {
	var (
		version string
		force   bool
	)
	cmd := &cobra.Command{
		Use:   "install <repo-url>",
		Short: "Install a plugin from its GitHub releases",
		Long: "Downloads the plugin archive (.tar.gz) of a GitHub release, the latest unless " +
			"--version names one, and installs it as ~/.machbox/plugins/<owner>/<repo>. " +
			"Other commands and run take owner/repo, or the plugin's name while only one " +
			"installed plugin has it. " +
			"Set GITHUB_TOKEN to raise GitHub's rate limit.",
		Example:      "  machbox plugin install https://github.com/user/machbox-plugin --version v0.1.0",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			in, err := pluginStore().Install(cmd.Context(), args[0], version, force)
			if err != nil {
				return err
			}
			printInstalled(cmd, in)
			return nil
		},
	}
	cmd.Flags().StringVar(&version, "version", "", "release tag to install (default: latest)")
	cmd.Flags().BoolVar(&force, "force", false, "reinstall a plugin already installed from this repository")
	return cmd
}

func newPluginListCommand() *cobra.Command {
	return &cobra.Command{
		Use:          "list",
		Short:        "List installed plugins",
		Aliases:      []string{"ls"},
		Args:         cobra.NoArgs,
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			list, err := pluginStore().List()
			if err != nil {
				return err
			}
			w := tabwriter.NewWriter(cmd.OutOrStdout(), 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "REPO\tNAME\tVERSION")
			for _, in := range list {
				fmt.Fprintf(w, "%s\t%s\t%s\n", in.Source.Repo, in.Name, in.Version)
			}
			return w.Flush()
		},
	}
}

func newPluginUpdateCommand() *cobra.Command {
	return &cobra.Command{
		Use:          "update <owner/repo|name>",
		Short:        "Update an installed plugin to its latest release",
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			in, changed, err := pluginStore().Update(cmd.Context(), args[0])
			if err != nil {
				return err
			}
			if !changed {
				fmt.Fprintf(cmd.OutOrStdout(), "%s is up to date (%s)\n", in.Source.Repo, in.Version)
				return nil
			}
			printInstalled(cmd, in)
			return nil
		},
	}
}

func newPluginRemoveCommand() *cobra.Command {
	return &cobra.Command{
		Use:          "remove <owner/repo|name>",
		Short:        "Remove an installed plugin",
		Aliases:      []string{"rm"},
		Args:         cobra.ExactArgs(1),
		SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			repo, err := pluginStore().Remove(args[0])
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), repo)
			return nil
		},
	}
}

func printInstalled(cmd *cobra.Command, in *store.Installed) {
	fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\t%s\t%s\n", in.Source.Repo, in.Name, in.Version, in.Dir)
}
