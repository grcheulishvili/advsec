package cmd

import (
	"fmt"
	"os"
	"sort"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/grcheulishvili/advsec/pkg/plugin"
)

func newPluginCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "plugin",
		Short: "Manage tactical plugins",
		Long:  "List, install, and update the declarative YAML plugins that drive advsec recommendations.",
	}
	c.AddCommand(newPluginListCmd())
	c.AddCommand(newPluginInstallCmd())
	c.AddCommand(newPluginUpdateCmd())
	return c
}

func newPluginListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List installed and active plugins",
		RunE: func(cmd *cobra.Command, args []string) error {
			dirs := plugin.SearchDirs()
			if flagPluginsDir != "" {
				dirs = append([]string{flagPluginsDir}, dirs...)
			}
			res := plugin.LoadFromDirs(dirs)
			for _, e := range res.Errors {
				fmt.Fprintln(os.Stderr, "advsec: warning: "+e.Error())
			}
			if len(res.Plugins) == 0 {
				fmt.Println("No plugins installed.")
				fmt.Println("User dir:   " + plugin.UserPluginDir())
				fmt.Println("System dir: " + plugin.SystemPluginDir())
				fmt.Println("Install some with: advsec plugin update")
				return nil
			}
			plugins := append([]plugin.Plugin{}, res.Plugins...)
			sort.Slice(plugins, func(i, j int) bool {
				if plugins[i].TargetType != plugins[j].TargetType {
					return plugins[i].TargetType < plugins[j].TargetType
				}
				return plugins[i].ID < plugins[j].ID
			})

			tw := tabwriter.NewWriter(os.Stdout, 0, 2, 2, ' ', 0)
			fmt.Fprintln(tw, "ID\tTYPE\tRULES\tTOOLS\tORIGIN\tNAME")
			for _, p := range plugins {
				fmt.Fprintf(tw, "%s\t%s\t%d\t%d\t%s\t%s\n",
					p.ID, orDash(p.TargetType), len(p.Match.Rules), len(p.Tactics.Tools),
					orDash(p.Origin), p.Name)
			}
			tw.Flush()
			fmt.Printf("\n%d plugin(s) loaded.\n", len(plugins))
			return nil
		},
	}
}

func newPluginInstallCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "install <github-repo | git-url | yaml-url>",
		Short: "Fetch and install community plugins",
		Args:  cobra.ExactArgs(1),
		Example: `  advsec plugin install owner/advsec-extra
  advsec plugin install https://github.com/owner/advsec-extra.git
  advsec plugin install https://example.com/rules/web.yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			mgr := plugin.NewManager()
			dest, err := mgr.Install(args[0])
			if err != nil {
				return err
			}
			// Validate what we just installed loads cleanly.
			loaded, lerr := plugin.LoadFile(dest)
			if lerr == nil && len(loaded) > 0 {
				fmt.Printf("Installed %d plugin(s) to %s\n", len(loaded), dest)
			} else {
				fmt.Printf("Installed to %s\n", dest)
			}
			return nil
		},
	}
}

func newPluginUpdateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "update",
		Short: "Pull latest official and community plugin rules",
		RunE: func(cmd *cobra.Command, args []string) error {
			mgr := plugin.NewManager()
			summary, err := mgr.Update()
			if err != nil {
				return err
			}
			for _, line := range summary {
				fmt.Println("  " + line)
			}
			// Refresh the package cache so new os_packages maps take effect.
			if n, cerr := mgr.UpdateCache(); cerr == nil {
				fmt.Printf("Package cache refreshed (%d entries).\n", n)
			}
			return nil
		},
	}
}

func newUpdateCacheCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "update-cache",
		Short: "Refresh local OS package mapping database",
		RunE: func(cmd *cobra.Command, args []string) error {
			mgr := plugin.NewManager()
			n, err := mgr.UpdateCache()
			if err != nil {
				return err
			}
			fmt.Printf("Package cache refreshed: %d tool/package entries.\n", n)
			return nil
		},
	}
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
