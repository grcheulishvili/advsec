package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

// Build metadata, overridable at link time via -ldflags.
var (
	Version = "0.1.0"
	Commit  = "dev"
	Date    = "unknown"
)

// Persistent flags shared across commands.
var (
	flagNoColor    bool
	flagPluginsDir string
	flagJSON       bool
	flagTop        int
	flagMissing    bool
)

var rootCmd = &cobra.Command{
	Use:   "advsec",
	Short: "Context-aware UNIX pipe recommendation engine",
	Long: `advsec reads piped stdin from upstream tools (nmap, file, curl, gdb,
journalctl, …), evaluates the operational context against a local YAML plugin
matrix, checks host capability, and prints prioritized, executable next steps.

Examples:
  file suspicious.bin | advsec
  nmap -sV 10.10.10.5 | advsec --top 3
  curl -sI https://target | advsec
  advsec plugin list`,
	Version:       Version,
	SilenceUsage:  true,
	SilenceErrors: true,
	// When invoked with no subcommand, behave as `analyze` so that
	// `… | advsec` works as the primary use case.
	RunE: func(cmd *cobra.Command, args []string) error {
		return runAnalyze(cmd, args)
	},
}

// Execute is the program entry point invoked from main.
func Execute() {
	rootCmd.SetVersionTemplate(fmt.Sprintf("advsec %s (commit %s, built %s)\n", Version, Commit, Date))
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, "advsec: "+err.Error())
		os.Exit(1)
	}
}

func init() {
	pf := rootCmd.PersistentFlags()
	pf.BoolVar(&flagNoColor, "no-color", false, "disable ANSI color output")
	pf.StringVar(&flagPluginsDir, "plugins-dir", "", "additional plugin directory to search first")

	// Analyze-oriented flags live on the root so `… | advsec --top N` works.
	rootCmd.Flags().BoolVar(&flagJSON, "json", false, "emit machine-readable JSON instead of styled text")
	rootCmd.Flags().IntVar(&flagTop, "top", 0, "limit output to the N highest-priority recommendations (0 = all)")
	rootCmd.Flags().BoolVar(&flagMissing, "missing-only", false, "only show tools that are not installed locally")

	rootCmd.AddCommand(newAnalyzeCmd())
	rootCmd.AddCommand(newPluginCmd())
	rootCmd.AddCommand(newUpdateCacheCmd())
}
