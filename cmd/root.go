package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/grcheulishvili/advsec/pkg/engine"
)

// Build metadata, overridable at link time via -ldflags.
var (
	Version = "1.4.0"
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
	flagContext    string
	flagSelect     bool
	flagMinConf    int
	flagAll        bool
	flagNoClassify bool
	flagFormat     string
	flagFlat       bool
	flagSemantic   bool
	flagCmd        string
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
	// `... | advsec` works as the primary use case. With no piped stdin and no
	// --input, there is nothing to analyze, so print help and exit 0.
	RunE: func(cmd *cobra.Command, args []string) error {
		if flagInputFile == "" && stdinIsTTY() {
			return cmd.Help()
		}
		return runAnalyze(cmd, args)
	},
}

// missingArg prints a friendly notice plus the command's own help, instead of a
// raw Cobra "accepts 1 arg(s)" error, and exits cleanly.
func missingArg(cmd *cobra.Command, name string) error {
	fmt.Fprintf(cmd.ErrOrStderr(), "advsec: missing required argument %s\n\n", name)
	_ = cmd.Help()
	return nil
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
	addAnalyzeFlags(rootCmd.Flags())

	rootCmd.AddCommand(newAnalyzeCmd())
	rootCmd.AddCommand(newPluginCmd())
	rootCmd.AddCommand(newUpdateCacheCmd())
	rootCmd.AddCommand(newInitCmd())
	rootCmd.AddCommand(newSetupSemanticCmd())
}

// addAnalyzeFlags registers the analysis flags on a flag set so both the root
// command (the default `… | advsec` path) and the explicit `analyze`
// subcommand expose an identical interface.
func addAnalyzeFlags(fs *pflag.FlagSet) {
	fs.BoolVar(&flagJSON, "json", false, "emit machine-readable JSON instead of styled text")
	fs.IntVar(&flagTop, "top", 0, "limit output to the N highest-priority recommendations (0 = all)")
	fs.BoolVar(&flagMissing, "missing-only", false, "only show tools that are not installed locally")
	fs.StringVarP(&flagContext, "context", "c", "", "scope rules to a domain (dfir, web, pwn, net, ad, sysadmin, crypto, cloud, ...)")
	fs.StringVar(&flagContext, "domain", "", "alias for --context")
	fs.BoolVarP(&flagSelect, "select", "i", false, "interactively pick the context before evaluating")
	fs.IntVar(&flagMinConf, "min-confidence", engine.DefaultMinConfidence, "minimum match confidence to render (0 = show all)")
	fs.BoolVarP(&flagAll, "all", "a", false, "show every match regardless of confidence (min-confidence=0)")
	fs.BoolVar(&flagNoClassify, "no-classify", false, "disable magic-byte format gating (evaluate all domains)")
	fs.StringVar(&flagFormat, "format", "", "force the input format (e.g. email/mime, binary/elf) instead of auto-detecting")
	fs.BoolVar(&flagFlat, "flat", false, "render a flat per-plugin list instead of phase-grouped action chains")
	fs.BoolVar(&flagSemantic, "semantic", false, "enable optional local embedding-based semantic classification (requires 'advsec setup-semantic')")
	fs.BoolVar(&flagSemantic, "embedding", false, "alias for --semantic")
	fs.StringVar(&flagCmd, "cmd", "", "upstream command line to fuse (auto-detected from the pipe when omitted)")
}
