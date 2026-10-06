package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/grcheulishvili/advsec/pkg/engine"
	"github.com/grcheulishvili/advsec/pkg/osdetect"
	"github.com/grcheulishvili/advsec/pkg/plugin"
)

// EnvContext lets the user pin a default context (e.g. export ADVSEC_CONTEXT=dfir).
const EnvContext = "ADVSEC_CONTEXT"

var flagInputFile string

func newAnalyzeCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "analyze",
		Short: "Analyze piped input and recommend next steps (default command)",
		Long: `Reads stdin (or --input FILE), parses it for actionable entities,
matches it against the plugin matrix, and prints prioritized recommendations.`,
		RunE: runAnalyze,
	}
	addAnalyzeFlags(c.Flags())
	c.Flags().StringVarP(&flagInputFile, "input", "f", "", "read input from FILE instead of stdin")
	return c
}

// resolveContext determines the active context from (in priority order) the
// --context/--domain flag, then $ADVSEC_CONTEXT. The result is canonicalized.
func resolveContext() string {
	raw := flagContext
	if raw == "" {
		raw = os.Getenv(EnvContext)
	}
	return plugin.CanonicalDomain(raw)
}

func runAnalyze(cmd *cobra.Command, args []string) error {
	input, err := readInput()
	if err != nil {
		return err
	}
	if strings.TrimSpace(input) == "" {
		return fmt.Errorf("no input: pipe data in (e.g. `file bin | advsec`) or use --input FILE")
	}

	ctx := engine.ParseString(input)
	host := osdetect.Detect()

	dirs := plugin.SearchDirs()
	if flagPluginsDir != "" {
		dirs = append([]string{flagPluginsDir}, dirs...)
	}
	load := plugin.LoadFromDirs(dirs)
	for _, e := range load.Errors {
		fmt.Fprintln(os.Stderr, "advsec: warning: "+e.Error())
	}

	// Resolve context: flag/env, or an interactive picker with --select.
	activeCtx := resolveContext()
	if flagSelect {
		picked, perr := selectContext(plugin.AvailableDomains(load.Plugins), activeCtx)
		if perr != nil {
			fmt.Fprintln(os.Stderr, "advsec: "+perr.Error())
		} else {
			activeCtx = picked
		}
	}
	if activeCtx != "" && !plugin.IsKnownDomain(activeCtx) {
		fmt.Fprintf(os.Stderr, "advsec: warning: unknown context %q; evaluating all domains\n", activeCtx)
		activeCtx = ""
	}

	// Determine the effective format (auto-detected or forced via --format).
	format := ctx.Format
	if flagFormat != "" {
		format = engine.Format(flagFormat)
	}

	// Rule scoping precedence: an explicit context wins; otherwise the
	// classified stream format gates which domains are relevant (so raw .eml
	// doesn't trigger Kerberoasting/Docker/SDR/etc).
	plugins := load.Plugins
	switch {
	case activeCtx != "":
		plugins = plugin.FilterByContext(plugins, activeCtx)
	case !flagNoClassify && engine.FormatRestricts(format):
		plugins = engine.FilterByFormat(plugins, format)
	}

	matcher := engine.NewMatcher(plugins)
	matches := matcher.Evaluate(ctx)

	// Confidence gate (suppresses weak, incidental matches).
	minConf := flagMinConf
	if flagAll {
		minConf = 0
	}
	if minConf > 0 {
		kept := matches[:0]
		for _, m := range matches {
			if m.Confidence >= minConf {
				kept = append(kept, m)
			}
		}
		matches = kept
	}

	report := engine.NewEvaluator(host).Evaluate(ctx, matches)

	if flagTop > 0 && len(report.Recommendations) > flagTop {
		report.Recommendations = report.Recommendations[:flagTop]
	}
	if flagMissing {
		filterMissing(report)
	}

	if flagJSON {
		return emitJSON(report, activeCtx, format)
	}
	renderText(os.Stdout, report, activeCtx, format)
	return nil
}

func readInput() (string, error) {
	if flagInputFile != "" {
		data, err := os.ReadFile(flagInputFile)
		if err != nil {
			return "", err
		}
		return string(data), nil
	}
	st, _ := os.Stdin.Stat()
	if st != nil && (st.Mode()&os.ModeCharDevice) != 0 {
		return "", fmt.Errorf("no input: pipe data in (e.g. `nmap -sV host | advsec`) or use --input FILE")
	}
	c, err := engine.Parse(io.Reader(os.Stdin))
	if err != nil {
		return "", err
	}
	return c.Raw, nil
}

func filterMissing(r *engine.Report) {
	var keep []engine.Recommendation
	for _, rec := range r.Recommendations {
		var tools []engine.ToolRec
		for _, t := range rec.Tools {
			if !t.Installed {
				tools = append(tools, t)
			}
		}
		if len(tools) > 0 {
			rec.Tools = tools
			keep = append(keep, rec)
		}
	}
	r.Recommendations = keep
}

// ---- JSON output ----

type jsonAssetNote struct {
	Path        string `json:"path"`
	Substituted string `json:"substituted,omitempty"`
	Tip         string `json:"tip,omitempty"`
}

type jsonTool struct {
	Name           string          `json:"name"`
	Purpose        string          `json:"purpose"`
	Command        string          `json:"command"`
	Binary         string          `json:"binary"`
	Installed      bool            `json:"installed"`
	InstallCommand string          `json:"install_command,omitempty"`
	Step           int             `json:"step,omitempty"`
	PhaseLabel     string          `json:"phase_label,omitempty"`
	AssetNotes     []jsonAssetNote `json:"asset_notes,omitempty"`
}

type jsonRec struct {
	PluginID   string     `json:"plugin_id"`
	Name       string     `json:"name"`
	Domain     string     `json:"domain"`
	Phase      string     `json:"phase"`
	NextStep   string     `json:"next_step"`
	Score      int        `json:"score"`
	Confidence int        `json:"confidence"`
	Tools      []jsonTool `json:"tools"`
}

type jsonReport struct {
	Context string `json:"context,omitempty"`
	Format  string `json:"format,omitempty"`
	Host    struct {
		ID         string `json:"id"`
		PrettyName string `json:"pretty_name"`
		Family     string `json:"family"`
		Manager    string `json:"package_manager"`
	} `json:"host"`
	Entities        map[string][]string `json:"entities"`
	Recommendations []jsonRec           `json:"recommendations"`
}

func emitJSON(r *engine.Report, activeCtx string, format engine.Format) error {
	var jr jsonReport
	jr.Context = activeCtx
	jr.Format = string(format)
	jr.Host.ID = r.Host.ID
	jr.Host.PrettyName = r.Host.PrettyName
	jr.Host.Family = string(r.Host.Family)
	jr.Host.Manager = r.Host.Manager.Name
	jr.Entities = map[string][]string{}
	for k, v := range r.Context.Entities {
		jr.Entities[string(k)] = v
	}
	for _, rec := range r.Recommendations {
		j := jsonRec{
			PluginID: rec.PluginID, Name: rec.Name, Domain: rec.Domain,
			Phase: rec.Phase, NextStep: rec.NextStep, Score: rec.Score, Confidence: rec.Confidence,
		}
		for _, t := range rec.Tools {
			jt := jsonTool{
				Name: t.Name, Purpose: t.Purpose, Command: t.Command,
				Binary: t.Binary, Installed: t.Installed, InstallCommand: t.InstallCommand,
				Step: t.Step, PhaseLabel: t.PhaseLabel,
			}
			for _, n := range t.AssetNotes {
				jt.AssetNotes = append(jt.AssetNotes, jsonAssetNote{Path: n.Path, Substituted: n.Substituted, Tip: n.Tip})
			}
			j.Tools = append(j.Tools, jt)
		}
		jr.Recommendations = append(jr.Recommendations, j)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(jr)
}
