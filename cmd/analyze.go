package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/spf13/cobra"

	"github.com/grcheulishvili/advsec/pkg/engine"
	"github.com/grcheulishvili/advsec/pkg/osdetect"
	"github.com/grcheulishvili/advsec/pkg/plugin"
)

var flagInputFile string

func newAnalyzeCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "analyze",
		Short: "Analyze piped input and recommend next steps (default command)",
		Long: `Reads stdin (or --input FILE), parses it for actionable entities,
matches it against the plugin matrix, and prints prioritized recommendations.`,
		RunE: runAnalyze,
	}
	c.Flags().BoolVar(&flagJSON, "json", false, "emit machine-readable JSON instead of styled text")
	c.Flags().IntVar(&flagTop, "top", 0, "limit output to the N highest-priority recommendations (0 = all)")
	c.Flags().BoolVar(&flagMissing, "missing-only", false, "only show tools that are not installed locally")
	c.Flags().StringVarP(&flagInputFile, "input", "f", "", "read input from FILE instead of stdin")
	return c
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

	matcher := engine.NewMatcher(load.Plugins)
	matches := matcher.Evaluate(ctx)
	report := engine.NewEvaluator(host).Evaluate(ctx, matches)

	if flagTop > 0 && len(report.Recommendations) > flagTop {
		report.Recommendations = report.Recommendations[:flagTop]
	}
	if flagMissing {
		filterMissing(report)
	}

	if flagJSON {
		return emitJSON(report)
	}
	renderText(os.Stdout, report, len(load.Plugins))
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
	// Only read stdin when it is actually piped/redirected; a bare TTY would
	// block forever.
	st, _ := os.Stdin.Stat()
	if st != nil && (st.Mode()&os.ModeCharDevice) != 0 {
		return "", fmt.Errorf("no input: pipe data in (e.g. `nmap -sV host | advsec`) or use --input FILE")
	}
	ctx, err := engine.Parse(io.Reader(os.Stdin))
	if err != nil {
		return "", err
	}
	return ctx.Raw, nil
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

type jsonTool struct {
	Name           string `json:"name"`
	Purpose        string `json:"purpose"`
	Command        string `json:"command"`
	Binary         string `json:"binary"`
	Installed      bool   `json:"installed"`
	InstallCommand string `json:"install_command,omitempty"`
}

type jsonRec struct {
	PluginID string     `json:"plugin_id"`
	Name     string     `json:"name"`
	Phase    string     `json:"phase"`
	NextStep string     `json:"next_step"`
	Score    int        `json:"score"`
	Tools    []jsonTool `json:"tools"`
}

type jsonReport struct {
	Host struct {
		ID         string `json:"id"`
		PrettyName string `json:"pretty_name"`
		Family     string `json:"family"`
		Manager    string `json:"package_manager"`
	} `json:"host"`
	Entities        map[string][]string `json:"entities"`
	Recommendations []jsonRec           `json:"recommendations"`
}

func emitJSON(r *engine.Report) error {
	var jr jsonReport
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
			PluginID: rec.PluginID,
			Name:     rec.Name,
			Phase:    rec.Phase,
			NextStep: rec.NextStep,
			Score:    rec.Score,
		}
		for _, t := range rec.Tools {
			j.Tools = append(j.Tools, jsonTool{
				Name: t.Name, Purpose: t.Purpose, Command: t.Command,
				Binary: t.Binary, Installed: t.Installed, InstallCommand: t.InstallCommand,
			})
		}
		jr.Recommendations = append(jr.Recommendations, j)
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(jr)
}

// ---- styled text output ----

func renderText(w io.Writer, r *engine.Report, pluginCount int) {
	styles := newStyles(!flagNoColor && isTTY(w))

	// Header / host line.
	fmt.Fprintln(w, styles.title.Render(" advsec ")+" "+styles.dim.Render(
		fmt.Sprintf("%s · %s · %d plugins", orUnknown(r.Host.PrettyName), r.Host.Manager.Name, pluginCount)))

	// Parsed entities summary.
	if sum := entitySummary(r.Context); sum != "" {
		fmt.Fprintln(w, styles.dim.Render("detected: ")+sum)
	}

	if len(r.Recommendations) == 0 {
		fmt.Fprintln(w, styles.warn.Render("No matching plugins for this input."))
		fmt.Fprintln(w, styles.dim.Render("Add rules under "+plugin.UserPluginDir()+" or run `advsec plugin update`."))
		return
	}

	for i, rec := range r.Recommendations {
		fmt.Fprintln(w)
		head := fmt.Sprintf("%d. %s", i+1, rec.Name)
		fmt.Fprintln(w, styles.rec.Render(head)+"  "+styles.badge.Render(rec.Phase))
		if rec.NextStep != "" {
			fmt.Fprintln(w, "   "+styles.step.Render("→ "+rec.NextStep))
		}
		for _, t := range rec.Tools {
			renderTool(w, styles, t)
		}
	}
}

func renderTool(w io.Writer, s styles, t engine.ToolRec) {
	mark := s.ok.Render("●")
	status := ""
	if !t.Installed {
		mark = s.miss.Render("○")
		status = s.miss.Render(" [not installed]")
	}
	fmt.Fprintf(w, "   %s %s%s\n", mark, s.toolName.Render(t.Name), status)
	if t.Purpose != "" {
		fmt.Fprintln(w, "       "+s.dim.Render(t.Purpose))
	}
	if t.Command != "" {
		fmt.Fprintln(w, "       "+s.cmd.Render("$ "+t.Command))
	}
	if !t.Installed && t.InstallCommand != "" {
		fmt.Fprintln(w, "       "+s.install.Render("install: "+t.InstallCommand))
	}
}

func entitySummary(ctx *engine.Context) string {
	order := []struct {
		kind  engine.EntityKind
		label string
	}{
		{engine.EntityIP, "ip"}, {engine.EntityIPv6, "ipv6"}, {engine.EntityDomain, "domain"},
		{engine.EntityURL, "url"}, {engine.EntityPort, "port"}, {engine.EntityHash, "hash"},
		{engine.EntityMemAddr, "addr"}, {engine.EntityCVE, "cve"}, {engine.EntityEmail, "email"},
	}
	var parts []string
	for _, o := range order {
		if vals := ctx.Entities[o.kind]; len(vals) > 0 {
			show := vals
			if len(show) > 3 {
				show = append(append([]string{}, show[:3]...), fmt.Sprintf("+%d", len(vals)-3))
			}
			parts = append(parts, fmt.Sprintf("%s=%s", o.label, strings.Join(show, ",")))
		}
	}
	return strings.Join(parts, "  ")
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown OS"
	}
	return s
}

// ---- styling ----

type styles struct {
	title, dim, rec, badge, step, toolName, cmd, install, ok, miss, warn lipgloss.Style
}

func newStyles(color bool) styles {
	if !color {
		// Return attribute-free styles so Render is an identity function and
		// no ANSI escape codes are emitted at all.
		plain := lipgloss.NewStyle()
		return styles{
			title: plain, dim: plain, rec: plain, badge: plain, step: plain,
			toolName: plain, cmd: plain, install: plain, ok: plain, miss: plain, warn: plain,
		}
	}
	return styles{
		title:    lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("231")).Background(lipgloss.Color("63")),
		dim:      lipgloss.NewStyle().Foreground(lipgloss.Color("244")),
		rec:      lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("81")),
		badge:    lipgloss.NewStyle().Foreground(lipgloss.Color("213")),
		step:     lipgloss.NewStyle().Foreground(lipgloss.Color("228")),
		toolName: lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("255")),
		cmd:      lipgloss.NewStyle().Foreground(lipgloss.Color("150")),
		install:  lipgloss.NewStyle().Foreground(lipgloss.Color("209")),
		ok:       lipgloss.NewStyle().Foreground(lipgloss.Color("76")),
		miss:     lipgloss.NewStyle().Foreground(lipgloss.Color("203")),
		warn:     lipgloss.NewStyle().Foreground(lipgloss.Color("214")),
	}
}

func isTTY(w io.Writer) bool {
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	if err != nil {
		return false
	}
	return (st.Mode() & os.ModeCharDevice) != 0
}
