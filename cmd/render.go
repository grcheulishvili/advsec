package cmd

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"

	"github.com/grcheulishvili/advsec/pkg/engine"
	"github.com/grcheulishvili/advsec/pkg/plugin"
)

// highConfidenceOrder lists the entity kinds worth surfacing as the "target
// artifact", most significant first.
var highConfidenceOrder = []engine.EntityKind{
	engine.EntityHash, engine.EntityURL, engine.EntityDomain,
	engine.EntityIP, engine.EntityIPv6, engine.EntityCVE, engine.EntityEmail,
}

func renderText(w io.Writer, r *engine.Report, activeCtx string, format engine.Format) {
	color := !flagNoColor && isTTY(w)
	s := newStyles(color)

	// ---- header box ----
	ctxLabel := "ALL DOMAINS"
	if activeCtx != "" {
		ctxLabel = strings.ToUpper(activeCtx)
	} else if format != "" && format != engine.FormatText && engine.FormatRestricts(format) {
		// No explicit context but the format scoped us — reflect that.
		ctxLabel = strings.ToUpper(string(format))
	}
	osLabel := orUnknown(r.Host.PrettyName)
	header := fmt.Sprintf("%s │ %s (%s) │ Context: [%s]",
		s.brand.Render("ADVSEC"), osLabel, r.Host.Manager.Name, s.ctx.Render(ctxLabel))
	fmt.Fprintln(w, s.box.Render(header))
	if format != "" && format != engine.FormatText {
		fmt.Fprintf(w, "%s %s\n", s.label.Render("Input Format:   "), s.value.Render(string(format)))
	}

	// ---- target artifact ----
	if kind, val := primaryArtifact(r.Context); val != "" {
		fmt.Fprintf(w, "%s %s\n", s.label.Render("Target Artifact:"), artifactName(kind, val))
		fmt.Fprintf(w, "%s %s\n", s.label.Render("Value:          "), s.value.Render(truncate(val, 64)))
	}

	if len(r.Recommendations) == 0 {
		fmt.Fprintln(w)
		if activeCtx != "" {
			fmt.Fprintln(w, s.warn.Render("No matching plugins in context '"+activeCtx+"'."))
			fmt.Fprintln(w, s.dim.Render("Widen with --context '' or lower --min-confidence."))
		} else {
			fmt.Fprintln(w, s.warn.Render("No high-confidence matches for this input."))
			fmt.Fprintln(w, s.dim.Render("Try --all to see weak matches, or add rules under "+plugin.UserPluginDir()+"."))
		}
		return
	}

	// ---- recommendations ----
	for i, rec := range r.Recommendations {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "%s %s\n", s.index.Render(fmt.Sprintf("[%d]", i+1)), s.title.Render(rec.Name))
		fmt.Fprintln(w, s.rule.Render(strings.Repeat("─", 74)))
		if rec.NextStep != "" {
			fmt.Fprintf(w, "%s %s\n", s.label.Render("Tactical Objective:"), rec.NextStep)
		}
		for _, t := range rec.Tools {
			fmt.Fprintln(w)
			renderTool(w, s, t)
		}
	}

	// ---- smart (non-intrusive) context suggestion ----
	if activeCtx == "" {
		suggestContext(r.Recommendations)
	}
}

func renderTool(w io.Writer, s styles, t engine.ToolRec) {
	if t.Installed {
		fmt.Fprintf(w, "%s %s %s\n", s.ok.Render("✔"), s.toolName.Render(t.Name), s.okDim.Render("(installed)"))
	} else {
		fmt.Fprintf(w, "%s %s %s\n", s.miss.Render("✖"), s.toolName.Render(t.Name), s.missDim.Render("(missing)"))
	}
	if t.Command != "" {
		fmt.Fprintln(w, "  "+s.cmd.Render("$ "+t.Command))
	}
	if t.Purpose != "" {
		fmt.Fprintln(w, "  "+s.label.Render("Purpose:")+" "+s.dim.Render(t.Purpose))
	}
	for _, n := range t.AssetNotes {
		if n.Substituted != "" {
			fmt.Fprintln(w, "  "+s.okDim.Render("[i] Using detected asset: "+n.Substituted))
		} else {
			fmt.Fprintln(w, "  "+s.warn.Render("[!] Missing Asset: "+n.Path))
			if n.Tip != "" {
				fmt.Fprintln(w, "      "+s.install.Render("Install: "+n.Tip))
			}
		}
	}
	if !t.Installed && t.InstallCommand != "" {
		fmt.Fprintln(w, "  "+s.install.Render("Install: "+t.InstallCommand))
	}
}

// suggestContext prints, to stderr, a one-line hint when results span multiple
// domains — a suggestion, never an automatic switch.
func suggestContext(recs []engine.Recommendation) {
	seen := map[string]bool{}
	var domains []string
	for _, rec := range recs {
		if rec.Domain != "" && rec.Domain != "general" && !seen[rec.Domain] {
			seen[rec.Domain] = true
			domains = append(domains, rec.Domain)
		}
	}
	if len(domains) < 2 {
		return
	}
	s := newStyles(!flagNoColor && isTTY(os.Stderr))
	shown := domains
	if len(shown) > 4 {
		shown = shown[:4]
	}
	fmt.Fprintln(os.Stderr, s.dim.Render(
		fmt.Sprintf("tip: results span %s — scope with  -c <domain>  (or export ADVSEC_CONTEXT)",
			strings.Join(shown, ", "))))
}

// primaryArtifact picks the most significant high-confidence entity to display.
func primaryArtifact(ctx *engine.Context) (engine.EntityKind, string) {
	for _, k := range highConfidenceOrder {
		if v := ctx.First(k); v != "" {
			return k, v
		}
	}
	return "", ""
}

func artifactName(kind engine.EntityKind, val string) string {
	switch kind {
	case engine.EntityHash:
		switch len(val) {
		case 32:
			return "Hash (MD5)"
		case 40:
			return "Hash (SHA-1)"
		case 64:
			return "Hash (SHA-256)"
		case 128:
			return "Hash (SHA-512)"
		default:
			return "Hash"
		}
	case engine.EntityURL:
		return "URL"
	case engine.EntityDomain:
		return "Domain"
	case engine.EntityIP:
		return "IPv4 Address"
	case engine.EntityIPv6:
		return "IPv6 Address"
	case engine.EntityCVE:
		return "CVE Identifier"
	case engine.EntityEmail:
		return "Email Address"
	}
	return "Artifact"
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 3 {
		return s[:n]
	}
	return s[:n-3] + "..."
}

func orUnknown(s string) string {
	if s == "" {
		return "unknown OS"
	}
	return s
}

// ---- styling ----

type styles struct {
	box, brand, ctx, label, value, index, title, rule, cmd,
	toolName, ok, okDim, miss, missDim, install, dim, warn lipgloss.Style
}

func newStyles(color bool) styles {
	if !color {
		p := lipgloss.NewStyle()
		// Keep the header border (box-drawing runes carry no color) for layout
		// parity in piped / no-color output.
		box := lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).Padding(0, 1)
		return styles{box: box, brand: p, ctx: p, label: p, value: p, index: p,
			title: p, rule: p, cmd: p, toolName: p, ok: p, okDim: p, miss: p,
			missDim: p, install: p, dim: p, warn: p}
	}
	return styles{
		box:      lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(lipgloss.Color("63")).Padding(0, 1),
		brand:    lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("231")).Background(lipgloss.Color("63")).Padding(0, 1),
		ctx:      lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("213")),
		label:    lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("111")),
		value:    lipgloss.NewStyle().Foreground(lipgloss.Color("150")),
		index:    lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("214")),
		title:    lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("81")),
		rule:     lipgloss.NewStyle().Foreground(lipgloss.Color("240")),
		cmd:      lipgloss.NewStyle().Foreground(lipgloss.Color("150")),
		toolName: lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("255")),
		ok:       lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("76")),
		okDim:    lipgloss.NewStyle().Foreground(lipgloss.Color("71")),
		miss:     lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("203")),
		missDim:  lipgloss.NewStyle().Foreground(lipgloss.Color("244")),
		install:  lipgloss.NewStyle().Foreground(lipgloss.Color("209")),
		dim:      lipgloss.NewStyle().Foreground(lipgloss.Color("244")),
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
