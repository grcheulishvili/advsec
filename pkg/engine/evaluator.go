package engine

import (
	"sort"
	"strings"

	"github.com/grcheulishvili/advsec/pkg/osdetect"
	"github.com/grcheulishvili/advsec/pkg/plugin"
)

// ToolRec is a single resolved, capability-checked tool recommendation.
type ToolRec struct {
	Name           string
	Purpose        string
	Command        string // placeholder-expanded
	Binary         string
	Installed      bool
	InstallCommand string // empty when already installed or no package mapping
}

// Recommendation is a matched plugin rendered into actionable output for a
// specific host.
type Recommendation struct {
	PluginID   string
	Name       string
	Domain     string
	Phase      string
	NextStep   string
	Score      int
	Confidence int
	Tools      []ToolRec
}

// Report is the complete evaluation result for one parsed input.
type Report struct {
	Host            osdetect.HostInfo
	Context         *Context
	Recommendations []Recommendation
}

// Evaluator turns Matches into host-specific Recommendations.
type Evaluator struct {
	host osdetect.HostInfo
}

// NewEvaluator builds an Evaluator bound to a detected host.
func NewEvaluator(host osdetect.HostInfo) *Evaluator {
	return &Evaluator{host: host}
}

// Evaluate ranks matches, expands command placeholders, checks local tool
// availability, and attaches install commands for missing tools.
func (e *Evaluator) Evaluate(ctx *Context, matches []Match) *Report {
	rep := &Report{Host: e.host, Context: ctx}

	// Highest score first; stable by plugin ID for deterministic output.
	sort.SliceStable(matches, func(i, j int) bool {
		if matches[i].Score != matches[j].Score {
			return matches[i].Score > matches[j].Score
		}
		return matches[i].Plugin.ID < matches[j].Plugin.ID
	})

	for _, m := range matches {
		rec := Recommendation{
			PluginID:   m.Plugin.ID,
			Name:       m.Plugin.Name,
			Domain:     m.Plugin.Domain,
			Phase:      m.Plugin.Tactics.Phase,
			NextStep:   m.Plugin.Tactics.NextStep,
			Score:      m.Score,
			Confidence: m.Confidence,
		}
		for _, t := range m.Plugin.Tactics.Tools {
			rec.Tools = append(rec.Tools, e.resolveTool(t, m.Plugin, ctx))
		}
		rep.Recommendations = append(rep.Recommendations, rec)
	}
	return rep
}

func (e *Evaluator) resolveTool(t plugin.Tool, p plugin.Plugin, ctx *Context) ToolRec {
	binary := t.Binary
	if binary == "" {
		binary = firstWord(t.Command)
	}
	installed := osdetect.IsInstalled(binary)

	tr := ToolRec{
		Name:      t.Name,
		Purpose:   t.Purpose,
		Command:   expandPlaceholders(t.Command, ctx),
		Binary:    binary,
		Installed: installed,
	}
	if !installed {
		tr.InstallCommand = e.installCommandFor(p, t, binary)
	}
	return tr
}

// installCommandFor resolves the package(s) that provide a tool for the host
// family and renders the manager-specific install command. It first looks for
// an exact binary->package name match within the plugin's os_packages list;
// failing that it offers the whole package set for the host family; failing
// that it falls back to installing a package named after the binary.
func (e *Evaluator) installCommandFor(p plugin.Plugin, t plugin.Tool, binary string) string {
	// 1. Prefer a native package whose name matches the binary exactly.
	for _, key := range e.host.PackageKeys() {
		for _, pkg := range p.OSPackages[key] {
			if strings.EqualFold(pkg, binary) {
				return e.host.Manager.InstallCommand(pkg)
			}
		}
	}
	// 2. A manager-agnostic install hint (pip/pipx/go/cargo/script) for tools
	//    that are not distro-packaged beats guessing a package name.
	if strings.TrimSpace(t.Install) != "" {
		return strings.TrimSpace(t.Install)
	}
	// 3. Otherwise offer the full toolchain declared for this host family.
	for _, key := range e.host.PackageKeys() {
		if pkgs := p.OSPackages[key]; len(pkgs) > 0 {
			return e.host.Manager.InstallCommand(pkgs...)
		}
	}
	// 4. Last resort: assume the package shares the binary's name.
	if binary != "" {
		return e.host.Manager.InstallCommand(binary)
	}
	return ""
}

// expandPlaceholders substitutes {target}, {target_ip}, {target_domain},
// {target_port}, {target_url}, {target_hash}, and {target_addr} using parsed
// entities. Unknown or unmatched placeholders are left intact so the operator
// can see what still needs filling in.
func expandPlaceholders(cmd string, ctx *Context) string {
	repl := map[string]string{
		"{target_ip}":     ctx.First(EntityIP),
		"{target_domain}": ctx.First(EntityDomain),
		"{target_port}":   ctx.First(EntityPort),
		"{target_url}":    ctx.First(EntityURL),
		"{target_hash}":   ctx.First(EntityHash),
		"{target_addr}":   ctx.First(EntityMemAddr),
		"{target_cve}":    ctx.First(EntityCVE),
	}
	// {target} is a generic best-guess: domain, then URL, then IP.
	repl["{target}"] = firstNonEmpty(
		ctx.First(EntityDomain),
		ctx.First(EntityURL),
		ctx.First(EntityIP),
	)

	out := cmd
	for k, v := range repl {
		if v != "" {
			out = strings.ReplaceAll(out, k, v)
		}
	}
	return out
}

func firstWord(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.IndexAny(s, " \t"); i >= 0 {
		return s[:i]
	}
	return s
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
