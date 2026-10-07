package engine

import (
	"regexp"
	"sort"
	"strings"

	"github.com/grcheulishvili/advsec/pkg/osdetect"
	"github.com/grcheulishvili/advsec/pkg/plugin"
)

// ToolRec is a single resolved, capability-checked tool recommendation.
type ToolRec struct {
	Name           string
	Purpose        string
	Command        string // placeholder-expanded, asset-verified
	Binary         string
	Installed      bool
	InstallCommand string // empty when already installed or no package mapping
	// AssetNotes carries warnings/substitutions for hardcoded asset paths
	// (e.g. a missing /usr/share/wordlists/rockyou.txt).
	AssetNotes []AssetNote
	// Domain is the source plugin's domain (for sequencing + source tags).
	Domain string
	// Step / PhaseLabel are the explicit action-chain hints from the plugin
	// (0 / "" when not specified; the sequencer then infers them).
	Step       int
	PhaseLabel string
	// Source is the name of the plugin this tool came from.
	Source string
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

	// Sanity guard: on list-style streams (wordlists/payloads/paths) the only
	// relevant output is general-domain triage; drop anything else that slipped
	// through, so a payload collection never yields exploit recommendations.
	listStream := IsListFormat(ctx.Format)

	for _, m := range matches {
		if listStream {
			// On list streams, only general-domain triage applies, and archive
			// extraction rules are never relevant to a text list.
			if m.Plugin.Domain != "general" {
				continue
			}
			if m.Plugin.TargetType == "archive" || m.Plugin.Domain == "archive" {
				continue
			}
		}
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
			tr, ok := e.resolveTool(t, m.Plugin, ctx)
			if !ok {
				continue // required target placeholder could not be resolved/synthesized
			}
			rec.Tools = append(rec.Tools, tr)
		}
		// Suppress a recommendation entirely when every one of its tools was
		// dropped for unresolved placeholders, rather than emitting commands
		// full of raw <target-domain>/<systemd-unit> template syntax.
		if len(rec.Tools) == 0 {
			continue
		}
		rep.Recommendations = append(rep.Recommendations, rec)
	}
	return rep
}

func (e *Evaluator) resolveTool(t plugin.Tool, p plugin.Plugin, ctx *Context) (ToolRec, bool) {
	binary := t.Binary
	if binary == "" {
		binary = firstWord(t.Command)
	}
	installed := osdetect.IsInstalled(binary)

	expanded, unresolved := expandPlaceholdersResolved(t.Command, ctx)
	if len(unresolved) > 0 {
		return ToolRec{}, false
	}
	cmd, notes := VerifyCommandAssets(expanded, e.host.Manager)
	tr := ToolRec{
		Name:       t.Name,
		Purpose:    t.Purpose,
		Command:    cmd,
		Binary:     binary,
		Installed:  installed,
		AssetNotes: notes,
		Domain:     p.Domain,
		Step:       t.Step,
		PhaseLabel: t.PhaseLabel,
		Source:     p.Name,
	}
	if !installed {
		tr.InstallCommand = e.installCommandFor(p, t, binary)
	}
	return tr, true
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

// suppressionPlaceholders are the target-binding tokens that MUST resolve (or
// be synthesizable) for a recommendation to be useful. A command still carrying
// any of these after expansion is dropped rather than rendered with raw
// <target-domain>/<systemd-unit> template syntax.
var suppressionPlaceholders = map[string]bool{
	"{target}":        true,
	"{target_ip}":     true,
	"{target_domain}": true,
	"{target_url}":    true,
	"{systemd_unit}":  true,
}

// expandPlaceholders substitutes entity placeholders, returning only the
// rendered string. Unresolved suppression placeholders are shown as readable
// angle-bracket fallbacks here (callers that must drop such commands use
// expandPlaceholdersResolved instead).
func expandPlaceholders(cmd string, ctx *Context) string {
	out, _ := expandPlaceholdersResolved(cmd, ctx)
	return out
}

// expandPlaceholdersResolved expands all placeholders and additionally reports
// which suppression placeholders could not be resolved or synthesized.
//
//   - {target_file} binds to the real input file path, or is elided so the tool
//     reads stdin. It is NEVER bound to an IP/URL/domain.
//   - {target_url} is synthesized as http://<domain|ip> when no URL was seen.
//   - {systemd_unit} binds to a recovered systemd unit name.
//   - {target}/{target_ip}/{target_domain} bind to their entities.
//
// Any suppression placeholder with no value is returned in `unresolved`; for
// display, all leftover tokens are rewritten to angle-bracket fallbacks so raw
// {curly} syntax never reaches output.
func expandPlaceholdersResolved(cmd string, ctx *Context) (string, []string) {
	out := cmd

	// {target_file}: the real input file path, or a readable <input-file>
	// placeholder for an anonymous stdin stream. It is NEVER bound to a network
	// entity - this is the core of the file-vs-entity binding fix, so a log's
	// extracted IP can never be substituted as a filename argument.
	if strings.Contains(out, "{target_file}") {
		if ctx.InputFile != "" {
			out = strings.ReplaceAll(out, "{target_file}", ctx.InputFile)
		} else {
			out = strings.ReplaceAll(out, "{target_file}", "<input-file>")
		}
	}

	bind := map[string]string{
		"{target_ip}":     ctx.First(EntityIP),
		"{target_domain}": ctx.First(EntityDomain),
		"{target_port}":   ctx.First(EntityPort),
		"{target_hash}":   ctx.First(EntityHash),
		"{target_addr}":   ctx.First(EntityMemAddr),
		"{target_cve}":    ctx.First(EntityCVE),
		"{systemd_unit}":  ctx.First(EntitySystemdUnit),
		"{target_url}":    synthURL(ctx),
		"{target}": firstNonEmpty(
			ctx.First(EntityDomain), ctx.First(EntityURL), ctx.First(EntityIP)),
	}

	var unresolved []string
	for tok, v := range bind {
		if !strings.Contains(out, tok) {
			continue
		}
		if v != "" {
			out = strings.ReplaceAll(out, tok, v)
		} else if suppressionPlaceholders[tok] {
			unresolved = append(unresolved, tok)
		}
	}

	// Angle-bracket fallback for any token still present (display safety).
	for tmpl, ph := range placeholderFallbacks {
		out = strings.ReplaceAll(out, tmpl, ph)
	}
	return collapseSpaces(out), unresolved
}

// synthURL returns a usable URL for {target_url}: an extracted URL, else a
// synthesized http:// address over a known domain or IP, else "".
func synthURL(ctx *Context) string {
	if u := ctx.First(EntityURL); u != "" {
		return u
	}
	if d := ctx.First(EntityDomain); d != "" {
		return "http://" + d
	}
	if ip := ctx.First(EntityIP); ip != "" {
		return "http://" + ip
	}
	return ""
}

// collapseSpaces normalizes runs of spaces left by elided placeholders and
// trims the result, so `jq -C .  | head` becomes `jq -C . | head`.
func collapseSpaces(s string) string {
	s = reMultiSpace.ReplaceAllString(s, " ")
	return strings.TrimSpace(s)
}

var reMultiSpace = regexp.MustCompile(`[ \t]{2,}`)

// placeholderFallbacks maps each template token to the human placeholder shown
// when no value was available to bind.
var placeholderFallbacks = map[string]string{
	"{target_ip}":     "<target-ip>",
	"{target_domain}": "<target-domain>",
	"{target_port}":   "<target-port>",
	"{target_url}":    "<target-url>",
	"{target_hash}":   "<target-hash>",
	"{target_addr}":   "<target-addr>",
	"{target_cve}":    "<target-cve>",
	"{target}":        "<target>",
	"{systemd_unit}":  "<systemd-unit>",
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
