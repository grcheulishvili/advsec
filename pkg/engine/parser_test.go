package engine

import (
	"strings"
	"testing"

	"github.com/grcheulishvili/advsec/pkg/osdetect"
	"github.com/grcheulishvili/advsec/pkg/plugin"
)

// fileInspectionBinaries are tools that take a file/stream argument and must
// never receive an extracted IP/URL as a filename.
var fileInspectionBinaries = map[string]bool{
	"jq": true, "yq": true, "rg": true, "xxd": true, "pdfid": true,
	"pdfinfo": true, "pdftotext": true, "sqlite3": true, "7z": true,
	"tar": true, "binwalk": true, "olevba": true, "samtools": true,
}

// mullvadLog is a realistic Mullvad VPN daemon log burst: bracketed ISO
// timestamps, a lifecycle line, a component tag, a service log path, and an
// upstream relay IP. It intentionally contains NO ".json" token.
const mullvadLog = `[2026-10-07 09:11:26.519][mullvad_daemon][INFO] Starting mullvad-daemon - 2026.4
[2026-10-07 09:11:27.004][talpid_core::tunnel_state_machine][INFO] Connecting to relay 45.83.223.196:51820 over WireGuard
[2026-10-07 09:11:28.223][mullvad_daemon][ERROR] Failed to set up routing table for /var/log/mullvad-vpn/daemon.log sink
[2026-10-07 09:11:29.880][talpid_core][WARN] Tunnel monitor timed out, reconnecting to 45.83.223.196
`

func mullvadHost() osdetect.HostInfo {
	return osdetect.HostInfo{
		Family:  osdetect.FamilyDebian,
		Manager: osdetect.PackageManager{Name: "apt", InstallTemplate: "sudo apt install -y %s"},
	}
}

// TestMullvadLogFileTriage locks the v1.5.0 contextual-binding fixes end to end.
func TestMullvadLogFileTriage(t *testing.T) {
	plugins := plugin.LoadFromDirs([]string{"../../plugins"}).Plugins

	ctx := ParseString(mullvadLog)

	// 1. Timestamped log must classify as text/log, NOT text/json.
	if ctx.Format != FormatLog {
		t.Fatalf("format = %q, want text/log (timestamped log misclassified)", ctx.Format)
	}

	// 2. {systemd_unit} must resolve to the real unit.
	unit := ctx.First(EntitySystemdUnit)
	if unit != "mullvad-daemon" && unit != "mullvad-vpn" {
		t.Errorf("systemd unit = %q, want mullvad-daemon or mullvad-vpn (all: %v)",
			unit, ctx.Entities[EntitySystemdUnit])
	}

	// Run the full pipeline the way the CLI does.
	scoped := FilterByFormat(plugins, ctx.Format)
	matches := NewMatcher(scoped).Evaluate(ctx)
	kept := matches[:0]
	for _, m := range matches {
		if m.Confidence >= DefaultMinConfidence {
			kept = append(kept, m)
		}
	}
	report := NewEvaluator(mullvadHost()).Evaluate(ctx, kept)

	sawUnitCommand := false
	for _, rec := range report.Recommendations {
		// 4. Log scope must not surface web-deobfuscation or wireless domains.
		for _, bad := range []string{"js", "web", "wireless"} {
			if rec.Domain == bad {
				t.Errorf("log stream surfaced unrelated domain %q (%s)", bad, rec.PluginID)
			}
		}
		for _, tool := range rec.Tools {
			cmd := tool.Command

			// 3. No file-inspection tool may take the relay IP as a filename.
			if fileInspectionBinaries[tool.Binary] && strings.Contains(cmd, "45.83.223.196") {
				t.Errorf("%s passed an IP as a file argument: %q", tool.Binary, cmd)
			}

			// 5. No unexpanded placeholder syntax may reach the output.
			for _, raw := range []string{"<unit>", "<systemd-unit>", "<target-domain>", "<target-url>"} {
				if strings.Contains(cmd, raw) {
					t.Errorf("unresolved placeholder %q leaked in %q (%s)", raw, cmd, rec.PluginID)
				}
			}
			for _, tok := range []string{"{target}", "{target_file}", "{systemd_unit}", "{target_domain}"} {
				if strings.Contains(cmd, tok) {
					t.Errorf("raw template %q leaked in %q (%s)", tok, cmd, rec.PluginID)
				}
			}

			if strings.HasPrefix(cmd, "journalctl -u ") && strings.Contains(cmd, unit) {
				sawUnitCommand = true
			}
		}
	}

	// The dynamic {systemd_unit} substitution must have produced a real command.
	if !sawUnitCommand {
		t.Errorf("expected a `journalctl -u %s ...` command from dynamic unit substitution", unit)
	}
}

// TestTimestampedLogNotJSON isolates the classifier priority fix: a log line
// that starts with `[` and mentions a .json path is a log, not JSON.
func TestTimestampedLogNotJSON(t *testing.T) {
	cases := []string{
		"[2026-10-07 09:11:26.519] INFO loaded config from /etc/app/config.json\n",
		"2026-10-07T09:11:26Z level=error msg=\"parse failed\" file=data.json\n",
		"Oct 07 09:11:26 host app[123]: wrote /var/lib/app/state.json\n",
	}
	for _, in := range cases {
		if got := Classify(in); got != FormatLog {
			t.Errorf("Classify(%q) = %q, want text/log", in, got)
		}
	}
	// A genuine JSON document is still JSON.
	if got := Classify("{\n  \"host\": \"a.test\",\n  \"ts\": \"2026-10-07T09:11:26\"\n}\n"); got != FormatJSON {
		t.Errorf("real JSON misclassified as %q", got)
	}
}

// TestTargetFileNeverBindsNetworkEntity verifies {target_file} elides to a safe
// stream placeholder (never an IP) when no input file is known, and binds to a
// real path when one is set.
func TestTargetFileNeverBindsNetworkEntity(t *testing.T) {
	ctx := ParseString("connection to 45.83.223.196 logged\n")
	ctx.Entities[EntityIP] = appendUnique(ctx.Entities[EntityIP], "45.83.223.196")

	out, unresolved := expandPlaceholdersResolved("jq -C . {target_file} | head", ctx)
	if strings.Contains(out, "45.83.223.196") {
		t.Errorf("{target_file} bound to an IP: %q", out)
	}
	if len(unresolved) != 0 {
		t.Errorf("{target_file} should never be unresolved, got %v", unresolved)
	}
	if strings.Contains(out, "{target_file}") {
		t.Errorf("raw {target_file} left in %q", out)
	}

	ctx.InputFile = "/var/log/mullvad-vpn/daemon.log"
	out, _ = expandPlaceholdersResolved("rg -i secret {target_file}", ctx)
	if !strings.Contains(out, "/var/log/mullvad-vpn/daemon.log") {
		t.Errorf("{target_file} did not bind to InputFile: %q", out)
	}
}

// TestUnresolvableTargetDomainSuppressed verifies a {target_domain} tool with no
// domain available is dropped rather than rendering raw template syntax.
func TestUnresolvableTargetDomainSuppressed(t *testing.T) {
	ctx := ParseString("just an IP here 45.83.223.196\n")
	ctx.Entities[EntityIP] = appendUnique(ctx.Entities[EntityIP], "45.83.223.196")

	_, unresolved := expandPlaceholdersResolved("dnsx -d {target_domain}", ctx)
	if len(unresolved) == 0 {
		t.Error("expected {target_domain} to be flagged unresolved with no domain present")
	}

	// {target_url} synthesizes from the IP, so it must NOT be unresolved.
	out, unresolved := expandPlaceholdersResolved("whatweb {target_url}", ctx)
	if len(unresolved) != 0 {
		t.Errorf("{target_url} should synthesize from IP, got unresolved %v", unresolved)
	}
	if !strings.Contains(out, "http://45.83.223.196") {
		t.Errorf("{target_url} not synthesized from IP: %q", out)
	}
}
