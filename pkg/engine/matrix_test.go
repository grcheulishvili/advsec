package engine

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/grcheulishvili/advsec/pkg/osdetect"
	"github.com/grcheulishvili/advsec/pkg/plugin"
)

// matrixScenario is one realistic payload plus the behavior we expect.
type matrixScenario struct {
	name        string
	input       string
	wantFormat  Format   // "" = don't assert a specific format
	wantDomains []string // at least one recommendation in each must appear
	suppressed  []string // none of these domains may appear
}

func matrixScenarios() []matrixScenario {
	return []matrixScenario{
		{
			name:        "code/javascript (obfuscated)",
			input:       `(function(_0x4a2b){var _0x1=['log'];window[_0x1[0]];eval(atob('ZG9j'));document.cookie;})(window);`,
			wantFormat:  FormatJavaScript,
			wantDomains: []string{"js"},
			suppressed:  []string{"network", "redteam", "cloud", "wireless"},
		},
		{
			name:        "code/powershell (encoded)",
			input:       "$env:TEMP; powershell -EncodedCommand ZwBlAHQA; IEX (New-Object Net.WebClient); [System.Convert]::FromBase64String($b)",
			wantFormat:  FormatPowerShell,
			wantDomains: []string{"redteam"},
			suppressed:  []string{"web", "wireless", "cloud"},
		},
		{
			name:       "code/shell (strap.sh with GPG fingerprint)",
			input:      "#!/bin/sh\nset -e\nsudo pacman-key --init\nsudo pacman-key --recv-keys 3056513887B78AEB0ECADC3CF45D6C00F7E14B0B\nexport PATH=/usr/local/bin:$PATH\n",
			wantFormat: FormatShell,
			suppressed: []string{"wireless"},
		},
		{
			name:        "network/nmap (multi-port + vendor url)",
			input:       "Starting Nmap 7.94 ( https://nmap.org )\nNmap scan report for shop.victim.test (203.0.113.10)\nPORT    STATE SERVICE\n80/tcp  open  http\n443/tcp open  https\n",
			wantFormat:  FormatNmap,
			wantDomains: []string{"network"},
			suppressed:  []string{"wireless", "mobile"},
		},
		{
			name:        "cloud (docker.sock + kubectl + terraform)",
			input:       "found /var/run/docker.sock mounted\nkubectl get pods -A ; apiVersion: v1\nresource \"aws_iam_role\" \"x\" {}\nterraform.tfstate present\n",
			wantDomains: []string{"cloud"},
		},
		{
			name:        "dfir (ssh brute-force burst)",
			input:       "Oct 05 10:00:01 h sshd[1]: Failed password for root from 203.0.113.9 port 4444\nOct 05 10:00:02 h sshd[2]: Failed password for root from 203.0.113.9 port 4445\nOct 05 10:00:03 h sshd[3]: Failed password for admin from 203.0.113.9 port 4446\n",
			wantFormat:  FormatLog,
			wantDomains: []string{"blueteam"}, // containment/detection fires on brute-force bursts
			suppressed:  []string{"pwn", "reversing", "wireless"},
		},
		{
			name:        "email/mime (dkim/spf + attachment)",
			input:       "Received: from mx.evil.test\r\nFrom: ceo@victim.test\r\nSubject: Invoice\r\nMIME-Version: 1.0\r\nAuthentication-Results: spf=fail dkim=fail\r\nContent-Disposition: attachment; name=\"x.docm\"\r\n\r\nYmFzZTY0\r\n",
			wantFormat:  FormatEmail,
			wantDomains: []string{"eml"},
			suppressed:  []string{"network", "redteam", "cloud", "wireless"},
		},
		{
			name:        "binary/elf (unstripped)",
			input:       "\x7fELF\x02\x01\x01\x00 target.bin: ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped",
			wantFormat:  FormatELF,
			wantDomains: []string{"pwn", "reversing"},
			suppressed:  []string{"web", "cloud", "eml", "wireless"},
		},
		{
			name:       "binary/pe",
			input:      "MZ\x90\x00\x03 This program cannot be run in DOS mode. PE  L  implant.exe",
			wantFormat: FormatPE,
			suppressed: []string{"web", "eml", "wireless"},
		},
	}
}

func matrixReport(t *testing.T, plugins []plugin.Plugin, in string) (*Context, *Report) {
	t.Helper()
	ctx := ParseString(in)
	scoped := FilterByFormat(plugins, ctx.Format)
	matches := NewMatcher(scoped).Evaluate(ctx)
	kept := matches[:0]
	for _, m := range matches {
		if m.Confidence >= DefaultMinConfidence {
			kept = append(kept, m)
		}
	}
	host := osdetect.HostInfo{Family: osdetect.FamilyDebian,
		Manager: osdetect.PackageManager{Name: "apt", InstallTemplate: "sudo apt install -y %s"}}
	return ctx, NewEvaluator(host).Evaluate(ctx, kept)
}

func recDomains(r *Report) map[string]bool {
	m := map[string]bool{}
	for _, rec := range r.Recommendations {
		m[rec.Domain] = true
	}
	return m
}

func TestMatrixDomains(t *testing.T) {
	plugins := plugin.LoadFromDirs([]string{"../../plugins"}).Plugins
	for _, sc := range matrixScenarios() {
		t.Run(sc.name, func(t *testing.T) {
			ctx, report := matrixReport(t, plugins, sc.input)
			if sc.wantFormat != "" && ctx.Format != sc.wantFormat {
				t.Errorf("format = %q, want %q", ctx.Format, sc.wantFormat)
			}
			doms := recDomains(report)
			for _, d := range sc.wantDomains {
				if !doms[d] {
					t.Errorf("expected a %q recommendation; got domains %v", d, keys(doms))
				}
			}
			for _, d := range sc.suppressed {
				if doms[d] {
					t.Errorf("domain %q should be suppressed for this input", d)
				}
			}
			// No raw placeholders in any rendered command.
			for _, rec := range report.Recommendations {
				for _, tool := range rec.Tools {
					assertNoRawPlaceholder(t, tool.Command, rec.PluginID)
				}
			}
		})
	}
}

// TestMatrixGPGFingerprint locks the GPG-vs-SHA1 disambiguation.
func TestMatrixGPGFingerprint(t *testing.T) {
	ctx := ParseString("sudo pacman-key --recv-keys 3056513887B78AEB0ECADC3CF45D6C00F7E14B0B")
	if !ctx.Has(EntityGPGKey) {
		t.Fatal("GPG fingerprint not recognized")
	}
	if ctx.Has(EntityHash) {
		t.Fatalf("GPG fingerprint misclassified as a hash: %v", ctx.Entities[EntityHash])
	}
	// A bare SHA-1 (no GPG context) must remain a hash.
	ctx2 := ParseString("sha1: da39a3ee5e6b4b0d3255bfef95601890afd80709")
	if !ctx2.Has(EntityHash) || ctx2.Has(EntityGPGKey) {
		t.Fatalf("bare SHA-1 misclassified: hash=%v gpg=%v", ctx2.Entities[EntityHash], ctx2.Entities[EntityGPGKey])
	}
}

// TestMatrixGlobalPlaceholderSanity renders every tool of every bundled plugin
// under several contexts and asserts no raw template tag survives.
func TestMatrixGlobalPlaceholderSanity(t *testing.T) {
	plugins := plugin.LoadFromDirs([]string{"../../plugins"}).Plugins
	ctxs := []*Context{
		ParseString(""),
		ParseString("Nmap scan report for h.test (198.51.100.7)\nhttps://h.test/a 0ad4d7e750c2607ecc9dc4ce5f84d57bfccca1ede2756909d4933c4dab12cd34"),
	}
	n := 0
	for _, ctx := range ctxs {
		for _, p := range plugins {
			for _, tool := range p.Tactics.Tools {
				assertNoRawPlaceholder(t, expandPlaceholders(tool.Command, ctx), p.ID)
				n++
			}
		}
	}
	t.Logf("checked %d tool-command renderings for placeholder leaks", n)
}

// TestMatrixDiagnostics runs every scenario, inspects the output for anomalies,
// and prints a self-diagnostic report (visible under `go test -v`). Advisory
// findings are reported, not failed; only hard contract breaks fail elsewhere.
func TestMatrixDiagnostics(t *testing.T) {
	plugins := plugin.LoadFromDirs([]string{"../../plugins"}).Plugins
	type finding struct{ scenario, kind, detail, fix string }
	var findings []finding

	for _, sc := range matrixScenarios() {
		ctx, report := matrixReport(t, plugins, sc.input)

		// (a) format misclassification
		if sc.wantFormat != "" && ctx.Format != sc.wantFormat {
			findings = append(findings, finding{sc.name, "misclassified-format",
				fmt.Sprintf("got %q want %q", ctx.Format, sc.wantFormat),
				"tighten the signature in classifier.go for this format"})
		}
		// (a2) no coverage: a recognized format produced zero recommendations
		if len(report.Recommendations) == 0 {
			findings = append(findings, finding{sc.name, "no-coverage",
				"format " + string(ctx.Format) + " matched no plugin",
				"add a plugin for this format/domain"})
		}
		// (b) vendor noise in extracted domains/URLs
		for _, d := range ctx.Entities[EntityDomain] {
			if isIgnoredDomain(d) {
				findings = append(findings, finding{sc.name, "vendor-noise-artifact",
					"vendor host leaked as a target domain: " + d,
					"add the host to pkg/engine/ignorelist.go"})
			}
		}
		for _, u := range ctx.Entities[EntityURL] {
			if isIgnoredDomain(urlHost(u)) {
				findings = append(findings, finding{sc.name, "vendor-noise-artifact",
					"vendor URL leaked: " + u,
					"filter the URL host in parser.go via isIgnoredDomain"})
			}
		}
		// (c) missing asset with no fallback tip, and (d) out-of-order chains
		prevStep := 0
		for _, rec := range report.Recommendations {
			seq := BuildSequence(report, rec.Domain, InferIntent(ctx))
			_ = seq
			for _, tool := range rec.Tools {
				for _, a := range tool.AssetNotes {
					if a.Substituted == "" && a.Tip == "" {
						findings = append(findings, finding{sc.name, "missing-asset-no-tip",
							"asset " + a.Path + " in " + rec.PluginID,
							"add an install tip branch in assets.go for this path class"})
					}
				}
			}
		}
		_ = prevStep

		// (e) action-chain ordering within the resolved domain
		dom := ""
		for _, rec := range report.Recommendations {
			if rec.Domain != "" && rec.Domain != "general" {
				dom = rec.Domain
				break
			}
		}
		seq := BuildSequence(report, dom, InferIntent(ctx))
		last := 0
		for _, ph := range seq.Phases {
			if ph.Order < last {
				findings = append(findings, finding{sc.name, "out-of-order-chain",
					fmt.Sprintf("phase %q order %d after %d", ph.Label, ph.Order, last),
					"check step tags / classifyStep in sequence.go"})
			}
			last = ph.Order
		}
	}

	// ---- print the report ----
	t.Log("================ advsec self-diagnostic report ================")
	if len(findings) == 0 {
		t.Log("no anomalies detected across " + fmt.Sprint(len(matrixScenarios())) + " domain scenarios.")
	} else {
		for _, f := range findings {
			t.Logf("[%s] %s: %s\n    proposed fix: %s", f.scenario, f.kind, f.detail, f.fix)
		}
	}
	t.Log("===============================================================")
}

// --- v1.1.0 real-world list / TLD scenarios ---

//  1. A list of Linux log-file paths must classify as text/path_list, must not
//     extract anaconda.xlog as a domain, and must yield no DNS/recon tools.
func TestRealWorld_LinuxLogFilesPathList(t *testing.T) {
	plugins := plugin.LoadFromDirs([]string{"../../plugins"}).Plugins
	in := "anaconda.xlog\n/var/log/auth.log\n/var/log/syslog\n/var/log/messages\n/var/log/kern.log\n"
	ctx, report := matrixReport(t, plugins, in)
	if ctx.Format != FormatPathList {
		t.Fatalf("format = %q, want text/path_list", ctx.Format)
	}
	for _, d := range ctx.Entities[EntityDomain] {
		if d == "anaconda.xlog" {
			t.Fatal("anaconda.xlog was extracted as a domain")
		}
	}
	if ctx.Has(EntityDomain) {
		t.Errorf("path list should yield no target domains, got %v", ctx.Entities[EntityDomain])
	}
	for _, rec := range report.Recommendations {
		for _, tool := range rec.Tools {
			for _, bad := range []string{"subfinder", "amass", "httpx", "dnsrecon", "dnsx"} {
				if strings.Contains(tool.Command, bad) {
					t.Errorf("path list produced a DNS/recon tool %q", bad)
				}
			}
		}
	}
}

//  2. A payload cheat-sheet (XSS + SQLi + traversal + an MD5) must classify as a
//     payload/word list, NOT code/javascript, and must not scan a dummy target.
func TestRealWorld_OffensivePayloadList(t *testing.T) {
	plugins := plugin.LoadFromDirs([]string{"../../plugins"}).Plugins
	in := strings.Join([]string{
		`<script>alert(document.cookie)</script>`,
		`<img src=x onerror=alert(1)>`,
		`' OR '1'='1' --`,
		`admin' UNION SELECT username,password FROM users--`,
		`../../../../etc/passwd`,
		`%2e%2e%2f%2e%2e%2fetc%2fpasswd`,
		`d41d8cd98f00b204e9800998ecf8427e`,
		`192.168.1.6`,
	}, "\n")
	ctx, report := matrixReport(t, plugins, in)
	if ctx.Format != FormatPayloadList && ctx.Format != FormatWordlist {
		t.Fatalf("format = %q, want payload/word list (not code/javascript)", ctx.Format)
	}
	if ctx.Has(EntityIP) || ctx.Has(EntityHash) {
		t.Errorf("payload lines should not be mined for IP/hash: ip=%v hash=%v",
			ctx.Entities[EntityIP], ctx.Entities[EntityHash])
	}
	for _, rec := range report.Recommendations {
		if rec.Domain != "general" {
			t.Errorf("payload list routed to non-general domain %q (%s)", rec.Domain, rec.PluginID)
		}
	}
	if InferIntent(ctx) != IntentNone {
		t.Errorf("payload list must not infer an intent, got %q", InferIntent(ctx))
	}
}

// 3. Domain suffix guard.
func TestRealWorld_DomainSuffixGuard(t *testing.T) {
	reject := []string{"file.txt", "script.php", "data.xlog", "archive.7z",
		"One-Liner-Reverse-Shell.php", "anaconda.xlog", "notes.md", "a.out"}
	for _, s := range reject {
		if IsValidDomain(s) {
			t.Errorf("IsValidDomain(%q) = true, want false", s)
		}
	}
	accept := []string{"target.com", "sub.domain.local", "api.mod.gov.ge",
		"example.org", "host.internal", "a.io"}
	for _, s := range accept {
		if !IsValidDomain(s) {
			t.Errorf("IsValidDomain(%q) = false, want true", s)
		}
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		if k != "" {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

var _ = strings.TrimSpace
