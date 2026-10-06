package engine

import (
	"strings"
	"testing"

	"github.com/grcheulishvili/advsec/pkg/osdetect"
	"github.com/grcheulishvili/advsec/pkg/plugin"
)

func TestParseExtractsNmap(t *testing.T) {
	in := "Nmap scan report for 10.10.10.5\n22/tcp open ssh\n445/tcp open microsoft-ds\n"
	ctx := ParseString(in)
	if got := ctx.First(EntityIP); got != "10.10.10.5" {
		t.Fatalf("ip = %q, want 10.10.10.5", got)
	}
	ports := ctx.Entities[EntityPort]
	if len(ports) != 2 || ports[0] != "22" || ports[1] != "445" {
		t.Fatalf("ports = %v, want [22 445]", ports)
	}
}

func TestParseRejectsTimestampNoise(t *testing.T) {
	in := "Oct 05 10:00:01 host sshd[123]: Failed password from 203.0.113.9 port 4444\n"
	ctx := ParseString(in)
	if ctx.Has(EntityIPv6) {
		t.Fatalf("timestamp wrongly parsed as ipv6: %v", ctx.Entities[EntityIPv6])
	}
	for _, p := range ctx.Entities[EntityPort] {
		if strings.HasPrefix(p, "0") {
			t.Fatalf("leading-zero port leaked: %v", ctx.Entities[EntityPort])
		}
	}
	if ctx.First(EntityIP) != "203.0.113.9" {
		t.Fatalf("ip = %q, want 203.0.113.9", ctx.First(EntityIP))
	}
}

func TestParseIPv6AndDomain(t *testing.T) {
	ctx := ParseString("conn from fe80::1 to blog.target.com:8443 lib=libc.so\n")
	if !ctx.Has(EntityIPv6) {
		t.Fatal("expected ipv6 fe80::1")
	}
	if ctx.First(EntityDomain) != "blog.target.com" {
		t.Fatalf("domain = %q", ctx.First(EntityDomain))
	}
	if ctx.First(EntityPort) != "8443" {
		t.Fatalf("port = %q, want 8443", ctx.First(EntityPort))
	}
	// libc.so must not be treated as a domain.
	for _, d := range ctx.Entities[EntityDomain] {
		if strings.HasSuffix(d, ".so") {
			t.Fatalf("filename parsed as domain: %v", ctx.Entities[EntityDomain])
		}
	}
}

func TestInvalidIPv4Rejected(t *testing.T) {
	ctx := ParseString("version 999.1.2.3 and 1.2.3.4")
	ips := ctx.Entities[EntityIP]
	if len(ips) != 1 || ips[0] != "1.2.3.4" {
		t.Fatalf("ips = %v, want [1.2.3.4]", ips)
	}
}

func testPlugin() plugin.Plugin {
	return plugin.Plugin{
		ID:         "t-elf",
		Name:       "Test ELF",
		TargetType: "binary",
		OSPackages: map[string][]string{
			"arch":   {"checksec", "gdb"},
			"debian": {"checksec", "gdb"},
		},
		Match: plugin.Match{
			Logic: "all",
			Rules: []plugin.Rule{{Regex: "ELF 64-bit"}, {Regex: "not stripped"}},
		},
		Tactics: plugin.Tactics{
			Phase:    "Pwn",
			NextStep: "exploit it",
			Priority: 50,
			Tools: []plugin.Tool{
				{Name: "checksec", Binary: "checksec", Command: "checksec --file={target}", Purpose: "protections"},
			},
		},
	}
}

func TestMatcherAllLogic(t *testing.T) {
	m := NewMatcher([]plugin.Plugin{testPlugin()})
	hit := m.Evaluate(ParseString("ELF 64-bit LSB, not stripped"))
	if len(hit) != 1 {
		t.Fatalf("expected 1 match, got %d", len(hit))
	}
	miss := m.Evaluate(ParseString("ELF 64-bit LSB, stripped"))
	if len(miss) != 0 {
		t.Fatalf("all-logic should not match when one rule fails, got %d", len(miss))
	}
}

func TestMatcherAnyLogic(t *testing.T) {
	p := testPlugin()
	p.Match.Logic = "any"
	m := NewMatcher([]plugin.Plugin{p})
	if len(m.Evaluate(ParseString("just ELF 64-bit here"))) != 1 {
		t.Fatal("any-logic should match on a single rule hit")
	}
}

func TestEvaluatorExpandsAndRecommendsInstall(t *testing.T) {
	host := osdetect.HostInfo{Family: osdetect.FamilyDebian, Manager: debianManager()}
	ctx := ParseString("file target.bin: ELF 64-bit, not stripped; host 10.0.0.9")
	// Force a domain-less target so {target} falls back to the IP.
	matches := NewMatcher([]plugin.Plugin{testPlugin()}).Evaluate(ctx)
	rep := NewEvaluator(host).Evaluate(ctx, matches)
	if len(rep.Recommendations) != 1 {
		t.Fatalf("want 1 rec, got %d", len(rep.Recommendations))
	}
	tool := rep.Recommendations[0].Tools[0]
	if !strings.Contains(tool.Command, "10.0.0.9") {
		t.Fatalf("placeholder not expanded: %q", tool.Command)
	}
	// checksec almost certainly not installed in CI → expect an apt install line.
	if !tool.Installed && !strings.HasPrefix(tool.InstallCommand, "sudo apt install") {
		t.Fatalf("install command = %q", tool.InstallCommand)
	}
}

// debianManager mirrors the internal apt manager for test isolation.
func debianManager() osdetect.PackageManager {
	return osdetect.PackageManager{
		Name:            "apt",
		InstallTemplate: "sudo apt install -y %s",
		RefreshCommand:  "sudo apt update",
	}
}
