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
	ctx := ParseString("version 999.1.2.3 and 8.8.4.4")
	ips := ctx.Entities[EntityIP]
	if len(ips) != 1 || ips[0] != "8.8.4.4" {
		t.Fatalf("ips = %v, want [8.8.4.4]", ips)
	}
}

// --- Parser hardening (v0.3.0) ---

func TestHexErrorCodeNotAddress(t *testing.T) {
	// A Windows HRESULT in ordinary output must NOT become an ipv4/ipv6/mem_addr.
	ctx := ParseString("Installation failed with error 0x8007000D (ERROR_INVALID_DATA)")
	if ctx.Has(EntityMemAddr) {
		t.Fatalf("hex error code parsed as mem_addr: %v", ctx.Entities[EntityMemAddr])
	}
	if ctx.Has(EntityIP) || ctx.Has(EntityIPv6) {
		t.Fatalf("hex error code parsed as an IP: v4=%v v6=%v",
			ctx.Entities[EntityIP], ctx.Entities[EntityIPv6])
	}
}

func TestHexAddressInDebuggerContext(t *testing.T) {
	// In a real gdb/pwn dump, hex values ARE memory addresses.
	dump := "Program received signal SIGSEGV\n0x00007ffff7a0d1c2 in __libc_start_main\nrip 0x401136 rsp 0x7fffffffe2a0"
	ctx := ParseString(dump)
	if !ctx.Has(EntityMemAddr) {
		t.Fatalf("expected mem_addr in debugger context, got none")
	}
}

func TestLoopbackAndBindSuppressed(t *testing.T) {
	ctx := ParseString("bound to 0.0.0.0, serving on 127.0.0.1 and ::1 (localhost)")
	if ctx.Has(EntityIP) {
		t.Fatalf("loopback/bind IPv4 not suppressed: %v", ctx.Entities[EntityIP])
	}
	if ctx.Has(EntityIPv6) {
		t.Fatalf("::1 not suppressed: %v", ctx.Entities[EntityIPv6])
	}
	if ctx.ExternalTarget {
		t.Fatalf("pure-loopback input should not flag an external target")
	}
}

func TestExternalTargetFlag(t *testing.T) {
	ctx := ParseString("listening on 127.0.0.1 but connected to 93.184.216.34")
	if !ctx.ExternalTarget {
		t.Fatalf("routable IP should set ExternalTarget")
	}
	if ctx.First(EntityIP) != "93.184.216.34" {
		t.Fatalf("ip = %q, want the routable one", ctx.First(EntityIP))
	}
}

func TestStrictIPv6RejectsJunk(t *testing.T) {
	// "C:c:F:" and similar debugger/path fragments must not parse as IPv6.
	ctx := ParseString("mov eax, C:c:F: ; path C:\\Users ; group 10:00:30")
	if ctx.Has(EntityIPv6) {
		t.Fatalf("junk parsed as ipv6: %v", ctx.Entities[EntityIPv6])
	}
}

func TestValidIPv6Accepted(t *testing.T) {
	ctx := ParseString("peer 2001:db8:85a3::8a2e:370:7334 established")
	if !ctx.Has(EntityIPv6) {
		t.Fatalf("valid ipv6 not detected")
	}
}

func TestReverseDNSNotDomain(t *testing.T) {
	ctx := ParseString("PTR query for 34.216.184.93.in-addr.arpa")
	for _, d := range ctx.Entities[EntityDomain] {
		if strings.HasSuffix(d, "arpa") {
			t.Fatalf("reverse-dns zone parsed as domain: %v", ctx.Entities[EntityDomain])
		}
	}
}

func TestConfidenceWeights(t *testing.T) {
	// A single short literal is weak; a regex rule is strong.
	weak := NewMatcher([]plugin.Plugin{{
		ID: "weak", Name: "w", Domain: "general",
		Match:   plugin.Match{Logic: "any", Rules: []plugin.Rule{{Contains: "err"}}},
		Tactics: plugin.Tactics{Phase: "p", NextStep: "n", Tools: []plugin.Tool{{Name: "x", Command: "x"}}},
	}})
	m := weak.Evaluate(ParseString("err"))
	if len(m) != 1 || m[0].Confidence >= 2 {
		t.Fatalf("short literal should be low confidence, got %+v", m)
	}
	strong := NewMatcher([]plugin.Plugin{{
		ID: "strong", Name: "s", Domain: "general",
		Match:   plugin.Match{Logic: "any", Rules: []plugin.Rule{{Regex: "ELF 64-bit"}}},
		Tactics: plugin.Tactics{Phase: "p", NextStep: "n", Tools: []plugin.Tool{{Name: "x", Command: "x"}}},
	}})
	m2 := strong.Evaluate(ParseString("ELF 64-bit LSB"))
	if len(m2) != 1 || m2[0].Confidence < 2 {
		t.Fatalf("regex rule should clear threshold, got %+v", m2)
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

func TestEvaluatorUsesInstallHintWhenNoPackage(t *testing.T) {
	host := osdetect.HostInfo{Family: osdetect.FamilyDebian, Manager: debianManager()}
	p := plugin.Plugin{
		ID:    "t-pipx",
		Name:  "pip tool",
		Match: plugin.Match{Logic: "any", Rules: []plugin.Rule{{Contains: "impacket"}}},
		Tactics: plugin.Tactics{
			Phase: "AD", NextStep: "relay",
			Tools: []plugin.Tool{{
				Name: "ntlmrelayx", Binary: "ntlmrelayx.py",
				Command: "ntlmrelayx.py -t {target_ip}",
				Install: "pipx install impacket",
			}},
		},
	}
	ctx := ParseString("found impacket usage against 10.0.0.1")
	matches := NewMatcher([]plugin.Plugin{p}).Evaluate(ctx)
	rep := NewEvaluator(host).Evaluate(ctx, matches)
	tool := rep.Recommendations[0].Tools[0]
	if !tool.Installed && tool.InstallCommand != "pipx install impacket" {
		t.Fatalf("install hint not used: %q", tool.InstallCommand)
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
