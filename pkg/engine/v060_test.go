package engine

import (
	"strings"
	"testing"

	"github.com/grcheulishvili/advsec/pkg/osdetect"
)

func TestClassifyCodeAndNetworkFormats(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want Format
	}{
		{"js", "var a=function(){document.cookie; eval(atob('x'));}", FormatJavaScript},
		{"js-obf", "var _0x1a2b=['abc'];window[_0x1a2b[0]]", FormatJavaScript},
		{"powershell", "$env:TEMP; Invoke-WebRequest -Uri x; [System.Text.Encoding]::UTF8", FormatPowerShell},
		{"shell", "#!/bin/bash\nsudo chmod +x payload\n", FormatShell},
		{"nmap", "Starting Nmap 7.94\nNmap scan report for 10.10.10.5\nPORT   STATE SERVICE", FormatNmap},
		{"socket", "Netid State  Recv-Q Send-Q Local Address:Port", FormatSocket},
	}
	for _, c := range cases {
		if got := Classify(c.in); got != c.want {
			t.Errorf("%s: Classify = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestFormatScopeJavaScript(t *testing.T) {
	ds := ScopeDomainsForFormat(FormatJavaScript)
	got := map[string]bool{}
	for _, d := range ds {
		got[d] = true
	}
	for _, want := range []string{"js", "web", "crypto"} {
		if !got[want] {
			t.Errorf("js scope missing %q (got %v)", want, ds)
		}
	}
	if got["network"] || got["wireless"] || got["redteam"] {
		t.Errorf("js scope should suppress network/wireless/redteam, got %v", ds)
	}
}

func TestIgnorelistFiltersVendorDomains(t *testing.T) {
	ctx := ParseString("Service banner: see https://nmap.org/book and report to target.corp.example-victim.net")
	for _, d := range ctx.Entities[EntityDomain] {
		if isIgnoredDomain(d) {
			t.Fatalf("ignored vendor domain leaked: %q (all: %v)", d, ctx.Entities[EntityDomain])
		}
	}
	// github.com subdomain must also be filtered.
	ctx2 := ParseString("cloned from raw.githubusercontent.com and api.github.com")
	if len(ctx2.Entities[EntityDomain]) != 0 {
		t.Fatalf("github subdomains not filtered: %v", ctx2.Entities[EntityDomain])
	}
}

func TestScanTargetPrecedence(t *testing.T) {
	in := "Starting Nmap\nNmap scan report for shop.victim.test (203.0.113.10)\n" +
		"Other noise: cdn.jsdelivr.example appears later\n"
	ctx := ParseString(in)
	if ctx.First(EntityDomain) != "shop.victim.test" {
		t.Fatalf("scan target not prioritized: domain first = %q (all %v)",
			ctx.First(EntityDomain), ctx.Entities[EntityDomain])
	}
	if ctx.First(EntityIP) != "203.0.113.10" {
		t.Fatalf("scan target IP not prioritized: %q", ctx.First(EntityIP))
	}
}

func TestSANExtraction(t *testing.T) {
	in := "ssl-cert: Subject Alternative Name: DNS:*.company.test, DNS:edge.company.test\n"
	ctx := ParseString(in)
	doms := strings.Join(ctx.Entities[EntityDomain], ",")
	if !strings.Contains(doms, "company.test") {
		t.Fatalf("SAN host not extracted: %v", ctx.Entities[EntityDomain])
	}
	// wildcard must be stripped
	for _, d := range ctx.Entities[EntityDomain] {
		if strings.HasPrefix(d, "*.") {
			t.Fatalf("wildcard not stripped: %q", d)
		}
	}
}

func TestPlaceholderFallback(t *testing.T) {
	host := osdetect.HostInfo{Family: osdetect.FamilyDebian, Manager: osdetect.PackageManager{Name: "apt", InstallTemplate: "sudo apt install -y %s"}}
	// Context has an IP but no domain; a {target_domain} command must fall back.
	ctx := ParseString("Nmap scan report for 10.0.0.9")
	cmd := expandPlaceholders("nslookup {target_domain} ; nmap {target_ip}", ctx)
	if strings.Contains(cmd, "{target_domain}") {
		t.Fatalf("raw template left unbound: %q", cmd)
	}
	if !strings.Contains(cmd, "<target-domain>") {
		t.Fatalf("expected <target-domain> fallback, got %q", cmd)
	}
	if !strings.Contains(cmd, "10.0.0.9") {
		t.Fatalf("ip not bound: %q", cmd)
	}
	_ = host
}

// Regression: a raw email must not surface the suppressed network/redteam/etc.
func TestEmailSuppressesOffensiveDomains(t *testing.T) {
	allowed, ok := formatScope(FormatEmail)
	if !ok {
		t.Fatal("email should impose a scope")
	}
	for _, bad := range []string{"network", "redteam", "cloud", "wireless"} {
		if allowed[bad] {
			t.Errorf("email scope must suppress %q", bad)
		}
	}
}
