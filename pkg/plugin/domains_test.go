package plugin

import "testing"

func TestCanonicalDomainAliases(t *testing.T) {
	cases := map[string]string{
		"net": "network", "NET": "network", "ad": "redteam",
		"ir": "dfir", "k8s": "cloud", "re": "reversing",
		"pwn": "pwn", "web": "web", "": "", "weirdthing": "weirdthing",
	}
	for in, want := range cases {
		if got := CanonicalDomain(in); got != want {
			t.Errorf("CanonicalDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFilterByContext(t *testing.T) {
	plugins := []Plugin{
		{ID: "a", Domain: "web"},
		{ID: "b", Domain: "dfir"},
		{ID: "c", Domain: "general"},
		{ID: "d", Domain: "network"},
	}
	got := FilterByContext(plugins, "web")
	ids := map[string]bool{}
	for _, p := range got {
		ids[p.ID] = true
	}
	if !ids["a"] || !ids["c"] { // matching domain + general
		t.Fatalf("web context should include a and c, got %v", ids)
	}
	if ids["b"] || ids["d"] {
		t.Fatalf("web context should exclude dfir/network, got %v", ids)
	}
	// Empty context keeps everything.
	if len(FilterByContext(plugins, "")) != 4 {
		t.Fatalf("empty context should keep all plugins")
	}
}

func TestBundledPluginsHaveDomains(t *testing.T) {
	res := LoadFromDirs([]string{"../../plugins"})
	for _, p := range res.Plugins {
		if p.Domain == "" {
			t.Errorf("%s: empty domain (should default to file stem)", p.ID)
		}
	}
}
