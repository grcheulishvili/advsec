package plugin

import (
	"regexp"
	"testing"
)

// bundleDir is the repository's shipped plugin directory, relative to this
// package's test working directory.
const bundleDir = "../../plugins"

var validEntityTypes = map[string]bool{
	"ip": true, "ipv6": true, "domain": true, "url": true, "port": true,
	"hash": true, "mem_addr": true, "cve": true, "email": true,
}

// TestBundledPluginsValid loads every shipped plugin and enforces the
// invariants the engine relies on: unique IDs, required fields, at least one
// valid rule per plugin, compilable regexes, known entity types, and tools
// that carry a runnable command.
func TestBundledPluginsValid(t *testing.T) {
	res := LoadFromDirs([]string{bundleDir})
	for _, e := range res.Errors {
		t.Errorf("load error: %v", e)
	}
	if len(res.Plugins) < 50 {
		t.Fatalf("expected a large bundled library, got %d plugins", len(res.Plugins))
	}

	seen := map[string]string{}
	for _, p := range res.Plugins {
		where := p.SourcePath
		if p.ID == "" {
			t.Errorf("%s: plugin with empty id", where)
			continue
		}
		if prev, dup := seen[p.ID]; dup {
			t.Errorf("duplicate plugin id %q in %s and %s", p.ID, prev, where)
		}
		seen[p.ID] = where

		if p.Name == "" {
			t.Errorf("%s (%s): missing name", p.ID, where)
		}
		if p.Tactics.Phase == "" || p.Tactics.NextStep == "" {
			t.Errorf("%s: missing tactics phase/next_step", p.ID)
		}
		if len(p.Match.Rules) == 0 {
			t.Errorf("%s: no match rules", p.ID)
		}
		if l := p.Match.Logic; l != "" && l != "all" && l != "any" {
			t.Errorf("%s: invalid match logic %q", p.ID, l)
		}

		for i, r := range p.Match.Rules {
			switch {
			case r.Regex != "":
				if _, err := regexp.Compile("(?im)" + r.Regex); err != nil {
					t.Errorf("%s rule[%d]: bad regex %q: %v", p.ID, i, r.Regex, err)
				}
			case r.Contains != "":
				// literal; always valid
			case r.EntityType != "":
				if !validEntityTypes[r.EntityType] {
					t.Errorf("%s rule[%d]: unknown entity_type %q", p.ID, i, r.EntityType)
				}
			case r.Format != "":
				// stream-format match (e.g. text/wordlist); valid as-is
			default:
				t.Errorf("%s rule[%d]: empty rule (no regex/contains/entity_type/format)", p.ID, i)
			}
		}

		if len(p.Tactics.Tools) == 0 {
			t.Errorf("%s: no tools", p.ID)
		}
		for _, tool := range p.Tactics.Tools {
			if tool.Name == "" || tool.Command == "" {
				t.Errorf("%s: tool with empty name/command (%q)", p.ID, tool.Name)
			}
		}
	}
	t.Logf("validated %d bundled plugins", len(res.Plugins))
}
