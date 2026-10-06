package plugin

import (
	"os"
	"path/filepath"
	"testing"
)

const sample = `
id: p1
name: One
target_type: binary
os_packages:
  arch: [gdb]
match:
  logic: all
  rules:
    - regex: "ELF 64-bit"
tactics:
  phase: Pwn
  next_step: go
  tools:
    - name: gdb
      binary: gdb
      command: "gdb {target}"
      purpose: debug
---
id: p2
name: Two
target_type: web
match:
  rules:
    - contains: wordpress
tactics:
  phase: Web
  next_step: scan
  tools:
    - name: wpscan
      command: "wpscan --url {target_url}"
`

func TestLoadBytesMultiDoc(t *testing.T) {
	plugins, err := LoadBytes([]byte(sample))
	if err != nil {
		t.Fatal(err)
	}
	if len(plugins) != 2 {
		t.Fatalf("got %d plugins, want 2", len(plugins))
	}
	if plugins[0].ID != "p1" || plugins[1].ID != "p2" {
		t.Fatalf("ids = %q %q", plugins[0].ID, plugins[1].ID)
	}
	if len(plugins[0].Match.Rules) != 1 || plugins[0].Match.Rules[0].Regex != "ELF 64-bit" {
		t.Fatalf("rule parse failed: %+v", plugins[0].Match.Rules)
	}
}

func TestLoadFromDirsDedupUserWins(t *testing.T) {
	user := t.TempDir()
	sys := t.TempDir()
	// Same ID in both; user version must win.
	must(t, filepath.Join(user, "a.yaml"),
		"id: dup\nname: UserWins\nmatch:\n  rules:\n    - contains: x\ntactics:\n  phase: p\n  next_step: n\n")
	must(t, filepath.Join(sys, "a.yaml"),
		"id: dup\nname: SysLoses\nmatch:\n  rules:\n    - contains: x\ntactics:\n  phase: p\n  next_step: n\n")

	res := LoadFromDirs([]string{user, sys})
	if len(res.Plugins) != 1 {
		t.Fatalf("got %d plugins, want 1 (deduped)", len(res.Plugins))
	}
	if res.Plugins[0].Name != "UserWins" {
		t.Fatalf("name = %q, want UserWins", res.Plugins[0].Name)
	}
}

func TestLoadFromDirsRecursive(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "community-repo", "rules")
	if err := os.MkdirAll(sub, 0o755); err != nil {
		t.Fatal(err)
	}
	must(t, filepath.Join(sub, "deep.yaml"),
		"id: deep\nname: Deep\nmatch:\n  rules:\n    - contains: y\ntactics:\n  phase: p\n  next_step: n\n")
	res := LoadFromDirs([]string{root})
	if len(res.Plugins) != 1 || res.Plugins[0].ID != "deep" {
		t.Fatalf("recursive load failed: %+v", res.Plugins)
	}
}

func must(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
