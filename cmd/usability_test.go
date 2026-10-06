package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/grcheulishvili/advsec/pkg/engine"
)

//  1. `advsec plugin install` with no args prints a friendly notice + its help,
//     not a raw Cobra error, and exits cleanly.
func TestPluginInstallNoArgs(t *testing.T) {
	cmd := newPluginInstallCmd()
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("expected clean exit, got error: %v", err)
	}
	s := buf.String()
	if !strings.Contains(s, "missing required argument") {
		t.Errorf("missing friendly notice; got:\n%s", s)
	}
	if !strings.Contains(s, "Usage:") || !strings.Contains(s, "advsec plugin install") {
		t.Errorf("full help page not shown; got:\n%s", s)
	}
}

// 2. advsec output / help text piped into advsec yields zero target extractions.
func TestSelfReferentialOutput(t *testing.T) {
	sample := strings.Join([]string{
		"ADVSEC │ Arch Linux (pacman) │ Domain: [WEB] │ Sequence: Linear",
		"Usage: advsec [flags]",
		"Examples:",
		"  curl -sI https://target | advsec",
		"  nmap -sV 10.10.10.5 | advsec",
		"  cat phish.eml | advsec",
		"[Phase 1: Passive Recon]",
	}, "\n")

	ctx := engine.ParseString(sample)
	if ctx.Format != engine.FormatAdvsecOutput {
		t.Fatalf("format = %q, want %q", ctx.Format, engine.FormatAdvsecOutput)
	}
	if len(ctx.Entities) != 0 {
		t.Fatalf("expected zero extracted entities from advsec output, got %v", ctx.Entities)
	}
	// Specifically, the example URL/IP placeholders must not appear.
	if ctx.First(engine.EntityURL) != "" || ctx.First(engine.EntityIP) != "" {
		t.Fatalf("example placeholders leaked: url=%q ip=%q",
			ctx.First(engine.EntityURL), ctx.First(engine.EntityIP))
	}
}

//  3. `advsec init --install` replaces an outdated block with refreshed,
//     multi-keybinding content.
func TestInitInstallOverwrite(t *testing.T) {
	home := t.TempDir()
	rc := filepath.Join(home, ".bashrc")
	old := "export PATH=/usr/bin\n\n" +
		"# >>> advsec shell integration (bash) >>>\n" +
		"_advsec_widget() { :; }\n" +
		"bind -x '\"\\e\\C-a\": _advsec_widget'   # only one, outdated binding\n" +
		"# <<< advsec shell integration (bash) <<<\n" +
		"alias ll='ls -la'\n"
	if err := os.WriteFile(rc, []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("SHELL", "/bin/bash")

	if err := runInitInstall("bash"); err != nil {
		t.Fatalf("install: %v", err)
	}
	data, _ := os.ReadFile(rc)
	s := string(data)

	// Surrounding content preserved.
	if !strings.Contains(s, "export PATH=/usr/bin") || !strings.Contains(s, "alias ll='ls -la'") {
		t.Errorf("surrounding rc content not preserved:\n%s", s)
	}
	// Exactly one advsec block remains.
	if c := strings.Count(s, blockStartPrefix); c != 1 {
		t.Errorf("expected exactly one advsec block, got %d", c)
	}
	// Refreshed multi-keybindings present.
	for _, kb := range []string{`\e\C-a`, `\e\C-A`, `\ea`, `\eA`} {
		if !strings.Contains(s, kb) {
			t.Errorf("updated keybinding %q missing after overwrite", kb)
		}
	}
	if strings.Contains(s, "only one, outdated binding") {
		t.Error("old block content was not replaced")
	}
}
