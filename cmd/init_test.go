package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Scenario 4 (shell configuration sourcing): --install appends a guarded,
// double-newline-separated block idempotently, and the result is valid shell.
func TestInitInstallAppendsGuardedBlock(t *testing.T) {
	home := t.TempDir()
	rc := filepath.Join(home, ".bashrc")
	if err := os.WriteFile(rc, []byte("export PATH=/usr/bin"), 0o644); err != nil { // no trailing newline
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("SHELL", "/bin/bash")

	if err := runInitInstall("bash"); err != nil {
		t.Fatalf("install: %v", err)
	}
	data, _ := os.ReadFile(rc)
	s := string(data)

	if !strings.Contains(s, "export PATH=/usr/bin\n\n# >>> advsec shell integration") {
		t.Fatalf("snippet not separated by blank line from prior content:\n%s", s)
	}
	if !strings.Contains(s, `if [ -n "$BASH_VERSION" ]; then`) {
		t.Fatal("bash block is not guarded by $BASH_VERSION")
	}
	if !strings.HasSuffix(s, "<<<\n") {
		t.Fatal("block does not end with a trailing newline")
	}

	// Idempotency: a second install must not duplicate the block.
	if err := runInitInstall("bash"); err != nil {
		t.Fatalf("second install: %v", err)
	}
	data2, _ := os.ReadFile(rc)
	if strings.Count(string(data2), blockMarker) != 1 {
		t.Fatalf("block inserted more than once (count=%d)", strings.Count(string(data2), blockMarker))
	}
}

// Both snippets must be syntactically valid shell (bash -n parses them; the
// runtime guard makes the zsh block a no-op under bash rather than an error).
func TestSnippetsAreValidShell(t *testing.T) {
	bash, err := exec.LookPath("bash")
	if err != nil {
		t.Skip("bash not available")
	}
	for _, shell := range []string{"zsh", "bash"} {
		snip, err := snippetFor(shell)
		if err != nil {
			t.Fatal(err)
		}
		f := filepath.Join(t.TempDir(), shell+".sh")
		if err := os.WriteFile(f, []byte(snip), 0o644); err != nil {
			t.Fatal(err)
		}
		if out, err := exec.Command(bash, "-n", f).CombinedOutput(); err != nil {
			t.Errorf("%s snippet fails bash -n: %v\n%s", shell, err, out)
		}
		// Sourcing the (cross-shell) snippet under bash must not error: the
		// guard skips the body when the matching *_VERSION var is unset.
		src := "unset ZSH_VERSION; source " + f + "; echo OK"
		if shell == "zsh" {
			if out, err := exec.Command(bash, "-c", src).CombinedOutput(); err != nil {
				t.Errorf("sourcing zsh snippet under bash errored: %v\n%s", err, out)
			}
		}
	}
}

func TestSnippetsHaveNoEmDash(t *testing.T) {
	const emDash = rune(0x2014)
	const enDash = rune(0x2013)
	for _, shell := range []string{"zsh", "bash"} {
		snip, _ := snippetFor(shell)
		if strings.ContainsRune(snip, emDash) || strings.ContainsRune(snip, enDash) {
			t.Errorf("%s snippet contains an em/en dash", shell)
		}
	}
}
