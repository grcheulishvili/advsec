package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/grcheulishvili/advsec/pkg/osdetect"
)

func aptMgr() osdetect.PackageManager {
	return osdetect.PackageManager{Name: "apt", InstallTemplate: "sudo apt install -y %s"}
}

func TestVerifyAssetPath(t *testing.T) {
	if !VerifyAssetPath("/") {
		t.Fatal("root should exist")
	}
	if VerifyAssetPath("/usr/share/definitely/not/here_zzz.txt") {
		t.Fatal("nonexistent path reported present")
	}
}

func TestMissingWordlistWarns(t *testing.T) {
	cmd := "hydra -P /usr/share/wordlists/rockyou.txt ssh://10.0.0.1"
	out, notes := VerifyCommandAssets(cmd, aptMgr())
	// rockyou is typically absent in CI; expect placeholder + a tip.
	if VerifyAssetPath("/usr/share/wordlists/rockyou.txt") {
		t.Skip("rockyou actually present in this environment")
	}
	if strings.Contains(out, "/usr/share/wordlists/rockyou.txt") {
		t.Fatalf("missing path was not rewritten: %q", out)
	}
	if len(notes) != 1 || notes[0].Tip == "" {
		t.Fatalf("expected one missing-asset note with a tip, got %+v", notes)
	}
	if !strings.Contains(out, "<path-to-wordlist>") {
		t.Fatalf("expected placeholder in command, got %q", out)
	}
}

func TestPresentAssetUnchanged(t *testing.T) {
	// Create a real file and reference it via an asset-root-looking path by
	// pointing FindWordlist-independent logic at an existing path (/etc/hostname
	// is not under an asset root, so use a temp under a fake share dir).
	dir := t.TempDir()
	share := filepath.Join(dir, "usr", "share", "wordlists")
	if err := os.MkdirAll(share, 0o755); err != nil {
		t.Fatal(err)
	}
	// Path must match the asset-root regex, so test VerifyAssetPath directly.
	f := filepath.Join(share, "list.txt")
	if err := os.WriteFile(f, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !VerifyAssetPath(f) {
		t.Fatalf("created file should verify present")
	}
}

func TestFoundWordlistSubstituted(t *testing.T) {
	// Seed a wordlist dir and confirm FindWordlist locates it.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "rockyou.txt"), []byte("pw"), 0o644); err != nil {
		t.Fatal(err)
	}
	// Temporarily point the search at our dir.
	old := wordlistDirs
	wordlistDirs = []string{dir}
	defer func() { wordlistDirs = old }()

	if got := FindWordlist("rockyou"); got == "" {
		t.Fatal("FindWordlist should locate the seeded rockyou.txt")
	}
	cmd := "john --wordlist=/usr/share/wordlists/rockyou.txt hash"
	out, notes := VerifyCommandAssets(cmd, aptMgr())
	if !strings.Contains(out, dir) {
		t.Fatalf("expected substitution with detected path, got %q", out)
	}
	if len(notes) != 1 || notes[0].Substituted == "" {
		t.Fatalf("expected a substitution note, got %+v", notes)
	}
}
