package osdetect

import (
	"os"
	"path/filepath"
	"testing"
)

func TestClassify(t *testing.T) {
	cases := []struct {
		id     string
		idLike []string
		want   Family
	}{
		{"arch", nil, FamilyArch},
		{"blackarch", nil, FamilyArch},
		{"manjaro", nil, FamilyArch},
		{"kali", []string{"debian"}, FamilyKali},
		{"ubuntu", []string{"debian"}, FamilyDebian},
		{"debian", nil, FamilyDebian},
		{"parrot", []string{"debian"}, FamilyDebian},
		{"someweirdistro", []string{"arch"}, FamilyArch},
		{"void", nil, FamilyUnknown},
	}
	for _, c := range cases {
		if got := classify(c.id, c.idLike); got != c.want {
			t.Errorf("classify(%q,%v) = %v, want %v", c.id, c.idLike, got, c.want)
		}
	}
}

func TestDetectFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "os-release")
	content := "NAME=\"Kali GNU/Linux\"\nID=kali\nID_LIKE=debian\nPRETTY_NAME=\"Kali GNU/Linux Rolling\"\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	info := detectFrom(path)
	if info.Family != FamilyKali {
		t.Fatalf("family = %v, want kali", info.Family)
	}
	if info.Manager.Name != "apt" {
		t.Fatalf("manager = %v, want apt", info.Manager.Name)
	}
	if info.PrettyName != "Kali GNU/Linux Rolling" {
		t.Fatalf("pretty = %q", info.PrettyName)
	}
}

func TestPackageKeysKaliFallsBackToDebian(t *testing.T) {
	h := HostInfo{Family: FamilyKali}
	keys := h.PackageKeys()
	if len(keys) != 2 || keys[0] != "kali" || keys[1] != "debian" {
		t.Fatalf("keys = %v, want [kali debian]", keys)
	}
}

func TestInstallCommand(t *testing.T) {
	pm := PackageManager{Name: "pacman", InstallTemplate: "sudo pacman -S --needed %s"}
	got := pm.InstallCommand("gdb", "radare2")
	want := "sudo pacman -S --needed gdb radare2"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
