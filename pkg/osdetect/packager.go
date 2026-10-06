package osdetect

import (
	"os/exec"
	"strings"
	"sync"
)

// PackageManager describes how to install packages on a host and how to
// phrase the install command for the user.
type PackageManager struct {
	// Name is the manager's short name (pacman, apt, yay, unknown).
	Name string
	// InstallTemplate is a format string with a single %s for the
	// space-joined package list.
	InstallTemplate string
	// RefreshCommand updates the package index/cache for this manager.
	RefreshCommand string
}

var (
	pacman = PackageManager{
		Name:            "pacman",
		InstallTemplate: "sudo pacman -S --needed %s",
		RefreshCommand:  "sudo pacman -Sy",
	}
	yay = PackageManager{
		Name:            "yay",
		InstallTemplate: "yay -S --needed %s",
		RefreshCommand:  "yay -Sy",
	}
	apt = PackageManager{
		Name:            "apt",
		InstallTemplate: "sudo apt install -y %s",
		RefreshCommand:  "sudo apt update",
	}
	unknownMgr = PackageManager{
		Name:            "unknown",
		InstallTemplate: "# install manually: %s",
		RefreshCommand:  "# refresh your package index manually",
	}
)

// managerFor returns the default package manager for a family. On Arch, if the
// `yay` AUR helper is available it is preferred for the broadest package
// coverage (BlackArch tooling often lives in the AUR).
func managerFor(f Family) PackageManager {
	switch f {
	case FamilyArch:
		if hasBinary("yay") {
			return yay
		}
		return pacman
	case FamilyDebian, FamilyKali:
		return apt
	default:
		return unknownMgr
	}
}

// InstallCommand renders the install command for the given packages.
func (p PackageManager) InstallCommand(pkgs ...string) string {
	if len(pkgs) == 0 {
		return ""
	}
	return strings.Replace(p.InstallTemplate, "%s", strings.Join(pkgs, " "), 1)
}

var (
	pathCache   = map[string]bool{}
	pathCacheMu sync.Mutex
)

// hasBinary reports whether name resolves on PATH, memoized per process.
func hasBinary(name string) bool {
	pathCacheMu.Lock()
	if v, ok := pathCache[name]; ok {
		pathCacheMu.Unlock()
		return v
	}
	pathCacheMu.Unlock()

	_, err := exec.LookPath(name)
	ok := err == nil

	pathCacheMu.Lock()
	pathCache[name] = ok
	pathCacheMu.Unlock()
	return ok
}

// IsInstalled is the exported capability check used by the evaluator.
func IsInstalled(binary string) bool {
	if binary == "" {
		return false
	}
	return hasBinary(binary)
}
