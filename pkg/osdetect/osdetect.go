// Package osdetect identifies the host Linux distribution and maps tactical
// package recommendations to the correct native package manager.
package osdetect

import (
	"bufio"
	"os"
	"strings"
)

// Family is a normalized distribution family used as the key into plugin
// os_packages maps and into the package-manager table.
type Family string

const (
	FamilyArch    Family = "arch"
	FamilyDebian  Family = "debian"
	FamilyKali    Family = "kali"
	FamilyUnknown Family = "unknown"
)

// HostInfo describes the detected operating system.
type HostInfo struct {
	// ID is the raw ID= field from /etc/os-release (e.g. "arch", "kali").
	ID string
	// IDLike holds the ID_LIKE= tokens (e.g. ["debian"]).
	IDLike []string
	// PrettyName is the human-readable NAME/PRETTY_NAME.
	PrettyName string
	// Family is the normalized family used for package resolution.
	Family Family
	// Manager is the resolved package manager for this host.
	Manager PackageManager
}

const osReleasePath = "/etc/os-release"

// Detect reads /etc/os-release and classifies the host. If the file is
// missing or unreadable, it returns a HostInfo with FamilyUnknown rather than
// an error so the caller can still degrade gracefully.
func Detect() HostInfo {
	return detectFrom(osReleasePath)
}

func detectFrom(path string) HostInfo {
	info := HostInfo{Family: FamilyUnknown}
	f, err := os.Open(path)
	if err != nil {
		info.Manager = managerFor(FamilyUnknown)
		return info
	}
	defer f.Close()

	fields := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		fields[strings.TrimSpace(k)] = unquote(strings.TrimSpace(v))
	}

	info.ID = strings.ToLower(fields["ID"])
	info.PrettyName = firstNonEmpty(fields["PRETTY_NAME"], fields["NAME"])
	if idl := fields["ID_LIKE"]; idl != "" {
		info.IDLike = strings.Fields(strings.ToLower(idl))
	}
	info.Family = classify(info.ID, info.IDLike)
	info.Manager = managerFor(info.Family)
	return info
}

// classify maps an ID / ID_LIKE combination onto a Family. Kali is treated as
// its own family (even though it is debian-like) so plugins can target it
// specifically; it still resolves to apt.
func classify(id string, idLike []string) Family {
	switch id {
	case "arch", "archarm", "artix", "manjaro", "endeavouros", "blackarch", "garuda":
		return FamilyArch
	case "kali":
		return FamilyKali
	case "debian", "ubuntu", "parrot", "linuxmint", "pop", "raspbian", "devuan":
		return FamilyDebian
	}
	for _, l := range idLike {
		switch l {
		case "arch":
			return FamilyArch
		case "debian", "ubuntu":
			return FamilyDebian
		}
	}
	return FamilyUnknown
}

// PackageKeys returns the ordered list of os_packages map keys to try for this
// host, most specific first. Kali falls back to debian entries when a plugin
// only defines debian packages.
func (h HostInfo) PackageKeys() []string {
	switch h.Family {
	case FamilyKali:
		return []string{"kali", "debian"}
	case FamilyDebian:
		return []string{"debian"}
	case FamilyArch:
		return []string{"arch"}
	default:
		return []string{"debian", "arch"}
	}
}

func unquote(s string) string {
	if len(s) >= 2 {
		if (s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
