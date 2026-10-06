package engine

import (
	"os"
	"regexp"
	"strings"

	"github.com/grcheulishvili/advsec/pkg/osdetect"
)

// AssetNote records the outcome of verifying a hardcoded asset path referenced
// by a tool command.
type AssetNote struct {
	Path        string // the referenced path
	Substituted string // a detected alternative that was used instead (if any)
	Tip         string // install/remediation tip (when missing and no alternative)
}

// assetPathRe captures absolute paths under common shared-asset roots. These
// are the paths worth verifying (wordlists, rule sets, dictionaries).
var assetPathRe = regexp.MustCompile(`(?:/usr/share|/usr/local/share|/opt)/[A-Za-z0-9._][A-Za-z0-9._/\-]*`)

// wordlistDirs are the usual install locations searched when a referenced
// wordlist is missing.
var wordlistDirs = []string{
	"/usr/share/wordlists",
	"/usr/share/seclists",
	"/usr/share/dict",
	"/usr/local/share/wordlists",
}

// VerifyAssetPath reports whether a path exists on the local filesystem.
func VerifyAssetPath(path string) bool {
	if path == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

// FindWordlist searches the common wordlist directories for a file whose name
// contains the given hint (e.g. "rockyou"). It returns the first match, or ""
// if none is installed. An empty hint returns the first wordlist-ish file found.
func FindWordlist(hint string) string {
	hint = strings.ToLower(hint)
	for _, dir := range wordlistDirs {
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		var found string
		_ = walkShallow(dir, 4, func(path, name string) bool {
			ln := strings.ToLower(name)
			if !strings.HasSuffix(ln, ".txt") {
				return false
			}
			if hint == "" || strings.Contains(ln, hint) {
				found = path
				return true // stop
			}
			return false
		})
		if found != "" {
			return found
		}
	}
	return ""
}

// walkShallow walks dir up to maxDepth levels, calling fn(path, name); it stops
// early when fn returns true.
func walkShallow(dir string, maxDepth int, fn func(path, name string) bool) bool {
	if maxDepth < 0 {
		return false
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		full := dir + "/" + e.Name()
		if e.IsDir() {
			if walkShallow(full, maxDepth-1, fn) {
				return true
			}
			continue
		}
		if fn(full, e.Name()) {
			return true
		}
	}
	return false
}

// kind classifies an asset path for remediation purposes.
func assetKind(path string) string {
	low := strings.ToLower(path)
	switch {
	case strings.Contains(low, "wordlist") || strings.Contains(low, "rockyou") ||
		strings.Contains(low, "seclists") || strings.Contains(low, "/dict") ||
		strings.Contains(low, "password"):
		return "wordlist"
	case strings.Contains(low, "yara"):
		return "yara"
	default:
		return "other"
	}
}

// VerifyCommandAssets scans a command for hardcoded asset paths, substitutes a
// detected alternative where possible, and returns the (possibly rewritten)
// command plus notes for any missing assets. mgr supplies host-appropriate
// install tips.
func VerifyCommandAssets(cmd string, mgr osdetect.PackageManager) (string, []AssetNote) {
	paths := assetPathRe.FindAllString(cmd, -1)
	if len(paths) == 0 {
		return cmd, nil
	}
	seen := map[string]bool{}
	var notes []AssetNote
	out := cmd
	for _, p := range paths {
		if seen[p] {
			continue
		}
		seen[p] = true
		if VerifyAssetPath(p) {
			continue // present; leave as-is
		}
		switch assetKind(p) {
		case "wordlist":
			hint := wordlistHint(p)
			if alt := FindWordlist(hint); alt != "" {
				out = strings.ReplaceAll(out, p, alt)
				notes = append(notes, AssetNote{Path: p, Substituted: alt})
			} else {
				out = strings.ReplaceAll(out, p, "<path-to-wordlist>")
				notes = append(notes, AssetNote{Path: p, Tip: mgr.InstallCommand("seclists", "wordlists")})
			}
		case "yara":
			out = strings.ReplaceAll(out, p, "<path-to-yara-rules>")
			notes = append(notes, AssetNote{Path: p,
				Tip: "git clone https://github.com/Yara-Rules/rules " + p})
		default:
			out = strings.ReplaceAll(out, p, "<missing:"+baseName(p)+">")
			notes = append(notes, AssetNote{Path: p,
				Tip: "install the package that provides this path"})
		}
	}
	return out, notes
}

func wordlistHint(path string) string {
	low := strings.ToLower(path)
	if strings.Contains(low, "rockyou") {
		return "rockyou"
	}
	return "" // any wordlist
}

func baseName(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}
