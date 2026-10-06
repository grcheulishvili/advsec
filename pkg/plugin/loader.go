package plugin

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Standard plugin search locations, most specific (user) first. A plugin ID
// loaded from an earlier directory wins over the same ID in a later one, so
// user plugins override system ones.
const (
	// EnvConfigDir lets the user relocate the config tree (used in tests and
	// by packagers).
	EnvConfigDir = "ADVSEC_CONFIG_DIR"
)

// UserPluginDir returns ~/.config/advsec/plugins honoring $XDG_CONFIG_HOME and
// $ADVSEC_CONFIG_DIR.
func UserPluginDir() string {
	if base := os.Getenv(EnvConfigDir); base != "" {
		return filepath.Join(base, "plugins")
	}
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		return filepath.Join(xdg, "advsec", "plugins")
	}
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return filepath.Join(".", ".config", "advsec", "plugins")
	}
	return filepath.Join(home, ".config", "advsec", "plugins")
}

// SystemPluginDir returns the system-wide plugin directory.
func SystemPluginDir() string {
	return "/usr/share/advsec/plugins"
}

// SearchDirs returns the ordered plugin directories.
func SearchDirs() []string {
	return []string{UserPluginDir(), SystemPluginDir()}
}

// LoadResult carries the plugins that loaded and any non-fatal errors so the
// CLI can warn about a broken plugin without aborting the whole run.
type LoadResult struct {
	Plugins []Plugin
	Errors  []error
}

// originFor labels a directory by scope for display purposes.
func originFor(dir string) string {
	switch {
	case dir == SystemPluginDir():
		return "system"
	case strings.Contains(dir, filepath.Join("advsec", "plugins")):
		return "user"
	default:
		return "user"
	}
}

// LoadAll loads every *.yaml / *.yml plugin from the standard search dirs,
// deduplicating by ID (first occurrence wins).
func LoadAll() LoadResult {
	return LoadFromDirs(SearchDirs())
}

// LoadFromDirs loads plugins from an explicit ordered list of directories.
func LoadFromDirs(dirs []string) LoadResult {
	var res LoadResult
	seen := map[string]bool{}

	for _, dir := range dirs {
		if _, err := os.Stat(dir); err != nil {
			// A missing directory is normal (e.g. no user plugins yet).
			if !os.IsNotExist(err) {
				res.Errors = append(res.Errors, fmt.Errorf("read %s: %w", dir, err))
			}
			continue
		}
		// Recursively discover YAML plugins (git-installed repos nest them in
		// subdirectories). Skip VCS metadata. Deterministic order via sort.
		var paths []string
		walkErr := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
			if err != nil {
				res.Errors = append(res.Errors, err)
				return nil
			}
			if d.IsDir() {
				if d.Name() == ".git" {
					return filepath.SkipDir
				}
				return nil
			}
			if isYAML(d.Name()) {
				paths = append(paths, p)
			}
			return nil
		})
		if walkErr != nil {
			res.Errors = append(res.Errors, fmt.Errorf("walk %s: %w", dir, walkErr))
		}
		sort.Strings(paths)

		for _, path := range paths {
			plugins, err := LoadFile(path)
			if err != nil {
				res.Errors = append(res.Errors, fmt.Errorf("%s: %w", path, err))
				continue
			}
			for _, p := range plugins {
				if p.ID == "" {
					res.Errors = append(res.Errors, fmt.Errorf("%s: plugin missing required 'id'", path))
					continue
				}
				if seen[p.ID] {
					continue // earlier dir already provided this ID
				}
				seen[p.ID] = true
				p.SourcePath = path
				p.Origin = originFor(dir)
				res.Plugins = append(res.Plugins, p)
			}
		}
	}
	return res
}

// LoadFile parses a YAML file that holds either a single plugin document or a
// stream of multiple plugin documents separated by `---`.
func LoadFile(path string) ([]Plugin, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return LoadBytes(data)
}

// LoadBytes parses one or more plugin documents from YAML bytes.
func LoadBytes(data []byte) ([]Plugin, error) {
	var out []Plugin
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	for {
		var p Plugin
		err := dec.Decode(&p)
		if err != nil {
			if err.Error() == "EOF" {
				break
			}
			return out, err
		}
		// Skip empty documents produced by stray separators.
		if p.ID == "" && p.Name == "" && len(p.Match.Rules) == 0 {
			continue
		}
		out = append(out, p)
	}
	return out, nil
}

func isYAML(name string) bool {
	l := strings.ToLower(name)
	return strings.HasSuffix(l, ".yaml") || strings.HasSuffix(l, ".yml")
}
