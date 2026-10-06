package plugin

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// OfficialRepo is the canonical community/official plugin repository pulled by
// `advsec plugin update`.
const OfficialRepo = "https://github.com/grcheulishvili/advsec-plugins.git"

// Manager performs plugin lifecycle operations (list/install/update) and
// package-cache maintenance against the user's config tree.
type Manager struct {
	UserDir string
}

// NewManager returns a Manager bound to the user plugin directory.
func NewManager() *Manager {
	return &Manager{UserDir: UserPluginDir()}
}

// configRoot returns the parent of the plugins dir (…/advsec).
func (m *Manager) configRoot() string {
	return filepath.Dir(m.UserDir)
}

// EnsureDirs creates the plugin and cache directories if missing.
func (m *Manager) EnsureDirs() error {
	for _, d := range []string{m.UserDir, m.cacheDir()} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) cacheDir() string {
	return filepath.Join(m.configRoot(), "cache")
}

// Install fetches a plugin source. It accepts:
//   - a direct URL to a .yaml/.yml file (downloaded into the plugins dir)
//   - a GitHub "owner/repo" shorthand
//   - a full git URL (https://… or git@…)
//
// Git repositories are cloned under plugins/<repo>/ and their YAML files are
// discovered recursively at load time.
func (m *Manager) Install(source string) (string, error) {
	if err := m.EnsureDirs(); err != nil {
		return "", err
	}
	source = strings.TrimSpace(source)
	if source == "" {
		return "", fmt.Errorf("no plugin source provided")
	}

	if isSingleFileURL(source) {
		return m.installFile(source)
	}
	return m.installGit(normalizeGit(source))
}

func (m *Manager) installFile(url string) (string, error) {
	data, err := httpGet(url)
	if err != nil {
		return "", err
	}
	// Validate it parses as at least one plugin before committing it to disk.
	plugins, err := LoadBytes(data)
	if err != nil {
		return "", fmt.Errorf("downloaded content is not a valid plugin: %w", err)
	}
	if len(plugins) == 0 {
		return "", fmt.Errorf("downloaded content contained no plugins")
	}
	name := filepath.Base(strings.SplitN(url, "?", 2)[0])
	if !isYAML(name) {
		name += ".yaml"
	}
	dest := filepath.Join(m.UserDir, name)
	if err := os.WriteFile(dest, data, 0o644); err != nil {
		return "", err
	}
	return dest, nil
}

func (m *Manager) installGit(gitURL string) (string, error) {
	if _, err := exec.LookPath("git"); err != nil {
		return "", fmt.Errorf("git is required to install plugin repositories but was not found on PATH")
	}
	repoName := repoDirName(gitURL)
	dest := filepath.Join(m.UserDir, repoName)

	if _, err := os.Stat(dest); err == nil {
		// Already present: update instead of re-clone.
		if err := gitPull(dest); err != nil {
			return "", fmt.Errorf("update existing %s: %w", repoName, err)
		}
		return dest, nil
	}

	cmd := exec.Command("git", "clone", "--depth", "1", gitURL, dest)
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("git clone failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return dest, nil
}

// Update pulls the official repo (installing it on first run) and refreshes
// every git-managed plugin directory already present. It returns a per-target
// summary.
func (m *Manager) Update() ([]string, error) {
	if err := m.EnsureDirs(); err != nil {
		return nil, err
	}
	var summary []string

	// Official repo first.
	if _, err := m.installGit(OfficialRepo); err != nil {
		summary = append(summary, "official: "+err.Error())
	} else {
		summary = append(summary, "official: up to date")
	}

	// Any other git repos living directly under the plugins dir.
	entries, _ := os.ReadDir(m.UserDir)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dir := filepath.Join(m.UserDir, e.Name())
		if !isGitRepo(dir) {
			continue
		}
		if dir == filepath.Join(m.UserDir, repoDirName(OfficialRepo)) {
			continue // already handled
		}
		if err := gitPull(dir); err != nil {
			summary = append(summary, e.Name()+": "+err.Error())
		} else {
			summary = append(summary, e.Name()+": up to date")
		}
	}
	return summary, nil
}

// PackageCache is the on-disk snapshot refreshed by `advsec update-cache`.
type PackageCache struct {
	UpdatedAt time.Time `json:"updated_at"`
	// Map is binary -> family -> package name.
	Map map[string]map[string]string `json:"map"`
}

// cachePath is where the package map snapshot is stored.
func (m *Manager) cachePath() string {
	return filepath.Join(m.cacheDir(), "packages.json")
}

// UpdateCache rebuilds the local OS package-mapping database by aggregating the
// os_packages declarations across all loaded plugins and writing a normalized
// snapshot. This gives `advsec` a fast, offline lookup of "which package
// provides tool X on family Y" independent of any single plugin.
func (m *Manager) UpdateCache() (int, error) {
	if err := m.EnsureDirs(); err != nil {
		return 0, err
	}
	res := LoadAll()
	cache := PackageCache{
		UpdatedAt: time.Now().UTC(),
		Map:       map[string]map[string]string{},
	}
	for _, p := range res.Plugins {
		for family, pkgs := range p.OSPackages {
			for _, pkg := range pkgs {
				if _, ok := cache.Map[pkg]; !ok {
					cache.Map[pkg] = map[string]string{}
				}
				cache.Map[pkg][family] = pkg
			}
		}
		// Also index declared tool binaries so lookups by binary work.
		for _, t := range p.Tactics.Tools {
			bin := t.Binary
			if bin == "" {
				continue
			}
			if _, ok := cache.Map[bin]; !ok {
				cache.Map[bin] = map[string]string{}
			}
			for family, pkgs := range p.OSPackages {
				for _, pkg := range pkgs {
					if strings.EqualFold(pkg, bin) {
						cache.Map[bin][family] = pkg
					}
				}
			}
		}
	}
	data, err := json.MarshalIndent(cache, "", "  ")
	if err != nil {
		return 0, err
	}
	if err := os.WriteFile(m.cachePath(), data, 0o644); err != nil {
		return 0, err
	}
	return len(cache.Map), nil
}

// ---- helpers ----

func isSingleFileURL(s string) bool {
	low := strings.ToLower(s)
	if !strings.HasPrefix(low, "http://") && !strings.HasPrefix(low, "https://") {
		return false
	}
	base := strings.SplitN(low, "?", 2)[0]
	return strings.HasSuffix(base, ".yaml") || strings.HasSuffix(base, ".yml")
}

// normalizeGit turns "owner/repo" shorthand into a full GitHub https URL and
// leaves full URLs untouched.
func normalizeGit(s string) string {
	if strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://") ||
		strings.HasPrefix(s, "git@") || strings.HasPrefix(s, "ssh://") {
		return s
	}
	// owner/repo shorthand.
	if strings.Count(s, "/") == 1 && !strings.Contains(s, " ") {
		return "https://github.com/" + s + ".git"
	}
	return s
}

func repoDirName(gitURL string) string {
	base := gitURL
	base = strings.TrimSuffix(base, ".git")
	base = strings.TrimSuffix(base, "/")
	if i := strings.LastIndexAny(base, "/:"); i >= 0 {
		base = base[i+1:]
	}
	if base == "" {
		base = "plugin-repo"
	}
	return base
}

func isGitRepo(dir string) bool {
	st, err := os.Stat(filepath.Join(dir, ".git"))
	return err == nil && st.IsDir()
}

func gitPull(dir string) error {
	cmd := exec.Command("git", "-C", dir, "pull", "--ff-only")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("%v: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func httpGet(url string) ([]byte, error) {
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected HTTP status %d fetching %s", resp.StatusCode, url)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 8*1024*1024))
}
