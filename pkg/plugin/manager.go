package plugin

import (
	"archive/zip"
	"bytes"
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

// Official plugin source. Plugins live in the main repo's plugins/ directory;
// `advsec plugin update` fetches them anonymously over public HTTPS (never SSH,
// never an authenticated remote) and falls back to the release ZIP if git is
// unavailable or errors.
const (
	OfficialRepo          = "https://github.com/grcheulishvili/advsec.git"
	OfficialBranch        = "main"
	OfficialZipURL        = "https://github.com/grcheulishvili/advsec/archive/refs/heads/main.zip"
	OfficialPluginsSubdir = "plugins"
	// officialDir is where fetched official plugins are stored under the user
	// plugin tree (kept separate from hand-authored user plugins).
	officialDir = "official"
)

// gitEnv returns the process environment with every interactive prompt
// disabled, so a public clone/pull can never block on a credential prompt.
func gitEnv() []string {
	return append(os.Environ(),
		"GIT_TERMINAL_PROMPT=0", // git: fail instead of prompting for user/pass
		"GIT_ASKPASS=/bin/echo", // neutralize any askpass helper
		"SSH_ASKPASS=/bin/echo",
		"GCM_INTERACTIVE=never", // git-credential-manager: never prompt
	)
}

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
	cmd.Env = gitEnv()
	if out, err := cmd.CombinedOutput(); err != nil {
		return "", fmt.Errorf("git clone failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	return dest, nil
}

// Update refreshes the official plugin set (from the main repo's plugins/
// directory) and any community git repos already installed. It is strictly
// anonymous/public: it never prompts for credentials, and if git is missing or
// errors it falls back to the public release ZIP. Returns a per-target summary.
func (m *Manager) Update() ([]string, error) {
	if err := m.EnsureDirs(); err != nil {
		return nil, err
	}
	var summary []string

	// Official plugins: git first, ZIP fallback.
	n, via, err := m.updateOfficial()
	if err != nil {
		summary = append(summary, "official: "+err.Error())
	} else {
		summary = append(summary, fmt.Sprintf("official: %d plugin file(s) via %s", n, via))
	}

	// Any community git repos living directly under the plugins dir.
	entries, _ := os.ReadDir(m.UserDir)
	for _, e := range entries {
		if !e.IsDir() || e.Name() == officialDir {
			continue
		}
		dir := filepath.Join(m.UserDir, e.Name())
		if !isGitRepo(dir) {
			continue
		}
		if err := gitPull(dir); err != nil {
			summary = append(summary, e.Name()+": "+err.Error())
		} else {
			summary = append(summary, e.Name()+": up to date")
		}
	}
	return summary, nil
}

// updateOfficial installs the official plugins into UserDir/official, returning
// the number of YAML files written and which transport was used ("git" or
// "zip"). git is tried first (shallow, prompt-free); on any failure it falls
// back to the public ZIP so a missing git binary or auth error is never fatal.
func (m *Manager) updateOfficial() (count int, via string, err error) {
	dest := filepath.Join(m.UserDir, officialDir)

	if _, lookErr := exec.LookPath("git"); lookErr == nil {
		if n, gerr := m.officialViaGit(dest); gerr == nil {
			return n, "git", nil
		}
		// else fall through to ZIP
	}
	n, zerr := m.officialViaZip(dest)
	if zerr != nil {
		return 0, "", fmt.Errorf("git and ZIP fetch both failed: %w", zerr)
	}
	return n, "zip", nil
}

// officialViaGit shallow-clones the repo to a temp dir and copies its plugins/
// directory into dest. Uses gitEnv() so it can never prompt.
func (m *Manager) officialViaGit(dest string) (int, error) {
	tmp, err := os.MkdirTemp("", "advsec-official-*")
	if err != nil {
		return 0, err
	}
	defer os.RemoveAll(tmp)

	cmd := exec.Command("git", "clone", "--depth", "1", "--branch", OfficialBranch,
		"--single-branch", OfficialRepo, tmp)
	cmd.Env = gitEnv()
	if out, err := cmd.CombinedOutput(); err != nil {
		return 0, fmt.Errorf("clone: %v: %s", err, strings.TrimSpace(string(out)))
	}
	src := filepath.Join(tmp, OfficialPluginsSubdir)
	return copyYAMLDir(src, dest)
}

// officialViaZip downloads the public branch ZIP and extracts the plugins/
// directory into dest. No git, no auth.
func (m *Manager) officialViaZip(dest string) (int, error) {
	data, err := httpGet(OfficialZipURL)
	if err != nil {
		return 0, fmt.Errorf("download zip: %w", err)
	}
	zr, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return 0, fmt.Errorf("open zip: %w", err)
	}
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return 0, err
	}
	// Entries look like "advsec-main/plugins/foo.yaml"; keep only YAML under
	// a top-level plugins/ directory.
	count := 0
	for _, f := range zr.File {
		if f.FileInfo().IsDir() || !isYAML(f.Name) {
			continue
		}
		parts := strings.Split(f.Name, "/")
		inPlugins := false
		for i := 0; i+1 < len(parts); i++ {
			if parts[i] == OfficialPluginsSubdir {
				inPlugins = true
				break
			}
		}
		if !inPlugins {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return count, err
		}
		body, err := io.ReadAll(io.LimitReader(rc, 4*1024*1024))
		rc.Close()
		if err != nil {
			return count, err
		}
		// Only persist files that actually parse as plugins.
		if _, perr := LoadBytes(body); perr != nil {
			continue
		}
		out := filepath.Join(dest, filepath.Base(f.Name))
		if err := os.WriteFile(out, body, 0o644); err != nil {
			return count, err
		}
		count++
	}
	if count == 0 {
		return 0, fmt.Errorf("no plugins found in ZIP under %s/", OfficialPluginsSubdir)
	}
	return count, nil
}

// copyYAMLDir copies every *.yaml/*.yml from src into dest (flat), returning
// the count written. Only files that parse as plugins are kept.
func copyYAMLDir(src, dest string) (int, error) {
	entries, err := os.ReadDir(src)
	if err != nil {
		return 0, fmt.Errorf("official plugins dir missing: %w", err)
	}
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return 0, err
	}
	count := 0
	for _, e := range entries {
		if e.IsDir() || !isYAML(e.Name()) {
			continue
		}
		body, err := os.ReadFile(filepath.Join(src, e.Name()))
		if err != nil {
			return count, err
		}
		if _, perr := LoadBytes(body); perr != nil {
			continue
		}
		if err := os.WriteFile(filepath.Join(dest, e.Name()), body, 0o644); err != nil {
			return count, err
		}
		count++
	}
	if count == 0 {
		return 0, fmt.Errorf("no valid plugin files in %s", src)
	}
	return count, nil
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
	cmd.Env = gitEnv()
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
