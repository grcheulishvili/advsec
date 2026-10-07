package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
)

// blockMarker identifies an already-installed integration block so --install
// stays idempotent.
const (
	blockStartPrefix = "# >>> advsec shell integration"
	blockEndPrefix   = "# <<< advsec shell integration"
	// blockMarker is kept for existing tests / presence checks.
	blockMarker = blockStartPrefix
)

var (
	flagInitInstall bool
	flagInitForce   bool
)

func newInitCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "init [zsh|bash]",
		Short: "Print (or install) a shell integration widget bound to a hotkey",
		Long: `Generates a non-intrusive shell widget. It does NOT run on every
command - it binds Ctrl+Alt+A to a widget that re-runs your last command, pipes
its output through advsec, and prints suggestions beneath the prompt without
touching your command buffer.

The snippet is guarded so a zsh block only runs under zsh and a bash block only
under bash - sourcing the wrong rc file across shells is a no-op, not a cascade
of syntax errors.

  advsec init zsh  >> ~/.zshrc      # print (redirect yourself)
  advsec init bash >> ~/.bashrc
  advsec init --install             # detect $SHELL and append safely (idempotent)`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if flagInitInstall {
				shell := ""
				if len(args) == 1 {
					shell = args[0]
				}
				return runInitInstall(shell)
			}
			if len(args) != 1 {
				return missingArg(cmd, "[zsh|bash] (or use --install)")
			}
			snippet, err := snippetFor(args[0])
			if err != nil {
				return err
			}
			// Lead with two newlines so appending to a config file whose last
			// line lacks a trailing newline cannot fuse the opening marker onto
			// it. Each snippet already ends with a trailing newline.
			fmt.Print("\n\n" + snippet)
			return nil
		},
	}
	c.Flags().BoolVar(&flagInitInstall, "install", false, "detect the active shell and append (or update) the snippet in its rc file")
	c.Flags().BoolVarP(&flagInitForce, "force", "f", false, "with --install, replace an existing advsec block even if unchanged")
	return c
}

func snippetFor(shell string) (string, error) {
	switch shell {
	case "zsh":
		return zshWidget, nil
	case "bash":
		return bashWidget, nil
	default:
		return "", fmt.Errorf("unsupported shell %q (use zsh or bash)", shell)
	}
}

// runInitInstall detects the active shell (explicit arg, then $SHELL) and
// appends the guarded snippet to its rc file, idempotently.
func runInitInstall(shell string) error {
	if shell == "" {
		shell = detectShell()
	}
	if shell != "zsh" && shell != "bash" {
		return fmt.Errorf("could not determine shell (set it explicitly: advsec init bash --install)")
	}
	snippet, err := snippetFor(shell)
	if err != nil {
		return err
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	rc := filepath.Join(home, map[string]string{"zsh": ".zshrc", "bash": ".bashrc"}[shell])

	existing, _ := os.ReadFile(rc)
	if updated, replaced := replaceBlock(string(existing), snippet); replaced {
		// An old block is present: update it in place (unless it is already
		// identical and --force was not given).
		if !flagInitForce && strings.Contains(string(existing), strings.TrimRight(snippet, "\n")) {
			fmt.Printf("advsec: integration already up to date in %s (use --force to rewrite)\n", rc)
			return nil
		}
		if err := os.WriteFile(rc, []byte(updated), 0o644); err != nil {
			return fmt.Errorf("update %s: %w", rc, err)
		}
		fmt.Printf("advsec: updated %s integration in %s (refreshed keybindings)\n", shell, rc)
		fmt.Printf("Reload it with:  source %s   (then press Alt+A)\n", rc)
		return nil
	}

	f, err := os.OpenFile(rc, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return fmt.Errorf("open %s: %w", rc, err)
	}
	defer f.Close()
	if _, err := f.WriteString("\n\n" + snippet); err != nil {
		return err
	}
	fmt.Printf("advsec: installed %s integration into %s\n", shell, rc)
	fmt.Printf("Reload it with:  source %s   (then press Alt+A)\n", rc)
	return nil
}

// replaceBlock swaps the content between the advsec start/end markers with the
// fresh snippet, preserving surrounding content. Returns (newContent, true) if
// a block was found and replaced, else ("", false).
func replaceBlock(content, snippet string) (string, bool) {
	start := strings.Index(content, blockStartPrefix)
	if start < 0 {
		return "", false
	}
	end := strings.Index(content[start:], blockEndPrefix)
	if end < 0 {
		return "", false
	}
	// Advance past the end-marker line.
	endAbs := start + end
	if nl := strings.IndexByte(content[endAbs:], '\n'); nl >= 0 {
		endAbs += nl + 1
	} else {
		endAbs = len(content)
	}
	// Trim a single trailing newline of the new snippet to match block framing.
	newBlock := strings.TrimRight(snippet, "\n") + "\n"
	return content[:start] + newBlock + content[endAbs:], true
}

// detectShell resolves the active shell from $SHELL, falling back to the parent
// process name in /proc/self/status (Linux).
func detectShell() string {
	if sh := os.Getenv("SHELL"); sh != "" {
		base := filepath.Base(sh)
		if strings.Contains(base, "zsh") {
			return "zsh"
		}
		if strings.Contains(base, "bash") {
			return "bash"
		}
	}
	if data, err := os.ReadFile("/proc/self/status"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "PPid:") {
				ppid := strings.TrimSpace(strings.TrimPrefix(line, "PPid:"))
				if comm, err := os.ReadFile("/proc/" + ppid + "/comm"); err == nil {
					name := strings.TrimSpace(string(comm))
					if strings.Contains(name, "zsh") {
						return "zsh"
					}
					if strings.Contains(name, "bash") {
						return "bash"
					}
				}
			}
		}
	}
	return ""
}

const zshWidget = `# >>> advsec shell integration (zsh) >>>
# Press Ctrl+Alt+A to re-run the last command and get advsec suggestions.
# Guarded so it is a no-op unless sourced under zsh.
if [ -n "$ZSH_VERSION" ]; then
    _advsec_widget() {
        local last
        last=$(fc -ln -1 2>/dev/null | sed 's/^[[:space:]]*//')
        [ -z "$last" ] && { echo; echo "advsec: no previous command"; return; }
        echo
        eval "$last" 2>&1 | advsec --cmd "$last" --top 3
    }
    zle -N _advsec_widget
    bindkey '^[^A' _advsec_widget 2>/dev/null   # Ctrl+Alt+A
    bindkey '^[a'  _advsec_widget 2>/dev/null   # Alt+a
    bindkey '^[A'  _advsec_widget 2>/dev/null   # Alt+A

    # Ctrl+Alt+S analyzes the current buffer instead of the last command.
    _advsec_buffer_widget() {
        [ -z "$BUFFER" ] && { zle -M "advsec: empty buffer"; return; }
        echo
        eval "$BUFFER" 2>&1 | advsec --cmd "$BUFFER" --top 3
        zle reset-prompt
    }
    zle -N _advsec_buffer_widget
    bindkey '^[^S' _advsec_buffer_widget 2>/dev/null   # Ctrl+Alt+S
fi
# <<< advsec shell integration (zsh) <<<
`

const bashWidget = `# >>> advsec shell integration (bash) >>>
# Press Ctrl+Alt+A to re-run the last command and get advsec suggestions.
# Guarded so it is a no-op unless sourced under bash.
if [ -n "$BASH_VERSION" ]; then
    _advsec_widget() {
        local last
        last=$(fc -ln -1 2>/dev/null | sed 's/^[[:space:]]*//')
        [ -z "$last" ] && { echo; echo "advsec: no previous command"; return; }
        echo
        eval "$last" 2>&1 | advsec --cmd "$last" --top 3
    }
    bind -x '"\e\C-a": _advsec_widget' 2>/dev/null   # Ctrl+Alt+A
    bind -x '"\e\C-A": _advsec_widget' 2>/dev/null   # Ctrl+Alt+Shift+A
    bind -x '"\ea": _advsec_widget' 2>/dev/null      # Alt+a
    bind -x '"\eA": _advsec_widget' 2>/dev/null      # Alt+Shift+A
fi
# <<< advsec shell integration (bash) <<<
`
