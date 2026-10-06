package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newInitCmd() *cobra.Command {
	c := &cobra.Command{
		Use:   "init [zsh|bash]",
		Short: "Print a shell integration widget (bind to a hotkey)",
		Long: `Generates a non-intrusive shell widget. It does NOT run on every
command - it binds a hotkey (Ctrl+Alt+A by default) that re-runs your last
command, pipes its output through advsec, and prints suggestions beneath the
prompt without touching your command buffer.

  advsec init zsh  >> ~/.zshrc
  advsec init bash >> ~/.bashrc`,
		Args:      cobra.ExactArgs(1),
		ValidArgs: []string{"zsh", "bash"},
		RunE: func(cmd *cobra.Command, args []string) error {
			// Lead with two newlines so that appending to a config file whose
			// last line has no trailing newline (`... >> ~/.zshrc`) cannot fuse
			// the opening marker onto that line and break the shell parser. Each
			// snippet already ends with a trailing newline.
			switch args[0] {
			case "zsh":
				fmt.Print("\n\n" + zshWidget)
			case "bash":
				fmt.Print("\n\n" + bashWidget)
			default:
				return fmt.Errorf("unsupported shell %q (use zsh or bash)", args[0])
			}
			return nil
		},
	}
	return c
}

const zshWidget = `# >>> advsec shell integration (zsh) >>>
# Press Ctrl+Alt+A to re-run the last command and get advsec suggestions.
# Non-intrusive: it prints beneath the prompt and leaves your buffer untouched.
_advsec_widget() {
    local last
    last=$(fc -ln -1 2>/dev/null)
    [ -z "$last" ] && { zle -M "advsec: no previous command"; return; }
    printf '\n'
    # Re-run the last command, capturing stdout+stderr, and analyze the top 3.
    eval "$last" 2>&1 | advsec --top 3
    # Redraw the prompt and restore the (unchanged) command line.
    zle reset-prompt
    zle redisplay
}
zle -N _advsec_widget
bindkey '^[^A' _advsec_widget   # Ctrl+Alt+A

# Optional: analyze whatever is already typed in the buffer instead (Ctrl+Alt+S)
_advsec_buffer_widget() {
    [ -z "$BUFFER" ] && { zle -M "advsec: empty buffer"; return; }
    printf '\n'
    eval "$BUFFER" 2>&1 | advsec --top 3
    zle reset-prompt
    zle redisplay
}
zle -N _advsec_buffer_widget
bindkey '^[^S' _advsec_buffer_widget   # Ctrl+Alt+S
# <<< advsec shell integration (zsh) <<<
`

const bashWidget = `# >>> advsec shell integration (bash) >>>
# Press Ctrl+Alt+A to re-run the last command and get advsec suggestions.
# Non-intrusive: prints beneath the prompt; the command line is preserved.
_advsec_widget() {
    local last
    last=$(fc -ln -1 2>/dev/null | sed 's/^[[:space:]]*//')
    [ -z "$last" ] && { echo; echo "advsec: no previous command"; return; }
    echo
    eval "$last" 2>&1 | advsec --top 3
}
# bind -x runs the function without disturbing the current READLINE_LINE.
bind -x '"\e\C-a": _advsec_widget'   # Ctrl+Alt+A
# <<< advsec shell integration (bash) <<<
`
