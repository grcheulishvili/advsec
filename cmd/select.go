package cmd

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/charmbracelet/lipgloss"
	xterm "github.com/charmbracelet/x/term"
)

// selectContext presents an interactive picker so the user chooses the active
// context before rule evaluation. Because stdin carries the piped data, the
// menu is driven entirely through /dev/tty. It returns the chosen canonical
// domain ("" = all domains). On cancel it returns the pre-selected value.
//
// A raw-mode arrow-key menu is used when /dev/tty supports it; otherwise it
// falls back to a numbered prompt. This keeps advsec a single static binary
// (no bubbletea dependency tree) while still giving an interactive selector.
func selectContext(domains []string, current string) (string, error) {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return current, fmt.Errorf("--select needs a terminal (/dev/tty): %w", err)
	}
	defer tty.Close()

	// Options: index 0 = "all domains" (empty context), then each domain.
	options := append([]string{"(all domains)"}, domains...)
	start := 0
	for i, d := range domains {
		if d == current {
			start = i + 1
		}
	}

	fd := tty.Fd()
	if xterm.IsTerminal(fd) {
		if sel, ok := rawMenu(tty, fd, options, start); ok {
			return optionToContext(options, sel), nil
		}
		// fall through to numbered prompt on raw-mode failure
	}
	return numberedMenu(tty, options, start), nil
}

func optionToContext(options []string, idx int) string {
	if idx <= 0 || idx >= len(options) {
		return ""
	}
	return options[idx]
}

// rawMenu renders an arrow-navigable list. Returns (selectedIndex, true) on
// Enter, or (_, false) if raw mode could not be entered.
func rawMenu(tty *os.File, fd uintptr, options []string, start int) (int, bool) {
	old, err := xterm.MakeRaw(fd)
	if err != nil {
		return 0, false
	}
	defer xterm.Restore(fd, old)

	sel := clamp(start, 0, len(options)-1)
	hi := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("231")).Background(lipgloss.Color("63"))
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("244"))

	draw := func(first bool) {
		if !first {
			fmt.Fprintf(tty, "\x1b[%dA", len(options)+1) // cursor up to redraw
		}
		fmt.Fprintf(tty, "\r\x1b[2K%s\n", dim.Render("Select context  (↑/↓ or j/k, Enter to confirm, q to cancel):"))
		for i, o := range options {
			label := "  " + o
			if i == sel {
				label = "› " + o
				label = hi.Render(label)
			}
			fmt.Fprintf(tty, "\r\x1b[2K%s\n", label)
		}
	}
	draw(true)

	buf := make([]byte, 3)
	for {
		n, err := tty.Read(buf)
		if err != nil || n == 0 {
			return 0, false
		}
		switch {
		case buf[0] == '\r' || buf[0] == '\n':
			return sel, true
		case buf[0] == 3 || buf[0] == 'q' || buf[0] == 27 && n == 1: // ctrl-c / q / bare ESC
			return start, true
		case buf[0] == 27 && n >= 3 && buf[1] == '[':
			if buf[2] == 'A' {
				sel = clamp(sel-1, 0, len(options)-1)
			} else if buf[2] == 'B' {
				sel = clamp(sel+1, 0, len(options)-1)
			}
			draw(false)
		case buf[0] == 'k':
			sel = clamp(sel-1, 0, len(options)-1)
			draw(false)
		case buf[0] == 'j':
			sel = clamp(sel+1, 0, len(options)-1)
			draw(false)
		case buf[0] >= '1' && buf[0] <= '9':
			if idx := int(buf[0]-'1') + 1; idx < len(options) {
				sel = idx
				draw(false)
			}
		}
	}
}

// numberedMenu is the non-raw fallback: print a numbered list and read a line.
func numberedMenu(tty *os.File, options []string, start int) string {
	fmt.Fprintln(tty, "Select context (enter a number, blank = keep current):")
	for i, o := range options {
		marker := "  "
		if i == start {
			marker = "* "
		}
		fmt.Fprintf(tty, "%s%2d) %s\n", marker, i, o)
	}
	fmt.Fprint(tty, "> ")
	sc := bufio.NewScanner(tty)
	if !sc.Scan() {
		return optionToContext(options, start)
	}
	line := strings.TrimSpace(sc.Text())
	if line == "" {
		return optionToContext(options, start)
	}
	if idx, err := strconv.Atoi(line); err == nil && idx >= 0 && idx < len(options) {
		return optionToContext(options, idx)
	}
	return optionToContext(options, start)
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
