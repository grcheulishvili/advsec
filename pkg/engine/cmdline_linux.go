//go:build linux

package engine

// Automatic upstream-command detection via /proc.
//
// When advsec's stdin is a pipe, the process on the write end is the upstream
// tool that produced the data (nmap, curl, journalctl, cat, ...). Resolving its
// command line lets advsec anchor on the operator's real target instead of
// guessing from stdout noise - with zero configuration and no extra flags.

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// traceUpstreamCommand resolves the command line of the process writing to our
// stdin pipe. It returns "" when stdin is not a pipe, or when the only writers
// are shells / advsec itself (in which case the caller falls back to
// $ADVSEC_CMD or --cmd).
func traceUpstreamCommand() string {
	inode, ok := stdinPipeInode()
	if !ok {
		return ""
	}
	return resolveUpstreamForInode(inode, os.Getpid())
}

// stdinPipeInode reads /proc/self/fd/0 and, if it is a pipe, returns the pipe's
// inode number as a string.
func stdinPipeInode() (string, bool) {
	return pipeInodeOfFD(0)
}

// pipeInodeOfFD returns the pipe inode backing a file descriptor of THIS
// process, or ("", false) if that fd is not a pipe.
func pipeInodeOfFD(fd int) (string, bool) {
	target, err := os.Readlink("/proc/self/fd/" + strconv.Itoa(fd))
	if err != nil {
		return "", false
	}
	return parsePipeInode(target)
}

// parsePipeInode extracts "123456" from a symlink target of the form
// "pipe:[123456]".
func parsePipeInode(target string) (string, bool) {
	if !strings.HasPrefix(target, "pipe:[") || !strings.HasSuffix(target, "]") {
		return "", false
	}
	inode := target[len("pipe:[") : len(target)-1]
	if inode == "" {
		return "", false
	}
	return inode, true
}

// resolveUpstreamForInode scans every process for the write end of the given
// pipe inode and returns the first non-shell, non-self command line found.
func resolveUpstreamForInode(inode string, self int) string {
	for _, pid := range scanWritersOfPipe(inode, self) {
		cmd := readCmdline(pid)
		if cmd == "" || isShellOrSelf(cmd) {
			continue
		}
		return cmd
	}
	return ""
}

// scanWritersOfPipe walks /proc/[0-9]*/fd/* and returns the PIDs (excluding
// self) that hold the WRITE end of the given pipe inode. The write end is
// distinguished from the read end via /proc/<pid>/fdinfo/<fd> access flags, so
// advsec's own read end is never mistaken for a writer.
func scanWritersOfPipe(inode string, self int) []int {
	want := "pipe:[" + inode + "]"
	procs, _ := filepath.Glob("/proc/[0-9]*")
	var writers []int
	for _, proc := range procs {
		pid, err := strconv.Atoi(filepath.Base(proc))
		if err != nil || pid == self {
			continue
		}
		fds, _ := filepath.Glob(proc + "/fd/*")
		for _, fd := range fds {
			if tgt, err := os.Readlink(fd); err != nil || tgt != want {
				continue
			}
			if isWriteEnd(proc, filepath.Base(fd)) {
				writers = append(writers, pid)
				break
			}
		}
	}
	return writers
}

// isWriteEnd reports whether fd of a process is opened for writing (O_WRONLY or
// O_RDWR), by parsing the octal "flags:" line in /proc/<pid>/fdinfo/<fd>.
func isWriteEnd(proc, fd string) bool {
	data, err := os.ReadFile(proc + "/fdinfo/" + fd)
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "flags:") {
			continue
		}
		val := strings.TrimSpace(strings.TrimPrefix(line, "flags:"))
		n, err := strconv.ParseInt(val, 8, 64)
		if err != nil {
			return false
		}
		switch n & 3 { // O_ACCMODE
		case 1, 2: // O_WRONLY, O_RDWR
			return true
		}
		return false
	}
	return false
}

// readCmdline reads /proc/<pid>/cmdline and joins its NUL-separated arguments
// into a single space-delimited command string.
func readCmdline(pid int) string {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/cmdline")
	if err != nil {
		return ""
	}
	parts := strings.Split(strings.Trim(string(data), "\x00"), "\x00")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if strings.TrimSpace(p) != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, " ")
}
