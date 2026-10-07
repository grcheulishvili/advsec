//go:build linux

package engine

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestAutoUpstreamCommandDetection verifies the /proc pipe inspector resolves
// the command line of the process holding the write end of a pipe. A real
// subprocess (`cat`, a non-shell) is attached to the write end; the test reads
// the read end's inode and asks the inspector to trace the writer.
func TestAutoUpstreamCommandDetection(t *testing.T) {
	// Pipe the subprocess READS from (so it stays alive until we close inW).
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer inW.Close()

	// Pipe under test: the subprocess writes here; we hold the read end.
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer outR.Close()

	// `cat` copies its stdin (inR) to its stdout (outW); it blocks until inW
	// is closed, so it remains the live writer on outR's pipe while we scan.
	catPath, err := exec.LookPath("cat")
	if err != nil {
		t.Skip("cat not available")
	}
	cmd := exec.Command(catPath)
	cmd.Stdin = inR
	cmd.Stdout = outW
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	// Parent drops its copies of the child's ends so the child is the SOLE
	// writer on outR's pipe.
	inR.Close()
	outW.Close()
	defer cmd.Wait()
	defer inW.Close()

	inode, ok := pipeInodeOfFD(int(outR.Fd()))
	if !ok {
		t.Fatalf("read end fd %d is not reported as a pipe", outR.Fd())
	}

	// The child's fds may take a moment to appear in /proc; poll briefly.
	var got string
	for i := 0; i < 50; i++ {
		if got = resolveUpstreamForInode(inode, os.Getpid()); got != "" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if got == "" {
		t.Fatalf("inspector did not resolve the upstream writer (pid %d) for inode %s", cmd.Process.Pid, inode)
	}
	if PrimaryBinary(got) != "cat" {
		t.Errorf("resolved upstream binary = %q (full %q), want cat", PrimaryBinary(got), got)
	}

	// Let cat finish.
	inW.Close()
}

// TestProcCmdlineRoundTrip checks the low-level NUL-separated cmdline reader
// against this test process.
func TestProcCmdlineRoundTrip(t *testing.T) {
	self, err := os.ReadFile("/proc/self/cmdline")
	if err != nil {
		t.Skip("/proc not available")
	}
	_ = self
	got := readCmdline(os.Getpid())
	if got == "" {
		t.Fatal("readCmdline(self) returned empty")
	}
	// The test binary path should be the first token; just assert non-garbage.
	if strings.Contains(got, "\x00") {
		t.Errorf("readCmdline left embedded NULs: %q", got)
	}
	if _, err := strconv.Atoi("x"); err == nil {
		t.Fatal("sanity")
	}
}

// TestCommandAndStreamFusion verifies that a command line's targets/ports are
// extracted at maximum priority and win over ambiguous stdout noise.
func TestCommandAndStreamFusion(t *testing.T) {
	// Ambiguous stdout that also happens to contain a *different* IP.
	stdout := "Connection logged from 198.51.100.7\nsome banner text\nnothing conclusive\n"
	ctx := ParseString(stdout)

	FuseCommandLine(ctx, "nmap -sV -p 22,80 10.0.0.1")

	if ctx.UpstreamBinary != "nmap" {
		t.Errorf("upstream binary = %q, want nmap", ctx.UpstreamBinary)
	}

	// The command-line IP must take priority over the stdout IP.
	if first := ctx.First(EntityIP); first != "10.0.0.1" {
		t.Errorf("First(IP) = %q, want 10.0.0.1 (command target must outrank stdout)", first)
	}
	if !ctx.IsCommandEntity(EntityIP, "10.0.0.1") {
		t.Error("10.0.0.1 not marked as a command entity")
	}
	if c := ctx.EntityConfidence(EntityIP, "10.0.0.1"); c != CommandEntityConfidence {
		t.Errorf("command IP confidence = %d, want %d", c, CommandEntityConfidence)
	}
	// The stdout IP remains present but at a lower (baseline) confidence.
	if c := ctx.EntityConfidence(EntityIP, "198.51.100.7"); c == CommandEntityConfidence {
		t.Error("stdout IP must not carry maximum command confidence")
	}

	// Both ports parsed from "-p 22,80".
	ports := strings.Join(ctx.Entities[EntityPort], ",")
	for _, want := range []string{"22", "80"} {
		if !containsStr(ctx.Entities[EntityPort], want) {
			t.Errorf("port %s missing from %q", want, ports)
		}
		if !ctx.IsCommandEntity(EntityPort, want) {
			t.Errorf("port %s not marked as a command entity", want)
		}
	}

	// The upstream command is surfaced in Raw so binary-name rules can fire.
	if !strings.Contains(ctx.Raw, "nmap -sV -p 22,80 10.0.0.1") {
		t.Error("upstream command not appended to Raw for rule matching")
	}
}

// TestParseCommandLineVariants exercises the argument parser across tools.
func TestParseCommandLineVariants(t *testing.T) {
	cases := []struct {
		cmd      string
		binary   string
		wantIP   string
		wantDom  string
		wantURL  string
		wantPath string
		ports    []string
	}{
		{cmd: "nmap -sV -p 22,80,443 scanme.corptest.net", binary: "nmap", wantDom: "scanme.corptest.net", ports: []string{"22", "80", "443"}},
		{cmd: "curl -sI https://target.corptest.net/login", binary: "curl", wantURL: "https://target.corptest.net/login"},
		{cmd: "cat /var/log/auth.log", binary: "cat", wantPath: "/var/log/auth.log"},
		{cmd: "sudo nmap --port=8080 10.10.10.5", binary: "nmap", wantIP: "10.10.10.5", ports: []string{"8080"}},
		{cmd: "journalctl -u ssh --no-pager", binary: "journalctl"},
		{cmd: "ffuf -w list.txt -u http://10.0.0.9/FUZZ", binary: "ffuf", wantURL: "http://10.0.0.9/FUZZ"},
	}
	for _, c := range cases {
		bin, ents := ParseCommandLine(c.cmd)
		if bin != c.binary {
			t.Errorf("%q: binary = %q, want %q", c.cmd, bin, c.binary)
		}
		if c.wantIP != "" && !containsStr(ents[EntityIP], c.wantIP) {
			t.Errorf("%q: IP %q missing (got %v)", c.cmd, c.wantIP, ents[EntityIP])
		}
		if c.wantDom != "" && !containsStr(ents[EntityDomain], c.wantDom) {
			t.Errorf("%q: domain %q missing (got %v)", c.cmd, c.wantDom, ents[EntityDomain])
		}
		if c.wantURL != "" && !containsStr(ents[EntityURL], c.wantURL) {
			t.Errorf("%q: URL %q missing (got %v)", c.cmd, c.wantURL, ents[EntityURL])
		}
		if c.wantPath != "" && !containsStr(ents[EntityPath], c.wantPath) {
			t.Errorf("%q: path %q missing (got %v)", c.cmd, c.wantPath, ents[EntityPath])
		}
		for _, p := range c.ports {
			if !containsStr(ents[EntityPort], p) {
				t.Errorf("%q: port %q missing (got %v)", c.cmd, p, ents[EntityPort])
			}
		}
	}
}

// TestResolveUpstreamFallbackOrder verifies env + flag fallbacks when auto
// tracing yields nothing (stdin here is the test harness, not a traced pipe).
func TestResolveUpstreamFallbackOrder(t *testing.T) {
	t.Setenv("ADVSEC_CMD", "")
	// Flag-only (Priority 3).
	if got := ResolveUpstreamCmd("curl https://x.example.com"); got != "curl https://x.example.com" {
		// Auto-trace may legitimately find the `go test` writer on some runners;
		// only assert the flag path when nothing was auto-detected.
		if traceUpstreamCommand() == "" {
			t.Errorf("flag fallback = %q, want the --cmd value", got)
		}
	}
	// Env (Priority 2) beats the flag (Priority 3) when auto-trace is empty.
	t.Setenv("ADVSEC_CMD", "nmap 10.0.0.1")
	if traceUpstreamCommand() == "" {
		if got := ResolveUpstreamCmd("ignored --flag"); got != "nmap 10.0.0.1" {
			t.Errorf("env fallback = %q, want ADVSEC_CMD value", got)
		}
	}
}

func containsStr(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
