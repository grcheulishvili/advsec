package engine

// Cross-platform upstream-command resolution, parsing, and context fusion.
// The Linux /proc tracer lives in cmdline_linux.go; everything here is portable.

import (
	"net"
	"os"
	"strings"
)

// CommandEntityConfidence is the (maximum) confidence assigned to entities that
// appear directly on the upstream command line. Command-line targets are the
// operator's explicit intent, so they outrank anything mined from stdout noise.
const CommandEntityConfidence = 3

// ResolveUpstreamCmd determines the upstream command string using the spec's
// fallback order:
//
//	Priority 1: automatic /proc pipe tracing (zero configuration)
//	Priority 2: the ADVSEC_CMD environment variable
//	Priority 3: an explicit --cmd override flag
//
// Automatic tracing only "wins" when it finds a real (non-shell) writer, so the
// explicit fallbacks still apply for the shell-widget case.
func ResolveUpstreamCmd(flagCmd string) string {
	if c := strings.TrimSpace(traceUpstreamCommand()); c != "" {
		return c
	}
	if c := strings.TrimSpace(os.Getenv("ADVSEC_CMD")); c != "" {
		return c
	}
	return strings.TrimSpace(flagCmd)
}

// cmdWrappers are launchers that precede the real tool on a command line; the
// binary that matters is the first token after them.
var cmdWrappers = map[string]bool{
	"sudo": true, "doas": true, "env": true, "nice": true, "ionice": true,
	"nohup": true, "time": true, "stdbuf": true, "setsid": true, "timeout": true,
	"proxychains": true, "proxychains4": true, "unbuffer": true,
}

// cmdShells are shells (and advsec itself) that are never treated as the
// meaningful upstream writer.
var cmdShells = map[string]bool{
	"advsec": true, "sh": true, "bash": true, "zsh": true, "dash": true,
	"ksh": true, "fish": true, "csh": true, "tcsh": true, "ash": true,
}

// isShellOrSelf reports whether a command line's primary binary is a shell or
// advsec itself.
func isShellOrSelf(cmd string) bool {
	return cmdShells[PrimaryBinary(cmd)]
}

// PrimaryBinary returns the base name of the real tool on a command line,
// skipping known launcher wrappers (sudo/env/...) and leading VAR=val
// assignments.
func PrimaryBinary(cmd string) string {
	fields := splitArgs(cmd)
	i := firstBinaryIndex(fields)
	if i < 0 {
		return ""
	}
	return baseName(fields[i])
}

// firstBinaryIndex returns the index of the real binary token, or -1.
func firstBinaryIndex(fields []string) int {
	i := 0
	for i < len(fields) {
		f := fields[i]
		if strings.Contains(f, "=") && !strings.HasPrefix(f, "-") && !strings.Contains(f, "/") {
			i++ // VAR=val assignment (env style)
			continue
		}
		if cmdWrappers[baseName(f)] {
			i++
			// skip any flags that belong to the wrapper (e.g. timeout 5s)
			for i < len(fields) && strings.HasPrefix(fields[i], "-") {
				i++
			}
			// a bare wrapper operand like `timeout 5s` - skip a lone duration arg
			if baseName(fieldsAt(fields, i-1)) == "timeout" && i < len(fields) && isDurationish(fields[i]) {
				i++
			}
			continue
		}
		return i
	}
	return -1
}

func fieldsAt(fields []string, i int) string {
	if i >= 0 && i < len(fields) {
		return fields[i]
	}
	return ""
}

func isDurationish(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if (r < '0' || r > '9') && r != 's' && r != 'm' && r != 'h' && r != 'd' && r != '.' {
			return false
		}
	}
	return s[0] >= '0' && s[0] <= '9'
}

// ParseCommandLine extracts the primary binary name and the target entities
// (IPs, IPv6, URLs, domains, file paths, ports) carried as arguments.
func ParseCommandLine(cmd string) (binary string, ents map[EntityKind][]string) {
	ents = make(map[EntityKind][]string)
	fields := splitArgs(cmd)
	bi := firstBinaryIndex(fields)
	if bi < 0 {
		return "", ents
	}
	binary = baseName(fields[bi])
	args := fields[bi+1:]

	add := func(k EntityKind, v string) {
		ents[k] = appendUnique(ents[k], v)
	}

	for idx := 0; idx < len(args); idx++ {
		a := args[idx]

		// Port flags: -p 80,443 / --port 8080 / -p80 / --port=8080.
		if a == "-p" || a == "--port" || a == "-port" || a == "--ports" {
			if idx+1 < len(args) {
				for _, p := range parsePortList(args[idx+1]) {
					add(EntityPort, p)
				}
				idx++
			}
			continue
		}
		if strings.HasPrefix(a, "-p") && len(a) > 2 && a[2] != '-' {
			for _, p := range parsePortList(a[2:]) {
				add(EntityPort, p)
			}
			continue
		}
		if v, ok := flagValue(a, "--port"); ok {
			for _, p := range parsePortList(v) {
				add(EntityPort, p)
			}
			continue
		}

		// Positional (non-flag) tokens carry targets.
		if strings.HasPrefix(a, "-") {
			continue
		}
		classifyCmdArg(a, add)
	}
	return binary, ents
}

// classifyCmdArg routes a single positional argument to the right entity kind.
func classifyCmdArg(a string, add func(EntityKind, string)) {
	if u := reURL.FindString(a); u != "" {
		if host := urlHost(u); host == "" || !isIgnoredDomain(host) {
			add(EntityURL, u)
		}
		return
	}
	// Strip a trailing :port so "10.0.0.1:8080" yields IP + port.
	host, port := splitHostPort(a)
	if port != "" && isValidPort(port) {
		add(EntityPort, port)
	}
	if ip := net.ParseIP(host); ip != nil {
		if loopbackOrBind(host) {
			return
		}
		if ip.To4() != nil {
			add(EntityIP, host)
		} else {
			add(EntityIPv6, host)
		}
		return
	}
	if looksLikePath(a) {
		add(EntityPath, a)
		return
	}
	if isPlausibleDomain(host) && !isIgnoredDomain(host) {
		add(EntityDomain, strings.ToLower(host))
	}
}

// splitHostPort splits "host:port" only when port is purely numeric; otherwise
// it returns (s, ""). IPv6 literals in brackets are handled.
func splitHostPort(s string) (host, port string) {
	if strings.HasPrefix(s, "[") {
		if i := strings.Index(s, "]"); i >= 0 {
			host = s[1:i]
			rest := s[i+1:]
			if strings.HasPrefix(rest, ":") {
				port = rest[1:]
			}
			return host, port
		}
	}
	// Exactly one colon → candidate host:port (avoid bare IPv6 which has many).
	if strings.Count(s, ":") == 1 {
		i := strings.IndexByte(s, ':')
		h, p := s[:i], s[i+1:]
		if p != "" && allDigits(p) {
			return h, p
		}
	}
	return s, ""
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// looksLikePath reports whether a token is a filesystem path argument.
func looksLikePath(a string) bool {
	switch {
	case strings.HasPrefix(a, "/"), strings.HasPrefix(a, "./"),
		strings.HasPrefix(a, "../"), strings.HasPrefix(a, "~/"):
		return true
	}
	return false
}

// parsePortList parses "22,80" / "22-25" / "8080" into individual valid ports.
// Ranges contribute their endpoints.
func parsePortList(s string) []string {
	var out []string
	for _, tok := range strings.Split(s, ",") {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		if strings.Contains(tok, "-") {
			for _, end := range strings.SplitN(tok, "-", 2) {
				if isValidPort(end) {
					out = append(out, end)
				}
			}
			continue
		}
		if isValidPort(tok) {
			out = append(out, tok)
		}
	}
	return out
}

// flagValue returns the value of a "--flag=value" token when name matches.
func flagValue(tok, name string) (string, bool) {
	prefix := name + "="
	if strings.HasPrefix(tok, prefix) {
		return tok[len(prefix):], true
	}
	return "", false
}

// FuseCommandLine merges a resolved upstream command string into a parsed
// Context: it records the command + binary, extracts the command's target
// entities, promotes them to the front of each entity list (maximum priority),
// marks them as command entities (confidence = CommandEntityConfidence), and
// appends the command text to Raw so binary-name regex/contains rules fire.
//
// It is called AFTER Classify, so stdout-based format detection is unchanged.
func FuseCommandLine(ctx *Context, cmd string) {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return
	}
	ctx.UpstreamCmd = cmd
	bin, ents := ParseCommandLine(cmd)
	ctx.UpstreamBinary = bin

	if ctx.cmdEntities == nil {
		ctx.cmdEntities = make(map[EntityKind]map[string]bool)
	}
	for k, vals := range ents {
		set := ctx.cmdEntities[k]
		if set == nil {
			set = make(map[string]bool)
			ctx.cmdEntities[k] = set
		}
		for _, v := range vals {
			set[strings.TrimSpace(v)] = true
		}
		ctx.Entities[k] = moveFront(ctx.Entities[k], vals)
	}

	if len(ents[EntityIP]) > 0 || len(ents[EntityIPv6]) > 0 ||
		len(ents[EntityDomain]) > 0 || len(ents[EntityURL]) > 0 {
		ctx.ExternalTarget = true
	}

	// Surface the upstream command to text/regex rules (so a plugin keyed on
	// `nmap`, `journalctl`, `ffuf`, ... recognizes it) without disturbing the
	// already-computed Format.
	ctx.Raw = ctx.Raw + "\n# advsec-upstream-cmd: " + cmd + "\n"
}

// IsCommandEntity reports whether value of kind k was taken from the upstream
// command line.
func (c *Context) IsCommandEntity(k EntityKind, v string) bool {
	if c.cmdEntities == nil {
		return false
	}
	return c.cmdEntities[k][strings.TrimSpace(v)]
}

// EntityConfidence returns CommandEntityConfidence for command-line entities and
// a baseline of 1 for entities mined from stdout.
func (c *Context) EntityConfidence(k EntityKind, v string) int {
	if c.IsCommandEntity(k, v) {
		return CommandEntityConfidence
	}
	return 1
}

// splitArgs is a minimal shell-style tokenizer: it splits on unquoted
// whitespace and honors single and double quotes. It is intentionally simple -
// enough to recover arguments from a /proc cmdline or a $last history line.
func splitArgs(s string) []string {
	var args []string
	var cur strings.Builder
	var quote rune
	inWord := false
	flush := func() {
		if inWord {
			args = append(args, cur.String())
			cur.Reset()
			inWord = false
		}
	}
	for _, r := range s {
		switch {
		case quote != 0:
			if r == quote {
				quote = 0
			} else {
				cur.WriteRune(r)
			}
			inWord = true
		case r == '\'' || r == '"':
			quote = r
			inWord = true
		case r == ' ' || r == '\t' || r == '\n' || r == '\r':
			flush()
		default:
			cur.WriteRune(r)
			inWord = true
		}
	}
	flush()
	return args
}
