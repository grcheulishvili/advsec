// Package engine implements the stdin parsing, plugin matching, and
// recommendation evaluation pipeline that powers advsec.
package engine

import (
	"bufio"
	"io"
	"net"
	"regexp"
	"sort"
	"strings"
)

// MaxBufferBytes is the upper bound on how much piped input advsec will read.
// The spec calls for a non-blocking 2MB streaming buffer so that a very
// chatty upstream (e.g. `journalctl -f`) cannot deadlock the pipe or exhaust
// memory. Input beyond this limit is discarded after the cap is reached.
const MaxBufferBytes = 2 * 1024 * 1024

// EntityKind enumerates the categories of token the parser extracts.
type EntityKind string

const (
	EntityIP      EntityKind = "ip"
	EntityIPv6    EntityKind = "ipv6"
	EntityDomain  EntityKind = "domain"
	EntityURL     EntityKind = "url"
	EntityPort    EntityKind = "port"
	EntityHash    EntityKind = "hash"
	EntityMemAddr EntityKind = "mem_addr"
	EntityCVE     EntityKind = "cve"
	EntityEmail   EntityKind = "email"
)

// Context is the structured view of a chunk of piped input. It carries both
// the raw text (for regex rule evaluation) and the deduplicated entities the
// parser recognized (for placeholder expansion and entity-type rules).
type Context struct {
	// Raw is the (possibly truncated) input text.
	Raw string
	// Truncated is true if input exceeded MaxBufferBytes.
	Truncated bool
	// ExternalTarget is true when at least one routable (non-loopback,
	// non-bind, non-private-noise) IP, IPv6, domain, or URL was found. Network
	// attack rules can consult this to avoid firing on pure-localhost output.
	ExternalTarget bool
	// Entities maps an EntityKind to the ordered, deduplicated values found.
	Entities map[EntityKind][]string
}

// First returns the first extracted value of the given kind, or "".
func (c *Context) First(k EntityKind) string {
	if vals := c.Entities[k]; len(vals) > 0 {
		return vals[0]
	}
	return ""
}

// Has reports whether at least one entity of the given kind was found.
func (c *Context) Has(k EntityKind) bool {
	return len(c.Entities[k]) > 0
}

var (
	// reIPv4 matches dotted-quad addresses. Octet range is validated in a
	// post-filter to keep the expression fast and readable.
	reIPv4 = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	// reIPv6 is a permissive *candidate* matcher — anything that looks roughly
	// like an IPv6 address. Every candidate is then validated with
	// net.ParseIP, which enforces the real 8-group / compression grammar and
	// eliminates junk like "C:c:F:" or register dumps. The candidate requires
	// at least one "::" or two colons with a hex group on each side.
	reIPv6 = regexp.MustCompile(`\b(?:[0-9A-Fa-f]{1,4}:){2,}[0-9A-Fa-f]{1,4}\b|\b(?:[0-9A-Fa-f]{1,4}:){1,}:(?:[0-9A-Fa-f]{1,4})?\b|::(?:[0-9A-Fa-f]{1,4}:)*[0-9A-Fa-f]{1,4}`)
	// reURL matches http/https/ftp URLs.
	reURL = regexp.MustCompile(`\b(?:https?|ftp)://[^\s"'<>) ]+`)
	// reDomain matches hostnames with a TLD of 2+ letters.
	reDomain = regexp.MustCompile(`\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,24}\b`)
	// rePortNmap matches nmap-style "22/tcp open" and "443/udp" lines.
	rePortNmap = regexp.MustCompile(`\b(\d{1,5})/(?:tcp|udp)\b`)
	// rePortColon matches "host:port" tokens where the host is a full IPv4
	// address or a name containing at least one letter. This deliberately
	// excludes bare-numeric "host" parts so clock times like 10:00:01 are not
	// mistaken for ports. The port must not be followed by another colon or
	// digit (another guard against HH:MM:SS).
	rePortColon = regexp.MustCompile(`(?:\d{1,3}(?:\.\d{1,3}){3}|[a-zA-Z0-9.-]*[a-zA-Z][a-zA-Z0-9.-]*):(\d{2,5})(?:[^:\d]|$)`)
	// reHash matches md5/sha1/sha256/sha512 hex digests.
	reHash = regexp.MustCompile(`\b[0-9a-fA-F]{32}\b|\b[0-9a-fA-F]{40}\b|\b[0-9a-fA-F]{64}\b|\b[0-9a-fA-F]{128}\b`)
	// reMemAddr matches hex memory addresses like 0x7ffff7a0d000.
	reMemAddr = regexp.MustCompile(`\b0x[0-9a-fA-F]{4,16}\b`)
	// reCVE matches CVE identifiers.
	reCVE = regexp.MustCompile(`\bCVE-\d{4}-\d{4,7}\b`)
	// reEmail matches email addresses.
	reEmail = regexp.MustCompile(`\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,24}\b`)
	// reDebugCtx detects debugger / pwn memory-dump context. Only then are bare
	// hex values treated as memory addresses (otherwise 0x8007000D-style error
	// codes would masquerade as pointers).
	reDebugCtx = regexp.MustCompile(`(?i)\b(?:r[a-ds]x|r[sbi]p|rsi|rdi|r8|r9|r1[0-5]|e[a-d]x|e[sb]p|eip|gdb|pwndbg|\bgef\b|\$pc\b|backtrace|#\d+\s+0x|Program received signal|SIGSEGV|vmmap|got\b|plt\b)`)
)

// loopbackOrBind reports whether an IP string is a loopback / unspecified /
// bind-only address that should not drive network attack recommendations.
func loopbackOrBind(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "0.0.0.0", "127.0.0.1", "::", "::1", "0:0:0:0:0:0:0:1", "localhost":
		return true
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return false
	}
	return ip.IsLoopback() || ip.IsUnspecified()
}

// commonTLDNoise filters out dotted tokens that look like domains but are
// almost certainly filenames or version strings.
var fileyTLDs = map[string]bool{
	"so": true, "go": true, "py": true, "js": true, "md": true, "sh": true,
	"c": true, "h": true, "o": true, "a": true, "yaml": true, "yml": true,
	"json": true, "txt": true, "log": true, "conf": true, "cfg": true,
	"exe": true, "dll": true, "bin": true, "dat": true, "db": true,
}

// Parse reads up to MaxBufferBytes from r and returns a populated Context.
// Reading is bounded and streaming: a LimitReader caps total bytes so an
// unbounded upstream cannot hang or OOM the process.
func Parse(r io.Reader) (*Context, error) {
	limited := io.LimitReader(r, MaxBufferBytes+1)
	br := bufio.NewReaderSize(limited, 64*1024)

	var sb strings.Builder
	buf := make([]byte, 64*1024)
	total := 0
	truncated := false
	for {
		n, err := br.Read(buf)
		if n > 0 {
			if total+n > MaxBufferBytes {
				take := MaxBufferBytes - total
				if take > 0 {
					sb.Write(buf[:take])
					total += take
				}
				truncated = true
				break
			}
			sb.Write(buf[:n])
			total += n
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
	}

	ctx := ParseString(sb.String())
	ctx.Truncated = truncated
	return ctx, nil
}

// ParseString runs the extraction pass over an in-memory string. It is split
// from Parse so it can be unit-tested and reused by callers that already hold
// the text.
func ParseString(raw string) *Context {
	ctx := &Context{
		Raw:      raw,
		Entities: make(map[EntityKind][]string),
	}

	add := func(k EntityKind, vals ...string) {
		for _, v := range vals {
			ctx.Entities[k] = appendUnique(ctx.Entities[k], v)
		}
	}

	external := false

	// URLs first so their host parts don't pollute bare-domain extraction.
	for _, u := range reURL.FindAllString(raw, -1) {
		add(EntityURL, u)
		if !urlIsLocal(u) {
			external = true
		}
	}

	// IPv4: validate with net.ParseIP, then suppress loopback/bind addresses
	// from the target list (they are not useful attack targets).
	for _, m := range reIPv4.FindAllString(raw, -1) {
		ip := net.ParseIP(m)
		if ip == nil || ip.To4() == nil {
			continue
		}
		if loopbackOrBind(m) {
			continue
		}
		add(EntityIP, m)
		external = true
	}

	// IPv6: candidate regex then strict net.ParseIP validation.
	for _, m := range reIPv6.FindAllString(raw, -1) {
		ip := net.ParseIP(m)
		if ip == nil || ip.To4() != nil { // reject invalid and IPv4-in-IPv6 noise
			continue
		}
		if loopbackOrBind(m) {
			continue
		}
		add(EntityIPv6, m)
		external = true
	}

	for _, m := range reDomain.FindAllString(raw, -1) {
		if isPlausibleDomain(m) {
			d := strings.ToLower(m)
			add(EntityDomain, d)
			external = true
		}
	}
	for _, m := range rePortNmap.FindAllStringSubmatch(raw, -1) {
		if isValidPort(m[1]) {
			add(EntityPort, m[1])
		}
	}
	for _, m := range rePortColon.FindAllStringSubmatch(raw, -1) {
		if isValidPort(m[1]) {
			add(EntityPort, m[1])
		}
	}
	add(EntityHash, reHash.FindAllString(raw, -1)...)

	// Memory addresses: only when the input is actually a debugger / pwn dump.
	// Otherwise hex values (Windows HRESULTs like 0x8007000D, color codes,
	// offsets in source) are left alone instead of posing as pointers.
	if reDebugCtx.MatchString(raw) {
		add(EntityMemAddr, reMemAddr.FindAllString(raw, -1)...)
	}

	add(EntityCVE, reCVE.FindAllString(raw, -1)...)
	add(EntityEmail, reEmail.FindAllString(raw, -1)...)
	ctx.ExternalTarget = external

	// Keep port output stable and human-friendly.
	if ports := ctx.Entities[EntityPort]; len(ports) > 1 {
		sort.Slice(ports, func(i, j int) bool { return atoiSafe(ports[i]) < atoiSafe(ports[j]) })
	}
	return ctx
}

func appendUnique(s []string, v string) []string {
	v = strings.TrimSpace(v)
	if v == "" {
		return s
	}
	for _, e := range s {
		if e == v {
			return s
		}
	}
	return append(s, v)
}

// urlIsLocal reports whether a URL points at localhost/loopback.
func urlIsLocal(u string) bool {
	low := strings.ToLower(u)
	return strings.Contains(low, "://localhost") ||
		strings.Contains(low, "://127.0.0.1") ||
		strings.Contains(low, "://[::1]") ||
		strings.Contains(low, "://0.0.0.0")
}

func isValidPort(s string) bool {
	if len(s) > 1 && s[0] == '0' {
		return false // leading-zero "ports" are really time/version fragments
	}
	n := atoiSafe(s)
	return n > 0 && n <= 65535
}

func isPlausibleDomain(s string) bool {
	s = strings.ToLower(s)
	// Reverse-DNS zones are not attack-surface domains.
	if strings.HasSuffix(s, "in-addr.arpa") || strings.HasSuffix(s, "ip6.arpa") {
		return false
	}
	if s == "localhost" {
		return false
	}
	// An all-numeric final label means it's really an IPv4 caught by the
	// domain regex; skip it.
	idx := strings.LastIndex(s, ".")
	if idx < 0 || idx == len(s)-1 {
		return false
	}
	tld := s[idx+1:]
	if fileyTLDs[tld] {
		return false
	}
	// Reject tokens whose TLD is numeric.
	for _, r := range tld {
		if r < 'a' || r > 'z' {
			return false
		}
	}
	return true
}

func atoiSafe(s string) int {
	n := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return -1
		}
		n = n*10 + int(r-'0')
	}
	return n
}
