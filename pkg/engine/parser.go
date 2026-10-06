// Package engine implements the stdin parsing, plugin matching, and
// recommendation evaluation pipeline that powers advsec.
package engine

import (
	"bufio"
	"io"
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
	// reIPv6 matches common IPv6 forms including compressed "::".
	reIPv6 = regexp.MustCompile(`\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{0,4}\b|::(?:[0-9A-Fa-f]{1,4}:){0,6}[0-9A-Fa-f]{1,4}`)
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
)

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

	// URLs first so their host parts don't pollute bare-domain extraction.
	urls := reURL.FindAllString(raw, -1)
	add(EntityURL, urls...)

	for _, m := range reIPv4.FindAllString(raw, -1) {
		if isValidIPv4(m) {
			add(EntityIP, m)
		}
	}
	for _, m := range reIPv6.FindAllString(raw, -1) {
		if isPlausibleIPv6(m) {
			add(EntityIPv6, m)
		}
	}
	for _, m := range reDomain.FindAllString(raw, -1) {
		if isPlausibleDomain(m) {
			add(EntityDomain, strings.ToLower(m))
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
	add(EntityMemAddr, reMemAddr.FindAllString(raw, -1)...)
	add(EntityCVE, reCVE.FindAllString(raw, -1)...)
	add(EntityEmail, reEmail.FindAllString(raw, -1)...)

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

func isValidIPv4(s string) bool {
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		n := atoiSafe(p)
		if n < 0 || n > 255 {
			return false
		}
		if len(p) > 1 && p[0] == '0' {
			return false // reject leading-zero octets (likely version strings)
		}
	}
	return true
}

func isValidPort(s string) bool {
	if len(s) > 1 && s[0] == '0' {
		return false // leading-zero "ports" are really time/version fragments
	}
	n := atoiSafe(s)
	return n > 0 && n <= 65535
}

// isPlausibleIPv6 filters the IPv6 regex's output to reject clock times and
// other all-decimal colon sequences. A candidate qualifies only if it uses
// "::" compression, or has a hextet containing a hex letter, or has at least
// three colons (true IPv6 segments), which excludes HH:MM:SS (two colons).
func isPlausibleIPv6(s string) bool {
	if s == "" || s == "::" {
		return false
	}
	if strings.Contains(s, "::") {
		return true
	}
	colons := strings.Count(s, ":")
	if colons < 2 {
		return false
	}
	hasHexLetter := strings.ContainsAny(s, "abcdefABCDEF")
	return hasHexLetter || colons >= 3
}

func isPlausibleDomain(s string) bool {
	s = strings.ToLower(s)
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
