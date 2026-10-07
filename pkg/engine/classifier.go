package engine

import (
	"regexp"
	"strings"

	"github.com/grcheulishvili/advsec/pkg/plugin"
)

// Format is a classified input stream type (a MIME-like "class/subtype").
type Format string

const (
	FormatUnknown Format = ""
	FormatText    Format = "text/plain"
	FormatLog     Format = "text/log"
	FormatPcap    Format = "text/pcap"
	FormatEmail   Format = "email/mime"
	FormatELF     Format = "binary/elf"
	FormatPE      Format = "binary/pe"
	FormatMachO   Format = "binary/macho"
	FormatZip     Format = "archive/zip"
	FormatGzip    Format = "archive/gzip"
	Format7z      Format = "archive/7z"
	FormatPDF     Format = "document/pdf"
	FormatJSON    Format = "text/json"

	FormatJavaScript Format = "code/javascript"
	FormatPowerShell Format = "code/powershell"
	FormatShell      Format = "code/shell"
	FormatNmap       Format = "network/nmap"
	FormatSocket     Format = "network/socket"

	// FormatAdvsecOutput marks advsec's own rendered output / help text piped
	// back into advsec, so we don't extract example placeholders as targets.
	FormatAdvsecOutput Format = "text/advsec_output"

	// List-style streams: wordlists, payload cheat-sheets, and path lists.
	// These are data to feed to fuzzers, not targets to scan.
	FormatWordlist    Format = "text/wordlist"
	FormatPayloadList Format = "text/payload_list"
	FormatPathList    Format = "text/path_list"
)

// IsListFormat reports whether a format is a wordlist/payload/path list, where
// individual lines are data (not targets to extract).
func IsListFormat(f Format) bool {
	return f == FormatWordlist || f == FormatPayloadList || f == FormatPathList
}

// classifyWindow is how many leading bytes the profiler inspects.
const classifyWindow = 512

var (
	reEmailHdr  = regexp.MustCompile(`(?im)^(received|from|to|subject|message-id|mime-version|dkim-signature|return-path|content-type:\s*(multipart|message/rfc822)):`)
	reSyslog    = regexp.MustCompile(`(?m)^([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}|\[\s*\d+\.\d+\])`)
	reAccessLog = regexp.MustCompile(`"(GET|POST|PUT|HEAD|DELETE) [^"]+ HTTP/[0-9.]+"\s+\d{3}`)
	reJSON      = regexp.MustCompile(`^\s*[\{\[]`)

	reNmap       = regexp.MustCompile(`(?m)Nmap scan report for|Starting Nmap|^PORT\s+STATE\s+SERVICE`)
	reSocket     = regexp.MustCompile(`(?m)^Netid\s+State|Recv-Q\s+Send-Q|Active Internet connections|^Proto\s+Recv-Q`)
	rePowerShell = regexp.MustCompile(`(?m)\$env:|Invoke-[A-Z]|-[Ee]ncodedCommand|\[System\.[A-Za-z]|\[Ref\]\.Assembly|\bIEX\b|New-Object\s+Net\.WebClient`)
	reJavaScript = regexp.MustCompile(`(?m)function\s*\(|=>|document\.(cookie|write|location)|window\[|window\.|eval\(|_0x[0-9a-fA-F]{2,}|console\.log|require\(|module\.exports|atob\(`)
	reShellBang  = regexp.MustCompile(`(?m)^#!\s*/(bin|usr/bin)/`)
	// reFileOut recognizes `file`-command textual output ("name: ELF 64-bit...")
	// so a description of a binary scopes like the binary itself.
	reFileOut = regexp.MustCompile(`(?im):\s+(ELF (?:32|64)-bit|PE32\+? executable|Mach-O (?:64-bit|universal|executable))`)
	// reFileArchive recognizes `file`-command output for archives.
	reFileArchive = regexp.MustCompile(`(?im):\s+.*?(Zip archive data|gzip compressed|POSIX tar|tar archive|7-zip archive|RAR archive|bzip2 compressed|XZ compressed|Microsoft Cabinet)`)
	// reAdvsecOut recognizes advsec's own banner, phase headers, and help page.
	reAdvsecOut = regexp.MustCompile(`(?m)ADVSEC\s*\xe2\x94\x82|ADVSEC \||\[Phase \d|Usage:\s+advsec|advsec reads piped stdin|Tactical Objective:|Inferred Intent:`)
)

// Classify profiles the first bytes of raw input and returns its format.
// Binary magic numbers are checked first (exact), then structured-text
// heuristics (email, logs, json), falling back to text/plain.
func Classify(raw string) Format {
	if raw == "" {
		return FormatUnknown
	}
	head := raw
	if len(head) > classifyWindow {
		head = head[:classifyWindow]
	}

	// --- binary magic bytes ---
	switch {
	case strings.HasPrefix(head, "\x7fELF"):
		return FormatELF
	case strings.HasPrefix(head, "MZ"):
		return FormatPE
	case strings.HasPrefix(head, "\xfe\xed\xfa\xce"), strings.HasPrefix(head, "\xfe\xed\xfa\xcf"),
		strings.HasPrefix(head, "\xce\xfa\xed\xfe"), strings.HasPrefix(head, "\xcf\xfa\xed\xfe"),
		strings.HasPrefix(head, "\xca\xfe\xba\xbe"): // Mach-O (incl. fat/universal)
		return FormatMachO
	case strings.HasPrefix(head, "PK\x03\x04"), strings.HasPrefix(head, "PK\x05\x06"):
		return FormatZip
	case strings.HasPrefix(head, "7z\xbc\xaf\x27\x1c"):
		return Format7z
	case strings.HasPrefix(head, "\x1f\x8b"):
		return FormatGzip
	case strings.HasPrefix(head, "%PDF-"):
		return FormatPDF
	case strings.HasPrefix(head, "\xd4\xc3\xb2\xa1"), strings.HasPrefix(head, "\xa1\xb2\xc3\xd4"),
		strings.HasPrefix(head, "\x0a\x0d\x0d\x0a"): // classic pcap / pcapng
		return FormatPcap
	}

	// --- structured text heuristics (most specific first) ---
	// advsec's own output / help text takes precedence so `advsec --help | advsec`
	// and `advsec | advsec` don't mine example placeholders as real targets.
	if reAdvsecOut.MatchString(head) {
		return FormatAdvsecOutput
	}
	if reEmailHdr.MatchString(head) {
		return FormatEmail
	}
	if reNmap.MatchString(head) {
		return FormatNmap
	}
	if reSocket.MatchString(head) {
		return FormatSocket
	}
	// Access logs look superficially code-ish; classify them before code.
	if reAccessLog.MatchString(head) {
		return FormatLog
	}
	// `file`-command output describing a binary scopes like that binary.
	if m := reFileOut.FindStringSubmatch(head); m != nil {
		switch {
		case strings.HasPrefix(m[1], "ELF"):
			return FormatELF
		case strings.HasPrefix(m[1], "PE32"):
			return FormatPE
		case strings.HasPrefix(m[1], "Mach-O"):
			return FormatMachO
		}
	}
	// `file`-command output describing an archive scopes as that archive, so a
	// described archive gets extraction tools while a text list never does.
	if m := reFileArchive.FindStringSubmatch(head); m != nil {
		a := strings.ToLower(m[1])
		switch {
		case strings.Contains(a, "gzip"):
			return FormatGzip
		case strings.Contains(a, "7-zip"):
			return Format7z
		default:
			return FormatZip
		}
	}
	// Wordlists / payload lists / path lists must be detected BEFORE code
	// heuristics, since a list of `<script>` payloads would otherwise look like
	// JavaScript, and a list of SQLi/traversal strings like code.
	if lf := detectListFormat(raw); lf != "" {
		return lf
	}
	if reShellBang.MatchString(head) {
		return FormatShell
	}
	if rePowerShell.MatchString(head) {
		return FormatPowerShell
	}
	if reJavaScript.MatchString(head) {
		return FormatJavaScript
	}
	if reSyslog.MatchString(head) {
		return FormatLog
	}
	if reJSON.MatchString(head) {
		return FormatJSON
	}
	return FormatText
}

// formatScope maps a classified format to the set of plugin domains that make
// sense for it. ok=false means "do not restrict" (the format is not a
// container, so normal/context-based evaluation applies).
//
// This is what stops `cat message.eml | advsec` from triggering Kerberoasting,
// Docker, SDR, Bluetooth, etc.: an email is scoped to the eml domain only.
func formatScope(f Format) (allowed map[string]bool, ok bool) {
	set := func(ds ...string) map[string]bool {
		m := make(map[string]bool, len(ds))
		for _, d := range ds {
			m[d] = true
		}
		return m
	}
	switch f {
	case FormatAdvsecOutput:
		return set(), true // scope to nothing: advsec output has no real targets
	case FormatWordlist, FormatPayloadList, FormatPathList:
		// Lists are fuzzing/grep input: only the general-domain wordlist triage
		// applies; active recon / exploitation / binary rules are suppressed.
		return set("general"), true
	case FormatEmail:
		return set("eml", "crypto"), true
	case FormatJavaScript:
		return set("js", "web", "crypto"), true
	case FormatPowerShell:
		return set("redteam", "crypto", "sysadmin"), true
	case FormatShell:
		return set("sysadmin", "dfir"), true
	case FormatNmap:
		return set("network", "recon", "web"), true
	case FormatSocket:
		return set("network", "sysadmin"), true
	case FormatPcap:
		return set("forensics", "network"), true
	case FormatZip, FormatGzip, Format7z:
		return set("general", "forensics", "ctf"), true
	case FormatPDF:
		return set("general", "forensics", "ctf"), true
	case FormatELF:
		return set("pwn", "reversing", "ctf"), true
	case FormatPE:
		return set("reversing", "redteam"), true
	case FormatMachO:
		return set("reversing", "pwn"), true
	case FormatLog:
		return set("blueteam", "dfir", "sysadmin", "general"), true
	default:
		// text/plain, json, unknown: no container, evaluate normally.
		return nil, false
	}
}

var (
	rePathish    = regexp.MustCompile(`(?i)^/(etc|var|proc|sys|home|usr|opt|tmp|root|boot|dev|run)/|^/[a-z0-9._-]+/|\.(x?log|conf|cfg|pid|sock)$|/var/log`)
	rePayXSS     = regexp.MustCompile(`(?i)<script|onerror=|onload=|<img\s|<svg|javascript:|alert\(|<iframe`)
	rePaySQLi    = regexp.MustCompile(`(?i)union\s+select|'\s*or\s|"\s*or\s|or\s+1=1|sleep\(|benchmark\(|information_schema|'--|waitfor\s+delay`)
	rePayTrav    = regexp.MustCompile(`(?i)\.\./|\.\.\\|%2e%2e|/etc/passwd|\.\.%2f|php://|file://|/proc/self/environ`)
	rePayCmdi    = regexp.MustCompile(`(?i);\s*id\b|\|\s*id\b|\$\(|` + "`" + `|;\s*ls\b|\|\s*whoami|&&\s*cat\s`)
	rePaySSTI    = regexp.MustCompile(`\{\{.*\}\}|\$\{.*\}|<%=|#\{`)
	reWordishTok = regexp.MustCompile(`^[A-Za-z0-9._/\-]{1,48}$`)
)

// detectListFormat inspects the stream line-by-line and classifies wordlists,
// payload cheat-sheets, and path lists. A stream whose lines carry two or more
// distinct payload categories (XSS + SQLi + traversal ...) is treated as a
// payload collection rather than any single code format.
func detectListFormat(raw string) Format {
	lines := strings.Split(raw, "\n")
	var total, payloadLines, pathLines, wordLines int
	cats := map[string]bool{}
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") {
			continue
		}
		total++
		if total > 200 {
			break
		}
		cat := ""
		switch {
		case rePayXSS.MatchString(ln):
			cat = "xss"
		case rePaySQLi.MatchString(ln):
			cat = "sqli"
		case rePayTrav.MatchString(ln):
			cat = "trav"
		case rePayCmdi.MatchString(ln):
			cat = "cmdi"
		case rePaySSTI.MatchString(ln):
			cat = "ssti"
		}
		if cat != "" {
			payloadLines++
			cats[cat] = true
			continue
		}
		if rePathish.MatchString(ln) {
			pathLines++
			continue
		}
		if reWordishTok.MatchString(ln) {
			wordLines++
		}
	}
	if total < 3 {
		return ""
	}
	// Multi-category payloads, or a stream dominated by payload lines, is a
	// payload collection. A single incidental payload-ish line (common in real
	// code) is not enough: require >=2 distinct categories, or >=2 payload
	// lines forming a clear majority.
	if len(cats) >= 2 || (payloadLines >= 2 && payloadLines*100 >= total*40) {
		return FormatPayloadList
	}
	if pathLines*100 >= total*60 {
		return FormatPathList
	}
	if wordLines*100 >= total*70 {
		return FormatWordlist
	}
	return ""
}

// ScopeDomainsForFormat returns the ordered list of allowed domains for a
// format (for display), or nil when the format imposes no restriction.
func ScopeDomainsForFormat(f Format) []string {
	allowed, ok := formatScope(f)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(allowed))
	for d := range allowed {
		out = append(out, d)
	}
	return out
}

// FormatRestricts reports whether a format imposes a domain allowlist.
func FormatRestricts(f Format) bool {
	_, ok := formatScope(f)
	return ok
}

// FilterByFormat keeps only the plugins whose domain is allowed for the given
// format. When the format imposes no restriction, the input is returned as-is.
func FilterByFormat(plugins []plugin.Plugin, f Format) []plugin.Plugin {
	allowed, ok := formatScope(f)
	if !ok {
		return plugins
	}
	out := make([]plugin.Plugin, 0, len(plugins))
	for _, p := range plugins {
		if allowed[p.Domain] {
			out = append(out, p)
		}
	}
	return out
}
