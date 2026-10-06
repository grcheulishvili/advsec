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
)

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
