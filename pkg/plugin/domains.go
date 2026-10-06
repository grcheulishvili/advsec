package plugin

import (
	"sort"
	"strings"
)

// canonicalDomains is the set of first-class domain categories, each the stem
// of a bundled plugin file. A plugin's Domain is one of these (or "general").
var canonicalDomains = []string{
	"pwn", "reversing", "web", "network", "recon", "redteam", "blueteam",
	"forensics", "crypto", "ctf", "cloud", "sysadmin", "dfir", "mobile",
	"wireless", "general",
}

// domainAliases maps user-friendly / short names onto a canonical domain so
// `-c net`, `-c ad`, `-c ir` all resolve to the right rule set.
var domainAliases = map[string]string{
	"net": "network", "networking": "network", "ports": "network", "svc": "network",
	"ad": "redteam", "activedirectory": "redteam", "active-directory": "redteam",
	"kerberos": "redteam", "red": "redteam", "offense": "redteam",
	"offensive": "redteam", "postex": "redteam", "post-exploitation": "redteam",
	"blue": "blueteam", "detection": "blueteam", "defend": "blueteam", "soc": "blueteam",
	"re": "reversing", "rev": "reversing", "reverse": "reversing", "malware": "reversing",
	"binexp": "pwn", "exploit": "pwn", "binary": "pwn", "exploitation": "pwn",
	"webapp": "web", "appsec": "web", "http": "web",
	"osint": "recon", "enum": "recon", "enumeration": "recon", "discovery": "recon",
	"ir": "dfir", "incident": "dfir", "incident-response": "dfir",
	"for": "forensics", "forensic": "forensics", "memory": "forensics",
	"cryptography": "crypto", "ciphers": "crypto", "encoding": "crypto",
	"container": "cloud", "containers": "cloud", "k8s": "cloud",
	"kubernetes": "cloud", "docker": "cloud", "aws": "cloud", "azure": "cloud", "gcp": "cloud",
	"sys": "sysadmin", "ops": "sysadmin", "system": "sysadmin", "admin": "sysadmin",
	"android": "mobile", "ios": "mobile", "apk": "mobile",
	"wifi": "wireless", "rf": "wireless", "bluetooth": "wireless", "ble": "wireless", "sdr": "wireless",
	"misc": "general", "util": "general", "general-usability": "general",
}

// CanonicalDomain normalizes free-form user input to a canonical domain name.
// Unknown inputs are returned lowercased unchanged so callers can still warn.
func CanonicalDomain(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return ""
	}
	if c, ok := domainAliases[s]; ok {
		return c
	}
	return s
}

// IsKnownDomain reports whether d (already canonical) is a first-class domain.
func IsKnownDomain(d string) bool {
	for _, c := range canonicalDomains {
		if c == d {
			return true
		}
	}
	return false
}

// AvailableDomains returns the canonical domains actually present in a plugin
// set, sorted, for menus and suggestions.
func AvailableDomains(plugins []Plugin) []string {
	seen := map[string]bool{}
	for _, p := range plugins {
		if p.Domain != "" && p.Domain != "general" {
			seen[p.Domain] = true
		}
	}
	out := make([]string, 0, len(seen))
	for d := range seen {
		out = append(out, d)
	}
	sort.Strings(out)
	return out
}

// InContext reports whether a plugin should be evaluated under the given
// context. An empty context matches everything; otherwise the plugin matches
// when its domain equals the context or it is tagged "general" (always-on).
func (p Plugin) InContext(context string) bool {
	if context == "" {
		return true
	}
	if p.Domain == "general" {
		return true
	}
	return p.Domain == context
}

// FilterByContext returns only the plugins in scope for context.
func FilterByContext(plugins []Plugin, context string) []Plugin {
	if context == "" {
		return plugins
	}
	out := make([]Plugin, 0, len(plugins))
	for _, p := range plugins {
		if p.InContext(context) {
			out = append(out, p)
		}
	}
	return out
}
