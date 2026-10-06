package engine

import "strings"

// ignoredDomains are vendor, documentation, and tool-header hosts that routinely
// appear in tool output (banners, XML namespaces, "see https://..." lines) but
// are never the operator's actual target. They are dropped during domain
// extraction so they can't pollute {target_domain} or trigger web rules.
var ignoredDomains = map[string]bool{
	"nmap.org":              true,
	"github.com":            true,
	"githubusercontent.com": true,
	"virustotal.com":        true,
	"censys.io":             true,
	"w3.org":                true,
	"apache.org":            true,
	"gnu.org":               true,
	"microsoft.com":         true,
	"kernel.org":            true,
	"shodan.io":             true,
	"projectdiscovery.io":   true,
	"example.com":           true,
	"example.org":           true,
	"localhost":             true,
}

// isIgnoredDomain reports whether a host is, or is a subdomain of, an ignored
// vendor/documentation domain (case-insensitive).
func isIgnoredDomain(host string) bool {
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return false
	}
	if ignoredDomains[host] {
		return true
	}
	for d := range ignoredDomains {
		if strings.HasSuffix(host, "."+d) {
			return true
		}
	}
	return false
}
