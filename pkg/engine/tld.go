package engine

import "strings"

// validTLDs is a curated set of common public TLDs. It is intentionally strict
// (not the full IANA list): a dotted token only counts as a domain when its
// final label is a real TLD here or an accepted internal suffix, which stops
// filenames like `anaconda.xlog` or `One-Liner.php` from being read as domains.
var validTLDs = map[string]bool{
	// generic
	"com": true, "org": true, "net": true, "info": true, "biz": true,
	"io": true, "co": true, "dev": true, "app": true, "ai": true,
	"xyz": true, "online": true, "site": true, "tech": true, "cloud": true,
	"pro": true, "name": true, "mobi": true, "asia": true, "gg": true,
	"tv": true, "cc": true, "me": true, "live": true, "page": true,
	"gov": true, "edu": true, "mil": true, "int": true,
	// country codes commonly seen in engagements
	"us": true, "uk": true, "ca": true, "au": true, "nz": true,
	"de": true, "fr": true, "es": true, "it": true, "nl": true, "pt": true,
	"ru": true, "ua": true, "pl": true, "cz": true, "ro": true, "se": true,
	"no": true, "fi": true, "dk": true, "ch": true, "at": true, "be": true,
	"ie": true, "eu": true, "ge": true, "tr": true, "gr": true, "hu": true,
	"jp": true, "cn": true, "kr": true, "in": true, "sg": true, "hk": true,
	"tw": true, "id": true, "my": true, "th": true, "vn": true, "ph": true,
	"br": true, "mx": true, "ar": true, "cl": true, "za": true, "il": true,
	"ae": true, "sa": true, "ng": true, "ke": true,
}

// internalSuffixes are accepted non-public suffixes for lab / internal hosts.
var internalSuffixes = map[string]bool{
	"local": true, "internal": true, "lan": true, "test": true,
	"corp": true, "home": true, "intra": true, "domain": true,
}

// fileExtensions are final labels that must NEVER be treated as a TLD, even if
// they happen to collide with a real ccTLD (e.g. `.sh`, `.zip`).
var fileExtensions = map[string]bool{
	"txt": true, "log": true, "xlog": true, "php": true, "js": true,
	"md": true, "py": true, "sh": true, "json": true, "xml": true,
	"conf": true, "cfg": true, "bak": true, "zip": true, "gz": true,
	"tar": true, "7z": true, "rar": true, "html": true, "htm": true,
	"css": true, "go": true, "rb": true, "pl": true, "yaml": true,
	"yml": true, "csv": true, "tsv": true, "ini": true, "toml": true,
	"png": true, "jpg": true, "jpeg": true, "gif": true, "svg": true,
	"pdf": true, "exe": true, "dll": true, "bin": true, "dat": true,
	"db": true, "sql": true, "sqlite": true, "pem": true, "key": true,
	"crt": true, "cer": true, "pcap": true, "pcapng": true, "dmp": true,
	"raw": true, "img": true, "iso": true, "elf": true, "o": true,
	"so": true, "a": true, "class": true, "jar": true, "war": true,
	"ps1": true, "bat": true, "vbs": true, "lnk": true, "docm": true,
	"xlsm": true, "lock": true, "old": true, "tmp": true, "swp": true,
	"map": true, "min": true, "ts": true, "jsx": true, "tsx": true,
	"c": true, "h": true, "cpp": true, "hpp": true, "java": true,
}

// IsValidDomain reports whether a candidate string is a real domain name rather
// than a filename, path fragment, or arbitrary dotted token.
func IsValidDomain(candidate string) bool {
	s := strings.ToLower(strings.TrimSpace(candidate))
	s = strings.TrimSuffix(s, ".")
	if s == "" || !strings.Contains(s, ".") {
		return false
	}
	// No path separators, spaces, or scheme.
	if strings.ContainsAny(s, "/\\ \t@:") {
		return false
	}
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return false
	}
	tld := labels[len(labels)-1]
	// A file extension as the final label is never a domain.
	if fileExtensions[tld] {
		return false
	}
	if !validTLDs[tld] && !internalSuffixes[tld] {
		return false
	}
	// Every label must be a valid DNS label.
	for _, l := range labels {
		if l == "" || len(l) > 63 {
			return false
		}
		for i := 0; i < len(l); i++ {
			c := l[i]
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
		if l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
	}
	return true
}
