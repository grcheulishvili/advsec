package engine

import (
	"regexp"
	"sort"
	"strings"
)

// Intent is the inferred primary objective of an analysis, used to reorder the
// action chain (e.g. prioritize reputation lookups over offline cracking).
type Intent string

const (
	IntentNone        Intent = ""
	IntentReputation  Intent = "Reputation & IOC Search"
	IntentPostMortem  Intent = "Post-Mortem Triage"
	IntentContainment Intent = "Immediate Containment"
)

// InferIntent derives the primary objective from the parsed context. Intent is
// never inferred from list-style streams or advsec's own output - a 32-char
// string inside a wordlist must not trigger crash-dump triage.
func InferIntent(ctx *Context) Intent {
	if IsListFormat(ctx.Format) || ctx.Format == FormatAdvsecOutput {
		return IntentNone
	}
	// A lone hash with no other routable target -> reputation / IOC search.
	if len(ctx.Entities[EntityHash]) >= 1 &&
		!ctx.Has(EntityURL) && !ctx.Has(EntityDomain) &&
		!ctx.Has(EntityIP) && !ctx.Has(EntityIPv6) {
		return IntentReputation
	}
	// Post-mortem triage requires genuine crash/debugger evidence - a real
	// signal (SIGSEGV, core dump, register/backtrace), not a stray hex token.
	if reCrash.MatchString(ctx.Raw) ||
		(ctx.Has(EntityMemAddr) && reDebugCtx.MatchString(ctx.Raw)) {
		return IntentPostMortem
	}
	// Immediate containment requires an actual log stream with timestamped
	// authentication failures, not merely a line that contains "failed".
	if ctx.Format == FormatLog && reActiveFailure.MatchString(ctx.Raw) && reSyslog.MatchString(ctx.Raw) {
		return IntentContainment
	}
	return IntentNone
}

var (
	reCrash         = regexp.MustCompile(`(?i)SIGSEGV|segfault|core dumped|Program received signal|general protection fault|kernel panic`)
	reActiveFailure = regexp.MustCompile(`(?i)Failed password|authentication failure|Invalid user|connection refused|repeated|brute|intrusion|\bDROP\b`)
)

// Standard domain execution sequences (phase index 1..4). The generic sequence
// is used for mixed-domain output or unknown domains.
var domainSequences = map[string][]string{
	"dfir": {
		"Phase 1: Artifact Triage & Preservation",
		"Phase 2: Live Containment",
		"Phase 3: Deep Forensic Analysis",
		"Phase 4: Remediation & Hardening",
	},
	"blueteam": {
		"Phase 1: Artifact Triage & Preservation",
		"Phase 2: Live Containment",
		"Phase 3: Deep Forensic Analysis",
		"Phase 4: Remediation & Hardening",
	},
	"forensics": {
		"Phase 1: Acquisition & Preservation",
		"Phase 2: Structure & Carving",
		"Phase 3: Deep Analysis",
		"Phase 4: Reporting & Remediation",
	},
	"reversing": {
		"Phase 1: Binary Identification & Mitigations",
		"Phase 2: Static Analysis",
		"Phase 3: Dynamic Instrumentation",
		"Phase 4: Exploit Generation / Patching",
	},
	"pwn": {
		"Phase 1: Binary Identification & Mitigations",
		"Phase 2: Static Analysis",
		"Phase 3: Dynamic Instrumentation",
		"Phase 4: Exploit Generation / Patching",
	},
	"web": {
		"Phase 1: Passive Recon & Fingerprinting",
		"Phase 2: Endpoint / Parameter Discovery",
		"Phase 3: Targeted Vulnerability Verification",
		"Phase 4: Hardening & Remediation",
	},
	"network": {
		"Phase 1: Passive Recon & Fingerprinting",
		"Phase 2: Service Enumeration",
		"Phase 3: Targeted Exploitation",
		"Phase 4: Hardening & Remediation",
	},
	"recon": {
		"Phase 1: Passive Collection",
		"Phase 2: Active Enumeration",
		"Phase 3: Validation",
		"Phase 4: Reporting",
	},
	"redteam": {
		"Phase 1: Situational Awareness",
		"Phase 2: Enumeration",
		"Phase 3: Credential Access / Exploitation",
		"Phase 4: Persistence & Cleanup",
	},
}

var genericSequence = []string{
	"Phase 1: Triage & Fingerprinting",
	"Phase 2: Enumeration & Discovery",
	"Phase 3: Exploitation & Analysis",
	"Phase 4: Remediation & Hardening",
}

func sequenceFor(domain string) []string {
	if s, ok := domainSequences[domain]; ok {
		return s
	}
	return genericSequence
}

// --- step classification (passive → active gradient) ---

var (
	reStep1 = regexp.MustCompile(`(?i)\b(file|checksec|strings|rabin2|readelf|nm|objdump|exiftool|whatweb|wafw00f|dig|host|whois|nslookup|subfinder|amass|httpx|tlsx|crt\.sh|sha256sum|md5sum|stat|pdfinfo|vt|nth|name-that-hash|hash-id|openssl x509|coredumpctl list|zbarimg|jq|showmount|ssh-hostkey)\b|curl -s[iI]?|nmap -sV|7z l|tar t`)
	reStep2 = regexp.MustCompile(`(?i)\b(gobuster|ffuf|feroxbuster|dnsx|dnsrecon|masscan|naabu|enum4linux(-ng)?|snmpwalk|onesixtyone|kerbrute|wpscan|ldapsearch|theHarvester|nuclei|smtp-user-enum|smbclient|nxc|bloodhound|GetUserSPNs|binwalk)\b|--script|--enumerate`)
	reStep3 = regexp.MustCompile(`(?i)\b(sqlmap|hydra|msfconsole|metasploit|gdb|pwn|ROPgadget|ropper|one_gadget|hashcat|john|GetNPUsers|secretsdump|ntlmrelayx|responder|evil-winrm|pacu|pypykatz|aircrack|bettercap|frida|objection|tplmap|xortool|RsaCtfTool|fcrackzip|zip2john|steghide|volatility|vol|tshark|zeek)\b`)
	reStep4 = regexp.MustCompile(`(?i)\b(fail2ban(-client)?|iptables|ufw|systemctl (disable|stop|mask)|rkhunter|debsums|chattr|patch|upgrade)\b|ban|block`)
	// Containment keywords get promoted to the "live containment" slot for
	// defensive domains.
	reContain = regexp.MustCompile(`(?i)fail2ban|iptables|ufw|\bban\b|\bblock\b|isolate|\bkill\b|quarantine`)
)

// classifyStep returns a 1..4 action-chain step for a tool, honoring an
// explicit step, then domain-aware keyword inference, then intent adjustments.
func classifyStep(t ToolRec, intent Intent) int {
	step := t.Step
	if step < 1 || step > 4 {
		step = inferStep(t)
	}
	return adjustForIntent(step, t, intent)
}

func inferStep(t ToolRec) int {
	hay := t.Name + " " + t.Binary + " " + t.Command
	defensive := t.Domain == "dfir" || t.Domain == "blueteam"
	if defensive && reContain.MatchString(hay) {
		return 2 // live containment
	}
	switch {
	case reStep4.MatchString(hay):
		if defensive {
			return 4
		}
		return 4
	case reStep3.MatchString(hay):
		if defensive {
			return 3 // deep forensic analysis
		}
		return 3
	case reStep2.MatchString(hay):
		return 2
	case reStep1.MatchString(hay):
		return 1
	default:
		return 2 // middle ground for unclassified tools
	}
}

func adjustForIntent(step int, t ToolRec, intent Intent) int {
	hay := strings.ToLower(t.Name + " " + t.Binary + " " + t.Command + " " + t.Purpose)
	switch intent {
	case IntentReputation:
		if strings.Contains(hay, "virustotal") || strings.Contains(hay, "reputation") ||
			strings.Contains(hay, "vt ") || strings.Contains(hay, "name-that-hash") ||
			strings.Contains(hay, "nth") || strings.Contains(hay, "crt.sh") {
			return 1 // reputation first
		}
		if strings.Contains(hay, "hashcat") || strings.Contains(hay, "john") {
			if step < 3 {
				return 3 // demote offline cracking
			}
		}
	case IntentPostMortem:
		if strings.Contains(hay, "bt") || strings.Contains(hay, "backtrace") ||
			strings.Contains(hay, "coredumpctl gdb") || strings.Contains(hay, "-c ") ||
			strings.Contains(hay, "info registers") || strings.Contains(hay, "$pc") {
			return 1 // stack trace before disassembly
		}
	case IntentContainment:
		if reContain.MatchString(hay) {
			return 1 // isolation first
		}
	}
	return step
}

// --- sequencing ---

// SeqTool is one tool placed in the action chain.
type SeqTool struct {
	Tool ToolRec
	Step int
}

// PhaseGroup is a set of tools sharing an action-chain phase.
type PhaseGroup struct {
	Order int // 1..4, drives display order
	Label string
	Tools []SeqTool
}

// Sequenced is the full ordered action chain for a report.
type Sequenced struct {
	Intent Intent
	Domain string // single active domain, or "" when mixed
	Phases []PhaseGroup
}

// BuildSequence flattens every recommended tool into domain-aware, intent-
// ordered phase groups. activeDomain is the resolved context/format domain, or
// "" for mixed output (which uses the generic sequence labels).
func BuildSequence(report *Report, activeDomain string, intent Intent) Sequenced {
	seq := sequenceFor(activeDomain)
	byLabel := map[string]*PhaseGroup{}
	var order []string

	for ri, rec := range report.Recommendations {
		for ti, tool := range rec.Tools {
			step := classifyStep(tool, intent)
			label := tool.PhaseLabel
			// Explicit labels only apply when they belong to the active domain
			// (or the output is single-domain); otherwise use the step label so
			// mixed output stays to four tidy groups.
			if label == "" || (activeDomain != "" && tool.Domain != activeDomain) || activeDomain == "" {
				label = seq[step-1]
			}
			g, ok := byLabel[label]
			if !ok {
				g = &PhaseGroup{Order: step, Label: label}
				byLabel[label] = g
				order = append(order, label)
			}
			if step < g.Order {
				g.Order = step
			}
			// Stable tie-break weight: recommendation then tool index.
			_ = ri
			_ = ti
			g.Tools = append(g.Tools, SeqTool{Tool: tool, Step: step})
		}
	}

	phases := make([]PhaseGroup, 0, len(order))
	for _, l := range order {
		g := byLabel[l]
		sort.SliceStable(g.Tools, func(i, j int) bool {
			if g.Tools[i].Step != g.Tools[j].Step {
				return g.Tools[i].Step < g.Tools[j].Step
			}
			// installed tools first within a step (ready to run)
			return g.Tools[i].Tool.Installed && !g.Tools[j].Tool.Installed
		})
		phases = append(phases, *g)
	}
	sort.SliceStable(phases, func(i, j int) bool {
		if phases[i].Order != phases[j].Order {
			return phases[i].Order < phases[j].Order
		}
		return phases[i].Label < phases[j].Label
	})

	return Sequenced{Intent: intent, Domain: activeDomain, Phases: phases}
}
