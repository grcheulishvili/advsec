package plugin

// Plugin is the declarative tactical rule unit loaded from a YAML file.
// It describes how to recognize a given operational context from piped
// input and what prioritized actions the operator should take next.
type Plugin struct {
	// ID is the unique, stable identifier for the plugin (kebab-case).
	ID string `yaml:"id"`
	// Name is a human-readable title shown in output.
	Name string `yaml:"name"`
	// TargetType is a free-form classification (binary, web, network, host...).
	TargetType string `yaml:"target_type"`
	// Domain is the operational category used for context scoping (dfir, web,
	// pwn, network, redteam, ...). When empty it defaults at load time to the
	// stem of the file the plugin was loaded from.
	Domain string `yaml:"domain"`
	// Author identifies the plugin source ("official", "community", handle...).
	Author string `yaml:"author"`
	// OSPackages maps a distribution family key (arch, debian, kali) to the
	// list of package names that provide the recommended tools.
	OSPackages map[string][]string `yaml:"os_packages"`
	// Match holds the detection rules.
	Match Match `yaml:"match"`
	// Tactics holds the recommended phase, next step, and tool commands.
	Tactics Tactics `yaml:"tactics"`

	// SourcePath records where the plugin was loaded from (populated at load
	// time, never serialized).
	SourcePath string `yaml:"-"`
	// Origin records the plugin scope: "user", "system", or "builtin".
	Origin string `yaml:"-"`
}

// Match defines how a plugin decides whether it applies to the input.
type Match struct {
	// Logic is "all" (default) or "any" and controls how multiple rules
	// combine.
	Logic string `yaml:"logic"`
	// Rules is the ordered set of detection rules.
	Rules []Rule `yaml:"rules"`
}

// Rule is a single detection predicate. Exactly one of the predicate fields
// should be set; Regex takes precedence when more than one is present.
type Rule struct {
	// Regex is a Go (RE2) regular expression matched against the raw input.
	Regex string `yaml:"regex"`
	// Contains is a case-insensitive literal substring match.
	Contains string `yaml:"contains"`
	// EntityType matches when the parser extracted at least one entity of the
	// given type (ip, domain, port, hash, mem_addr).
	EntityType string `yaml:"entity_type"`
	// Format matches when the classified input stream equals this format
	// (e.g. "text/wordlist", "code/javascript").
	Format string `yaml:"format"`
}

// Tactics describes what to do once a plugin matches.
type Tactics struct {
	// Phase is the kill-chain / methodology phase label.
	Phase string `yaml:"phase"`
	// NextStep is a one-line tactical recommendation.
	NextStep string `yaml:"next_step"`
	// Priority biases ranking; higher wins. 0 means "auto" (derived from the
	// number of matched rules).
	Priority int `yaml:"priority"`
	// Tools is the ordered list of concrete commands to run.
	Tools []Tool `yaml:"tools"`
}

// Tool is a concrete, executable recommendation.
type Tool struct {
	// Name is the display name.
	Name string `yaml:"name"`
	// Binary is the executable looked up on PATH to decide if the tool is
	// installed. Defaults to the first word of Command when empty.
	Binary string `yaml:"binary"`
	// Command is the suggested command line, with {placeholders} expanded
	// from parsed entities.
	Command string `yaml:"command"`
	// Purpose explains what the tool achieves.
	Purpose string `yaml:"purpose"`
	// Install is an optional manager-agnostic install command used when the
	// tool is not found in PATH and no native package mapping resolves it
	// (e.g. "pipx install impacket", "go install ...@latest"). It is a
	// fallback preferred over guessing a distro package name for tools that
	// ship only via pip/pipx/go/cargo or a vendor script.
	Install string `yaml:"install"`
	// Step is the explicit 1-based position of this tool in the operational
	// action-chain (1 = earliest/most passive). 0 means "infer it".
	Step int `yaml:"step"`
	// PhaseLabel is an explicit human-readable phase heading for this tool
	// (e.g. "Phase 1: Header & Mitigation Audit"). Empty = derive from the
	// domain's standard execution sequence.
	PhaseLabel string `yaml:"phase_label"`
}
