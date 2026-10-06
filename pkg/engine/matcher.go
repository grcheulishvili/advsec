package engine

import (
	"regexp"
	"strings"
	"sync"

	"github.com/grcheulishvili/advsec/pkg/plugin"
)

// Match is the result of evaluating a single plugin against a Context.
type Match struct {
	Plugin       plugin.Plugin
	MatchedRules int
	TotalRules   int
	// Score is the ranking weight used to order recommendations.
	Score int
}

// compiledRule caches the compiled regex for a rule so repeated matches
// across many input lines stay cheap.
type compiledRule struct {
	raw plugin.Rule
	re  *regexp.Regexp
}

var (
	reCache   = map[string]*regexp.Regexp{}
	reCacheMu sync.Mutex
)

// compile returns a cached compiled expression for pattern, or nil if the
// pattern fails to compile (a malformed plugin rule is skipped, not fatal).
func compile(pattern string) *regexp.Regexp {
	reCacheMu.Lock()
	defer reCacheMu.Unlock()
	if re, ok := reCache[pattern]; ok {
		return re
	}
	// Case-insensitive, multiline by default so rules read naturally against
	// multi-line command output.
	re, err := regexp.Compile("(?im)" + pattern)
	if err != nil {
		reCache[pattern] = nil
		return nil
	}
	reCache[pattern] = re
	return re
}

// Matcher evaluates a set of plugins against parsed input contexts.
type Matcher struct {
	plugins []plugin.Plugin
}

// NewMatcher builds a Matcher over the given plugin set.
func NewMatcher(plugins []plugin.Plugin) *Matcher {
	return &Matcher{plugins: plugins}
}

// Evaluate returns every plugin that matches ctx, unsorted. The caller (the
// evaluator) is responsible for ranking and capability checks.
func (m *Matcher) Evaluate(ctx *Context) []Match {
	var out []Match
	for _, p := range m.plugins {
		matched, total := evaluatePlugin(p, ctx)
		logic := strings.ToLower(strings.TrimSpace(p.Match.Logic))
		if logic == "" {
			logic = "all"
		}
		hit := false
		switch logic {
		case "any":
			hit = matched > 0
		default: // "all"
			hit = total > 0 && matched == total
		}
		if !hit {
			continue
		}
		out = append(out, Match{
			Plugin:       p,
			MatchedRules: matched,
			TotalRules:   total,
			Score:        score(p, matched, total),
		})
	}
	return out
}

// evaluatePlugin counts how many of a plugin's rules fire against ctx.
func evaluatePlugin(p plugin.Plugin, ctx *Context) (matched, total int) {
	for _, r := range p.Match.Rules {
		total++
		if ruleMatches(r, ctx) {
			matched++
		}
	}
	return matched, total
}

func ruleMatches(r plugin.Rule, ctx *Context) bool {
	switch {
	case r.Regex != "":
		re := compile(r.Regex)
		return re != nil && re.MatchString(ctx.Raw)
	case r.Contains != "":
		return strings.Contains(strings.ToLower(ctx.Raw), strings.ToLower(r.Contains))
	case r.EntityType != "":
		return ctx.Has(EntityKind(strings.ToLower(r.EntityType)))
	}
	return false
}

// score derives a ranking weight. Explicit tactics.priority dominates; absent
// that, more specific plugins (more matched rules) rank higher.
func score(p plugin.Plugin, matched, total int) int {
	if p.Tactics.Priority > 0 {
		return 1000 + p.Tactics.Priority
	}
	// Reward specificity: each matched rule is worth 10, with a small bonus
	// for fully-satisfied multi-rule plugins.
	s := matched * 10
	if total > 1 && matched == total {
		s += total
	}
	return s
}
