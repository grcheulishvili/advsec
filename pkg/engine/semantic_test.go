package engine

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/grcheulishvili/advsec/pkg/plugin"
)

// --- 1. Prefix formatting ------------------------------------------------

func TestFormatSemanticInput(t *testing.T) {
	const prefix = "task: classification | query: "

	// Short input: verbatim body behind the classification prefix.
	got := FormatSemanticInput("hello world")
	if got != prefix+"hello world" {
		t.Fatalf("short format = %q, want %q", got, prefix+"hello world")
	}
	if !strings.HasPrefix(got, prefix) {
		t.Fatalf("missing classification prefix: %q", got)
	}

	// Long input: truncated to exactly maxSnippetLen characters behind prefix.
	long := strings.Repeat("A", maxSnippetLen+512)
	got = FormatSemanticInput(long)
	if !strings.HasPrefix(got, prefix) {
		t.Fatalf("missing prefix on long input")
	}
	body := strings.TrimPrefix(got, prefix)
	if n := len([]rune(body)); n != maxSnippetLen {
		t.Fatalf("truncated body length = %d, want %d", n, maxSnippetLen)
	}

	// Multibyte truncation must count characters, not bytes.
	multi := strings.Repeat("é", maxSnippetLen+10)
	body = strings.TrimPrefix(FormatSemanticInput(multi), prefix)
	if n := len([]rune(body)); n != maxSnippetLen {
		t.Fatalf("multibyte truncated length = %d, want %d", n, maxSnippetLen)
	}
}

// --- 2. Offline performance: zero HTTP + sub-20ms deterministic path -----

func TestDeterministicOfflineZeroHTTP(t *testing.T) {
	plugins := plugin.LoadFromDirs([]string{"../../plugins"}).Plugins
	sample := "suspicious.bin: ELF 64-bit LSB executable, x86-64, dynamically linked, not stripped\n"

	// Default config must not trip the semantic pass on confident input.
	if ShouldRunSemantic(DefaultSemanticConfig(), false, 5) {
		t.Fatal("default (disabled) config must not run semantic on confident input")
	}

	ResetEmbedHTTPCalls()

	// Time the full deterministic pipeline; take the min of several runs to be
	// robust against scheduler jitter.
	best := time.Hour
	for i := 0; i < 5; i++ {
		start := time.Now()
		ctx := ParseString(sample)
		scoped := FilterByFormat(plugins, ctx.Format)
		matches := NewMatcher(scoped).Evaluate(ctx)
		_ = NewEvaluator(fuzzHost()).Evaluate(ctx, matches)
		if d := time.Since(start); d < best {
			best = d
		}
	}
	if best > 20*time.Millisecond {
		t.Errorf("deterministic classification took %v, want < 20ms", best)
	}
	if n := EmbedHTTPCalls(); n != 0 {
		t.Errorf("deterministic path issued %d embedding HTTP calls, want 0", n)
	}
}

// --- 3. Mock API response: ambiguous input maps to the expected domain ---

// mockDomainKeywords mirrors the in-code domainSeeds vocabulary closely enough
// that each seed scores on its own dimension and a web-flavored query lands on
// the web centroid. Dimension order follows sortedDomainKeys().
var mockDomainKeywords = map[string][]string{
	"cloud":     {"kubernetes", "kubectl", "docker", "aws", "s3", "iam", "terraform", "cluster", "namespace"},
	"crypto":    {"rsa", "x509", "pem", "sha256", "gpg", "cipher", "aes", "jwt", "base64", "certificate"},
	"dfir":      {"syslog", "auth log", "journalctl", "volatility", "forensic", "incident", "failed password"},
	"js":        {"javascript", "eval", "webpack", "require", "module exports", "atob", "prototype"},
	"pwn":       {"segmentation", "rip", "rsp", "gdb", "buffer overflow", "rop", "canary", "pwntools"},
	"redteam":   {"kerberos", "spn", "kerberoast", "mimikatz", "cobalt", "beacon", "powershell"},
	"reversing": {"disassembly", "ghidra", "radare2", " ida ", "decompiler", "obfuscated binary"},
	"sysadmin":  {"systemctl", "cron", "unit file", "package manager", "disk usage", "hostname", "uptime"},
	"web":       {"http", "cookie", "xss", "sql injection", "apache", "nginx", "burp", "get ", "post "},
}

// mockEmbed turns text into a keyword-overlap vector in sorted-domain order.
func mockEmbed(text string) []float64 {
	low := strings.ToLower(text)
	doms := sortedDomainKeys()
	vec := make([]float64, len(doms))
	for i, d := range doms {
		var score float64
		for _, kw := range mockDomainKeywords[d] {
			if strings.Contains(low, kw) {
				score++
			}
		}
		vec[i] = score
	}
	return vec
}

func TestSemanticMockMapping(t *testing.T) {
	var badPrompts int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/embeddings" {
			http.NotFound(w, r)
			return
		}
		var req struct {
			Model  string `json:"model"`
			Prompt string `json:"prompt"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// Every input must carry EmbeddingGemma's classification prefix.
		if !strings.HasPrefix(req.Prompt, "task: classification | query: ") {
			atomic.AddInt32(&badPrompts, 1)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"embedding": mockEmbed(req.Prompt)})
	}))
	defer srv.Close()

	cfg := SemanticConfig{
		EnableSemantic:      true,
		SemanticEndpoint:    srv.URL,
		SemanticModel:       "embeddinggemma-2",
		SimilarityThreshold: 0.4,
	}

	// A web-flavored, otherwise ambiguous blob.
	snippet := "GET /admin/login.php?id=1 HTTP/1.1\nSet-Cookie: SESSID=abc\nreflected xss in search\nServer: apache/2.4 nginx"

	sc := NewSemanticClassifier(cfg)
	res, err := sc.Classify(context.Background(), snippet)
	if err != nil {
		t.Fatalf("Classify error: %v", err)
	}
	if atomic.LoadInt32(&badPrompts) != 0 {
		t.Errorf("%d prompts reached the endpoint without the classification prefix", badPrompts)
	}
	if res.Domain != "web" {
		t.Errorf("semantic domain = %q (cos %.3f), want web", res.Domain, res.Similarity)
	}
	if !res.Matched {
		t.Errorf("web similarity %.3f did not exceed threshold %.2f", res.Similarity, cfg.SimilarityThreshold)
	}

	// SemanticSuggest convenience returns the same mapping, no notice emitted.
	var stderr bytes.Buffer
	got, ok := SemanticSuggest(cfg, snippet, &stderr)
	if !ok || got.Domain != "web" {
		t.Errorf("SemanticSuggest = (%+v, %v), want web/true", got, ok)
	}
	if stderr.Len() != 0 {
		t.Errorf("unexpected stderr on success: %q", stderr.String())
	}
}

// --- 4. Fallback resiliency: unreachable daemon degrades gracefully ------

func TestSemanticFallbackResiliency(t *testing.T) {
	cfg := SemanticConfig{
		EnableSemantic:      true,
		SemanticEndpoint:    "http://127.0.0.1:59999", // nothing is listening
		SemanticModel:       "embeddinggemma-2",
		SimilarityThreshold: 0.75,
	}

	start := time.Now()
	var stderr bytes.Buffer
	res, ok := SemanticSuggest(cfg, "ambiguous input with no clear signal", &stderr)
	elapsed := time.Since(start)

	if ok {
		t.Errorf("expected ok=false against a dead endpoint, got %+v", res)
	}
	if !strings.Contains(stderr.String(), "semantic daemon offline") {
		t.Errorf("missing fallback notice; stderr = %q", stderr.String())
	}
	// Must bail out well within the budget (connection refused is immediate; the
	// 500ms timeout is only an upper bound).
	if elapsed > time.Second {
		t.Errorf("fallback took %v, expected near-instant failure", elapsed)
	}
}

// --- 5. ShouldRunSemantic decision table ---------------------------------

func TestShouldRunSemantic(t *testing.T) {
	disabled := SemanticConfig{EnableSemantic: false}
	enabled := SemanticConfig{EnableSemantic: true}
	cases := []struct {
		name   string
		cfg    SemanticConfig
		forced bool
		conf   int
		want   bool
	}{
		{"forced-overrides-disabled", disabled, true, 9, true},
		{"disabled-no-flag", disabled, false, 0, false},
		{"enabled-low-confidence", enabled, false, DefaultMinConfidence - 1, true},
		{"enabled-high-confidence", enabled, false, DefaultMinConfidence, false},
	}
	for _, c := range cases {
		if got := ShouldRunSemantic(c.cfg, c.forced, c.conf); got != c.want {
			t.Errorf("%s: ShouldRunSemantic = %v, want %v", c.name, got, c.want)
		}
	}
}

// --- 6. Config round-trip -------------------------------------------------

func TestSemanticConfigRoundTrip(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", dir)

	// Missing file yields defaults, no error.
	cfg, err := LoadSemanticConfig()
	if err != nil {
		t.Fatalf("load (missing) error: %v", err)
	}
	if cfg.EnableSemantic || cfg.SemanticModel != DefaultSemanticModel {
		t.Fatalf("missing-file load did not return defaults: %+v", cfg)
	}

	cfg.EnableSemantic = true
	cfg.SimilarityThreshold = 0.8
	if err := SaveSemanticConfig(cfg); err != nil {
		t.Fatalf("save error: %v", err)
	}
	got, err := LoadSemanticConfig()
	if err != nil {
		t.Fatalf("reload error: %v", err)
	}
	if !got.EnableSemantic || got.SimilarityThreshold != 0.8 {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
}
