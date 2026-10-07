package engine

// Optional, opt-in semantic classification backend.
//
// This file adds a *hybrid* classifier: the deterministic regex / magic-byte /
// TLD engine remains the mandatory primary path (see classifier.go). Semantic
// classification is a strictly optional fallback that talks to a *local* Ollama
// daemon over HTTP and never links any C/C++/GGUF code into the binary
// (CGO_ENABLED=0 stays intact). When the daemon is absent or slow, every call
// degrades silently back to the deterministic result.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"
)

// SemanticConfig mirrors ~/.config/advsec/config.yaml.
type SemanticConfig struct {
	EnableSemantic      bool    `yaml:"enable_semantic"`
	SemanticEndpoint    string  `yaml:"semantic_endpoint"`
	SemanticModel       string  `yaml:"semantic_model"`
	SimilarityThreshold float64 `yaml:"similarity_threshold"`
}

const (
	// DefaultSemanticEndpoint is the local Ollama daemon base URL.
	DefaultSemanticEndpoint = "http://localhost:11434"
	// DefaultSemanticModel is the preferred embedding model.
	DefaultSemanticModel = "embeddinggemma-2"
	// DefaultSimilarity is the cosine-similarity floor for a semantic match.
	DefaultSimilarity = 0.75

	// semanticTimeout bounds the ENTIRE semantic pass (centroid seeding +
	// query). If the local daemon cannot answer in this window we fall back.
	semanticTimeout = 500 * time.Millisecond

	// maxSnippetLen caps the characters sent to the embedding model.
	maxSnippetLen = 1024
)

// DefaultSemanticConfig returns the built-in defaults (semantic disabled).
func DefaultSemanticConfig() SemanticConfig {
	return SemanticConfig{
		EnableSemantic:      false,
		SemanticEndpoint:    DefaultSemanticEndpoint,
		SemanticModel:       DefaultSemanticModel,
		SimilarityThreshold: DefaultSimilarity,
	}
}

// ConfigDir resolves the advsec config directory, honoring $XDG_CONFIG_HOME.
func ConfigDir() (string, error) {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "advsec"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "advsec"), nil
}

// ConfigPath resolves ~/.config/advsec/config.yaml.
func ConfigPath() (string, error) {
	dir, err := ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.yaml"), nil
}

// LoadSemanticConfig reads the on-disk config, filling any unset field with its
// default. A missing file is not an error: it yields the defaults (semantic
// disabled), so the deterministic engine is never perturbed by config state.
func LoadSemanticConfig() (SemanticConfig, error) {
	cfg := DefaultSemanticConfig()
	path, err := ConfigPath()
	if err != nil {
		return cfg, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, err
	}
	var fc SemanticConfig
	if err := yaml.Unmarshal(data, &fc); err != nil {
		return cfg, err
	}
	cfg.EnableSemantic = fc.EnableSemantic
	if fc.SemanticEndpoint != "" {
		cfg.SemanticEndpoint = fc.SemanticEndpoint
	}
	if fc.SemanticModel != "" {
		cfg.SemanticModel = fc.SemanticModel
	}
	if fc.SimilarityThreshold > 0 {
		cfg.SimilarityThreshold = fc.SimilarityThreshold
	}
	return cfg, nil
}

// SaveSemanticConfig persists the config to ~/.config/advsec/config.yaml,
// creating the directory as needed.
func SaveSemanticConfig(cfg SemanticConfig) error {
	dir, err := ConfigDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	out, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	path := filepath.Join(dir, "config.yaml")
	return os.WriteFile(path, out, 0o644)
}

// FormatSemanticInput prepares a raw snippet for EmbeddingGemma: it truncates
// to maxSnippetLen characters, then prepends EmbeddingGemma's symmetric
// classification task-instruction prefix. The same prefix is applied to every
// input being compared (query + centroid seeds), as the model requires for
// symmetric tasks.
func FormatSemanticInput(rawSnippet string) string {
	r := []rune(rawSnippet)
	if len(r) > maxSnippetLen {
		r = r[:maxSnippetLen]
	}
	return fmt.Sprintf("task: classification | query: %s", string(r))
}

// embedHTTPCalls counts outbound embedding requests, for test observability
// (the deterministic path must perform exactly zero).
var embedHTTPCalls int64

// EmbedHTTPCalls returns the number of embedding HTTP requests issued so far.
func EmbedHTTPCalls() int64 { return atomic.LoadInt64(&embedHTTPCalls) }

// ResetEmbedHTTPCalls zeroes the embedding-request counter (tests).
func ResetEmbedHTTPCalls() { atomic.StoreInt64(&embedHTTPCalls, 0) }

// EmbeddingClient is a decoupled HTTP client for a local Ollama daemon. No
// native inference library is linked; all vector work happens out of process.
type EmbeddingClient struct {
	Endpoint string
	Model    string
	HTTP     *http.Client
}

// NewEmbeddingClient builds a client bound to the configured endpoint/model.
func NewEmbeddingClient(cfg SemanticConfig) *EmbeddingClient {
	ep := cfg.SemanticEndpoint
	if ep == "" {
		ep = DefaultSemanticEndpoint
	}
	model := cfg.SemanticModel
	if model == "" {
		model = DefaultSemanticModel
	}
	return &EmbeddingClient{
		Endpoint: strings.TrimRight(ep, "/"),
		Model:    model,
		HTTP:     &http.Client{Timeout: semanticTimeout},
	}
}

type embedRequest struct {
	Model  string `json:"model"`
	Prompt string `json:"prompt"`
}

// embedResponse accepts either Ollama's {"embedding":[...]} shape or the
// newer {"embeddings":[[...]]} batch shape.
type embedResponse struct {
	Embedding  []float64   `json:"embedding"`
	Embeddings [][]float64 `json:"embeddings"`
}

// Embed formats text with the classification prefix and POSTs it to
// /api/embeddings, returning the resulting vector.
func (c *EmbeddingClient) Embed(ctx context.Context, text string) ([]float64, error) {
	atomic.AddInt64(&embedHTTPCalls, 1)
	payload, err := json.Marshal(embedRequest{Model: c.Model, Prompt: FormatSemanticInput(text)})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Endpoint+"/api/embeddings", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.HTTP.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("embeddings endpoint returned %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}
	var er embedResponse
	if err := json.NewDecoder(resp.Body).Decode(&er); err != nil {
		return nil, err
	}
	vec := er.Embedding
	if len(vec) == 0 && len(er.Embeddings) > 0 {
		vec = er.Embeddings[0]
	}
	if len(vec) == 0 {
		return nil, fmt.Errorf("embeddings endpoint returned an empty vector")
	}
	return vec, nil
}

// domainSeeds are short, representative phrases per target domain. Their mean
// embedding forms that domain's centroid. Keeping them in-code (rather than
// shipping a precomputed matrix) lets the centroids track whatever embedding
// model the user actually has installed.
var domainSeeds = map[string][]string{
	"pwn": {
		"segmentation fault core dump rip rsp registers gdb buffer overflow exploit",
		"ELF binary ROP gadget stack canary pwntools heap corruption",
	},
	"reversing": {
		"disassembly decompiler strings packed upx obfuscated binary sample",
		"ida ghidra radare2 control flow graph assembly reverse engineering",
	},
	"web": {
		"http response headers cookies xss sql injection web server apache nginx",
		"get post request parameter burp suite url endpoint vulnerability",
	},
	"dfir": {
		"syslog auth log failed password forensic timeline incident response",
		"journalctl systemd memory image volatility artifact investigation",
	},
	"cloud": {
		"kubernetes pod container docker aws s3 iam role terraform",
		"kubectl cluster namespace cloud metadata service account",
	},
	"sysadmin": {
		"systemctl service unit file cron permissions package manager",
		"disk usage network interface configuration hostname uptime",
	},
	"crypto": {
		"rsa private key certificate x509 pem hash sha256 gpg encryption",
		"cipher aes base64 jwt token signature decryption keypair",
	},
	"redteam": {
		"kerberos ticket spn kerberoast active directory lateral movement mimikatz",
		"powershell encoded command cobalt strike beacon privilege escalation",
	},
	"js": {
		"javascript function eval document cookie window obfuscated webpack",
		"node require module exports atob fetch prototype pollution",
	},
}

// SemanticResult is the outcome of a semantic classification.
type SemanticResult struct {
	Domain     string  // best-scoring domain (canonical)
	Similarity float64 // cosine similarity to that domain's centroid
	Matched    bool    // Similarity exceeded the configured threshold
}

// SemanticClassifier compares an input's embedding against per-domain centroids.
type SemanticClassifier struct {
	client    *EmbeddingClient
	threshold float64
	centroids map[string][]float64
}

// NewSemanticClassifier builds a classifier from config.
func NewSemanticClassifier(cfg SemanticConfig) *SemanticClassifier {
	th := cfg.SimilarityThreshold
	if th <= 0 {
		th = DefaultSimilarity
	}
	return &SemanticClassifier{client: NewEmbeddingClient(cfg), threshold: th}
}

// ensureCentroids lazily embeds the domain seed phrases and caches the mean
// (normalized) vector per domain.
func (s *SemanticClassifier) ensureCentroids(ctx context.Context) error {
	if s.centroids != nil {
		return nil
	}
	cents := make(map[string][]float64, len(domainSeeds))
	for _, dom := range sortedDomainKeys() {
		var acc []float64
		for _, seed := range domainSeeds[dom] {
			v, err := s.client.Embed(ctx, seed)
			if err != nil {
				return err
			}
			acc = addVec(acc, v)
		}
		cents[dom] = normalize(acc)
	}
	s.centroids = cents
	return nil
}

// Classify embeds the snippet and returns its nearest domain centroid.
func (s *SemanticClassifier) Classify(ctx context.Context, snippet string) (SemanticResult, error) {
	if err := s.ensureCentroids(ctx); err != nil {
		return SemanticResult{}, err
	}
	v, err := s.client.Embed(ctx, snippet)
	if err != nil {
		return SemanticResult{}, err
	}
	nv := normalize(v)
	var best SemanticResult
	for _, dom := range sortedDomainKeys() {
		cent, ok := s.centroids[dom]
		if !ok {
			continue
		}
		sim := cosine(nv, cent)
		if sim > best.Similarity {
			best = SemanticResult{Domain: dom, Similarity: sim}
		}
	}
	best.Matched = best.Similarity > s.threshold
	return best, nil
}

// ShouldRunSemantic decides whether the optional semantic pass is warranted:
// either the user forced it (--semantic/--embedding), or it is enabled in
// config AND the deterministic engine was not confident.
func ShouldRunSemantic(cfg SemanticConfig, forced bool, topConfidence int) bool {
	if forced {
		return true
	}
	return cfg.EnableSemantic && topConfidence < DefaultMinConfidence
}

// SemanticSuggest runs the classifier with graceful offline degradation. On any
// transport failure/timeout it writes a single one-line notice to w and returns
// ok=false, so the caller instantly continues with the deterministic result.
func SemanticSuggest(cfg SemanticConfig, snippet string, w io.Writer) (SemanticResult, bool) {
	sc := NewSemanticClassifier(cfg)
	ctx, cancel := context.WithTimeout(context.Background(), semanticTimeout)
	defer cancel()
	res, err := sc.Classify(ctx, snippet)
	if err != nil {
		fmt.Fprintln(w, "advsec: semantic daemon offline (run 'advsec setup-semantic' to configure). Falling back to deterministic engine.")
		return SemanticResult{}, false
	}
	return res, res.Matched
}

// BoostConfidence raises the confidence of every match by `by`, used to let
// semantically-selected matches clear the rendering gate.
func BoostConfidence(ms []Match, by int) {
	for i := range ms {
		ms[i].Confidence += by
	}
}

// --- small vector helpers (pure Go, no external deps) ---

func sortedDomainKeys() []string {
	keys := make([]string, 0, len(domainSeeds))
	for k := range domainSeeds {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func addVec(acc, v []float64) []float64 {
	if acc == nil {
		out := make([]float64, len(v))
		copy(out, v)
		return out
	}
	n := len(acc)
	if len(v) < n {
		n = len(v)
	}
	for i := 0; i < n; i++ {
		acc[i] += v[i]
	}
	return acc
}

func normalize(v []float64) []float64 {
	var sum float64
	for _, x := range v {
		sum += x * x
	}
	norm := math.Sqrt(sum)
	if norm == 0 {
		out := make([]float64, len(v))
		return out
	}
	out := make([]float64, len(v))
	for i, x := range v {
		out[i] = x / norm
	}
	return out
}

// cosine returns the cosine similarity of two vectors. Inputs need not be
// pre-normalized; mismatched lengths are compared over the shared prefix.
func cosine(a, b []float64) float64 {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	var dot, na, nb float64
	for i := 0; i < n; i++ {
		dot += a[i] * b[i]
		na += a[i] * a[i]
		nb += b[i] * b[i]
	}
	if na == 0 || nb == 0 {
		return 0
	}
	return dot / (math.Sqrt(na) * math.Sqrt(nb))
}
