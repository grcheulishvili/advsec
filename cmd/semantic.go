package cmd

import (
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/grcheulishvili/advsec/pkg/engine"
	"github.com/grcheulishvili/advsec/pkg/osdetect"
)

func newSetupSemanticCmd() *cobra.Command {
	var model string
	c := &cobra.Command{
		Use:   "setup-semantic",
		Short: "Configure the optional local Ollama embedding backend for --semantic",
		Long: `Prepares the optional, local, hybrid semantic classifier.

It verifies a local Ollama daemon is reachable (http://localhost:11434), pulls
an embedding model (embeddinggemma-2, falling back to embeddinggemma or
all-minilm), and writes ~/.config/advsec/config.yaml with enable_semantic:true.

The deterministic engine is unaffected: semantic classification only ever runs
when you pass --semantic/--embedding, or on genuinely low-confidence input once
enabled in config. If the daemon is offline at analysis time, advsec silently
falls back to the deterministic result.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSetupSemantic(model)
		},
	}
	c.Flags().StringVar(&model, "model", engine.DefaultSemanticModel, "embedding model to pull and record in config")
	return c
}

func runSetupSemantic(model string) error {
	cfg := engine.DefaultSemanticConfig()
	if strings.TrimSpace(model) != "" {
		cfg.SemanticModel = model
	}

	fmt.Printf("advsec: checking for a local Ollama daemon at %s ...\n", cfg.SemanticEndpoint)
	if !ollamaReachable(cfg.SemanticEndpoint) {
		fmt.Fprintln(os.Stderr, "advsec: Ollama daemon not reachable.")
		printOllamaInstall(osdetect.Detect())
		return nil
	}
	fmt.Println("advsec: Ollama is up.")

	pulled, err := pullModel(cfg.SemanticModel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "advsec: warning: could not pull a model automatically (%v)\n", err)
		fmt.Fprintf(os.Stderr, "advsec: pull one manually, e.g.:  ollama pull %s\n", cfg.SemanticModel)
	} else {
		cfg.SemanticModel = pulled
		fmt.Printf("advsec: model ready: %s\n", pulled)
	}

	cfg.EnableSemantic = true
	if err := engine.SaveSemanticConfig(cfg); err != nil {
		return fmt.Errorf("save config: %w", err)
	}
	path, _ := engine.ConfigPath()
	fmt.Printf("advsec: semantic classification enabled (model %q, threshold %.2f)\n", cfg.SemanticModel, cfg.SimilarityThreshold)
	fmt.Printf("advsec: wrote %s\n", path)
	fmt.Println("Try it:  cat ambiguous.log | advsec --semantic")
	return nil
}

// ollamaReachable probes GET /api/tags with a short timeout.
func ollamaReachable(endpoint string) bool {
	client := &http.Client{Timeout: 1500 * time.Millisecond}
	resp, err := client.Get(strings.TrimRight(endpoint, "/") + "/api/tags")
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// pullModel runs `ollama pull` for the preferred model, falling back to
// embeddinggemma and then all-minilm. Returns the model that pulled cleanly.
func pullModel(primary string) (string, error) {
	candidates := []string{primary, "embeddinggemma", "all-minilm"}
	seen := map[string]bool{}
	var lastErr error
	for _, m := range candidates {
		if m == "" || seen[m] {
			continue
		}
		seen[m] = true
		fmt.Printf("advsec: ollama pull %s\n", m)
		c := exec.Command("ollama", "pull", m)
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
		if err := c.Run(); err == nil {
			return m, nil
		} else {
			lastErr = err
			fmt.Fprintf(os.Stderr, "advsec: pull %q failed, trying fallback ...\n", m)
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no candidate model to pull")
	}
	return primary, lastErr
}

func printOllamaInstall(host osdetect.HostInfo) {
	var inst string
	switch host.Family {
	case osdetect.FamilyArch:
		inst = "sudo pacman -S ollama"
	case osdetect.FamilyDebian, osdetect.FamilyKali:
		inst = "sudo apt install ollama"
	default:
		inst = host.Manager.InstallCommand("ollama")
		if strings.TrimSpace(inst) == "" {
			inst = "install the 'ollama' package for your distribution"
		}
	}
	fmt.Println()
	fmt.Println("Install the Ollama daemon:")
	fmt.Println("  " + inst)
	fmt.Println("Enable and start the service:")
	fmt.Println("  sudo systemctl enable --now ollama")
	fmt.Println("Then re-run:")
	fmt.Println("  advsec setup-semantic")
}
