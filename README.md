# advsec

**Your quiet terminal sidekick for "what do I run next?"**

advsec looks at the output of a command you just ran - an `nmap` scan, a `file` on a suspicious binary, an SSH log, a raw email, a chunk of obfuscated JavaScript - and prints the next logical commands to run, ordered as a clean action chain and tailored to the tools actually installed on your box.

```sh
file suspicious.bin | advsec
nmap -sV 10.10.10.5  | advsec
cat phish.eml        | advsec
```

It stays out of your way until you ask.

> **Current version: `advsec 1.4.1`** - run `advsec --version` to confirm your build.

---

## What advsec is (and is not)

**advsec is** an intelligent, context-aware UNIX pipeline assistant. It parses the structured output of security, system, and triage tools, maps the entities it extracts (IPs, domains, hashes, ports, crash addresses, headers, ...) against local rule matrices, and suggests immediate, executable next steps - phase-ordered and tailored to the tools actually installed on your box.

**advsec is NOT** an automated vulnerability scanner, an exploit framework, or a background daemon that continuously intercepts your shell. It never runs on its own, never executes the commands it suggests, and never phones home.

### Who it is for

| Role | How advsec helps |
| :--- | :--- |
| **Penetration Testers & Red Teams** | Accelerates manual enumeration and suggests phase-ordered action chains during reconnaissance, web testing, and binary triage. |
| **Incident Responders & Blue Teams** | Rapid triage of raw log bursts (`journalctl`, syslog), email headers (`.eml`), and suspicious file artifacts. |
| **DevSecOps & Systems Engineers** | Infrastructure auditing, container/orchestration configuration checks (`docker`, `k8s`), and local troubleshooting. |

---

## How to use advsec effectively

| Mode | Usage pattern | Best for |
| :--- | :--- | :--- |
| **Piped stream (default)** | `<tool_command> \| advsec` | Real-time analysis of live tool stdout (`nmap`, `curl`, `file`, `journalctl`). |
| **Instant hotkey (`Alt+A`)** | Press `Alt+A` / `Ctrl+Alt+A` after running a command | Zero-friction analysis of the previous shell command without altering history. |
| **Domain scoping (`-c`)** | `... \| advsec -c web` | Narrowing matches to one domain when analyzing multi-purpose output. |
| **Interactive selection (`-i`)** | `... \| advsec -i` | Manually selecting the rule context from an interactive menu. |
| **File reading (`-f`)** | `advsec -f /path/to/artifact` | Direct inspection of static log files, payloads, or script artifacts. |

### Anti-patterns (what NOT to do)

- **Do not pipe completely unstructured raw prose.** advsec relies on structural signatures, tool headers, and entity patterns; a paragraph of free text gives it nothing to anchor on.
- **Do not expect automated execution.** advsec generates prioritized, ready-to-copy commands. It never runs destructive actions for you - you stay in control of every step.

---

## The 3 golden rules

1. **Non-intrusive.** advsec runs only when you pipe into it or press **`Alt+A`**. It never runs on every command, never edits your command line, and never touches your shell history.
2. **OS-native.** Recommended a tool you don't have? advsec gives you the exact install command for *your* system - `pacman`/`yay` on Arch/BlackArch, `apt` on Debian/Kali, or a `pipx`/`go`/`cargo` hint for tools that aren't packaged.
3. **100% offline and fast.** Everything runs locally in a single static binary, typically in a few milliseconds. No telemetry, no cloud, no network calls at runtime.

---

## Advanced examples by domain

Pipe a tool's output straight in. advsec figures out the format, scopes to the relevant domain, and prints an ordered action chain. The `-c` flag below is optional - advsec auto-scopes by detected format - but shown explicitly to make each domain clear.

### 1. Reverse engineering (`reversing`)

```sh
file suspicious_elf | advsec -c reversing
```

- **Extracted entity:** `ELF 64-bit LSB executable, x86-64`
- **Suggested action chain:**
  - **Phase 1:** `checksec --file=suspicious_elf` - audit ASLR / NX / stack canary.
  - **Phase 2:** `rabin2 -I suspicious_elf` and `gdb suspicious_elf` - static then dynamic analysis.

### 2. Web & API assessment (`web`)

```sh
curl -sI https://api.target.local | advsec -c web
```

- **Extracted entity:** `Server: nginx/1.18.0`, `X-Powered-By: Express`
- **Suggested action chain:**
  - **Phase 1:** `whatweb -a 3 https://api.target.local` - technology fingerprinting.
  - **Phase 2:** `ffuf -u 'https://api.target.local/FUZZ' -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt` - content discovery.

### 3. Binary exploitation (`pwn`)

```sh
gdb -ex 'run' -ex 'bt' ./vulnerable_bin | advsec -c pwn
```

- **Extracted entity:** memory crash address (`0x41414141`), SIGSEGV pattern
- **Suggested action chain:**
  - **Phase 1:** `pattern create 200` and `checksec` - offset discovery and mitigation audit.
  - **Phase 2:** `ropgadget --binary ./vulnerable_bin` - gadget hunting for ROP chains.

### 4. Incident response & DFIR (`dfir`)

```sh
journalctl -u sshd --since "10 min ago" | advsec -c dfir
```

- **Extracted entity:** authentication failure bursts, source IP
- **Suggested action chain:**
  - **Phase 1:** `grep -i "failed" /var/log/auth.log | awk '{print $11}' | sort | uniq -c` - rank offending sources.
  - **Phase 2:** `fail2ban-client status sshd` - confirm containment and active bans.

### 5. Email & phishing triage (`eml`)

```sh
advsec -f suspicious_message.eml
```

- **Extracted entity:** `email/mime` format, header IPs, URLs
- **Suggested action chain:**
  - **Phase 1:** `eml-parser -i suspicious_message.eml` - structured header/attachment carve.
  - **Phase 2:** extract headers and check SPF / DKIM / DMARC alignment.

### 6. Cloud & container security (`cloud`)

```sh
kubectl get pods --all-namespaces | advsec -c cloud
```

- **Extracted entity:** Kubernetes pod inventory, privileged context markers
- **Suggested action chain:**
  - **Phase 1:** `trivy k8s --report summary cluster` - cluster-wide vulnerability and misconfig summary.
  - **Phase 2:** audit RBAC bindings via `popeye` or `kube-bench`.

### 7. Obfuscated code & JavaScript (`js`)

```sh
cat payload.js | advsec -c js
```

- **Extracted entity:** `code/javascript`, packed `_0x` string arrays
- **Suggested action chain:**
  - **Phase 1:** `js-beautify payload.js -o formatted.js` - normalize layout.
  - **Phase 2:** `webcrack formatted.js -o ./decompiled` - AST-level deobfuscation and unpacking.

---

## Hotkey integration (`Alt+A` / `Ctrl+Alt+A`)

Install the shell widget once:

```sh
advsec init --install    # detects your $SHELL and appends safely to ~/.zshrc or ~/.bashrc
source ~/.zshrc          # (or ~/.bashrc) - done!
```

Now, after running any command, press **`Alt+A`** (or **`Ctrl+Alt+A`**). The widget re-runs your last command, pipes its output to `advsec --top 3`, and prints the suggestions *below* your prompt. Under zsh, **`Ctrl+Alt+S`** analyzes whatever is currently typed instead.

- It reads your **last command's output** - it does not modify, submit, or clear what you're typing.
- `advsec init --install` is idempotent (won't double-insert) and writes with blank-line padding so it can never fuse onto an existing line.
- Each block is **shell-guarded** (`$ZSH_VERSION` / `$BASH_VERSION`), so sourcing the wrong rc file across shells is a silent no-op, not a wall of syntax errors. Every keybind is muted with `2>/dev/null`.

Prefer to do it by hand? `advsec init zsh >> ~/.zshrc` or `advsec init bash >> ~/.bashrc`.

---

## Domain scoping (`-c`)

Working on one thing and don't want suggestions from everything else? Scope it:

```sh
... | advsec -c web      # web / API testing
... | advsec -c dfir     # incident response
... | advsec -c pwn      # binary exploitation
... | advsec -c js       # JavaScript analysis
... | advsec -i          # pick the context from an interactive menu
```

You can also pin a default for the session with `export ADVSEC_CONTEXT=web`. Short aliases work too (`net`, `ad`, `ir`, `k8s`, `re`). With no context set, advsec still scopes automatically by detected format, and if results span several domains it prints a one-line "scope with -c ..." hint - it never switches for you.

Running `advsec` on its own (no pipe) just prints help.

---

## Creating & sharing custom plugins

advsec rules are plain YAML - you can add your own in minutes.

**1. Where they live.** Drop `.yaml` files in `~/.config/advsec/plugins/`. They load automatically and override bundled rules that share the same `id`.

**2. Minimal template.** Save this as `~/.config/advsec/plugins/my-rule.yaml`:

```yaml
id: my-jwt-check                 # unique id
name: "JWT in Response"
domain: web                      # which -c context it belongs to
match:
  logic: any
  rules:
    - regex: 'eyJ[A-Za-z0-9_-]{10,}\.'   # a JWT in the stream
tactics:
  phase: "Web Auth"
  next_step: "Decode the token and test for weak signing."
  tools:
    - name: "jwt_tool"
      binary: "jwt_tool"
      command: "jwt_tool {target_url}"
      purpose: "Inspect and attack the JWT."
      install: "pipx install jwt-tool"   # shown if jwt_tool isn't on PATH
```

**3. Test it locally.** Point advsec at a folder without installing:

```sh
echo 'set-cookie: s=eyJhbGciOiJ...' | advsec --plugins-dir ./my-plugins
# or just place the file in ~/.config/advsec/plugins/ and pipe as usual
advsec plugin list    # confirm it loaded
```

**4. Share it.** Publish your `.yaml` (or a repo of them) on GitHub, and anyone can install it anonymously:

```sh
advsec plugin install owner/advsec-extra          # a GitHub repo of rules
advsec plugin install https://example.com/x.yaml   # a single hosted rule
```

See the appendix for the full field reference (`step`, `phase_label`, `os_packages`, entity placeholders).

## Installation

Requires Go 1.22+ to build.

```sh
# Arch / BlackArch
makepkg -si

# Any supported distro (detects distro, installs Go if needed, builds, installs)
sudo ./install.sh          # add -u to uninstall

# Manual
make build                 # -> ./bin/advsec
sudo make install          # -> /usr/local/bin + /usr/share/advsec/plugins
```

---

## Keeping rules fresh

advsec ships 137 rules across 17 domains and works fully offline. To pull the latest community rules:

```sh
advsec plugin update       # anonymous public HTTPS - never prompts for credentials
advsec plugin list         # see what's installed
```

---

## Optional AI classification (`--semantic`)

The deterministic regex / magic-byte / TLD engine is always the primary
classifier: plain `cat file | advsec` never touches a model, never opens a
socket, and stays sub-20ms. For genuinely ambiguous streams - a weird log, a
mixed dump, a snippet that matches nothing cleanly - advsec can *optionally*
consult a **local** embedding model to guess the right domain.

It is strictly opt-in and strictly offline-friendly:

- The binary stays a pure static build (`CGO_ENABLED=0`). No llama.cpp, no GGUF,
  no C++ is linked in. All vector work is done out-of-process by a local
  [Ollama](https://ollama.com) daemon, reached over plain HTTP.
- It runs **only** when you pass `--semantic` (alias `--embedding`), or when
  `enable_semantic: true` is set in config *and* the deterministic engine
  returned low confidence.
- If the daemon is missing or slow (500ms budget), advsec prints one quiet line
  to stderr and instantly falls back to the deterministic result. Pipes never
  hang and never break.

### One-time setup

```sh
advsec setup-semantic
```

This checks for a running Ollama daemon (`http://localhost:11434`), pulls an
embedding model (`embeddinggemma-2`, falling back to `embeddinggemma` or
`all-minilm`), and writes `~/.config/advsec/config.yaml`:

```yaml
enable_semantic: true
semantic_endpoint: "http://localhost:11434"
semantic_model: "embeddinggemma-2"
similarity_threshold: 0.75
```

If Ollama isn't installed, `setup-semantic` prints the host-specific commands,
e.g. on Arch:

```sh
sudo pacman -S ollama            # sudo apt install ollama on Debian/Kali
sudo systemctl enable --now ollama
advsec setup-semantic
```

### How it classifies

Each input snippet is truncated to 1,024 characters and wrapped in
EmbeddingGemma's symmetric classification prefix before being embedded:

```
task: classification | query: <snippet>
```

The resulting vector is compared (cosine similarity) against pre-seeded domain
centroids (`pwn`, `reversing`, `web`, `dfir`, `cloud`, `sysadmin`, `crypto`,
`redteam`, `js`). If the best score clears `similarity_threshold`, that domain
scopes the recommendations and its matches are confidence-boosted.

```sh
cat weird_unlabeled.log | advsec --semantic
```

---

## CLI quick reference

| Flag | What it does |
|------|--------------|
| `-c, --context <domain>` | Scope to one domain (or `$ADVSEC_CONTEXT`) |
| `-i, --select` | Pick the context interactively |
| `--top N` | Show only the N highest-priority recommendations |
| `-a, --all` | Show every match, including low-confidence |
| `--flat` | Flat per-plugin list instead of phase-grouped chains |
| `--json` | Machine-readable output |
| `--no-color` | Plain output |
| `-f, --input FILE` | Read from a file instead of stdin |
| `--semantic`, `--embedding` | Opt in to the local AI classifier (see below) |
| `--cmd "<command>"` | Upstream command to fuse (auto-detected from the pipe when omitted) |

Subcommands: `plugin list|install|update`, `update-cache`, `init zsh|bash|--install`, `setup-semantic`.

**Zero-config upstream detection.** When advsec reads from a pipe it traces
`/proc` to recover the writer's command line (e.g. `nmap -sV -p 22,80 10.10.10.5`)
with no flags required, so targets and ports from your *command* take priority
over noise in the tool's stdout. Resolution order: automatic `/proc` tracing ->
`$ADVSEC_CMD` -> an explicit `--cmd`. Instant-exit or shell-wrapped writers fall
through to the fallbacks; the `Alt+A` widget passes `--cmd "$last"` for exactly
that reason.

---

# Appendix: how it works

Everything below is reference material - you don't need it to use advsec.

### Pipeline

1. **Classify.** The first bytes and line structure of the stream are profiled into a format: `binary/elf|pe|macho`, `archive/zip|gzip|7z`, `email/mime`, `code/javascript|powershell|shell`, `network/nmap|socket`, `text/log`, `text/wordlist|payload_list|path_list` (lists of fuzzing data, not targets), `document/pdf`, `text/json`, or `text/plain`. Dotted tokens are validated against a strict TLD list, so `anaconda.xlog` or `script.php` are never mistaken for domains.
2. **Scope.** The format (or an explicit `-c`) narrows evaluation to the relevant domains, so a `.eml` never triggers Kerberoasting and a JS payload never triggers SDR rules.
3. **Parse.** A bounded 2 MB reader extracts targets - IPs, domains, URLs, ports, hashes, CVEs - with vendor/doc hosts (nmap.org, github.com, ...) filtered out, loopback/bind addresses suppressed, scan targets and cert SANs promoted, and GPG fingerprints kept distinct from SHA-1 hashes.
4. **Match + score.** Plugin rules (regex / substring / entity-type) match with a confidence weight; weak incidental matches are dropped.
5. **Sequence.** Surviving tools are grouped into ordered phases (passive triage first, destructive last) and reordered around an inferred intent (reputation lookup, post-mortem triage, immediate containment).
6. **Render.** Phases print with `checksec`-style readiness marks (installed vs missing), expanded commands (no raw `{target}` ever leaks), and per-tool install hints. Missing asset paths (e.g. `rockyou.txt`) are detected and substituted or flagged.

### Domains

`pwn`, `reversing`, `web`, `network`, `recon`, `redteam`, `blueteam`, `forensics`, `crypto`, `ctf`, `cloud`, `sysadmin`, `dfir`, `mobile`, `wireless`, `eml`, `js`, plus always-on `general`.

### Plugin authoring

Plugins are YAML in `~/.config/advsec/plugins/` (user) and `/usr/share/advsec/plugins/` (system); user files override system by `id`, and one file may hold many plugins separated by `---`.

```yaml
id: rev-elf-triage
name: "ELF Binary Triage"
domain: reversing                  # optional; defaults to the file stem
os_packages:
  arch:   [radare2, binutils]
  debian: [radare2, binutils]
match:
  logic: all                       # all (default) | any
  rules:
    - regex: 'ELF (32|64)-bit'     # regex | contains | entity_type
tactics:
  phase: "Reverse Engineering"
  priority: 60
  next_step: "Identify, analyze statically, then debug."
  tools:
    - name: "file & checksec"
      binary: "checksec"           # PATH check
      step: 1                      # action-chain position (1 passive .. 4 active)
      phase_label: "Phase 1: Identification & Mitigations"
      command: "file {target} ; checksec --file={target}"
      purpose: "Verify architecture and security mitigations."
      install: "pipx install ..."  # fallback when not distro-packaged
```

Placeholders expand from parsed entities: `{target}`, `{target_ip}`, `{target_domain}`, `{target_url}`, `{target_hash}`, `{target_addr}`, `{target_cve}`, `{target_port}`.

### Project layout

```
advsec/
|- cmd/            root, analyze, plugin, init commands + render/select
|- pkg/
|  |- engine/      parser, classifier, matcher, evaluator, sequence, assets
|  |- osdetect/    distro detection + package manager mapping
|  |- plugin/      YAML types, loader, lifecycle manager
|- plugins/        137 rules across 17 domain files
|- Makefile, PKGBUILD, install.sh
```

### Testing

`go test ./...` runs unit, sandbox, and domain-matrix suites (realistic payloads for every format, placeholder-leak checks across every plugin). `go test -v -run Diagnostics ./pkg/engine/` prints a self-diagnostic report of any classification, scoping, or action-chain anomalies.

## License

MIT - see [LICENSE](LICENSE).
