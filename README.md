# advsec

**Your quiet terminal sidekick for "what do I run next?"**

advsec looks at the output of a command you just ran - an `nmap` scan, a `file` on a suspicious binary, an SSH log, a raw email, a chunk of obfuscated JavaScript - and prints the next logical commands to run, ordered as a clean action chain and tailored to the tools actually installed on your box.

```sh
file suspicious.bin | advsec
nmap -sV 10.10.10.5  | advsec
cat phish.eml        | advsec
```

It stays out of your way until you ask.

---

## The 3 golden rules

1. **Non-intrusive.** advsec runs only when you pipe into it or press **`Alt+A`**. It never runs on every command, never edits your command line, and never touches your shell history.
2. **OS-native.** Recommended a tool you don't have? advsec gives you the exact install command for *your* system - `pacman`/`yay` on Arch/BlackArch, `apt` on Debian/Kali, or a `pipx`/`go`/`cargo` hint for tools that aren't packaged.
3. **100% offline and fast.** Everything runs locally in a single static binary, typically in a few milliseconds. No telemetry, no cloud, no network calls at runtime.

---

## Real-world workflows

Pipe a tool's output straight in. advsec figures out the format, scopes to the relevant domain, and prints an ordered action chain.

### Web & API assessment

```sh
curl -sI https://target | advsec
```
Reads the HTTP response headers, then suggests a security-header audit, technology fingerprinting (`whatweb`), directory discovery (`feroxbuster`/`ffuf`), and template-driven vuln scanning (`nuclei`).

### Binary triage & reverse engineering

```sh
file suspicious.bin | advsec
```
Detects the ELF64 architecture and walks the RE chain: mitigation audit (`checksec`) in Phase 1, static symbols and strings (`rabin2`, `radare2`) in Phase 2, then a GDB debugging session in Phase 3.

### Incident response & log triage

```sh
journalctl -u ssh | advsec
```
Spots the SSH brute-force burst, infers an **Immediate Containment** intent, and leads with log isolation (`grep`/`journalctl`), source banning (`fail2ban-client`), and account/session audits (`lastb`).

### Phishing & email analysis

```sh
cat phish.eml | advsec
```
Auto-detects RFC822/MIME and scopes to email triage only - no unrelated network or AD noise. Checks SPF/DKIM/DMARC results, carves attachments (`ripmime`/`munpack`), and defangs URLs for safe reputation checks.

### Obfuscated code analysis

```sh
cat payload.js | advsec
```
Recognizes packed JavaScript (`_0x` arrays, `eval(atob(...))`), skips network/AD/cloud rules entirely, and routes straight to beautifying (`js-beautify`), AST deobfuscation (`webcrack`), and sandboxed V8 debugging (`node --inspect-brk`).

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

advsec ships 130+ rules across 17 domains and works fully offline. To pull the latest community rules:

```sh
advsec plugin update       # anonymous public HTTPS - never prompts for credentials
advsec plugin list         # see what's installed
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

Subcommands: `plugin list|install|update`, `update-cache`, `init zsh|bash|--install`.

---

# Appendix: how it works

Everything below is reference material - you don't need it to use advsec.

### Pipeline

1. **Classify.** The first bytes of the stream are profiled by magic number and structure into a format: `binary/elf|pe|macho`, `archive/zip|gzip|7z`, `email/mime`, `code/javascript|powershell|shell`, `network/nmap|socket`, `text/log`, `document/pdf`, `text/json`, or `text/plain`.
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
|- plugins/        130+ rules across 17 domain files
|- Makefile, PKGBUILD, install.sh
```

### Testing

`go test ./...` runs unit, sandbox, and domain-matrix suites (realistic payloads for every format, placeholder-leak checks across every plugin). `go test -v -run Diagnostics ./pkg/engine/` prints a self-diagnostic report of any classification, scoping, or action-chain anomalies.

## License

MIT - see [LICENSE](LICENSE).
