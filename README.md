# advsec

A context-aware UNIX pipeline utility for Linux (Arch/BlackArch, Debian/Kali) that reads the output of a tool you just ran and tells you what to do next.

Pipe it `file`, `nmap`, `curl`, `journalctl`, a raw `.eml`, a packet capture - anything. advsec classifies the stream, extracts the entities that matter, matches them against a local plugin library, and prints an ordered, ready-to-run action chain scoped to your host and your task.

```sh
file suspicious.bin | advsec
nmap -sV 10.10.10.5  | advsec -c net
cat phish.eml        | advsec
```

---

## Key capabilities

- **UNIX pipe stream parsing** - bounded 2 MB streaming reader; extracts IPs, IPv6, domains, URLs, ports, hashes, CVEs and (in debugger output) memory addresses, with loopback/bind and reverse-DNS noise suppressed.
- **Magic-byte & structural format profiling** - classifies the input (binary, archive, email, source code, scanner output, logs) and auto-scopes rules so a raw `.eml` never triggers Kerberoasting and a JS payload never triggers SDR rules. See the table below.
- **Action-chain phase sequencing** - groups suggestions into ordered phases (passive triage first, destructive actions last) and reorders them around an inferred intent (reputation lookup, post-mortem triage, immediate containment).
- **Native package manager integration** - every suggested tool is checked against `PATH`; missing ones come with the exact install command for the host (`pacman`/`yay` on Arch, `apt` on Debian/Kali, or a `pipx`/`go`/`cargo` hint when not distro-packaged).
- **Asset verification** - hardcoded paths like `/usr/share/wordlists/rockyou.txt` are `os.Stat`-checked, substituted from known locations when possible, or flagged with an install tip.
- **Offline YAML plugin system** - 132 rules across 17 domains, loaded from local files. No network needed at runtime; `advsec plugin update` pulls the latest set anonymously over HTTPS.
- **Single static binary** - Go, zero runtime dependencies, sub-20 ms on typical piped input.

---

## Supported format domains

The stream profiler reads the leading bytes and scopes evaluation to the relevant domains:

| Format | Detected by | Active scope |
|--------|-------------|--------------|
| `code/javascript` | `function(`, `document.`, `eval(`, packed `_0x` arrays | js, web, crypto |
| `code/powershell` | `$env:`, `Invoke-`, `-EncodedCommand`, `[System.`, `[Ref].Assembly` | redteam, crypto, sysadmin |
| `code/shell` | `#!/bin/...` shebang | sysadmin, dfir |
| `network/nmap` | `Nmap scan report for`, `PORT STATE SERVICE` | network, recon, web |
| `network/socket` | `ss`/`netstat`/`lsof -i` tables | network, sysadmin |
| `email/mime` | `Received:`, `From:`, `MIME-Version:` | eml, crypto |
| `binary/elf` | magic `\x7fELF` | reversing, pwn, ctf |
| `binary/pe` | magic `MZ` | reversing, redteam |
| `text/log` | syslog / journalctl / access logs | blueteam, dfir, sysadmin |

Other formats (`binary/macho`, `archive/zip|gzip|7z`, `text/pcap`, `document/pdf`, `text/json`, `text/plain`) are profiled too. An explicit `-c` overrides the gate; `--no-classify` disables it; `--format` forces one.

## Installation

Requires Go 1.22+ to build.

### Arch / BlackArch (PKGBUILD)

```sh
makepkg -si
```

### Script installer (any supported distro)

Detects the distro, installs Go if missing, builds, and installs the binary plus the bundled plugins:

```sh
sudo ./install.sh        # install
sudo ./install.sh -u     # uninstall
```

### Manual (make)

```sh
make build               # -> ./bin/advsec
sudo make install        # -> /usr/local/bin + /usr/share/advsec/plugins
```

---

## Usage

Pipe a tool's output into advsec; the default command analyzes it:

```sh
<command> | advsec [flags]
```

### Examples

```sh
file suspicious.bin        | advsec              # binary triage -> RE action chain
nmap -sV 10.10.10.5        | advsec -c net       # scope to network services
curl -sI https://target    | advsec -c web       # web fingerprint -> recon chain
cat message.eml            | advsec              # auto-detected as email, eml-scoped rules
cat payload.js             | advsec              # auto-detected as JavaScript, js chain
cat implant.ps1            | advsec -c redteam   # PowerShell
journalctl -u ssh          | advsec -c dfir      # incident-response chain
sha256sum sample.bin       | advsec              # lone hash -> reputation intent
```

### Domain scoping

Scope evaluation to the job at hand. Only that domain plus always-on `general` rules run:

```sh
... | advsec -c dfir       # or web, pwn, net, ad, js, sysadmin, crypto, cloud, ...
... | advsec -i            # pick the context from an interactive menu
export ADVSEC_CONTEXT=ad   # pin a default for the session
```

Aliases resolve to canonical domains (`net`->network, `ad`->redteam, `ir`->dfir, `k8s`->cloud, `re`->reversing). With no context set, advsec evaluates everything and, when results span domains, prints a one-line scoping suggestion to stderr - it never switches for you.

---

## Shell integration (Ctrl+Alt+A)

A non-intrusive widget that, on a hotkey, re-runs your last command, pipes it through `advsec --top 3`, and prints suggestions beneath the prompt. It does not run on every command and never alters your command buffer.

### Automatic install (recommended)

```sh
advsec init --install        # detects your shell via $SHELL, appends to the right rc file
source ~/.zshrc              # or ~/.bashrc
```

`--install` is idempotent (it skips if the block is already present) and separates the block with blank lines so it can never fuse onto an existing line.

### Manual

```sh
advsec init zsh  >> ~/.zshrc     # or:
advsec init bash >> ~/.bashrc
```

Then press **Ctrl+Alt+A** after any command. (Under zsh, Ctrl+Alt+S analyzes the current buffer instead.)

### Shell runtime guards

Each block is wrapped in a shell check - the zsh block runs only when `$ZSH_VERSION` is set, the bash block only when `$BASH_VERSION` is set. If you source the wrong rc file across a shell boundary (e.g. `source ~/.zshrc` inside bash), the block is a silent no-op instead of a cascade of `bindkey`/`zle`/`setopt` syntax errors.

The generated snippet is self-delimited (`# >>> advsec ... >>>` / `# <<< advsec ... <<<`) and prepends blank lines, so appending it is always safe.

---

## Plugin schema

Plugins are YAML, loaded from `~/.config/advsec/plugins/` (user) and `/usr/share/advsec/plugins/` (system); user files override system by `id`. One file may hold many plugins separated by `---`.

```yaml
id: rev-elf-triage                 # unique, required
name: "ELF Binary Triage"
target_type: binary
domain: reversing                  # optional; defaults to the file stem. Used by -c
author: official
os_packages:                       # family -> packages that provide the tools
  arch:   [radare2, binutils]
  debian: [radare2, binutils]
  kali:   [radare2, binutils]
match:
  logic: all                       # all (default) | any
  rules:
    - regex: 'ELF (32|64)-bit'     # regex (RE2) | contains | entity_type
    # - contains: "literal"
    # - entity_type: hash          # ip|ipv6|domain|url|port|hash|mem_addr|cve|email
tactics:
  phase: "Reverse Engineering"
  priority: 60                     # higher ranks first; 0 = auto from specificity
  next_step: "Identify, then analyze statically, then debug."
  tools:
    - name: "file & checksec"
      binary: "checksec"           # PATH check; defaults to first word of command
      step: 1                      # action-chain position (1 passive .. 4 active)
      phase_label: "Phase 1: Identification & Mitigations"
      command: "file {target} ; checksec --file={target}"
      purpose: "Verify architecture and security mitigations."
      install: "pipx install ..."  # optional fallback when not distro-packaged
```

**Placeholders** expanded from parsed entities: `{target}`, `{target_ip}`, `{target_domain}`, `{target_port}`, `{target_url}`, `{target_hash}`, `{target_addr}`, `{target_cve}`.

**Domains**: `pwn`, `reversing`, `web`, `network`, `recon`, `redteam`, `blueteam`, `forensics`, `crypto`, `ctf`, `cloud`, `sysadmin`, `dfir`, `mobile`, `wireless`, `eml`, `js`, `general`.

Manage plugins:

```sh
advsec plugin list                 # installed + active plugins
advsec plugin install owner/repo   # GitHub shorthand, git URL, or a .yaml URL
advsec plugin update               # pull latest official rules (anonymous HTTPS)
advsec update-cache                # refresh the OS package-mapping cache
```

---

## CLI reference

| Flag | Effect |
|------|--------|
| `-c, --context <domain>` / `--domain` | Scope rules to one domain (also via `$ADVSEC_CONTEXT`) |
| `-i, --select` | Pick the context from an interactive menu |
| `-a, --all` | Show every match regardless of confidence |
| `--min-confidence N` | Minimum match confidence to render (default 2) |
| `--top N` | Show only the N highest-priority recommendations |
| `--missing-only` | Only show tools not installed locally |
| `--flat` | Flat per-plugin list instead of phase-grouped action chains |
| `--no-classify` | Disable magic-byte format gating (evaluate all domains) |
| `--format <fmt>` | Force the input format instead of auto-detecting |
| `--json` | Machine-readable output (domain, confidence, step, asset notes) |
| `--no-color` | Disable ANSI styling |
| `-f, --input FILE` | Read from a file instead of stdin |

Subcommands: `analyze` (default), `plugin list|install|update`, `update-cache`, `init zsh|bash`.

---

## Project layout

```
advsec/
|- main.go
|- cmd/            root, analyze, plugin, init commands + render/select (cobra)
|- pkg/
|  |- engine/      parser, classifier, matcher, evaluator, sequence, assets
|  |- osdetect/    distro detection + package manager mapping
|  |- plugin/      YAML types, loader, lifecycle manager
|- plugins/        132 rules across 17 domain files
|- Makefile
|- PKGBUILD
|- install.sh
```

## License

MIT - see [LICENSE](LICENSE).
