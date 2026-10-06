# advsec

**Context-aware UNIX pipe recommendation engine.**

`advsec` reads piped `stdin` from upstream tools (`nmap`, `file`, `curl`, `gdb`,
`journalctl`, …), evaluates the operational context against a local YAML plugin
matrix, checks whether the recommended tooling is installed on the host, and
prints prioritized, executable next steps to `stdout`.

Built for cybersecurity researchers, systems/network engineers, penetration
testers, reverse engineers, and malware analysts. Single static Go binary, zero
runtime dependencies, sub-millisecond parsing.

```
file suspicious.bin | advsec
nmap -sV 10.10.10.5 | advsec --top 3
curl -sI https://target | advsec
journalctl -u ssh --since -1h | advsec
```

---

## Install

### Arch / BlackArch (PKGBUILD)

```sh
makepkg -si
```

### Universal (build from source)

```sh
sudo ./install.sh          # detects distro, installs Go if needed, builds, installs
sudo ./install.sh -u       # uninstall
```

### Make

```sh
make build                 # -> ./bin/advsec
sudo make install          # -> /usr/local/bin + /usr/share/advsec/plugins
```

Requires Go 1.22+.

---

## Usage

Piping into `advsec` runs the analyzer (the default command):

```sh
<upstream-command> | advsec [--top N] [--missing-only] [--json] [--no-color]
```

| Flag | Effect |
|------|--------|
| `-c, --context <domain>` / `--domain` | Scope rules to one domain (`dfir`, `web`, `pwn`, `net`, `ad`, `sysadmin`, `crypto`, `cloud`, …). Also via `$ADVSEC_CONTEXT`. |
| `-i, --select` | Interactively pick the context before evaluation (reads `/dev/tty`) |
| `--min-confidence N` | Minimum match confidence to render (default `2`) |
| `-a, --all` | Show every match regardless of confidence |
| `--top N` | Show only the N highest-priority recommendations |
| `--missing-only` | Only show tools not installed locally (plus their install command) |
| `--json` | Machine-readable output (includes `domain` and `confidence`) |
| `--no-color` | Disable ANSI styling |
| `-f, --input FILE` | Read from a file instead of stdin |

### Context scoping

Rules carry a `domain` (defaulting to their file stem). Scope evaluation to the
job at hand — only that domain plus always-on `general` rules run:

```sh
journalctl -u ssh | advsec -c dfir      # incident response only
ffuf ... | advsec -c web                # web only
export ADVSEC_CONTEXT=ad                # pin a default (Active Directory)
nmap ... | advsec -i                    # pick interactively
```

Aliases resolve to canonical domains (`net`→network, `ad`→redteam, `ir`→dfir,
`k8s`→cloud, `re`→reversing, …). With no context set, advsec evaluates
everything and, if results span multiple domains, prints a one-line scoping
*suggestion* to stderr — it never switches context for you.

### Shell integration

`advsec init zsh` / `advsec init bash` emit a non-intrusive widget bound to
**Ctrl+Alt+A**: it re-runs your last command, pipes the output through
`advsec --top 3`, and prints suggestions beneath the prompt without touching
your command buffer. It does **not** run on every command.

```sh
advsec init zsh  >> ~/.zshrc
advsec init bash >> ~/.bashrc
```

### Plugin management

```sh
advsec plugin list                      # installed + active plugins
advsec plugin install owner/repo        # GitHub shorthand
advsec plugin install https://host/x.yaml
advsec plugin update                    # pull official + community rules
advsec update-cache                     # refresh OS package mapping database
```

---

## How it works

1. **Parse** — a bounded 2 MB streaming buffer reads stdin and extracts IPs,
   domains, URLs, ports, file headers, protocol banners, hashes, memory
   addresses, and CVEs. Every IP is validated with `net.ParseIP`; loopback/bind
   addresses and reverse-DNS zones are suppressed; hex values only count as
   memory addresses inside genuine debugger/pwn output (so `0x8007000D`-style
   error codes don't masquerade as pointers).
2. **Scope** — if a context is set (`-c`, `$ADVSEC_CONTEXT`, or `--select`),
   only that domain's rules plus always-on `general` rules are evaluated.
3. **Match + score** — each plugin's `match.rules` (regex / substring /
   entity-type) run with `all`/`any` logic; matched rules accrue a confidence
   weight, and matches below `--min-confidence` (default 2) are suppressed to
   kill incidental false positives.
4. **Evaluate** — matches are ranked by priority, command placeholders
   (`{target}`, `{target_ip}`, …) are expanded, and each tool is checked
   against `PATH`.
5. **Recommend** — phases, objectives, and ready-to-run commands are printed;
   missing tools come with the exact native install command (`pacman`/`yay` on
   Arch, `apt` on Debian/Kali) or a pip/go/cargo hint when not distro-packaged.

---

## Plugins

Plugins are declarative YAML, loaded from (user overrides system):

- `~/.config/advsec/plugins/` (also honors `$XDG_CONFIG_HOME` / `$ADVSEC_CONFIG_DIR`)
- `/usr/share/advsec/plugins/`

The bundled library ships 125+ rules across 15 domains (a file may hold many
plugins separated by `---`):

`pwn` · `reversing` · `web` · `network` · `recon` · `redteam` · `blueteam` ·
`forensics` · `crypto` · `ctf` · `cloud` · `sysadmin` · `dfir` · `mobile` ·
`wireless` · `general` — covering pentest, red team, blue team / DFIR, RE,
CTF, cloud/container, wireless, and day-to-day sysadmin triage.

### Schema

```yaml
id: pwn-elf64-exec-stack          # unique, required
name: ELF 64-bit (Executable Stack)
target_type: binary
domain: pwn                       # optional; defaults to the file stem. Used by -c/--context
author: official
os_packages:                      # family -> packages providing the tools
  arch:   [checksec, gdb, radare2]
  debian: [checksec, gdb, radare2]
  kali:   [checksec, gdb, radare2]
match:
  logic: all                      # all (default) | any
  rules:
    - regex: "ELF 64-bit"
    - regex: "executable stack"
    # - contains: "literal substring"
    # - entity_type: hash         # ip|ipv6|domain|url|port|hash|mem_addr|cve
tactics:
  phase: "Binary Exploitation"
  priority: 60                    # higher wins; 0 = auto from rule specificity
  next_step: "Find the overflow offset and build a payload."
  tools:
    - name: checksec
      binary: checksec            # PATH check; defaults to first word of command
      command: "checksec --file={target}"
      purpose: "Enumerate binary protections."
      install: "pipx install ..."  # optional: fallback when not distro-packaged
```

`install` is an optional manager-agnostic install command (pip/pipx/go/cargo or
a vendor script). It is used only when the tool is missing from `PATH` **and**
no native package in `os_packages` provides it — so distro-packaged tools still
get a native `pacman`/`apt` command, while pip/go-only tooling gets an accurate
one.

### Command placeholders

`{target}` · `{target_ip}` · `{target_domain}` · `{target_port}` ·
`{target_url}` · `{target_hash}` · `{target_addr}` · `{target_cve}`

Unmatched placeholders are left intact so you can see what still needs filling.

---

## Project layout

```
advsec/
├── main.go
├── cmd/            root, analyze, plugin, init commands + render/select (cobra)
├── pkg/
│   ├── engine/     parser, matcher, evaluator
│   ├── osdetect/   distro detection + package manager mapping
│   └── plugin/     YAML types, loader, lifecycle manager
├── plugins/        125+ rules across 15 domain files (see below)
├── Makefile
├── PKGBUILD
└── install.sh
```

## License

MIT — see [LICENSE](LICENSE).
