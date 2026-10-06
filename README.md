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
| `--top N` | Show only the N highest-priority recommendations |
| `--missing-only` | Only show tools not installed locally (plus their install command) |
| `--json` | Machine-readable output |
| `--no-color` | Disable ANSI styling |
| `-f, --input FILE` | Read from a file instead of stdin |

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

1. **Parse** - a bounded 2 MB streaming buffer reads stdin and extracts IPs,
   domains, URLs, ports, file headers, protocol banners, hashes, memory
   addresses, and CVEs with a fast RE2 engine.
2. **Match** - each plugin's `match.rules` (regex / substring / entity-type) are
   evaluated with `all`/`any` logic against the input.
3. **Evaluate** - matched plugins are ranked by priority, command placeholders
   (`{target}`, `{target_ip}`, `{target_port}`, …) are expanded from parsed
   entities, and each recommended tool is checked against `PATH`.
4. **Recommend** - prioritized phases, next steps, and ready-to-run commands are
   printed; missing tools come with the exact native install command for the
   detected distro (`pacman`/`yay` on Arch, `apt` on Debian/Kali).

---

## Plugins

Plugins are declarative YAML, loaded from (user overrides system):

- `~/.config/advsec/plugins/` (also honors `$XDG_CONFIG_HOME` / `$ADVSEC_CONFIG_DIR`)
- `/usr/share/advsec/plugins/`

Bundled domains: `web`, `pwn`, `network`, `dfir`. A file may hold multiple
plugins separated by `---`.

### Schema

```yaml
id: pwn-elf64-exec-stack          # unique, required
name: ELF 64-bit (Executable Stack)
target_type: binary
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
```

### Command placeholders

`{target}` · `{target_ip}` · `{target_domain}` · `{target_port}` ·
`{target_url}` · `{target_hash}` · `{target_addr}` · `{target_cve}`

Unmatched placeholders are left intact so you can see what still needs filling.

---

## Project layout

```
advsec/
├── main.go
├── cmd/            root, analyze, plugin commands (cobra)
├── pkg/
│   ├── engine/     parser, matcher, evaluator
│   ├── osdetect/   distro detection + package manager mapping
│   └── plugin/     YAML types, loader, lifecycle manager
├── plugins/        web.yaml, pwn.yaml, network.yaml, dfir.yaml
├── Makefile
├── PKGBUILD
└── install.sh
```

## License

MIT - see [LICENSE](LICENSE).
