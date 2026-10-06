#!/usr/bin/env bash
#
# advsec universal installer.
#
# Builds (or reuses) the advsec binary and installs it system-wide along with
# the bundled tactical plugins. Detects the host distribution and uses the
# native package manager to install the Go toolchain if it is missing.
#
# Usage:
#   sudo ./install.sh            # build from source and install to /usr/local
#   PREFIX=/opt sudo ./install.sh
#   ./install.sh --uninstall     # remove an installed advsec
#
set -euo pipefail

PREFIX="${PREFIX:-/usr/local}"
BINDIR="$PREFIX/bin"
PLUGINDIR="/usr/share/advsec/plugins"
REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

c_green()  { printf '\033[0;32m%s\033[0m\n' "$*"; }
c_blue()   { printf '\033[0;34m%s\033[0m\n' "$*"; }
c_yellow() { printf '\033[0;33m%s\033[0m\n' "$*"; }
c_red()    { printf '\033[0;31m%s\033[0m\n' "$*" >&2; }

die() { c_red "error: $*"; exit 1; }

need_root() {
  if [ "$(id -u)" -ne 0 ]; then
    die "this action needs root; re-run with sudo."
  fi
}

detect_family() {
  if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    case "${ID:-}" in
      arch|archarm|artix|manjaro|endeavouros|blackarch|garuda) echo "arch"; return ;;
      kali)                                                     echo "kali"; return ;;
      debian|ubuntu|parrot|linuxmint|pop|raspbian|devuan)      echo "debian"; return ;;
    esac
    case " ${ID_LIKE:-} " in
      *" arch "*)             echo "arch"; return ;;
      *" debian "*|*" ubuntu "*) echo "debian"; return ;;
    esac
  fi
  echo "unknown"
}

pm_install() {
  # pm_install <family> <pkg...>
  local family="$1"; shift
  case "$family" in
    arch)         pacman -S --needed --noconfirm "$@" ;;
    kali|debian)  apt-get update -y && apt-get install -y "$@" ;;
    *)            die "unsupported distribution; install [$*] manually and re-run." ;;
  esac
}

ensure_go() {
  if command -v go >/dev/null 2>&1; then
    c_green "✓ Go toolchain found: $(go version)"
    return
  fi
  local family="$1"
  c_yellow "Go toolchain not found; installing via package manager…"
  case "$family" in
    arch)        pm_install arch go ;;
    kali|debian) pm_install debian golang-go ;;
    *)           die "Go is required. Install Go >= 1.22 and re-run." ;;
  esac
  command -v go >/dev/null 2>&1 || die "Go installation failed."
}

do_build() {
  c_blue "Building advsec…"
  ( cd "$REPO_DIR" && CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o bin/advsec . )
  [ -x "$REPO_DIR/bin/advsec" ] || die "build did not produce bin/advsec"
  c_green "✓ Built $REPO_DIR/bin/advsec"
}

do_install() {
  need_root
  local family; family="$(detect_family)"
  c_blue "Detected distribution family: $family"

  ensure_go "$family"
  do_build

  c_blue "Installing binary to $BINDIR …"
  install -d "$BINDIR"
  install -Dm0755 "$REPO_DIR/bin/advsec" "$BINDIR/advsec"

  c_blue "Installing bundled plugins to $PLUGINDIR …"
  install -d "$PLUGINDIR"
  install -Dm0644 "$REPO_DIR"/plugins/*.yaml -t "$PLUGINDIR"

  # Seed per-user config dir for the invoking (sudo) user, if we can tell who.
  local real_user="${SUDO_USER:-}"
  if [ -n "$real_user" ] && [ "$real_user" != "root" ]; then
    local home; home="$(getent passwd "$real_user" | cut -d: -f6)"
    if [ -n "$home" ]; then
      install -d "$home/.config/advsec/plugins"
      chown -R "$real_user":"$real_user" "$home/.config/advsec"
      c_green "✓ Prepared user plugin dir: $home/.config/advsec/plugins"
    fi
  fi

  c_green "✓ advsec installed."
  echo
  c_yellow "Try it:"
  echo "  file /bin/ls | advsec"
  echo "  advsec plugin list"
}

do_uninstall() {
  need_root
  c_blue "Removing advsec…"
  rm -f "$BINDIR/advsec"
  rm -rf /usr/share/advsec
  c_green "✓ Removed binary and system plugins (user config left intact)."
}

main() {
  case "${1:-}" in
    --uninstall|-u) do_uninstall ;;
    --help|-h)
      sed -n '2,20p' "$0"
      ;;
    *) do_install ;;
  esac
}

main "$@"
