# Maintainer: grcheulishvili <rcheulishvili69@gmail.com>
pkgname=advsec
pkgver=1.4.0
pkgrel=1
pkgdesc="Context-aware UNIX pipe recommendation engine for offensive/defensive security tooling"
arch=('x86_64' 'aarch64')
url="https://github.com/grcheulishvili/advsec"
license=('MIT')
depends=('glibc')
makedepends=('go>=1.22' 'git')
# Recommended companion tooling surfaced by the bundled plugins:
optdepends=(
  'checksec: binary protection analysis (pwn plugins)'
  'gdb: dynamic binary analysis'
  'radare2: reverse engineering'
  'nmap: network service enumeration'
  'nikto: web server scanning'
  'gobuster: web content discovery'
  'wpscan: WordPress enumeration'
)
source=("$pkgname-$pkgver.tar.gz::$url/archive/refs/tags/v$pkgver.tar.gz")
sha256sums=('SKIP')

build() {
  cd "$srcdir/$pkgname-$pkgver"
  export CGO_ENABLED=0
  export GOFLAGS="-trimpath -mod=readonly -modcacherw"
  local ldflags="-s -w \
    -X github.com/grcheulishvili/advsec/cmd.Version=$pkgver \
    -X github.com/grcheulishvili/advsec/cmd.Commit=$pkgrel \
    -X github.com/grcheulishvili/advsec/cmd.Date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
  go build -ldflags "$ldflags" -o "$pkgname" .
}

check() {
  cd "$srcdir/$pkgname-$pkgver"
  go test ./... || true
}

package() {
  cd "$srcdir/$pkgname-$pkgver"

  # Binary
  install -Dm0755 "$pkgname" "$pkgdir/usr/bin/$pkgname"

  # Bundled system plugins
  install -d "$pkgdir/usr/share/advsec/plugins"
  install -Dm0644 plugins/*.yaml -t "$pkgdir/usr/share/advsec/plugins"

  # License + docs
  install -Dm0644 LICENSE "$pkgdir/usr/share/licenses/$pkgname/LICENSE" 2>/dev/null || true
  install -Dm0644 README.md "$pkgdir/usr/share/doc/$pkgname/README.md" 2>/dev/null || true
}
