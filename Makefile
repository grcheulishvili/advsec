# advsec — build, test, and install targets.
BINARY      := advsec
PKG         := github.com/grcheulishvili/advsec
CMD_PKG     := $(PKG)/cmd

VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 0.3.0)
COMMIT      ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
DATE        ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS     := -s -w \
	-X '$(CMD_PKG).Version=$(VERSION)' \
	-X '$(CMD_PKG).Commit=$(COMMIT)' \
	-X '$(CMD_PKG).Date=$(DATE)'

PREFIX      ?= /usr/local
BINDIR      := $(DESTDIR)$(PREFIX)/bin
SHAREDIR    := $(DESTDIR)$(PREFIX)/share/advsec/plugins
# System plugin path is hard-coded to /usr/share/advsec/plugins in the loader;
# honor DESTDIR for packaging but install there by default.
SYSPLUGINS  := $(DESTDIR)/usr/share/advsec/plugins

GOFLAGS     ?=
GO          ?= go

.PHONY: all build install uninstall clean test vet fmt tidy run plugins-install release

all: build

## build: compile a static single binary into ./bin
build:
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) -trimpath -ldflags "$(LDFLAGS)" -o bin/$(BINARY) .

## test: run unit tests
test:
	$(GO) test ./... -count=1

## vet: run go vet
vet:
	$(GO) vet ./...

## fmt: gofmt all sources
fmt:
	$(GO) fmt ./...

## tidy: sync go.mod/go.sum
tidy:
	$(GO) mod tidy

## run: build and analyze a sample against the in-repo plugins
run: build
	@printf 'ELF 64-bit LSB executable, x86-64, not stripped, executable stack\n' | ./bin/$(BINARY) --plugins-dir ./plugins

## install: install binary + bundled plugins system-wide
install: build
	install -Dm0755 bin/$(BINARY) $(BINDIR)/$(BINARY)
	install -d $(SYSPLUGINS)
	install -Dm0644 plugins/*.yaml -t $(SYSPLUGINS)
	@echo "Installed $(BINARY) to $(BINDIR) and plugins to $(SYSPLUGINS)"

## uninstall: remove installed files
uninstall:
	rm -f $(BINDIR)/$(BINARY)
	rm -rf $(DESTDIR)/usr/share/advsec
	@echo "Removed $(BINARY)"

## clean: remove build artifacts
clean:
	rm -rf bin dist

## release: cross-compile static binaries for common arches into ./dist
release:
	@mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-amd64 .
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o dist/$(BINARY)-linux-arm64 .
	@echo "Built dist/ binaries"
