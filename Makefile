BIN     := grokpatrol
PKG     := github.com/optimuslabs/grokpatrol/internal/buildinfo
MAIN    := ./cmd/$(BIN)
DIST    := dist

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
# SOURCE_DATE_EPOCH makes the stamp reproducible; the fallback covers BSD and GNU date.
DATE    ?= $(shell date -u -d "@$${SOURCE_DATE_EPOCH:-$$(date +%s)}" +%Y-%m-%dT%H:%M:%SZ 2>/dev/null || date -u -r "$${SOURCE_DATE_EPOCH:-$$(date +%s)}" +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
  -X $(PKG).Version=$(VERSION) \
  -X $(PKG).Commit=$(COMMIT) \
  -X $(PKG).Date=$(DATE)

# -trimpath        strips local filesystem paths: reproducible, and no path leakage
# -buildvcs=false  identical output whether the tree is dirty or clean
# CGO_ENABLED=0    static, no libc, cross-compiles cleanly, keeps cgo's os/user out
GOFLAGS := -trimpath -buildvcs=false -mod=readonly
GOBUILD := CGO_ENABLED=0 go build $(GOFLAGS) -ldflags '$(LDFLAGS)'

PLATFORMS := darwin/amd64 darwin/arm64 linux/amd64 linux/arm64 windows/amd64 windows/arm64

# Where `make demo` builds its synthetic compromised host.
FAKEHOME ?= /tmp/grokpatrol-fakehome

.DEFAULT_GOAL := help

## help: list the available targets
.PHONY: help
help:
	@echo "grokpatrol $(VERSION)"
	@echo
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /' | awk -F': ' '{printf "  \033[1m%-16s\033[0m %s\n", $$1, $$2}' | sed 's/^  //'

# --- build -------------------------------------------------------------------

## build: build ./dist/grokpatrol for this machine
.PHONY: build
build:
	@mkdir -p $(DIST)
	$(GOBUILD) -o $(DIST)/$(BIN) $(MAIN)
	@echo "built $(DIST)/$(BIN)"

## install: install grokpatrol into $GOPATH/bin
.PHONY: install
install:
	CGO_ENABLED=0 go install $(GOFLAGS) -ldflags '$(LDFLAGS)' $(MAIN)

## run: build, then scan this machine (ARGS="--json" to pass flags)
.PHONY: run
run: build
	@$(DIST)/$(BIN) $(ARGS)

## release: cross-compile all six platforms into ./dist with SHA256SUMS
.PHONY: release
release: clean-dist verify-deps
	@mkdir -p $(DIST)
	@for p in $(PLATFORMS); do \
	  os=$${p%/*}; arch=$${p#*/}; \
	  ext=""; [ "$$os" = "windows" ] && ext=".exe"; \
	  out="$(DIST)/$(BIN)_$(VERSION)_$${os}_$${arch}$${ext}"; \
	  echo "  -> $$out"; \
	  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch \
	    go build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o "$$out" $(MAIN) || exit 1; \
	done
	@cd $(DIST) && (shasum -a 256 $(BIN)_* 2>/dev/null || sha256sum $(BIN)_*) > SHA256SUMS
	@echo && cat $(DIST)/SHA256SUMS

# --- verification ------------------------------------------------------------

# This target IS the no-network guarantee. A binary whose dependency graph contains
# no net, no net/http and no crypto/tls cannot phone home. That is a property of the
# linker, not a promise in a README -- which is why it runs before every release.
## verify-deps: prove the binary is stdlib-only, with no network and no cgo
.PHONY: verify-deps
verify-deps:
	@test ! -s go.sum || { echo "FAIL: go.sum is non-empty - a third-party dependency crept in"; exit 1; }
	@if go list -deps ./... | grep -qxE 'net|net/http|net/http/.*|crypto/tls|os/user'; then \
	  echo "FAIL: a network or cgo package is linked into the binary:"; \
	  go list -deps ./... | grep -xE 'net|net/http|net/http/.*|crypto/tls|os/user'; \
	  exit 1; \
	fi
	@echo "OK: stdlib-only, no net, no cgo"

## test: run the test suite with the race detector
.PHONY: test
test:
	go test -race ./...

## fuzz: fuzz the log parser for 60s (it must never panic on a malformed line)
.PHONY: fuzz
fuzz:
	go test ./internal/detect/logs -run=Fuzz -fuzz=FuzzParseLine -fuzztime=60s

## bench: benchmark the marker scanner's throughput
.PHONY: bench
bench:
	go test ./internal/scan -bench=. -benchtime=3x -run=XXX

## fmt: gofmt the tree in place
.PHONY: fmt
fmt:
	gofmt -w .

## vet: run go vet
.PHONY: vet
vet:
	go vet ./...

## check: everything CI runs -- deps, fmt, vet, race tests, cross-compile smoke
.PHONY: check
check: verify-deps
	@gofmt -l . | (! grep .) || { echo "FAIL: run 'make fmt'"; exit 1; }
	go vet ./...
	go test -race ./...
	@echo "cross-compile smoke (catches //go:build mistakes before release, not during):"
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 go build $(GOFLAGS) -o /dev/null ./...
	GOOS=linux   GOARCH=arm64 CGO_ENABLED=0 go build $(GOFLAGS) -o /dev/null ./...
	GOOS=darwin  GOARCH=arm64 CGO_ENABLED=0 go build $(GOFLAGS) -o /dev/null ./...
	@echo "OK: check passed"

# --- demo --------------------------------------------------------------------

# There is no real Grok install to test against, so the compromised case has to be
# constructed. This builds a synthetic host with every host-side indicator planted --
# including a repo whose secrets were committed and then deleted -- and scans it.
## demo: build a synthetic compromised host and scan it (expect COMPROMISED, exit 4)
.PHONY: demo
demo: build
	@./testdata/make_fakehome.sh $(FAKEHOME) >/dev/null
	@echo "synthetic compromised host: $(FAKEHOME)"
	@echo
	@$(DIST)/$(BIN) --home $(FAKEHOME) --grok-home $(FAKEHOME)/.grok || \
	  echo "exit=$$?  (4 = COMPROMISED, which is the expected result here)"

# --- cleanup -----------------------------------------------------------------

# Release artifacts only. Deliberately does NOT remove ./dist/grokpatrol, so that
# `make release` cannot pull the dev binary out from under a shell you are using.
.PHONY: clean-dist
clean-dist:
	@rm -f $(DIST)/$(BIN)_* $(DIST)/SHA256SUMS

## clean: remove build output
.PHONY: clean
clean:
	rm -rf $(DIST)

## distclean: remove build output, the Go build/test cache, and the demo fixture
.PHONY: distclean
distclean: clean
	rm -rf $(FAKEHOME)
	go clean -cache -testcache -fuzzcache
