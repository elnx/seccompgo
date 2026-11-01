GO      ?= go
BIN     ?= bin/seccomp-tools
RUBY_SRC ?= ../seccomp-tools

.PHONY: all build test fix fix-check vet fmt generate clean install

all: build

build:
	@mkdir -p $(dir $(BIN))
	$(GO) build -trimpath -o $(BIN) ./cmd/seccomp-tools

test:
	$(GO) test ./...

# Apply go fix modernizations. Two passes: a fixer can expose another
# (e.g. newexpr adds a //go:fix inline directive the inline fixer consumes).
fix:
	$(GO) fix ./...
	$(GO) fix ./...

# Fail with a patch when a fixer would rewrite any package.
fix-check:
	$(GO) fix -diff ./...

vet: fix-check
	$(GO) vet ./...

fmt:
	gofmt -w $$($(GO) list -f '{{.Dir}}' ./...)

# Regenerate the syscall tables from the upstream Ruby sources.
generate:
	$(GO) run ./tools/gen -src $(RUBY_SRC)/lib/seccomp-tools/consts

clean:
	rm -rf bin

install:
	$(GO) install ./cmd/seccomp-tools
