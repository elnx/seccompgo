GO      ?= go
BIN     ?= bin/seccomp-tools
RUBY_SRC ?= ../seccomp-tools

.PHONY: all build test vet fmt generate clean install

all: build

build:
	@mkdir -p $(dir $(BIN))
	$(GO) build -trimpath -o $(BIN) ./cmd/seccomp-tools

test:
	$(GO) test ./...

vet:
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
