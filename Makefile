BINARY=envseal
VERSION?=0.2.0
LDFLAGS=-ldflags "-s -w -X github.com/Jackson2403/envseal/internal/cli.Version=$(VERSION)"

GO=go
ifeq ($(OS),Windows_NT)
	UNAME := Windows
else
	UNAME := $(shell uname -s)
endif

PLATFORMS=linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64

.PHONY: all build test test-race vet fmt lint run clean install cross dist man

all: build

## build: compile a local binary into ./bin
build:
	$(GO) build $(LDFLAGS) -o bin/$(BINARY) ./cmd/envseal

## install: install into GOPATH/bin
install:
	$(GO) install $(LDFLAGS) ./cmd/envseal

## test: run unit tests
test:
	$(GO) test ./... -count=1 -v

## test-race: run tests with the race detector where supported
test-race:
	$(GO) test ./... -race -count=1

## vet: run go vet
vet:
	$(GO) vet ./...

## fmt: format all Go sources
fmt:
	$(GO) fmt ./...

## tidy: sync module dependencies
tidy:
	$(GO) mod tidy

## man: regenerate the man page into docs/envseal.1
man:
	@mkdir -p docs
	$(GO) run ./cmd/envseal man > docs/envseal.1

## cross: build for all target platforms into ./dist
cross: tidy
	$(GO) mod download
	@mkdir -p dist
	@for p in $(PLATFORMS); do \
		os=$${p%/*}; arch=$${p#*/}; \
		ext=""; \
		if [ "$$os" = "windows" ]; then ext=".exe"; fi; \
		out="dist/envseal-$${os}-$${arch}$${ext}"; \
		echo "==> $$p"; \
		env GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 $(GO) build $(LDFLAGS) -o "$$out" ./cmd/envseal || exit 1; \
	done

## run: run with a doc string
run:
	$(GO) run ./cmd/envseal --help

## clean: remove build artifacts
clean:
	rm -rf bin dist
