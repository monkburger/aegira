# ---------------------------------------------------------------------------
# Aegira — Makefile
# ---------------------------------------------------------------------------

BINARY      := aegira
BUILD_DIR   := dist
CONFIG      ?= configs/aegira.toml

CARGO       := cargo
VERSION     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT      := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_DATE  := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

export AEGIRA_VERSION := $(VERSION)
export AEGIRA_COMMIT := $(COMMIT)
export AEGIRA_BUILD_DATE := $(BUILD_DATE)

.DEFAULT_GOAL := build

.PHONY: build release run test check fmt lint clippy check-config check-config-release clean help

## help: Show available targets.
help:
	@echo "Aegira make targets:" 
	@grep -E '^## [a-zA-Z0-9_-]+:' $(MAKEFILE_LIST) | sed 's/^## /  /'

## build: Build debug binary.
build:
	$(CARGO) build

## release: Build optimized release binary.
release:
	$(CARGO) build --release

## run: Run the daemon using CONFIG (default: configs/aegira.toml).
run:
	$(CARGO) run -- --config $(CONFIG)

## test: Run unit tests.
test:
	$(CARGO) test

## check: Fast compile-time checks without building binaries.
check:
	$(CARGO) check

## fmt: Format Rust source code.
fmt:
	$(CARGO) fmt

## lint: Run lint checks (warnings as errors).
lint:
	$(CARGO) clippy -- -D warnings

## clippy: Alias for lint.
clippy: lint

## check-config: Validate config and rules with debug build.
check-config:
	$(CARGO) run -- --check-config --config $(CONFIG)

## check-config-release: Validate config and rules with release build.
check-config-release:
	$(CARGO) run --release -- --check-config --config $(CONFIG)

## clean: Remove local build artifacts.
clean:
	rm -rf $(BUILD_DIR) target
