.DEFAULT_GOAL := help
SHELL := /usr/bin/env bash

help: ## show this help
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

lint: ## rustfmt + clippy + shellcheck
	cargo fmt --all -- --check
	cargo clippy --all-targets -- -D warnings
	@if command -v shellcheck > /dev/null; then \
	    shellcheck verify.sh tests/*.sh; \
	  else \
	    echo "  (shellcheck not installed — skipped)"; \
	  fi

test: ## unit tests
	cargo test

# Both implementations, against the same fixtures. This is the target that
# matters: it is the only thing keeping verify.sh and git-attest from drifting.
#
# `legacy` is a NEGATIVE control and is expected to FAIL — it is the verifier
# this project replaces, and a fixture suite it passed would be testing
# nothing. `make conformance` therefore asserts it fails.
conformance: ## run the fixtures against both implementations
	cargo build --release
	@echo "--- verify.sh ---"
	@./tests/conformance.sh "bash $(PWD)/verify.sh --quiet"
	@echo "--- git-attest ---"
	@./tests/conformance.sh "$(PWD)/target/release/git-attest covered"
	@echo "--- legacy.sh (negative control: MUST fail) ---"
	@if SKIP_JSON=1 ./tests/conformance.sh "bash $(PWD)/tests/legacy.sh" > /dev/null 2>&1; then \
	    echo "  ✗ legacy.sh PASSED the suite — the fixtures no longer prove anything"; \
	    exit 1; \
	else \
	    echo "  ok  legacy.sh still fails the defects it shipped with"; \
	fi

check: lint test conformance ## everything CI runs

fmt: ## format
	cargo fmt --all

msrv: ## prove the rust-version floor in Cargo.toml is real
	@v=$$(awk -F'"' '/^rust-version/ {print $$2}' Cargo.toml); \
	  echo "checking MSRV $$v"; \
	  rustup toolchain install "$$v" --profile minimal 2> /dev/null || true; \
	  cargo "+$$v" check --locked

.PHONY: help lint test conformance check fmt msrv
