.DEFAULT_GOAL := help
SHELL := /usr/bin/env bash

help: ## show this help
	@grep -hE '^[a-z-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

lint: ## rustfmt + clippy + shellcheck
	cargo fmt --all -- --check
	cargo clippy --all-targets -- -D warnings
	@if command -v shellcheck > /dev/null; then \
	    shellcheck verify.sh sign/sign.sh tests/*.sh tests/fault/git; \
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

# A 1.1.0 verifier reads ONE block of a note. This proves what SPEC.md claims:
# on a multi-block note it reports block 1's gates or nothing, never a gate
# from a later block. The shell copy is frozen in the tree; the binary is built
# from the v1.1.0 tag, which a shallow CI checkout fetches on demand.
# The binary of a released tag, built into target/compat/<tag>/. A shallow CI
# checkout fetches the tag on demand.
define build_tag
	@git rev-parse -q --verify $(1) > /dev/null 2>&1 || git fetch -q --depth 1 origin tag $(1)
	@rm -rf target/compat/$(1)/src && mkdir -p target/compat/$(1)/src
	@git archive $(1) | tar -x -C target/compat/$(1)/src
	@cargo build -q --release --manifest-path target/compat/$(1)/src/Cargo.toml --target-dir target/compat/$(1)/target
endef

compat: ## prove released verifiers degrade safely on newer notes
	@echo "--- multi-block notes: verify.sh 1.1.0 (frozen copy) ---"
	@./tests/compat.sh "bash $(PWD)/tests/compat/verify-1.1.0.sh --quiet"
	@echo "--- multi-block notes: git-attest 1.1.0 (built from the tag) ---"
	$(call build_tag,v1.1.0)
	@./tests/compat.sh "$(PWD)/target/compat/v1.1.0/target/release/git-attest covered"
	@echo "--- input lines: verify.sh 1.1.0 (frozen copy) ---"
	@./tests/compat-fields.sh "bash $(PWD)/tests/compat/verify-1.1.0.sh --quiet" old
	@echo "--- input lines: git-attest 1.1.0 ---"
	@./tests/compat-fields.sh "$(PWD)/target/compat/v1.1.0/target/release/git-attest covered" old
	@echo "--- input lines: verify.sh 1.2.0 (frozen copy) ---"
	@./tests/compat-fields.sh "bash $(PWD)/tests/compat/verify-1.2.0.sh --quiet" old
	@echo "--- input lines: git-attest 1.2.0 (built from the tag) ---"
	$(call build_tag,v1.2.0)
	@./tests/compat-fields.sh "$(PWD)/target/compat/v1.2.0/target/release/git-attest covered" old
	@echo "--- input lines: current verify.sh ---"
	@./tests/compat-fields.sh "bash $(PWD)/verify.sh --quiet" new
	@echo "--- input lines: current git-attest ---"
	@cargo build -q --release
	@./tests/compat-fields.sh "$(PWD)/target/release/git-attest covered" new

sign-test: ## the producer's fixtures (sign/sign.sh against a bare origin)
	@echo "--- sign/sign.sh ---"
	@./tests/sign.sh

check: lint test conformance compat sign-test ## everything CI runs

fmt: ## format
	cargo fmt --all

msrv: ## prove the rust-version floor in Cargo.toml is real
	@v=$$(awk -F'"' '/^rust-version/ {print $$2}' Cargo.toml); \
	  echo "checking MSRV $$v"; \
	  rustup toolchain install "$$v" --profile minimal 2> /dev/null || true; \
	  cargo "+$$v" check --locked

.PHONY: help lint test conformance compat sign-test check fmt msrv
