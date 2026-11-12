---
canonical: fredericrous/homelab docs/plans/2026-11-11-attest-signer.md
phases: [2]
status: done
branch: feat/platform-bound-principals
repos: [attest]
---
# In-cluster attestation signer: platform-bound principals (pointer)

This repository's slice of the homelab plan: Phase 2. The plan, its review
panel (body-sha 26070db06523) and its Decision log are canonical in the
private homelab repository (homelab#1169, Phase 1 recorded in homelab#1172).

## Phase 2

A principal is **platform-bound** when the text after its last `@` is
`<arch>-<os>` from closed sets (arch: `x86_64`, `aarch64`; os: `linux`,
`macos`, `windows`). Inside `sign::verify`, after the signature verifies, a
platform-bound signer's block must carry that same `platform`, or `verify`
returns a new error whose text reads
`<principal> may sign only <bound-platform> blocks; this block is <platform>`.
Every caller gets the rule: the scan in `verify.rs` and library callers such
as greengate's collect. Unbound principals (`zougi.fr@gmail.com`,
`ci@relais`, `dev@my-corp.io`) are unchanged. `SPEC.md`'s Trust section
documents it.

Tests: a matching platform passes; a mismatch is refused, also with
`require_platform` None and with the gate in `anywhere`; a dashed email
domain stays unbound; the existing principals are unchanged.

Released with `tag-release`.

## Code review

- attest: backend, lang:rust (unix and tui left out: no CLI or output change)

## Verification (row 3)

| Check | Expected | Actual |
| --- | --- | --- |
| A bound signer, matching platform | covered | `a_bound_principal_covers_its_own_platform` ok; conformance "bound signer, matching platform: covered" ok (verify.sh and git-attest) |
| A bound signer, mismatched platform | nothing | `a_bound_principal_covers_nothing_on_another_platform` ok; conformance "mismatched platform: nothing" ok (both) |
| The same, `require_platform` None or `--platform any` | nothing | conformance "mismatched platform, --platform any: nothing" ok (both) |
| The same, gate in `anywhere` | nothing | `the_anywhere_list_does_not_admit_a_refused_block` ok; conformance "--anywhere: nothing" ok (both) |
| One key under an unbound and a bound principal | nothing | `every_principal_of_the_key_is_checked` ok; conformance "a key also listed as a bound principal" ok (both) |
| An explicit bound principal | refused off-platform, covered on it | `an_explicit_bound_principal_is_checked` ok |
| No platform line, via `sign::verify` | `PlatformBound { platform: None }` | `sign_verify_refuses_a_bound_signer_payload_with_no_platform` ok |
| Unbound principals (`zougi.fr@gmail.com`, `ci@relais`, `dev@my-corp.io`, `x@x86_64-linux-gnu`) | unchanged | `bound_platform_reads_only_a_closed_arch_and_os_after_the_last_at` ok; `an_unbound_principal_is_unchanged` ok |

`make check` rc=0 on 403e46c: lint, cargo 34+8+9, conformance 230/0 and 153/0.

## Decision log

- 2026-11-12 · Fix found on the way: the Makefile built test paths from `$(PWD)`, the inherited environment variable, so a `make` started with a stale `PWD` (relais) looked outside the repository. It now uses `$(CURDIR)` (3db6b16).
- 2026-11-12 · Fix found on the way: shellcheck 0.11 reports the canon-vector runner's `git()` shadow as SC2329. It is now a stub script on PATH, which also drops the SC2317 suppression (1c18617).
- 2026-11-12 · The rule is enforced in `verify.sh` too: it is the action's fallback verifier, and `make conformance` keeps the two in agreement (backend review).
- 2026-11-12 · deliberate: there is no verify.sh conformance case for a bound signer's block with no platform. verify.sh refuses such a block as malformed (line 851) before the bound check; the library path is covered by a direct `sign::verify` test.
- 2026-11-12 · Files differ from the canonical Phase 2 line: `src/verify.rs` is unchanged (its scan calls `sign::verify`, so it gets the rule); the tests are `tests/platform_principal.rs` and `tests/conformance.sh`, not `tests/verify.rs`.

## Implementation review

- implementation-review: round 1 approve-with-changes, delta approve-with-changes, then approve. Fixed: discard reasons, `f` renamed to `fixture`, direct `sign::verify` no-platform test. deliberate: no verify.sh no-platform case.
- code-review backend: round 1 approve-with-changes (verify.sh rule, every principal, rollout order, tests), delta approve-with-changes (locals, direct test, multi-principal conformance), then approve.
- code-review lang:rust: round 1 approve-with-changes (Option platform, field order, no-platform test), delta approve.
