---
canonical: fredericrous/decisions:docs/plans/2026-11-12-greengate-signs-notes-under-green-names.md
phases: [1, 4, 5]
status: active
---
# greengate signs its notes under green names

Pointer plan. The canonical plan (see `canonical` above) moves every signed-notes name from `amont-*` to `greengate-*` (ADR-0068). Here: Phase 1 makes git-attest read both name sets (new ref first, then the old), with `format::LEGACY` and `format::GREEN` beside the unchanged constants, while writers still write the old names; Phase 4 swaps the constants and the writers to the green names; Phase 5 removes the old reads after the 30-day window.

## Code review
- attest: backend, lang:rust, unix, architect (lang:typescript left out: no TypeScript here; tui left out: verify output unchanged apart from names)

## Phases (this repository)

- [x] Phase 1 — git-attest reads both, writes old (commits 9e8ff62, 9f7224f). `fetch.sh` needed no change: it names no notes ref.
- [ ] Phase 4 — writers switch (`format::WRITE` becomes `GREEN`). Implemented on `feat/notes-writers-green` for 1.10.0: `sign/sign.sh` names its whole set at the top (header, refs, namespace, both domains, producer word), the shared canon block's `canon_key` takes `$CANON_DOMAIN`; ticked at the release.
- [ ] Phase 5 — census: the legacy reads go.

## Verification

Phase 1, input → expected → actual:

| check | input | expected | actual |
|---|---|---|---|
| old-name note verifies | `tests/names.rs` `an_amont_note_is_verified_and_named`; conformance `names: an amont-attest note covers` | covered, `verified under amont-attest` | pass (both implementations) |
| new-name note verifies | `a_greengate_note_is_verified_and_named`; `names: a greengate-attest note covers` | covered, `verified under greengate-attest` | pass |
| old header under the new namespace refused | `an_old_header_block_is_refused_under_the_new_namespace`; `names: an old header signed under the new namespace in the legacy ref is refused` | nothing covered | pass |
| new header under the old namespace refused | `a_new_header_block_is_refused_under_the_old_namespace`; `names: a green header signed under the old namespace is refused` | nothing covered | pass |
| missing old ref on origin | `a_missing_old_ref_on_origin_leaves_the_verdict_unchanged`; `names: origin has only the green ref (no amont ref): covered` | covered; `legacy_notes=absent`; no "running everything" | pass |
| missing new ref on origin | `a_missing_new_ref_on_origin_leaves_the_verdict_unchanged`; `names: origin has only the amont ref (no green ref): covered` | covered; `notes=absent` | pass |
| new ref wins | `the_greengate_ref_wins_when_both_exist`, `the_green_ref_wins_on_origin_too`; `names: both exist, the greengate ref wins` | green gates only | pass |
| constants still LEGACY | `the_constants_still_equal_the_legacy_names`, `every_written_name_derives_from_write` | `WRITE == LEGACY`; keys and producer word from `WRITE` | pass |
| unreadable green note | `an_unreadable_green_note_does_not_fall_back_to_legacy`; `names: an unreadable green note does not fall back to the legacy ref` | nothing covered, trail names it | pass |
| full suite | `make check` (lint, `cargo test`, conformance both implementations + legacy negative control, compat, sign-test, fetch-test) | 0 failed | conformance 260/260 (verify.sh), 252/252 (git-attest); sign-test 153/153/152/152; fetch-test 24/24; exit 0 |
| the tests fail without the change | the same `tests/conformance.sh` against `origin/main` (1.8.0) built from `git archive` | the green-name and output-key cases fail | verify.sh 245 passed, 15 failed; git-attest 237 passed, 15 failed (the 12 green-name cases and 3 `github-output` cases); `tests/names.rs` does not compile against 1.8.0 |

After the release (not pending here): the CI action on a scratch repository verifies a 1.8.0-signed note.

Phase 4, input → expected → actual:

| check | input | expected | actual |
|---|---|---|---|
| `git-attest sign` writes only green | `tests/names.rs` `git_attest_sign_writes_only_the_green_names`, `git_attest_sign_no_push_writes_the_green_local_refs` | origin has only `refs/notes/greengate-attest[-inputs]`; header `greengate-attest-v2`, `greengate attest-sign`; inputs note under the GREEN key; signers listing `greengate-attest` alone verify it, `verified under greengate-attest`; `--no-push` writes `attest-local/greengate-attest[-inputs]` | pass |
| `sync_mirrors` follows the written set | `sync_mirrors_touches_only_the_green_refs` | GREEN mirror deleted, LEGACY one kept | pass |
| constants and keys | `the_constants_are_the_green_names`, `each_set_keys_its_lookups_under_its_own_domain`, `key_preimage_is_exact`, `the_written_keys_are_the_green_known_answers` (keys from `git hash-object`, sha1 and sha256) | GREEN values | pass |
| `sign.sh` and `git-attest sign` write the same green set | `tests/sign.sh` read-backs (the first case asserts the refs, header and producer word), all four signer × verifier pairs | 0 failed | 157/157/156/156 |
| a 1.9-signed note still verifies | `tests/sign.sh`: `tests/compat/sign-1.9.0.sh` (v1.9.0's `sign/sign.sh`) signs, a fresh clone is covered; `an_amont_note_is_verified_and_named` | LEGACY refs on origin; covered | pass |
| full suite | `make check` | 0 failed | conformance 260/260, 252/252; compat all pass; sign-test as above; fetch-test 24/24; exit 0 |
| the tests fail without the change | the same tests on `origin/main` + this diff with `WRITE = LEGACY` and the old `sign/sign.sh` | the write-path tests fail | `cargo test`: 9 failed (4 lib, 5 `names.rs`); `tests/sign.sh` (sign.sh, verify.sh): 37 failures in the first part, run stopped there |
| the CI `action` job | its steps 2–6 replayed locally with the built binary (green signer) and `sign-1.9.0.sh` (the `release` leg's LEGACY signer) | every assertion holds | pass, both; not run on CI here |

## Decision log

- 2026-11-12 — the ref a note sits in picks the name set, and the header of each block must match it: stricter than "the header decides". A green header found under the old ref (or an old header under the new ref) is refused, never re-read under the other set.
- 2026-11-12 — a note the ref lists but git cannot read counts as found: the other set is not read for that object.
- 2026-11-12 — `verified under <ns>` is printed only for a block that covered at least one gate, in every mode.

## Implementation review

- Phase 1, round 1 then two deltas, all approve on tree f9129a4f: implementation-review (round 1 approve-with-changes: plan record, output parameter, flag argument, single-letter names; fixed in 9f7224f and 2d117a5) · backend (unreadable note fell through, verified-under before coverage, doubled remote cost; fixed) · lang:rust (`#[non_exhaustive] Verdict`, positional states, `Lookup`, argument order; fixed) · unix (`--explain`, timeout skip, `--quiet` doc; fixed) · architect (one `WRITE` owner of written names, high; fixed).
- Kept as deliberate (low): CHANGELOG does not repeat that `#[non_exhaustive]` breaks struct-literal construction (no dependent builds a `Verdict`); no existence guard after the conformance test deletes an object (the Rust twin `unwrap`s its delete); `matches!`, `pub(crate) origin_silent` and a loose-object test comment (cosmetic).
- Carried: greengate prints `Verdict::verified_under` (its Phase 2); "Phase 5 is git-attest 2.0.0" goes into the canonical plan before the 1.9.0 tag.

## Implementation review (Phase 4, writers switch)

- implementation-review: approve-with-changes ×2, then approve (084b9d90).
  - Fixed: the `repo_dir` / `sixty_four_hex_a` names.
  - The caret hazard is named in the CHANGELOG and SPEC: dependents pin `~1.9` until their writer switch.
  - Bare-constant readers are greengate's: about 40 uses are listed for its Phase 4 PR, which bumps its pin.
- backend: approve-with-changes ×2, then approve.
  - Kept as reviewed: a note is read whole under one name and the green note wins. A green note hides its object's legacy blocks, so `v1` moves to 1.10.0 with the laptop's Phase 4 install (stated in the CHANGELOG and SPEC).
  - CI requires green writes off the `release` leg, which picks its name set by its note.
- lang:rust: approve-with-changes, then approve. Fixed: a Drop guard, a slice pattern, the inputs mirror asserted, and a real canon-key check.
- unix: approve. The worst-case remote wait (about 90 s) is documented.
- architect: approve-with-changes, then approve. The decisions plan record will carry the rollback (yank 1.10.0, publish 1.10.1 with `WRITE = LEGACY`, beside the `v1` rollback) and the three name-writing files for Phase 5.
