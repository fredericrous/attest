---
status: active
branch: feat/canonical-tree
repos: [attest, amont, decisions]
adrs: [ADR-0033]
---
# Plan-only commits skip with no per-repository declaration

## Review panel

👉 **Decide:** (1) the default is on for every repository: a plans-only change skips already-signed gates unless a gate reads plan contents (audited once per repository, step 4; opt-out `set planExempt off`); (2) releasing attest 1.5.0 moves the floating `v1` for every consumer, so it happens only after both pilot proofs and on exactly the proven sha; (3) two records: a fleet ADR replacing ADR-0033's head and an amont ADR replacing ADR-0011.
📍 attest, amont and decisions · reviewed, nothing changed yet · next: the attest branch (SPEC, both verifiers, signer, tests), then amont 1.56.0. Panel: backend (six passes on this design) plus your external review, folded in.
**Changed by review:** the opt-out is one tree-based policy read identically by every producer and verifier, failing narrow; the proof isolates the canonical route (no exact-tree note, reason and key asserted); `read_spec` distinguishes absent from invalid; symlinks and gitlinks are never neutralised; the audit precedes the amont install.
**Verdicts:** backend approve-with-changes on every pass, the last with one low item carried; the four external findings are resolved and none regresses the original target; 0 rework.
📄 Full reviews: [2026-10-15-plan-only-commits-skip-no-declaration.reviews.md](2026-10-15-plan-only-commits-skip-no-declaration.reviews.md).

## Context

amont 1.55.0 reuses a gate's result when a branch's closing commit (docs/plans only)
changes nothing the gate declared as input. It needs a `.forgejo/attest-inputs` file,
a completeness check and a trusted `amont.conf` line in every repository: sixteen
Forgejo repositories, a trust prompt each, and a check that only the laptop runs. The
person asked whether it can work without the extra declaration.

It can. What the declaration says, in every repository, is "everything tracked except
docs/plans", and that can be the default, computed from the tree itself, with no file
to write and nothing to keep complete.

## Design: the canonical tree

`canon(T)` is a fingerprint of the tree `T` in which the **content** of everything
under `docs/plans/` is not counted but its **existence** is: take
`git ls-tree -r -z --full-tree T`; in every record whose path starts with the
top-level `docs/plans/`, if its mode is `100644` or `100755`, replace `<oid>` with zeros of the same length (40 or 64), keeping mode and type; symlink (`120000`) and gitlink (`160000`) records stay byte for byte; paths compare as raw bytes;
keep all other records byte for byte, in listing order; hash the result with
`git hash-object --stdin`.

- Editing a plan (the closing commit) leaves `canon` unchanged. Adding, deleting or
  renaming a plan file, or changing any other path, changes it. So aval's citation
  checks (`links-resolve` on a cited `docs/plans/…` path) cannot be hidden by a reused
  result.
- Nothing is declared, so nothing can be under-declared: a new top-level file, a new
  `docs/` page or an edit to `amont.conf` changes `canon` by construction. The
  completeness check, the generator, the `amont.conf` guard and `amont trust` all
  fall away.
- It is the same exemption the declared mode already uses (`docs/plans/` only, root
  only: a nested `x/docs/plans/` is not exempt), made automatic.

## What changes

**attest 1.5.0** (additive; the format token stays `amont-attest-v2`):
- SPEC: a "Canonical tree" subsection: the `canon <oid>` payload line, the definition
  above, the key `Kc(canon) = hash-object("amont-attest-canon <oid>\n")` in the
  existing `refs/notes/amont-attest-inputs` (no third ref to mirror), the lookup step
  after the tree and input routes with its place in the 64-verification budget, and
  the compatibility statement: older verifiers read fields by prefix and ignore
  `canon`, so they only lose a skip.
- `verify.sh` and the Rust `git-attest` (`src/attest.rs`): compute `canon(HEAD^{tree})`,
  look up `Kc`, and make the per-gate rule "tree equal, or input fingerprint equal, or
  canon equal" (`kept_gates`, `covered_gates`), evaluated against the checked-out tree
  so a block filed under several keys is judged the same wherever it is first met.
  Signature, principal, platform and `anywhere` rules apply unchanged, after the
  signature verifies. A gate covered this way is reported with the reason `(by canonical tree)` and the `Kc` key used, as the input route reports `(by input fingerprint)`. `verify.sh` and `sign.sh` first run a known-answer self-test (a fixed NUL listing with newline and non-UTF-8 names under docs/plans, sha1 and sha256); an `awk` that fails it (BWK awk reads a NUL RS as paragraph mode) means canon unavailable: no `canon` line, nothing covered, and one stderr line `canon unavailable: awk self-test failed (<awk version>)`; step 3 records each pilot runner's awk. Shared vectors run against both verifiers and amont.
- `sign/sign.sh`: emit the `canon` line at a fixed position (re-runs stay
  byte-identical) and publish the block under `Kc` as well.
- Tests: conformance cases (equal canon after a plan edit; changed by any other path;
  changed by a plan add, delete or rename; nested `x/docs/plans/` not exempt; gitlink
  records; platform, `anywhere`, budget order, the dedup case), `sign.sh` cases, a
  frozen 1.4.1 verifier in the compat set, both implementations agreeing. CHANGELOG
  and a 1.5.0 release (the release workflow's alias job moves the floating `v1`).

**amont 1.56.0**:
- `attest_inputs.rs`: `canonical_fingerprint(tree)` (the definition, in Rust, through
  `git hash-object`; no hash code) and the `Kc` key function.
- `attest.rs`: `attest_push` adds the `canon <fp>` line and files the same signed block
  under `Kc`, whether or not the repository has a declaration (a declaration, when
  present, still adds its `input` lines and keeps precedence for its own gates).
- `gate_stamp.rs` and `attest_push`: use `read_spec`, not `spec_at` (which returns `None` for absent, invalid and ambiguous alike). Missing only when `git ls-tree --full-tree <tree> -- <both spec paths>` succeeds and lists neither (presence is read from that listing, not from today's `cat-file -e` probe at attest_inputs.rs:136, which cannot tell absent from unreadable); `ls-tree` failing is Unlisted; a listed spec whose blob cannot be read stays Invalid (attest_inputs.rs:143): the route is canonical for every gate (`file_inputs` and `input_tokens` key the full token under a canon-specific gate key) and `attest_push` adds the `canon` line. Ok: today's declared route, plus the `canon` line. Invalid, Ambiguous or Unlisted: today's fail-open, no `canon` line and no canonical stamps. The manifest rule is skipped on the canon route (`amont.conf` is part of the canonical tree).
- One opt-out for a repository whose gate reads the contents of a plan: `set planExempt
  off` (boolean, default on; `SETTABLE` in `manifest.rs`, documented in
  `docs/configuration.md`). Off means no `canon` line, no `Kc` block and no canonical
  stamps. `off` only narrows, so it is honoured trusted or not: every producer and verifier reads ONE tree-based policy, `plan_exempt_off(T)`, from the bytes of `T:amont.conf` itself (not through the trust-gated settings). If `amont.conf` is listed in T but its blob cannot be read, the policy is off (fail narrow); an absent file means on. Normalisation, identical in amont (Rust) and attest (shell and Rust): strip CR, trim ASCII blanks, compare the words `set`, `planExempt` and `off` case-insensitively, words separated by blanks; a line that is not exactly those three words (a trailing comment, another value) does not match. `off` dominates: any matching line anywhere means off, and amont reports a second `planExempt` line (any value) as a broken line, so no conflicting pair can exist. When off, canon equality is ignored in EVERY block, whichever candidate found it (tree, HEAD, HEAD^2 or Kc); `sign.sh` and amont emit no `canon` line and no `Kc` block; amont keeps no canonical stamps. Shared table-driven vectors (CRLF, tabs, case, comments, duplicates, off then on, on then off, `amont.conf` listed but unreadable: off, absent: on) run in both implementations, and a test reaches a canon claim through each candidate route with the repository opted out.
- `check-inputs` stays for repositories that prefer a narrower declaration.
- Tests: stamps reused across a plans-only commit with no spec; changed by a plan add,
  delete or rename; one test per `read_spec` state (absent with a working `ls-tree`: canonical; valid: declared; invalid, ambiguous, listed but unreadable blob, `ls-tree` failing: whole tree with no canon); the opt-out vectors above; precedence of a valid spec; the two existing tests that assert "no spec means whole tree" are rewritten.

**Records**: a fleet ADR that replaces ADR-0033's head for `ci.attested-skip` ("…or a
tree whose canonical form is identical") and amends the rules (the completeness rule
stays for declared specs; a new constraint: no gate may read the contents of
`docs/plans/`, and `set planExempt off` is the sanction), and an amont ADR that
replaces ADR-0011. amont `docs/ci.md` and `docs/configuration.md` updated.

## Rollout

Nothing per repository. The sixteen Forgejo repositories (and any future one) gain the
skip when the laptop runs amont 1.56 and their CI's `attest@v1` is 1.5.0. Before that,
once: in each of the sixteen, check that no gate reads the contents of a plan
(`git grep -nw 'docs/plans'` outside markdown, reading each hit: a comment is not a
read; and `\bdocs\b`/`\bplans\b` in configs, scripts, tests, Makefiles and Go or Python
tests that walk `docs/`, with a planted control line). A repository with a real read
gets a `docs/plans` ignore in that gate's config or `set planExempt off` in a pull request (step 4); a whole-tree formatter or linter counts as a read. Untracked inputs a gate
reads (application-landscape's `.env`, gtm-agent's `uv.lock`) are as unfingerprinted
as under the exact-tree skip today, and are reported, not held.

## Steps

1. attest on a branch: SPEC, `verify.sh`, `src/attest.rs`, `sign.sh`, tests, CHANGELOG.
   Do not tag yet.
2. Run step 4 and merge its config-ignore pull requests first: once installed, amont 1.56's local canon route is live everywhere. A `set planExempt off` line cannot land before the install (amont 1.55 rejects an unknown `set` key as `UnsettableKey`, manifest.rs:1237-1250): merge those right after `brew upgrade`, before any other push to that repository and before step 5; CI (`v1` still 1.4.1) runs every gate until step 5. Then amont: the canon code, the opt-out, tests, docs, release 1.56.0, `brew upgrade`,
   replace the shadowing `~/.local/bin/amont` as before.
3. Proof, pilot social-planner (JavaScript) then sre-agent (Python); neither has a declaration, so only the canonical route can cover a plans-only change. A disposable pull request whose workflow pins `https://github.com/fredericrous/attest@<sha of step 1>` (the floating `v1` is untouched). (a) Baseline: a scope-touching edit landed with `amont.attest` on; the pre-push output prints the canon block published and `git ls-remote origin refs/notes/amont-attest-inputs` lists the ref; CI in full. (b) A plans-only edit, landed with `amont.attest` set to false in the checkout (local checks still run, nothing new is published): assert `git notes --ref amont-attest` holds no note for the new tree or commit; CI must then report the gate covered, the verify step must name the canonical route and the `Kc` key it used, and the gated steps are skipped (step conclusions). (c) Negative commits, also with attestation off: a new plan file, and a non-plans file edit: no route can cover them and the gates run. (d) The local route is proved separately, with no CI involved: after (a), a plans-only commit's pre-commit and pre-push reuse the canon stamps (record the output), and with `planExempt off` committed on a scratch branch the gates run. Wait for an idle runner pool and a terminal previous run before each push; record durations, the covered line and the runner's `awk --version`. Close the pull requests unmerged and restore `amont.attest`. If either proof does not skip, stop.
4. In each of the sixteen, table every gate (amont.conf lines, enabled built-ins, CI steps) with its file set. A gate over the whole tree or a glob matching `docs/plans/*.md` (`prettier --check .`, the built-in prettier, markdownlint, typos, codespell, link checkers) is a reader: ignore `docs/plans` in its config or `set planExempt off`. The grep above supplements this table.
5. Tag attest 1.5.0 on exactly the sha proven in step 3 (if it moved, re-run step 3; the alias job moves `v1` fleet-wide at once), verify the published release and the
   moved alias, then watch the next plans-only push in one repository.
6. Records: the fleet ADR and rule change, the amont ADR, pack refreshes as the
   repositories next sync; update memory.

## Soundness

- A gate is skipped on a plans-only change only if it does not read the content of a
  plan. Verified once per repository (step 4) and enforced by the rule and the opt-out
  rather than by a per-repository list that could go stale.
- Existence, not content, of plan files is part of the fingerprint, so a gate that
  checks that a cited plan exists is still re-run when one is added, deleted or renamed.
- Fail safe on both sides: an old verifier ignores `canon`; a `verify.sh` without a
  NUL-capable `awk` covers nothing; an unsigned, wrong-principal or wrong-platform
  block never covers (the existing order: signature first, then claims).
- Anyone with push access can write the notes ref, so a `Kc` note can be flooded with
  junk blocks; the 32-block and 64-verification budgets already bound the cost and a
  flood can only lose a skip. Deleting the inputs ref revokes Kc-keyed skips only: a laptop push that reused canon stamps re-signs those gates under the new tree and commit keys (amont attest.rs:360-361), so full revocation also needs those notes or the key revoked.
- A repository whose test result depends on untracked or external inputs (a `.env`, an
  unpinned registry package) is as exposed as under the exact-tree skip it replaces.

## Non-goals

- No change to the sixteen repositories except a `docs/plans` ignore or a `planExempt off`
  where step 4 finds a reader. No CI workflow edits. No change to `amont attest covered` (frozen).
- Plan directories other than `docs/plans/` are not exempt.

## Verification

- Unit and conformance tests in attest (both implementations agree) and amont, run
  locally and in CI; `make check` in amont.
- Step 3 on both pilots, with durations and the covered line; the negative commits
  re-run the gates.
- After step 5, the next real plans-only push in one repository skips; record it.
- Canon cost: in the largest fleet repository (state its file count), time canon in verify.sh and in pre-commit; expected under 100 ms; record the actual.
- Rollback: `set planExempt off` per repository; or ignore `canon` (old verifiers do);
  or revert the attest release (the alias job moves `v1` back with a new tag).

## Implementation review

approve after a Delta and a one-comment confirmation. Round 1 (83k tokens, 112 s): 3 medium, 2 low, all fixed: the opt-out is now tested through the tree key and HEAD^2; `plan_exempt_off` has three states so the log says "cannot read amont.conf"; a failed canonical fingerprint is said, not swallowed; the canonical key is named only when it covered a gate. Delta (77k, 44 s) and confirmation (95k, 74 s): resolved.

## Outcome

Phase 1 (this repository, no tag): the canonical-tree route in `verify.sh`, `git-attest` and `sign/sign.sh`; SPEC "Canonical tree"; conformance 185/186, sign 148, compat including a frozen 1.4.1 verifier. Next: amont 1.56.0 (pointer plan in that repository), the audit, the pilot proofs, then the tag on the proven sha.

## Decision log

- 2026-10-15 — **Quoted listing, not NUL records.** The canonical fingerprint hashes `git -c core.quotePath=true ls-tree -r --full-tree` with the oid of regular files under the top-level `docs/plans/` zeroed, not the `-z` listing the plan names. BSD awk reads a NUL record separator as paragraph mode and mawk's behaviour differs; the quoted form is injective (one record per line), needs no NUL-capable awk, and the shell signer, the Rust verifier and the test oracle all compute it. The awk known-answer self-test and its `canon unavailable` stderr line fall away with it. A quoted plan path is recognised by its unescaped prefix `"docs/plans/`.
- 2026-10-15 — **A tree-ref deletion no longer revokes a plans-only skip.** The canonical block lives in the inputs ref, so SPEC "Revoking" says to delete both refs. The mirror fixtures in `tests/sign.sh` use a repository opted out of the canonical route to keep testing the tree ref alone.
- 2026-10-15 — **Audit scope.** Step 4 covers every consumer of `attest@v1` (the GitHub repositories too: amont, attest, and any other pinned to the floating alias), not only the sixteen Forgejo repositories, because tagging 1.5.0 moves `v1` for all of them.
- 2026-10-15 — **CI's shellcheck is newer than the local one.** It flagged SC2015 (`A && B || C`) in the canon fallback of `sign/sign.sh`; rewritten without it (93f75d4), reviewed again (approve).


<!-- panel: repos=attest,amont,decisions reviewers=backend body-sha=1156cc02d5b7 -->
