---
status: draft
repos: [attest, amont-agent, amont]
adrs: [ADR-0034, ADR-0036]
---
# Plan: one canonical tree across the fleet

## Review panel

(pending)

## Context

The SOLID audit of aval, amont, amont-agent, attest and relais found one boundary problem that is a correctness bug, not a smell: two different values are both called "canonical tree".

- **canon(T)**: attest SPEC "Canonical tree" (`SPEC.md:336-357`). The `ls-tree -r --full-tree` listing with `core.quotePath=true`, where every regular file under the top-level `docs/plans/` has its oid zeroed, hashed with `git hash-object --stdin`: 40 or 64 hex. Implemented in amont (`attest_inputs.rs:466-507`), in attest's Rust (`src/attest.rs:949-990`) and in `verify.sh` and `sign.sh`. A plan's content does not count; whether it exists does. It is a tree's identity, used to skip gates and for attestations.
- **The review/preview binding** (`amont-agent/src/implementation_review.rs:72-93`). The sha256 of the `ls-tree -z` entries with every `docs/plans/` entry dropped: always 64 hex. Adding a plan file does not change it, which is deliberate and pinned by `tests/tree_sha.rs:105-113`. It is what a reviewer or the person judged (ADR-0034), and it keys reviews and preview approvals (`preview.rs:857,871`).

These are two concepts under one name. The provenance note (ADR-0036; amont-agent #119 and amont #343 are merged but not yet released) writes the second value into the `canon` line, which the SPEC (`SPEC.md:610,613`) defines as the first. Every signed provenance record would therefore carry a `canon` that matches no tree and no attestation. If this ships, wrong signed notes would sit on remotes for good.

The fix keeps both concepts and gives each one owner and one name.

- **canon(T)** stays attest's SPEC concept. It is computed only by the implementations that already have it, and the signer, amont, is the one that writes it into the provenance note.
- **content id** is the new name for amont-agent's binding value. Its definition is unchanged. The SPEC defines it for the `review` line, so a reader can recompute it.
- amont-agent stops writing a derived tree fact it does not own. It records only what it witnesses: plan, review, preview.

Considered and not chosen: switching the review key to canon(T). It would have:

- amended ADR-0034;
- made reviews and preview approvals stale whenever a plan file is added, costing a 2–3 min re-review of 50–100k tokens each time;
- churned the store and the block format between 40 and 64 hex.

Out of scope, as next steps after this plan:

- a boundaries ADR in `decisions`;
- splitting relais's large modules.

relais's `tree_fingerprint` is a cache key for reusing relais's own worktrees, and stays.

## Changes

### 1. attest: SPEC terms and shared vectors (patch release)

- `amont-provenance-v1`:
  - The payload amont-agent hands over has **no** `canon` line.
  - The signer computes `canon <canon(T)>` of the pushed tree and inserts it right after `tree`, before signing. `planExempt` does not apply, because it governs skipping a gate, not a tree's identity.
  - A handed-over payload that already carries a `canon` line is refused.
  - `review <how> <content-id>`: define **content id** in a new subsection. It is the lowercase sha256 of the raw `git ls-tree -r -z --full-tree` records in git's order, leaving out every record whose raw path starts with `docs/plans/`, each kept record followed by one NUL (the last included), with no decoding; no records left hashes the empty string. Always 64 hex. amont-agent gains known-answer tests (zero, one, several records, a path with a newline), and the SPEC quotes them. It is the value ADR-0034 binds a review and an approval to. Say that it differs from canon(T) on purpose: it ignores whether a plan exists.
- Add `tests/vectors/canon.txt`: raw quotePath `ls-tree` listings, each with its expected canonical text, in a strict line format. The cases are those already duplicated inline in `src/attest.rs:1804-1870` and amont `attest_inputs.rs:596-640`:
  - plan content zeroed;
  - a symlink and a gitlink under `docs/plans/` kept;
  - a nested `x/docs/plans/` kept;
  - a `docs/plans-…` path kept;
  - a quoted `"docs/plans/…` path;
  - sha256-length oids;
  - an empty or malformed listing gives no canon.
- The Rust tests read that file. `tests/conformance.sh` runs it through `verify.sh` and `sign.sh`. Altering one expected line must fail both.
- Add the `amont-provenance` namespace to `allowed_signers`, which the ADR-0036 plan still owes.

### 2. amont-agent: name the content id; stop writing `canon` (minor release)

- Rename `canonical_tree` to `content_id` (`src/implementation_review.rs:72`) and the `review_canon` field and parameter to `review_content` (`src/provenance.rs:58,164`). Use LSP findReferences first: callers include `main.rs:1009` and `preview.rs:857,871`. The value, the store keys and the 64-hex block format do not change, so stored reviews and approvals keep matching.
- `provenance::payload` (`src/provenance.rs:64-67`) drops the `canon` line, and `Push.canon` and `Record.canon` go away. The payload test at `:237` is updated.
- Update `TREE_SHA_USAGE` (`src/main.rs:937-953`): "the content id an implementation review and a preview approval bind to (not attest's canonical tree)". The definition and the exit codes stay as they are.
- Update `docs/implementation-review.md` the same way, so it no longer calls this value the "canonical tree".
- No payload carrying a `canon` line exists to migrate: no released amont-agent contains #119 (2.42.0 is installed), and `~/.claude/amont-agent/provenance/` does not exist on this machine. So `provenance::write` gets no migration code. If a development build ever left one, the person deletes the file the signer names.
- CHANGELOG: the payload no longer carries `canon`; the signer writes it.

### 3. amont: the signer writes `canon` (minor release, with the unreleased provenance)

- In `provenance_push_from` (`crates/amont-runtime/src/attest.rs:494-518`), after the existing `tree` check:
  - refuse a payload that has a `canon` line;
  - otherwise compute `attest_inputs::canon(&tree)` and insert `canon <c>` after the `tree` line;
  - if `canon` returns `None`, sign nothing and keep the payload for the next push (fail closed).
- Do not call `canon_unless_off` (see §1). `canon` runs in the hook's cwd, which git sets to the worktree top, so the object format is the repository's. A test in a `--object-format=sha256` repository pins that.
- The refusal keeps the first line of today's message (`attest.rs:511-514`) and adds the reason and the fix: `carries a canon line (a pre-release amont-agent wrote it); delete <path> and upgrade amont-agent`. The payload is never signed or removed by amont. No output line is wider than 80 columns.
- Vendor `canon.txt` and point the inline tests at `attest_inputs.rs:596-640` to it. The fixture at `attest.rs:1358`, which writes `canon {tree}`, changes to write no `canon` line. New tests:
  - the canon is inserted and equals canon(T);
  - an old-format payload is refused;
  - a failed canon keeps the payload.

### Order

1. attest.
2. amont-agent and amont, in parallel. They share only the SPEC; only amont vendors the vectors file.
3. Release amont-agent, then amont.

Each PR follows `worktree-task`: plan commit, verification, implementation review, `merge-when-green`. Releases go through `tag-release`.

## Verification

- In attest and amont, every `canon.txt` case gives its expected text through `canon_text` (and `tests/conformance.sh` in attest). Altering one expected line makes the run fail.
- In a sha1 scratch repository and in a `--object-format=sha256` one, each holding a `docs/plans/` file, a nested `x/docs/plans/` path and a symlink: `verify.sh`'s canon and amont's `attest_inputs::canon` must print the same id. amont's comes from a named `#[test]` that prints it for a tree built the same way.
- `amont-agent tree-sha` prints the same value before and after this change on the same commit, so the content id is unchanged.
- End to end, in a scratch repository with `amont.attest` on:
  1. Push a branch carrying a plan and a recorded review.
  2. The note in `refs/notes/amont-provenance` verifies with `ssh-keygen -Y verify -n amont-provenance`.
  3. Its `canon` equals `verify.sh`'s canon(T) of the pushed tree, and its `review` id equals `amont-agent tree-sha` of the reviewed commit.
  4. Hand-add a `canon` line to a pending payload. The push still reaches the remote; provenance says "not signed", names the line and the file to delete, and no line is wider than 80 columns.
- After the releases, `amont-agent --version` and `amont --version` on this machine show the new versions. The next real fleet push publishes a provenance note whose `canon` equals the canon(T) of its tree.

<!-- panel: repos=attest,amont-agent,amont -->
