# `amont-attest-v2`

A signed statement that a named set of checks passed against a specific git
**tree**, on a specific platform. It exists so CI can skip work a developer's
machine already did, without CI having to trust that machine.

This document is the contract. Two implementations in this repository —
`verify.sh` and `git-attest` — target it, and `tests/conformance.sh` is what
proves they agree. A third implementation should pass that suite.

## Why the name still says `amont`

The format was born inside [amont](https://github.com/fredericrous/amont),
which is still the only producer. The identifiers are **frozen**, not
aspirational: renaming them would orphan every note already signed, every
`allowed_signers` entry already pinned to the namespace, and every workflow
already deployed — to make a string prettier. Read `amont-` as a version
prefix that happens to be a word.

## The note

One note per attested object, in `refs/notes/amont-attest`. A note holds one
or more **blocks**, each a payload and its signature:

```
amont-attest-v2
tree 4b825dc642cb6eb9a060e54bf8d69288fbee4904
gates pre-push-cargo-test pre-push-clippy
platform aarch64-macos
amont 1.23.0

-----BEGIN SSH SIGNATURE-----
U1NIU0lHAAAAAQAAADMAAAALc3NoLWVkMjU1MTkAAAAg…
-----END SSH SIGNATURE-----
```

**Payload** — everything before the first blank line, **including its trailing
newline**. Those are the exact bytes the signature covers; a verifier that
drops the newline reconstructs bytes no signature will ever match. This is the
single most common way to get an implementation wrong.

| line | meaning |
|---|---|
| `amont-attest-v2` | format token, always first. An unrecognised value means **absent** — see below. |
| `tree <oid>` | the git tree the checks ran against |
| `gates <names…>` | space-separated names of checks that **passed**. Never empty in a valid note. |
| `platform <arch>-<os>` | where they ran, e.g. `x86_64-linux`, `aarch64-macos`, `x86_64-windows` |
| `amont <version>` | the producer version, informational |

`tree`, `gates` and `platform` are **required**. A v2 payload missing any of
them is not a valid note and covers nothing — `platform` included, even for a
verifier told to accept any platform: a note that does not say where it ran is
not evidence about anywhere.

Fields are read **by prefix, never by position**. The payload has already grown
a line once (v1 → v2 added `platform`), and a positional reader mis-assigns
every field after an insertion rather than failing. Where a field appears more
than once, the **first** occurrence wins and the rest are ignored.

**Signature** — an armored `ssh-keygen -Y sign` block, namespace
`amont-attest`, separated from the payload by a blank line.

### Several blocks in one note

A laptop attests a tree on `aarch64-macos`; the CI job that tests the same
tree attests it on `x86_64-linux`. One note per object, so both statements
live in the same note, as blocks separated by one or more blank lines:

```
amont-attest-v2
tree 4b825dc6…
gates pre-push-cargo-test
platform aarch64-macos
amont 1.34.0

-----BEGIN SSH SIGNATURE-----
…
-----END SSH SIGNATURE-----

amont-attest-v2
tree 4b825dc6…
gates pre-push-cargo-test ci-fmt
platform x86_64-linux
amont attest-sign

-----BEGIN SSH SIGNATURE-----
…
-----END SSH SIGNATURE-----
```

That is exactly the shape `git notes append -m <block>` produces, and its
stripspace pass (trailing whitespace stripped, runs of blank lines collapsed)
leaves it unchanged — the grammar is that command's fixed point, so a
producer needs no flags. The parse, which both implementations perform with
the same state machine:

1. Skip blank lines. A payload starts at the first non-blank line and runs to
   the next blank line; its trailing newline is part of the signed bytes.
2. Skip blank lines. The next line must be exactly
   `-----BEGIN SSH SIGNATURE-----`. If it is not, **parsing stops**; blocks
   already collected still count.
3. The signature runs to and including `-----END SSH SIGNATURE-----`. End of
   input closes an open signature. A block that never ends swallows whatever
   follows, and then fails to verify.
4. At most **32 blocks** are read; any beyond are ignored, and the verifier
   says so. Every block costs two `ssh-keygen` runs, and the notes ref is
   writable by anyone with push access.

Lines are split on LF only; a carriage return is content. A CRLF note has no
blank line, yields no block, and covers nothing.

Each block is judged **on its own** by every rule under "Verifying". The
isolation guarantee, precisely: a correctly framed block whose payload or
signature fails any check does not affect the other blocks; a framing error
(a missing BEGIN, a missing END) ends parsing where it occurs. The verifier
reports the **union** of the gates of the blocks that pass, in first-appearance
order, without duplicates. A note reached through more than one candidate
object (a producer that wrote it to the tree and the commit) is judged once.

**Compatibility.** The 1.1.0 verifiers read one block: the payload before the
first blank line and the signature from the first BEGIN marker to the end of
the note, of which OpenSSH parses up to the first END marker. On a multi-block
note they therefore report block 1's gates, or nothing. They can under-report,
which is safe; they can never report a gate that only a later block names.
`tests/compat.sh` proves this against the frozen 1.1.0 implementations.

## Which object carries the note

**The tree.** The signature covers a tree because tests read content, not
commit messages — so a reword, an amend, a rebase or a forge's squash-merge all
preserve the attestation, and each of those would break a commit-keyed one.

Verifiers should also look at `HEAD` and then `HEAD^2`, in that order after the
tree, for notes written by producers that keyed by commit only. `HEAD^2` is
there because a pull-request checkout is a merge commit the forge made a moment
ago, whose second parent is the pushed tip.

A note found that way is still judged by its `tree` line, and on a
pull-request checkout the tree of that merge commit equals the pushed tip's
tree only when the branch is up to date with its base. Otherwise the
attestation does not apply — correctly, since the merged result was never
tested — and the verifier says so. A `push` trigger sees the pushed tip
itself and has no such gap.

## Verifying

A verifier reports gates as covered when **all** of these hold. Anything else,
including any error, reports nothing covered:

1. the payload's first line is exactly `amont-attest-v2`;
2. `tree` equals the tree actually checked out (`git rev-parse 'HEAD^{tree}'`);
3. `gates` is non-empty;
4. `platform` matches what the caller asked for (see below);
5. `ssh-keygen -Y verify -n amont-attest` succeeds against an `allowed_signers`
   file **committed in the consuming repository**, for a principal that file
   names.

```
you@example.com namespaces="amont-attest" ssh-ed25519 AAAAC3Nza…
```

### Platform

| the caller passes | an attestation is accepted from |
|---|---|
| nothing | this machine's `<arch>-<os>`, exactly |
| `<arch>-<os>` (contains a dash) | that string, exactly |
| `<os>` (no dash) | any `<arch>-<os>` whose part after the **last** dash is `<os>` — never a substring, so `inux` matches nothing and `x86_64` does not match `x86_64-linux` |
| `any` | anywhere |

A pass is a pass on something: a macOS `cargo test` is no evidence about the
Windows leg of a matrix. `any` is the caller's statement that the whole suite's
result cannot depend on where it ran.

**Gates accepted from anywhere.** Some checks cannot depend on where they ran:
formatting, shell lint, secret scanning, dependency audit. A verifier may take
a list of gate names the caller accepts from any platform (`--anywhere`, the
action's `anywhere` input); those names are admitted from a verified block on
any platform, and other names in the same block are still held to the table
above. The list is the caller's committed statement about those checks, made
once. It is applied strictly **after** signature verification: an unverified
block contributes nothing, listed or not. Never list a check that compiles or
executes the product — tests, clippy, a typecheck under `cfg`, a build —
whatever its name says.

### Principal

`-Y verify` demands a principal, and the right one is read from the signature
rather than guessed: `ssh-keygen -Y find-principals -s <sig> -f
<allowed_signers>` names the principal whose key made the signature, if that
key is in the file, and that is the identity to verify as. A verifier may let
its caller narrow this to one identity; it must not default to a guess such as
the file's first entry, which silently uncovers every other signer.

Two things pin the namespace. The `-n amont-attest` on `verify` rejects a
signature whose embedded namespace is anything else, which is what stops a
signature minted for another purpose — a signed commit, say — being replayed
here. The `namespaces="amont-attest"` option in the file works the other way:
it stops this key being trusted for anything else, should the same file ever
be reused as `gpg.ssh.allowedSignersFile`.

That file is read from the tree being verified, so **a change to it is a
change to who may skip CI**. Anyone who can push a branch and the notes ref
can add a key there and attest the same tree with it. That is the trust level
of editing a workflow file, no more — but repositories that guard
`.github/workflows/` with CODEOWNERS or required review should guard
`allowed_signers` the same way.

### Fail-open is the contract

Every failure — no note, no signers file, no `ssh-keygen`, a tree that moved, a
signature that does not verify, an unknown format version — means **not
covered**, which means the caller runs its tests. A verifier must **exit 0**
regardless.

This is deliberate and it is the whole safety argument: nothing in this format
can cause an untested tree to skip CI. It can only cost a redundant run. A
verifier that could fail a build would have turned a CI accelerator into a CI
dependency.

The cost of that choice is **silence** — when a skip does not happen, nothing
says why. Implementations must therefore report their reasoning on stderr
(`verify.sh` does so by default; `git-attest explain` prints the trail).

### Two things a verifier must not do

- **Do not match gate names as substrings.** `pre-push-cargo-test-slow` is not
  `pre-push-cargo-test`. Emit gates as a list and compare elements; on GitHub
  and Forgejo that means `contains(fromJSON(outputs.gates), 'name')`, never
  `contains(outputs.covered, 'name')`.
- **Do not resolve `allowed_signers` relative to the working directory.**
  Resolve it from the repository root, or a job that sets `working-directory`
  finds no signers, covers nothing, and fails open forever with CI still green.

## Producing

amont's pre-push hook is the reference producer for a laptop; `sign/sign.sh`
in this repository (the `fredericrous/attest/sign` action) is the reference
producer for CI. What a producer owes this format:

- Sign only checks that actually **passed** — not warned, not skipped, not
  unavailable. A CI producer signs only gates whose steps ran and passed in
  that job: never under `if: always()`, and never a gate that was skipped
  because it was already attested — that would launder another platform's
  result into this one.
- Run them against **the tree being signed**. A pre-push hook runs in a
  working directory that may carry uncommitted or untracked changes, and a
  suite that passed on that is no evidence about `HEAD^{tree}`. Refuse to
  sign while the working tree has modified or non-ignored untracked files, or
  check out a clean export of the tree. The `tree` line is the tree of the
  object the note is attached to — `HEAD^{tree}` by default — and a producer
  must not sign any other. On a `pull_request` checkout that tree is the
  forge's merge tree.
- Name the platform honestly, and key the note to the tree.
- **Append, never replace.** Write the block with `git notes append`; `git
  notes add -f` erases every other producer's block on that tree. Keep the
  `amont <version>` line stable across runs — no run id, no timestamp — so a
  re-run recognises its own block as already present instead of appending it
  again. Use an ed25519 key: its signatures are deterministic, which is what
  makes that recognition exact.
- Keep the **gate name** an honest contract. It is the only thing tying the
  hook's command to the CI step that trusts it: a gate called
  `pre-push-cargo-test` that ran `cargo test --lib` covers a CI step running
  `cargo test --workspace` in name only. Same name, same command.
