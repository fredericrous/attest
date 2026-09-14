# attest

**Your laptop already ran the tests. Stop paying CI to run them again.**

When a pre-push hook runs your test suite, that result is thrown away the
moment the push succeeds — and CI runs the same suite again, on the same
content, for minutes you pay for. `attest` lets the hook **sign** what it
proved, and lets CI **verify** that signature and skip the work.

```yaml
- uses: actions/checkout@v4
- id: attest
  uses: fredericrous/attest@v1

- run: cargo test --workspace
  if: ${{ !contains(fromJSON(steps.attest.outputs.gates), 'pre-push-cargo-test') }}
```

That is the whole integration. Nothing is skipped unless a signature by a key
**you committed to the repository** covers the **exact tree** CI checked out,
on the **same platform** the job is running.

## Safety, stated plainly

**Nothing here can make an untested tree skip CI. It can only cost a redundant
run.** Every failure path — no note, no key, no `ssh-keygen`, a rebase, a
tampered payload, a signature from a stranger — reports "nothing covered", and
nothing covered means your tests run. The verifier always exits 0; it can never
fail your build.

The price of that is silence, so the action explains itself in the job log:

```
attest: attested on aarch64-macos, this leg is x86_64-linux
attest: no attestation found for tree 9f2a1c…
attest: covered by you@example.com: pre-push-cargo-test pre-push-clippy
```

## Setup

Three steps, once.

**1. Make a signing key** and tell your hook runner to use it:

```sh
ssh-keygen -t ed25519 -N '' -C "$(git config user.email)" -f ~/.ssh/amont-attest
git config --global amont.attest true
```

**2. Commit the public half** as `.github/allowed_signers` (or
`.forgejo/allowed_signers`), pinned to the namespace:

```
you@example.com namespaces="amont-attest" ssh-ed25519 AAAAC3Nza…
```

> Use **your real address**, the one in the note's principal column. The
> verifier reads the signer's identity from the signature itself, so a file
> naming a whole team just works and there is nothing to keep in sync.

This file decides who may skip CI, and it is read from the tree being
verified: a pull request that adds a key to it can attest itself. That is the
same trust as editing a workflow file, so give it the same protection — if
`.github/workflows/` is under CODEOWNERS or required review, put
`allowed_signers` there too.

**3. Add the step**, as shown at the top. The action is pinned by a moving
`v1` tag above; for a step that decides whether tests run, prefer pinning the
commit — each release's notes name it:

```yaml
- uses: fredericrous/attest@<sha>  # v1.x.y
```

## What gets skipped, and when

The gate name is the whole contract between your hook and your CI step. A hook
gate called `pre-push-cargo-test` that runs `cargo test --lib` does not cover
a CI step running `cargo test --workspace`, whatever the name says — make them
the same command.

The signature covers the **tree**, so an attestation survives a reword, an
amend, a rebase and a squash-merge. On a `pull_request` trigger, though, CI
checks out a merge commit the forge just made, and its tree equals your pushed
tip's tree only when the branch is up to date with its base. Otherwise the job
log reads `attested tree … is not the checked-out tree …` and the tests run —
correctly, because that merged result was never tested. Rebase to get the skip
back, or verify on `push`.

The attestation is only as honest as the machine that made it. The signing key
is a file on that machine, and anything running there as you can sign with it;
so can anything that runs your test suite as you. Nothing here protects
against that, any more than a green CI run protects against a developer with
push access.

## Producing attestations

[amont](https://github.com/fredericrous/amont) is the reference producer: with
`amont.attest` enabled it signs a note at `pre-push` naming the gates that
actually passed. Any tool can produce one — [`SPEC.md`](SPEC.md) is the format,
and it is short.

An attestation is only as honest as the push that produced it, and the way a
push gets dishonest in practice is a coding agent masking its failure —
`git push … 2>&1 | tail -5` reports tail's exit status, so a rejected push
reads as success. [amont-agent](https://github.com/fredericrous/amont-agent)
guards that end: a `PreToolUse` hook that refuses the command shape before it
runs. Independent of this verifier — related by author, and by the shared
conviction: trust what was verified, never what was reported.

## What is in here

| | |
|---|---|
| [`SPEC.md`](SPEC.md) | the `amont-attest-v2` wire format |
| [`action.yml`](action.yml) | the composite action, for GitHub **and** Forgejo |
| [`verify.sh`](verify.sh) | the verifier the action runs. `git` and `ssh-keygen`, nothing else |
| `src/` | `git-attest`, the same contract as a binary |
| [`tests/conformance.sh`](tests/conformance.sh) | the fixtures both implementations must pass |

### Forgejo

Same file, full-URL `uses:`:

```yaml
- uses: https://github.com/fredericrous/attest@v1
```

### Other CI

```sh
cargo install git-attest
git-attest covered                     # names, or nothing
git-attest explain                     # ...and why
```

`git-attest explain` is the answer to "why didn't it skip?", which is otherwise
unanswerable by design.

## Zero dependencies

The verifier decides whether tests may be skipped, so it is a security
boundary, and everything it links is something you have to trust. It links
nothing. The hard parts — ed25519, the OpenSSH signature envelope — are handled
by `ssh-keygen`, which is already on every runner and audited by people who do
that for a living.

## Contributing

`tests/conformance.sh` runs the fixtures against any implementation:

```sh
make check                                  # both implementations
./tests/conformance.sh ./verify.sh
./tests/conformance.sh "target/release/git-attest covered"
```

`tests/legacy.sh` is a **negative control** — the verifier this project
replaces, kept so the suite can prove it is not vacuous. Cases marked
`(defect N)` must fail against it. Please don't fix it.

MIT.
