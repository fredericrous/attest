# Changelog

## 1.2.0

Why so few skips, answered. With only a laptop producing and the platform
rule applied to every gate, a macOS developer with Linux CI skipped nothing.
Two additions, no wire-format change (the format token stays
`amont-attest-v2`).

- **Gates accepted from anywhere.** The action's `anywhere` input (CLI
  `--anywhere`) names gates whose result cannot depend on where they ran —
  formatting, shell lint, secret scanning, dependency audit — and admits them
  from a verified attestation on any platform. Declared once, applied only
  after signature verification. Not for anything that compiles or executes
  the product, clippy included.
- **OS-only platform matching.** `platform: linux` accepts any architecture.
- **CI as a producer.** `fredericrous/attest/sign@v1` signs, from a job, the
  gates that ran and passed there, and pushes the note — so the push to main
  after a merge, a re-run, or a duplicated matrix leg skips what the pull
  request already proved. Refuses a dirty working tree, a foreign
  `--object`, and non-ed25519 keys; retries a push that lost a race; never
  fails the job.
- **Several blocks per note.** A laptop's and a CI job's attestations of the
  same tree live in one note as blank-line-separated blocks (what `git notes
  append` writes). Every block is judged on its own; the answer is the union.
  At most 32 blocks are read. 1.1.0 verifiers read block 1 only and can never
  report a later block's gates — `make compat` proves it against the frozen
  1.1.0 shell and Rust implementations.
- A note containing a carriage return anywhere is rejected whole, by both
  implementations, before parsing.

**Follow-up for amont:** its pre-push hook writes with `git notes add -f`,
which erases CI's block on the next push of the same tree. Switch to `append`.

## 1.1.0

An audit of 1.0.0, applied. Nothing here changes the wire format.

**Fixed:**

- **Every later run on a Mac could fail open forever.** `verify.sh` asked
  `mktemp` for `attest-XXXXXX.sig`, and stock macOS `mktemp` does not
  substitute a template whose Xs are not at the very end: it created that
  literal file, and the next run — after a killed one had left it behind —
  failed with "File exists" and covered nothing. The template has no suffix
  now.
- **A failed fetch of the notes ref was silent.** A checkout with
  `persist-credentials: false`, a remote not named `origin`, or no network
  read as "no attestation found", indefinitely. Both implementations now say
  when the ref could not be fetched and no local copy exists — and stay quiet
  when origin simply has no such ref.
- **The principal was guessed.** 1.0.0 verified as the first entry of
  `allowed_signers`, so on a team every other signer's notes silently covered
  nothing. The identity is now read from the signature
  (`ssh-keygen -Y find-principals`); `--principal` and the action's
  `principal` input restrict to one identity instead of naming the only one.
- **Control characters in a gate name reached the JSON output raw** from
  `verify.sh`, where they would make the consumer's `fromJSON` throw and fail
  the job. They leave as `\u00xx`, as the comment always claimed and as
  `git-attest` already did.
- **The two implementations disagreed on a note with no `platform` line**
  under `--platform any`: the shell covered it, the binary did not. Both
  reject it now, and the spec says the field is required.
- **`git-attest` ignored flags it did not know**, so `--platfrom any` fell
  back to this machine's platform and never covered anything. Unknown flags
  are a usage error (exit 2) in both implementations.
- **`git-attest --signers` resolved a relative path from the working
  directory**, unlike `verify.sh`; both resolve from the repository root now,
  and a path to a missing file says so.
- `verify.sh --help` printed three lines of code after the usage text.

**Documented:** why a `pull_request` checkout rarely matches the attested
tree; that `allowed_signers` deserves the same review protection as a workflow
file; what a producer owes the tree it signs (a clean working tree, an honest
gate name); pin the action by commit.

**CI:** actions pinned by commit SHA, release permissions scoped to the jobs
that write, a Windows leg in the conformance matrix, and fixtures for every
case above.

## 1.0.0

First release.

`attest` verifies a signed note proving a test suite already passed on the
exact tree CI checked out, so the job can skip it. It is the consumer half of
the `amont-attest-v2` format, extracted from
[amont](https://github.com/fredericrous/amont) — which stays the producer.

The extraction is not a move; it is a rewrite of the part that was never
tested. amont's CI templates carried the verifier as ~30 lines of shell copied
into eight workflow files, covered by no test anywhere, and that duplication
had produced four defects. All four are fixed here and pinned by
`tests/conformance.sh`, which runs every fixture against **both**
implementations plus `tests/legacy.sh` — the old shell, kept as a negative
control so the suite cannot quietly become vacuous.

**Fixed, relative to the inline templates:**

- **The identity was hardcoded to `you@example.com`.** Anyone whose
  `allowed_signers` named their real address — the obvious thing to write —
  got `ssh-keygen -Y verify` rejecting a perfectly good signature, no skip, and
  CI green. The gate was dead and said nothing. The principal now defaults to
  the first entry of the signers file.
- **Gate names were matched as substrings.** `contains(covered, 'x')` is
  satisfied by a gate named `x-slow`, skipping the real suite on an
  attestation that never covered it. The action now also publishes `gates` as
  a JSON array, for `contains(fromJSON(...), 'x')`, which matches elements.
- **`allowed_signers` was resolved relative to the working directory.** A
  monorepo matrix using `working-directory` found no signers, covered nothing,
  and failed open forever. It is resolved from the repository root.
- **Nothing explained itself.** Every failure path is a silent success by
  design, so a missing skip was undiagnosable. Reasons now go to stderr, and
  `git-attest explain` prints the whole chain.

**Interface:** `action.yml` for GitHub and Forgejo; `verify.sh` for anyone who
would rather not depend on an action; `git-attest` for other CI. No
dependencies in any of them beyond `git` and `ssh-keygen`.
