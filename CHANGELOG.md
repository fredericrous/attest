# Changelog

## Unreleased

- **The actions run the binary** (decisions ADR-0037). `action.yml` runs
  `git-attest covered` and `sign/action.yml` runs `git-attest sign`, at the
  version the new `RELEASE` file names and only from an archive whose sha256
  it names: the commit a workflow pins names the bytes it runs. `fetch.sh`
  takes the archive from the runner's tool cache or the release, re-checks it
  on every use, extracts a private copy and proves it runs. Linux x86_64 takes
  the static musl build.
- **Still fail-open.** A failed download, a digest mismatch, no asset for the
  runner, a binary that will not run, or a run that fails or writes no
  `covered=` / `status=` line prints one `::warning` and falls back to
  `verify.sh` / `sign.sh`. Outputs are unchanged on every path.
- **`binary:`**, a test-only input on both actions: run a built binary
  instead of the pinned one, with a notice. attest's CI runs the action suite
  four ways: this branch's binary, the pinned release, and two broken
  binaries that must fall back.
- **`verify.sh` and `sign.sh` are deprecated as entry points**, and go away
  in 2.0.0: one line on stderr (a `::warning` under GitHub Actions), even
  under `--quiet`; stdout is unchanged. `ATTEST_NO_DEPRECATION=1` silences
  it, and the actions set it when they fall back.
- **The release is built before it is tagged.** `prepare-release` builds the
  archives into a draft and hands back `RELEASE` for the release PR; the tag
  publishes that draft only if its archives match the tagged digests, and
  rebuilds nothing. `v1` no longer moves on the tag: `move-major` moves it
  once the canary has passed. README, "Releasing".
- SPEC.md's `amont-provenance-v1` section is now a pointer: the format is
  specified in amont, which produces it.

## 1.6.0

- **One implementation, as a library** (decisions ADR-0037). `git-attest` is
  now the std-only `git_attest` library with the binary as a thin command line
  over it: `format`, `spec`, `fingerprint`, `sign`, `notes`, `produce` and
  `verify`. Every entry point takes the repository as a path and never reads
  the working directory, errors are typed, and nothing prints. amont links it
  in place of its own copies.
- **`git-attest sign`.** `sign/sign.sh`'s flags, outputs and exit contract,
  over the library; `tests/sign.sh` runs against both, and both make the
  identical block.
- **`git-attest check-inputs --require GATE... [--tree REV]`.** Proves that
  `attest-inputs` declares every tracked file for the named gates, moved from
  `amont attest check-inputs` with the same output and exit codes.
- **`@plan-exempt off`.** The canonical opt-out moves into `attest-inputs`,
  read by the library and by both shell scripts. `set planExempt off` in
  `amont.conf` is still read and reported as deprecated; until 2.0.0 an
  opt-out writes both, because a verifier before 1.6.0 reads the directive as
  an invalid gate name (which disables its fingerprints, not its canonical
  tree).
- **Known answers** for the payload (blocks captured from `sign.sh` 1.5.1 and
  amont 1.57.0), the spec grammar and the note keys, in `tests/vectors/`.
- The release publishes to crates.io or fails: amont depends on the crate.
- **An unusable spec degrades to the object key**, as SPEC.md says: a
  producer that finds an invalid, ambiguous or unreadable `attest-inputs`
  attaches neither `input` lines nor a `canon` line. `sign.sh` attached a
  `canon` line all the same; amont never did.
- **Whether a tree holds a spec comes from a listing**, as amont reads it:
  a tree git cannot list has no known spec (`AtError::Unlisted`), which
  opens no route, instead of looking like a tree with none.

## 1.5.1

- **SPEC: `amont-provenance-v1`.** The format of the signed record amont
  publishes in `refs/notes/amont-provenance` (decisions ADR-0036): the plan
  and the review verdict a push carried, its tree and its branch patch. It is
  not an attestation, and no verifier here reads it; the section is the
  contract between amont-agent, which writes the payload, and amont, which
  signs it.
- **SPEC: one owner per line of `amont-provenance-v1`.** The payload
  amont-agent hands over carries no `canon` line; the signer computes canon(T)
  of the pushed tree and inserts it after `tree`, whatever `planExempt` says,
  and refuses a payload that already has one. The `review` line carries the
  **content id**, a new subsection that defines the value an implementation
  review binds to (ADR-0034) with known answers, and says why it differs from
  canon(T): it ignores whether a plan exists.
- **Shared canonical-tree vectors.** `tests/vectors/canon.txt` holds raw
  listings and the canonical text each gives, in a strict line format. The
  Rust tests read it, and `tests/conformance.sh` runs it through the canon
  block of both `verify.sh` and `sign/sign.sh`; amont vendors the file.
- `.github/allowed_signers` lists the `amont-provenance` namespace.

## 1.5.0

Plan-only commits skip with no declaration.

- **The canonical tree.** A producer adds `canon <oid>`, the fingerprint of the
  tree with the *content* of everything under the top-level `docs/plans/` left
  out and its *existence* kept, and files the block under a second synthetic
  key in `refs/notes/amont-attest-inputs`. A verifier covers every gate of a
  block whose `canon` equals the checked-out tree's, reported as
  `(by canonical tree)`. Nothing is declared, so nothing can be
  under-declared; `verify.sh` and `git-attest` agree on the same vectors.
- **Opt-out.** `set planExempt off` in `amont.conf`, read by every producer and
  verifier from the committed bytes and failing narrow, for a repository whose
  gate reads the contents of a plan.
- Additive: the format token stays `amont-attest-v2`; older verifiers ignore
  the new line and only lose a skip. `make lint` keeps the shell block
  byte-identical in `verify.sh` and `sign/sign.sh`.

## 1.4.1

Two defects in 1.4.0's remote calls, found while bringing amont to parity.

- **A fetch killed by the deadline could wedge the mirror.** It fetched
  straight into `refs/notes/amont-attest[-inputs]`; killed mid-write, git
  could leave a `.lock` that failed every later update, and later runs then
  judged a copy nobody refreshed. Fetches now land in a throwaway ref
  (`refs/attest-tmp/<pid>/…`, outside `refs/notes/`) and become the mirror
  by compare-and-swap; after a failed swap the mirror is judged only if it
  holds exactly what was fetched (`notes=unwritable` otherwise). A lock left
  by an older version is reported with the `rm` that clears it.
- **`GIT_TERMINAL_PROMPT=0` did not stop askpass.** git runs `GIT_ASKPASS`,
  `core.askPass` and `SSH_ASKPASS` before consulting it, so a verifier under
  VS Code, or with an interactive credential manager, could open a prompt and
  sit out the deadline. Remote calls now set `GIT_ASKPASS` present and empty,
  `GCM_INTERACTIVE=never` and `credential.interactive=never`.
- A fetch that timed out is no longer followed by `ls-remote`: a silent
  origin costs 15 s, not 30.

## 1.4.0

An audit of 1.3.1, applied.

- **The notes refs are origin's mirror, and revoking works.**
  `refs/notes/amont-attest[-inputs]` follow origin: fetched, **deleted** when
  origin no longer has them (1.3.1 kept a local copy forever, so deleting a
  ref on origin revoked nothing in a clone that had fetched it), and not read
  at all when origin is configured but does not answer — a stale copy on a
  persistent runner no longer covers anything. The deletion is announced with
  the command that restores it. New outputs `notes=` and `inputs_notes=` say
  which of `fetched`, `absent`, `unreachable`, `undeletable`, `no-origin`
  happened; the action warns on `unreachable`.
- **Unpushed blocks have a ref of their own.** `sign.sh --no-push` writes to
  `refs/notes/attest-local/*`, which a verify run never touches — 1.3.1's
  verifier force-fetched over the local ref and dropped them. Origin cannot
  revoke such a block, so verifiers read it only with `--include-local` (the
  action's `include-local` input). A push no longer carries local blocks
  along: it publishes origin's ref plus the new block, nothing else.
- **Optional paths in the input spec.** A leading `?` marks a path that may
  be absent — `?build.rs`, `?clippy.toml` — whose appearance must re-run the
  gate; it was unbindable before, since every declared path had to exist.
  1.3.x readers reject the marker as a wildcard, so such a spec only costs
  them their fingerprint skips.
- **This repository's own spec under-declared its cargo gates**: `tests`,
  which cargo discovers by itself, was missing, so a new integration test
  could have ridden an old attestation. Fixed, with the optional tool files.
- **The weekly CI run no longer skips anything.** It exists to catch what no
  fingerprint binds (a new runner image, new tools), and it skipped every
  gate. Scheduled and manual runs do not verify now; write gate conditions
  as `fromJSON(steps.attest.outputs.gates || '[]')` so a skipped attest step
  reads as "nothing covered".
- **Revoking is documented** (SPEC.md, "Revoking"), including why tightening
  the spec alone does not retire old attestations.
- **No prompts, no hangs.** Remote calls run with prompts off, ssh in batch
  mode (unless you configured your own ssh command), curl's low-speed limit,
  and a 15 s deadline each: at most 30 s against a dead origin, 45 s in the
  worst case.
- **The signing key stays out of child environments.** The sign action set
  it as step environment, so git, ssh-keygen and any hook or credential
  helper inherited it; it is now unset before anything runs and reaches
  `sign.sh` on stdin only.
- **Platform names match git-attest's.** The shell called every unknown OS
  `windows` and passed `uname -m` through raw, so a BSD, an ARM board or an
  illumos host never matched git-attest; one table, checked identical in all
  three copies, now emits Rust's `std::env::consts` names.
- **`verify.sh` could cover a gate nobody signed under that name**: `awk -v`
  processes backslash escapes, so a signed `te\163t` resolved to the declared
  gate `test`. Values reach awk through `ENVIRON` now.
- An empty `--signers`, `--principal` or `--platform` means "not given" in
  git-attest too.
- `git-attest explain` prefixes its reasons with `attest: `, like `verify.sh`.

**Upgrading.** The main ref becomes a mirror, so a block that exists only
there — a 1.3.1 `--no-push` block absorbed into it, or any note in a clone
whose origin never had the ref — is dropped by the first 1.4.0 verify, which
prints how to restore it. Re-sign with `--no-push` to keep one. An origin
that is configured but unreachable now covers nothing.

## 1.3.1

Three findings from a review of 1.3.0, all with fixtures now.

- **A wildcard gate name could cover a gate nobody signed.** `verify.sh`
  word-split the signed gate list with globbing on, so a gate called
  `pre-push-*` next to a file called `pre-push-cargo-test` became that
  file's name. Both scripts now run with globbing off; the binary was
  already literal.
- **The producer's clean-tree guard could be hidden or fail open.**
  `status.showUntrackedFiles=no` hid untracked files, `diff.ignoreSubmodules`
  hid submodule changes, and a `git status` that failed (a corrupt index)
  read as clean. The guard now passes explicit flags for both and refuses to
  sign, `--allow-dirty` or not, when status fails.
- **A successful push dropped local-only blocks.** Publishing replaced the
  local notes ref with the remote-derived one, so a block written by a
  `--no-push` run vanished on the next push. Local blocks the remote lacks
  are now carried into the updated LOCAL ref, on both refs — kept there, never
  published. (1.4.0 moves them to a ref of their own.)

## 1.3.0

- **Input fingerprints.** A committed `.github/attest-inputs` (or
  `.forgejo/`) names the paths each gate reads. A gate is then covered by an
  attestation of ANY tree whose declared inputs are byte-identical, so a docs
  commit on main, an unrelated package in a monorepo, or a moved base no
  longer voids it. The fingerprint is `git hash-object` over the `ls-tree`
  listing of those paths (plus the spec itself, `.gitmodules` and ancestor
  `.gitattributes`); producers write it as an `input <gate> <fp>` payload line
  and attach the block under a synthetic key in a second notes ref,
  `refs/notes/amont-attest-inputs`. Both verifiers read that ref; verifiers
  before 1.3.0 ignore the new lines and never reach it. The spec grammar is
  strict (literal paths only — `ls-tree` does not glob — ASCII only, whole
  spec invalid on any error) and it is a trust boundary like
  `allowed_signers`. Each run verifies at most 64 signatures. Never run
  `git notes prune` on the inputs ref.
- **The sign action writes them.** With a committed spec, `sign/sign.sh` adds
  an `input` line for each signed gate the spec declares and files the block
  under its fingerprint key in the inputs ref, publishing that ref on its own
  so a run whose inputs push failed repairs the keys next time. A fifth output
  line, `inputs=<published>/<wanted>`. This repository's own spec covers its
  five gates, so a docs-only change now skips all of them.

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
