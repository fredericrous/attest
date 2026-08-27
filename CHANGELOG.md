# Changelog

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
