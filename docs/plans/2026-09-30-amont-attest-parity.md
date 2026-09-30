---
canonical: fredericrous/amont docs/plans/2026-09-30-amont-attest-parity.md
phases: "attest 1.4.1: fetch into a throwaway ref, never prompt (change 4)"
status: active
---
# amont + attest: 1.4.0 parity and remote-call hardening (pointer)

The plan lives in amont, where most of the work is. This repository carries
its change 4: fetches into a throwaway ref with compare-and-swap, askpass and
interactive credential managers off, no `ls-remote` after a timed-out fetch,
dead-PID sweep of throwaways, stale-lock report. Released as 1.4.1.

## Decision log (this slice)

- 2026-09-30 — attest keeps the third call (a second fetch after `ls-remote`
  answers): its bound is 15 s for a silent origin, 30 s for one that fails
  fast, and 45 s worst case, not the plan's 30 s. SPEC states it.
- 2026-09-30 — `notes=unwritable` is a new output value; `action.yml` lists
  it and warns on it, as it does on `unreachable`.
- 2026-09-30 — each run clears a lock a dead run with the same pid left on
  its own throwaway ref, so a reused pid cannot wedge the fetch.
- 2026-09-30 — implementation-review → approve-with-changes: the no-lock
  fixture could not fail (fault `hang` took no lock); `hang` now plants the
  lock a killed fetch leaves on every refspec destination.

- 2026-09-30 — delta implementation-review of tree 513a33f → approve-with-changes: both
  action warnings can print; two known limits are stated in code rather than
  fixed (a failed rm of our own throwaway's lock reads as `unreachable`,
  safe; a killed fetch's lock with no ref beside it is not swept, only
  replaced when its pid comes round). The own-pid clearing has no fixture:
  a test cannot know the verifier's pid.

- 2026-09-30 — delta implementation-review of tree 9accc9b →
  approve-with-changes, low only: this entry's tree ids, and `unwritable`
  missing from one verify.sh comment (fixed).

## Verification record (attest 1.4.1; input → expected → actual)

| check | expected | actual |
|---|---|---|
| `make check` (tree 513a33f and after) | green | conformance 152 (sh) / 144 (rust), legacy control fails, compat all, sign 129 × 2 |
| silent origin (fault `hang`) | 1 remote call, ~15 s, no lock on the mirror, next run fetches | 1 call, 17–18 s, as expected |
| origin answering 401, `core.askPass` marker | no askpass; plain git runs it | as expected, both implementations |
| stale lock, origin unchanged / rewritten / lock removed | covered / `unwritable` + `rm` line / `notes=fetched` (coverage gone: origin holds a rewritten note) | as expected |
| dead-PID throwaway / live one | swept / kept | as expected (unix; skipped on Windows) |
| the new fixtures against v1.4.0's verify.sh | fail | 9 failed (one call, one deadline, no lock on the mirror, askpass, stale lock ×2, sweep, …) |
