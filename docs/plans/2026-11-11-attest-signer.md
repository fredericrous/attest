---
canonical: fredericrous/homelab docs/plans/2026-11-11-attest-signer.md
phases: [2]
status: active
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
