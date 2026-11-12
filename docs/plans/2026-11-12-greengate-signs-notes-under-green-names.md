---
canonical: fredericrous/decisions:docs/plans/2026-11-12-greengate-signs-notes-under-green-names.md
phases: [1, 4, 5]
status: active
---
# greengate signs its notes under green names

Pointer plan. The canonical plan (see `canonical` above) moves every signed-notes name from `amont-*` to `greengate-*` (ADR-0068). Here: Phase 1 makes git-attest read both name sets (new ref first, then the old), with `format::LEGACY` and `format::GREEN` beside the unchanged constants, while writers still write the old names; Phase 4 swaps the constants and the writers to the green names; Phase 5 removes the old reads after the 30-day window.

## Code review
- attest: backend, lang:rust, unix, architect (lang:typescript left out: no TypeScript here; tui left out: verify output unchanged apart from names)
