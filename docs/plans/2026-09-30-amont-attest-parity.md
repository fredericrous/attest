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
