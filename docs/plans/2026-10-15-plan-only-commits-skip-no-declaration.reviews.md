# Reviews: plan-only commits skip with no declaration

## Full reviews (reference)

Panel for this change: backend only (the person's change path: "can't we support without extra declaration"; architect, platform, po and the others had reviewed the superseded sixteen-repository rollout).

Pass 1 (body b8a891f81678; 72k tokens, 230 s): 7 findings, all applied (1 blocking: the opt-out did not reach CI; 3 high; 2 medium; 1 low).
Pass 2 (9c73b21fe095; 28k, 119 s): 4 findings, all applied (1 blocking: `set planExempt off` cannot land before amont 1.56 is installed; 1 high: the two readers could disagree).
Pass 3 (dc8a8765dc78; 21k, 59 s): a medium and two lows, carried.
External review (ChatGPT, pasted by the person; it stops mid-sentence at point 4): 2 high and 2 medium findings. Each was checked against the code before editing: `attest_push` files the block under tree and commit (attest.rs:350-360) and `attestable` drops gates whose scope the push does not touch; `spec_at` returns `None` for absent, invalid and ambiguous alike; `parse_lines` trims before parsing. All four are applied: the proof isolates canon (baseline attested, then plans-only and negative commits with attestation off, no tree or commit note asserted, reason and key asserted, local reuse proved separately); the opt-out is one policy for every route with `off` dominating; `read_spec` states are explicit; "strict spelling" was replaced by one tolerant normalisation, since strictness cannot be implemented after `parse_lines` normalises.
Pass 4 (5763c36e3cb8; 26k, 46 s): the four resolved, no regression to the original target; two medium fail-safe additions applied.
Pass 5 (6a150eafab0f; 25k, 36 s): caught that the new wording would make every repository without a spec Unlisted (so no closing commit would ever skip); corrected by reading presence from a successful `ls-tree` listing.
Pass 6 (final body 1156cc02d5b7; 21k, 17 s): approve-with-changes, one low item carried.

**Carried into implementation (override the body where they differ)**
- `plan_exempt_off(T)` fails narrow on every read error: if the `ls-tree` or `cat-file` that looks for `amont.conf` fails, the policy is off; only a successful `ls-tree` that does not list it means on. Add that vector, in both implementations.
- Step 2: the `set planExempt off` pull requests merge after `brew upgrade` (the text should say so in that order), with no other commit or push in those repositories until each has merged, and all before step 5.
- amont tests: `set planExempt off` and `set planExempt on` are accepted; a second `planExempt` line (any value) is a broken line; spelling variants are read by `plan_exempt_off` as the body says (one tolerant normalisation, not strict spelling).
- Step 3: record each pilot runner's `awk --version`; a pilot that step 4 opted out is replaced by one it cleared.
- Measure canon and `T:amont.conf` read time on the largest fleet repository (state its file count); expected under 100 ms.
