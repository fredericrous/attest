#!/usr/bin/env bash
# Backward compatibility of multi-block notes with the verifiers released in
# 1.1.0, which read ONE block. Run against a FROZEN implementation:
#
#   tests/compat.sh "bash tests/compat/verify-1.1.0.sh --quiet"
#   tests/compat.sh "target/compat/target/release/git-attest covered"   # built from v1.1.0
#
# The claim SPEC.md makes: a 1.1.0 verifier takes the payload before the first
# blank line and the signature from the first BEGIN marker to the end of the
# note, so on a multi-block note it reports block 1's gates or nothing. It can
# UNDER-report, which is safe; it can never report a gate that only a later
# block names, which is the only thing that would be unsafe. This file is the
# proof of that claim, and it is what lets the 1.2.0 producer append blocks to
# notes that 1.1.0 consumers will still read.
set -u

IMPL=${1:?usage: compat.sh <frozen implementation command>}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
# shellcheck source=tests/lib.sh
. "$(dirname "$0")/lib.sh"
gen_keys

R=$WORK/r

# Sanity: the frozen verifier still reads a one-block note.
make_repo "$R" signer@example.org "$WORK/key"
attach_note "$R" "$(payload_for "$R" g1 "$PLATFORM")" "$WORK/key"
check "1.1.0 reads a single block" "g1" "$R"

# Block 1 on this platform, block 2 foreign: block 1's gates, or nothing.
make_repo "$R" signer@example.org "$WORK/key"
append_note "$R" "$(payload_for "$R" g1 "$PLATFORM")" "$WORK/key"
append_note "$R" "$(payload_for "$R" g2 s390x-aix)" "$WORK/key"
check_one_of "local then foreign: block 1 or nothing" "g1|" "$R"

# Block 1 foreign, block 2 on this platform: NOTHING. Block 2's gate must not
# surface through any reading of the note.
make_repo "$R" signer@example.org "$WORK/key"
append_note "$R" "$(payload_for "$R" g1 s390x-aix)" "$WORK/key"
append_note "$R" "$(payload_for "$R" g2 "$PLATFORM")" "$WORK/key"
check "foreign then local: nothing" "" "$R"
check_one_of "foreign then local, --platform any" "g1|" "$R" --platform any

# Block 1 tampered, block 2 valid: NOTHING.
make_repo "$R" signer@example.org "$WORK/key"
append_note "$R" "$(payload_for "$R" g1 "$PLATFORM")" "$WORK/key"
append_note "$R" "$(payload_for "$R" g2 "$PLATFORM")" "$WORK/key"
tree=$(git -C "$R" rev-parse 'HEAD^{tree}')
body=$(git -C "$R" notes --ref amont-attest show "$tree")
raw_note "$R" "$(printf '%s' "$body" | sed 's/^gates g1$/gates g1 g3/')"
check "first block tampered, second valid: nothing" "" "$R"

# Block 1 by a stranger, block 2 by the signer: NOTHING.
make_repo "$R" signer@example.org "$WORK/key"
append_note "$R" "$(payload_for "$R" g1 "$PLATFORM")" "$WORK/other"
append_note "$R" "$(payload_for "$R" g2 "$PLATFORM")" "$WORK/key"
check "first block by a stranger, second valid: nothing" "" "$R"

# Two valid blocks with different gates: block 1's, or nothing — never both.
make_repo "$R" signer@example.org "$WORK/key"
append_note "$R" "$(payload_for "$R" g1 "$PLATFORM")" "$WORK/key"
append_note "$R" "$(payload_for "$R" g2 "$PLATFORM")" "$WORK/key"
check_one_of "two valid blocks: block 1 or nothing, never the union" "g1|" "$R"

summary
