#!/usr/bin/env bash
# The additive `input` lines of 1.3.0 against verifiers that predate them.
#
#   tests/compat-fields.sh "bash tests/compat/verify-1.1.0.sh --quiet" old
#   tests/compat-fields.sh "bash tests/compat/verify-1.2.0.sh --quiet" old
#   tests/compat-fields.sh "bash verify.sh --quiet" new
#
# The claim SPEC.md makes: fields are read by prefix and unknown lines are
# ignored, so a block that carries `input` lines is reported by a 1.1.0 or
# 1.2.0 verifier exactly as before — by tree — and neither ever reaches a
# fingerprint-keyed note. `old` expects that; `new` expects the current
# behaviour, so the same fixtures also pin what 1.3.0 adds.
set -u

# shellcheck disable=SC2034  # read by lib.sh
IMPL=${1:?usage: compat-fields.sh <implementation command> old|new}
AGE=${2:?usage: compat-fields.sh <implementation command> old|new}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
# The helper is sourced, which shellcheck follows only under -x; the hook
# runs without it, so the two findings that follow from that are silenced.
# shellcheck source=lib.sh disable=SC1091
. "$(dirname "$0")/lib.sh"
gen_keys

R=$WORK/r

make_repo "$R" signer@example.org "$WORK/key"
mkdir -p "$R/src"; echo 'fn main() {}' > "$R/src/main.rs"; echo '[package]' > "$R/Cargo.toml"
git -C "$R" add -A; git -C "$R" commit -q -m src
write_spec "$R" <<'EOF'
test src Cargo.toml
EOF
fp=$(fp_of "$R" test)

# A tree-matching block that carries an `input` line: reported by everyone.
attach_note "$R" "$(payload_for "$R" test "$PLATFORM" "" "test=$fp")" "$WORK/key"
check "a tree-matching block with an input line is reported" "test" "$R"

# The same block only under the fingerprint key, after the tree moved: an old
# verifier never looks there; a new one does.
make_repo "$R" signer@example.org "$WORK/key"
mkdir -p "$R/src"; echo 'fn main() {}' > "$R/src/main.rs"; echo '[package]' > "$R/Cargo.toml"
git -C "$R" add -A; git -C "$R" commit -q -m src
write_spec "$R" <<'EOF'
test src Cargo.toml
EOF
fp=$(fp_of "$R" test)
attach_input "$R" "$(payload_for "$R" test "$PLATFORM" "" "test=$fp")" "$WORK/key" test "$fp"
move_tree "$R"
if [ "$AGE" = old ]; then
    check "a block reachable only by fingerprint is not reported" "" "$R"
else
    check "a block reachable only by fingerprint is reported" "test" "$R"
fi

# A moved tree with the block under the TREE key only: nothing, for everyone —
# the tree route is unchanged, and the old key is the old tree.
make_repo "$R" signer@example.org "$WORK/key"
mkdir -p "$R/src"; echo 'fn main() {}' > "$R/src/main.rs"; echo '[package]' > "$R/Cargo.toml"
git -C "$R" add -A; git -C "$R" commit -q -m src
write_spec "$R" <<'EOF'
test src Cargo.toml
EOF
fp=$(fp_of "$R" test)
attach_note "$R" "$(payload_for "$R" test "$PLATFORM" "" "test=$fp")" "$WORK/key"
move_tree "$R"
check "a moved tree with the block under the old tree only: nothing" "" "$R"

summary
