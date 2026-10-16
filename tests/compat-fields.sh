#!/usr/bin/env bash
# The additive `input` lines of 1.3.0 against verifiers that predate them.
#
#   tests/compat-fields.sh "bash tests/compat/verify-1.1.0.sh --quiet" old
#   tests/compat-fields.sh "bash tests/compat/verify-1.2.0.sh --quiet" old
#   tests/compat-fields.sh "bash tests/compat/verify-1.3.1.sh --quiet" fp13
#   tests/compat-fields.sh "bash verify.sh --quiet" new
#
# The claim SPEC.md makes: fields are read by prefix and unknown lines are
# ignored, so a block that carries `input` lines is reported by a 1.1.0 or
# 1.2.0 verifier exactly as before — by tree — and neither ever reaches a
# fingerprint-keyed note. `old` expects that; `new` expects the current
# behaviour, so the same fixtures also pin what 1.3.0 adds. `fp13` is a 1.3.x
# verifier: it reads fingerprints, but not a spec with an optional `?path`
# (1.4.0), which it rejects as a wildcard — so such a spec only loses skips.
# `fp14` is a 1.4.x verifier: it reads optional paths, but not the `canon` line
# of 1.5.0, which it ignores — so a canonical claim only loses a skip. `fp15`
# is a 1.5.x verifier: it reads `canon`, but not the `@plan-exempt off`
# directive of 1.6.0, which invalidates its spec without switching the
# canonical route off — the reason an opt-out writes both forms until 2.0.0.
set -u

# shellcheck disable=SC2034  # read by lib.sh
IMPL=${1:?usage: compat-fields.sh <implementation command> old|fp13|fp14|fp15|new}
AGE=${2:?usage: compat-fields.sh <implementation command> old|fp13|fp14|fp15|new}
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

# A spec with an optional path, the block only under its fingerprint key:
# covered by a 1.4.0 reader, by nobody older — never wrongly.
make_repo "$R" signer@example.org "$WORK/key"
mkdir -p "$R/src"; echo 'fn main() {}' > "$R/src/main.rs"; echo '[package]' > "$R/Cargo.toml"
git -C "$R" add -A; git -C "$R" commit -q -m src
write_spec "$R" <<'EOF'
test src Cargo.toml ?build.rs
EOF
fp=$(fp_of "$R" test)
attach_input "$R" "$(payload_for "$R" test "$PLATFORM" "" "test=$fp")" "$WORK/key" test "$fp"
move_tree "$R"
if [ "$AGE" = new ] || [ "$AGE" = fp14 ] || [ "$AGE" = fp15 ]; then
    check "a spec with an optional path is read" "test" "$R"
else
    check "a spec with an optional path covers nothing here" "" "$R"
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

# The canonical tree (1.5.0): a `canon` line is an unknown field to every
# older verifier. A block that carries one is reported by tree exactly as
# before; one reachable only through its canonical key is found by 1.5.0 and
# by nobody older, so an old verifier only loses the skip, never gains one.
make_repo "$R" signer@example.org "$WORK/key"
mkdir -p "$R/docs/plans"; echo p > "$R/docs/plans/a.md"; echo c > "$R/code.txt"
git -C "$R" add -A; git -C "$R" commit -q -m src
c=$(canon_fp "$R")
attach_note "$R" "$(payload_for "$R" test "$PLATFORM" | with_canon "$c")" "$WORK/key"
check "a tree-matching block with a canon line is reported" "test" "$R"

make_repo "$R" signer@example.org "$WORK/key"
mkdir -p "$R/docs/plans"; echo p > "$R/docs/plans/a.md"; echo c > "$R/code.txt"
git -C "$R" add -A; git -C "$R" commit -q -m src
c=$(canon_fp "$R")
attach_canon "$R" "$(payload_for "$R" test "$PLATFORM" | with_canon "$c")" "$WORK/key" "$c"
echo edited > "$R/docs/plans/a.md"; git -C "$R" commit -qam plan-edit
if [ "$AGE" = new ] || [ "$AGE" = fp15 ]; then
    check "a block reachable only by its canonical tree is reported" "test" "$R"
else
    check "a block reachable only by its canonical tree is not reported" "" "$R"
fi

# The opt-out directive (1.6.0). Alone, a 1.5.x verifier still uses the
# canonical tree: it reads the directive as an invalid gate name, which only
# disables input fingerprints. With amont.conf's line too, nobody does.
optout_repo() { # attest-inputs [amont.conf]
    make_repo "$R" signer@example.org "$WORK/key"
    mkdir -p "$R/docs/plans" "$R/.github"; echo p > "$R/docs/plans/a.md"; echo c > "$R/code.txt"
    printf '%b' "$1" > "$R/.github/attest-inputs"
    if [ $# -gt 1 ]; then printf '%b' "$2" > "$R/amont.conf"; fi
    git -C "$R" add -A; git -C "$R" commit -q -m src
    c=$(canon_fp "$R")
    attach_canon "$R" "$(payload_for "$R" test "$PLATFORM" | with_canon "$c")" "$WORK/key" "$c"
    echo edited > "$R/docs/plans/a.md"; git -C "$R" commit -qam plan-edit
}
optout_repo '@plan-exempt off\n'
if [ "$AGE" = fp15 ]; then
    check "the directive alone: a 1.5.x verifier still covers by canonical tree" "test" "$R"
else
    check "the directive alone: nothing by canonical tree" "" "$R"
fi
optout_repo '@plan-exempt off\n' 'set planExempt off\n'
check "both opt-outs: nothing by canonical tree, whatever the version" "" "$R"

summary
