#!/usr/bin/env bash
# The contract, as fixtures. Run against ANY implementation:
#
#   tests/conformance.sh ./verify.sh
#   tests/conformance.sh "./target/release/git-attest covered"
#   tests/conformance.sh tests/legacy.sh        # the shell attest used to ship
#
# The implementation is invoked in a prepared repository with the same flags
# `verify.sh` accepts and must print the covered gate names — space separated,
# nothing at all when nothing is covered — and exit 0 either way.
#
# Two implementations exist (a shell verifier the actions run, and a Rust
# binary), and this file is the only thing keeping them from drifting apart.
# `tests/legacy.sh` is here as a NEGATIVE control: it is the verifier the amont
# CI templates shipped, and cases marked (defect N) must FAIL against it. A
# fixture every implementation passes is testing nothing.
set -u

# shellcheck disable=SC2034  # read by lib.sh
IMPL=${1:?usage: conformance.sh <implementation command>}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
# The helper is sourced, which shellcheck follows only under -x; the hook
# runs without it, so the two findings that follow from that are silenced.
# shellcheck source=lib.sh disable=SC1091
. "$(dirname "$0")/lib.sh"
gen_keys

R=$WORK/r

# --- the happy path -------------------------------------------------------
make_repo "$R" signer@example.org "$WORK/key"
attach_note "$R" "$(payload_for "$R" pre-push-cargo-test "$PLATFORM")" "$WORK/key"
check "valid note on this platform" "pre-push-cargo-test" "$R"

check "explicit --platform any" "pre-push-cargo-test" "$R" --platform any

attach_note "$R" "$(payload_for "$R" "pre-push-cargo-test pre-push-clippy" "$PLATFORM")" "$WORK/key"
check "several gates" "pre-push-cargo-test pre-push-clippy" "$R"

# (defect 1) The principal is NOT passed and allowed_signers names a real
# address. The templates hardcoded `-I you@example.com` and covered nothing.
check "principal defaults to the signers file" "pre-push-cargo-test pre-push-clippy" "$R"

# (defect 5) A team: two signers in the file, the note signed by the SECOND.
# The first release guessed the file's first entry as the principal, so every
# signer but one got a gate that never fired. The principal is read from the
# signature now, and `--principal` is a restriction, not a hint.
make_repo "$R" signer@example.org "$WORK/key" second@example.org "$WORK/second"
attach_note "$R" "$(payload_for "$R" pre-push-cargo-test "$PLATFORM")" "$WORK/second"
check "signed by the second signer in the file" "pre-push-cargo-test" "$R"
check "--principal names the second signer" "pre-push-cargo-test" "$R" --principal second@example.org
check "--principal names the OTHER signer" "" "$R" --principal signer@example.org

# A producer that keyed by commit rather than tree: the note hangs off HEAD,
# and the tree line inside it still has to match.
make_repo "$R" signer@example.org "$WORK/key"
attach_note "$R" "$(payload_for "$R" pre-push-cargo-test "$PLATFORM")" "$WORK/key" HEAD
check "note keyed by commit (HEAD fallback)" "pre-push-cargo-test" "$R"

# Fields are read by prefix and the FIRST occurrence wins; a second `gates`
# line cannot smuggle a name past the caller or break the name=value output.
# A fresh repository, so the commit-keyed note above cannot answer for it.
make_repo "$R" signer@example.org "$WORK/key"
attach_note "$R" "$(printf '%s\ngates pre-push-cargo-test\n' "$(payload_for "$R" pre-push-clippy "$PLATFORM")")" "$WORK/key"
check "duplicate field: first occurrence wins" "pre-push-clippy" "$R"

# --- everything that must NOT cover ---------------------------------------
# A fresh repository: the commit-keyed note above would otherwise be found
# through the HEAD fallback and cover every case below.
make_repo "$R" signer@example.org "$WORK/key"
attach_note "$R" "$(payload_for "$R" pre-push-cargo-test "$PLATFORM")" "$WORK/other"
check "signed by a key not in allowed_signers" "" "$R"

attach_note "$R" "$(payload_for "$R" pre-push-cargo-test "$PLATFORM")" "$WORK/key"
check "platform mismatch" "" "$R" --platform s390x-aix

attach_note "$R" "$(printf 'amont-attest-v2\ntree %s\ngates pre-push-cargo-test\nplatform %s\namont 1.23.0\n' \
    0000000000000000000000000000000000000000 "$PLATFORM")" "$WORK/key"
check "tree mismatch" "" "$R"

attach_note "$R" "$(payload_for "$R" "" "$PLATFORM")" "$WORK/key"
check "no gates listed" "" "$R"

attach_note "$R" "$(payload_for "$R" pre-push-cargo-test "$PLATFORM" amont-attest-v1)" "$WORK/key"
check "unknown format version" "" "$R"

# Every v2 field is required. A note that does not say where it ran is not
# evidence about anywhere — not even for a caller accepting any platform.
attach_note "$R" "$(payload_for "$R" pre-push-cargo-test "$PLATFORM" | grep -v '^platform ')" "$WORK/key"
check "missing platform line" "" "$R"
check "missing platform line, --platform any" "" "$R" --platform any

# A typo in a flag is refused, not skipped: `--platfrom any` that fell back
# to this machine's platform would silently never cover anything.
check_usage "unknown flag is a usage error" "$R" --platfrom any

attach_note "$R" "$(payload_for "$R" pre-push-cargo-test "$PLATFORM")" "$WORK/key"
git -C "$R" notes --ref amont-attest add -f -m "$(payload_for "$R" pre-push-cargo-test "$PLATFORM")" \
    "$(git -C "$R" rev-parse 'HEAD^{tree}')" 2> /dev/null
check "payload with no signature block" "" "$R"

# A tampered payload: the signature is real but covers different bytes.
make_repo "$R" signer@example.org "$WORK/key"
attach_note "$R" "$(payload_for "$R" pre-push-cargo-test "$PLATFORM")" "$WORK/key"
tree=$(git -C "$R" rev-parse 'HEAD^{tree}')
body=$(git -C "$R" notes --ref amont-attest show "$tree")
git -C "$R" notes --ref amont-attest add -f \
    -m "$(printf '%s' "$body" | sed 's/gates pre-push-cargo-test/gates pre-push-cargo-test pre-push-audit-rust/')" "$tree" 2> /dev/null
check "payload edited after signing" "" "$R"

# A note containing a carriage return anywhere is rejected whole, whether
# some tool converted an LF-signed note to CRLF or the payload was signed with
# carriage returns in it. Both cover nothing, in both implementations.
make_repo "$R" signer@example.org "$WORK/key"
raw_note "$R" "$(sign_block "$R" "$(payload_for "$R" pre-push-cargo-test "$PLATFORM")" "$WORK/key" | sed 's/$/\r/')"
check "LF-signed note converted to CRLF" "" "$R"
attach_note "$R" "$(payload_for "$R" pre-push-cargo-test "$PLATFORM" | sed 's/$/\r/')" "$WORK/key"
check "payload signed with CRLF" "" "$R"

make_repo "$R" signer@example.org "$WORK/key"
check "no note at all" "" "$R"

attach_note "$R" "$(payload_for "$R" pre-push-cargo-test "$PLATFORM")" "$WORK/key"
rm -f "$R/.github/allowed_signers"
check "no allowed_signers file" "" "$R"

# --- the properties that make it usable ------------------------------------
make_repo "$R" signer@example.org "$WORK/key"
attach_note "$R" "$(payload_for "$R" pre-push-cargo-test "$PLATFORM")" "$WORK/key"
mkdir -p "$R/packages/api"
check "found from a subdirectory (monorepo)" "pre-push-cargo-test" "$R/packages/api"
# An explicit relative --signers is resolved the same way: from the root.
check "relative --signers from a subdirectory" "pre-push-cargo-test" "$R/packages/api" \
    --signers .github/allowed_signers
check "--signers to a missing file" "" "$R" --signers nope/allowed_signers

# The tree is what the signature covers, so an amend that preserves it keeps
# its attestation. This is the property that survives a forge's squash-merge.
git -C "$R" commit -q --amend -m "reworded, same tree"
check "survives a reword (same tree)" "pre-push-cargo-test" "$R"

# --- platform matching (1.2.0) ----------------------------------------------
# An OS alone matches any architecture; it is compared to the part after the
# LAST dash of the note's platform, never as a substring.
make_repo "$R" signer@example.org "$WORK/key"
attach_note "$R" "$(payload_for "$R" pre-push-cargo-test "$PLATFORM")" "$WORK/key"
check "os-only platform matches this arch" "pre-push-cargo-test" "$R" --platform "$OS"
check "os-only platform mismatch" "" "$R" --platform aix
attach_note "$R" "$(payload_for "$R" pre-push-cargo-test x86_64-linux)" "$WORK/key"
check "os-only linux matches x86_64-linux" "pre-push-cargo-test" "$R" --platform linux
check "os-only is not a substring match" "" "$R" --platform inux
check "os-only is not an arch match" "" "$R" --platform x86_64
check "a dashed platform is still exact" "" "$R" --platform aarch64-linux

# --- gates accepted from anywhere (1.2.0) -----------------------------------
# The caller's committed statement that the NAMED gates cannot depend on where
# they ran. It admits nothing from a block that did not verify.
make_repo "$R" signer@example.org "$WORK/key"
attach_note "$R" "$(payload_for "$R" "ci-fmt pre-push-cargo-test" s390x-aix)" "$WORK/key"
check "foreign platform covers nothing by default" "" "$R"
check "--anywhere admits the named gate only" "ci-fmt" "$R" --anywhere ci-fmt
check "--anywhere with two names" "ci-fmt pre-push-cargo-test" "$R" --anywhere "ci-fmt pre-push-cargo-test"
check "--anywhere does not admit an unlisted name" "" "$R" --anywhere ci-clippy
attach_note "$R" "$(payload_for "$R" ci-fmt s390x-aix)" "$WORK/other"
check "--anywhere never rescues an unverifiable block" "" "$R" --anywhere ci-fmt
attach_note "$R" "$(printf 'amont-attest-v2\ntree %s\ngates ci-fmt\nplatform s390x-aix\namont 1.23.0\n' \
    0000000000000000000000000000000000000000)" "$WORK/key"
check "--anywhere never rescues a stale tree" "" "$R" --anywhere ci-fmt
attach_note "$R" "$(payload_for "$R" ci-fmt s390x-aix | grep -v '^platform ')" "$WORK/key"
check "--anywhere never rescues a missing platform line" "" "$R" --anywhere ci-fmt
attach_note "$R" "$(payload_for "$R" ci-fmt s390x-aix amont-attest-v1)" "$WORK/key"
check "--anywhere never rescues an unknown format" "" "$R" --anywhere ci-fmt

# --- several blocks in one note (1.2.0) -------------------------------------
# A laptop and a CI job both attest the same tree, each on its own platform,
# by APPENDING a block. Every block is judged on its own; the answer is the
# union of the ones that pass.
make_repo "$R" signer@example.org "$WORK/key" second@example.org "$WORK/second"
append_note "$R" "$(payload_for "$R" g1 "$PLATFORM")" "$WORK/key"
append_note "$R" "$(payload_for "$R" g2 "$PLATFORM")" "$WORK/second"
check "two blocks written by git notes append, union in order" "g1 g2" "$R"

make_repo "$R" signer@example.org "$WORK/key"
append_note "$R" "$(payload_for "$R" g1 s390x-aix)" "$WORK/key"
append_note "$R" "$(payload_for "$R" g2 "$PLATFORM")" "$WORK/key"
check "foreign block then local block: local gates only" "g2" "$R"
check "foreign then local, --platform any takes both" "g1 g2" "$R" --platform any
check "foreign then local, --anywhere admits the foreign gate" "g1 g2" "$R" --anywhere g1

# The compatibility shape: block 1 on this platform, block 2 foreign. A 1.1.0
# verifier reads block 1 only (tests/compat.sh proves it); this one reads both
# and still answers block 1's gates here.
make_repo "$R" signer@example.org "$WORK/key"
append_note "$R" "$(payload_for "$R" g1 "$PLATFORM")" "$WORK/key"
append_note "$R" "$(payload_for "$R" g2 s390x-aix)" "$WORK/key"
check "local block then foreign block" "g1" "$R"

make_repo "$R" signer@example.org "$WORK/key"
append_note "$R" "$(payload_for "$R" g1 "$PLATFORM")" "$WORK/key"
append_note "$R" "$(payload_for "$R" g2 "$PLATFORM")" "$WORK/key"
tree=$(git -C "$R" rev-parse 'HEAD^{tree}')
body=$(git -C "$R" notes --ref amont-attest show "$tree")
raw_note "$R" "$(printf '%s' "$body" | sed 's/^gates g2$/gates g2 g3/')"
check "second block tampered: first still counts" "g1" "$R"

make_repo "$R" signer@example.org "$WORK/key"
append_note "$R" "$(payload_for "$R" g1 "$PLATFORM")" "$WORK/other"
append_note "$R" "$(payload_for "$R" g2 "$PLATFORM")" "$WORK/key"
check "first block by a stranger: second still counts" "g2" "$R"

make_repo "$R" signer@example.org "$WORK/key"
append_note "$R" "$(payload_for "$R" g1 "$PLATFORM")" "$WORK/key"
append_note "$R" "$(payload_for "$R" g2 "$PLATFORM" amont-attest-v3)" "$WORK/key"
check "second block is a newer format: first still counts" "g1" "$R"

make_repo "$R" signer@example.org "$WORK/key"
block=$(sign_block "$R" "$(payload_for "$R" g1 "$PLATFORM")" "$WORK/key")
raw_note "$R" "$(printf '%s\n\n%s' "$block" "$block")"
check "duplicate identical blocks: gate listed once" "g1" "$R"

make_repo "$R" signer@example.org "$WORK/key"
append_note "$R" "$(payload_for "$R" g1 "$PLATFORM")" "$WORK/key"
append_note "$R" "$(payload_for "$R" g1 s390x-aix)" "$WORK/key"
check "same gate on two platforms, listed once" "g1" "$R" --platform any

make_repo "$R" signer@example.org "$WORK/key"
b1=$(sign_block "$R" "$(payload_for "$R" g1 "$PLATFORM")" "$WORK/key")
b2=$(sign_block "$R" "$(payload_for "$R" g2 "$PLATFORM")" "$WORK/key")
raw_note "$R" "$(printf '%s\n\n\n\n%s\n' "$b1" "$b2")"
check "several blank lines between blocks" "g1 g2" "$R"
raw_note "$R" "$(printf '%s\n\ngarbage after the last block' "$b1")"
check "garbage after the last block is ignored" "g1" "$R"
raw_note "$R" "$(printf '%s\n\npayload2\n\nnot a signature' "$b1")"
check "a second block without BEGIN: parsing stops, first counts" "g1" "$R"
raw_note "$R" "$(printf 'p\n\n-----BEGIN SSH SIGNATURE-----\nx\n\n%s' "$b2")"
check "a block missing END swallows the valid block after it" "" "$R"

# A note reached through the tree AND the commit is judged once.
make_repo "$R" signer@example.org "$WORK/key"
append_note "$R" "$(payload_for "$R" g1 "$PLATFORM")" "$WORK/key"
append_note "$R" "$(payload_for "$R" g2 "$PLATFORM")" "$WORK/key"
git -C "$R" notes --ref amont-attest copy -f "$(git -C "$R" rev-parse 'HEAD^{tree}')" HEAD 2> /dev/null
check "note on tree and commit is judged once" "g1 g2" "$R"

# At most 32 blocks are read. 31 stranger blocks then a valid one is covered;
# 39 then a valid one is not.
make_repo "$R" signer@example.org "$WORK/key"
stranger=$(sign_block "$R" "$(payload_for "$R" g0 "$PLATFORM")" "$WORK/other")
valid=$(sign_block "$R" "$(payload_for "$R" g1 "$PLATFORM")" "$WORK/key")
many() { local _; for _ in $(seq "$1"); do printf '%s\n\n' "$stranger"; done; printf '%s' "$valid"; }
raw_note "$R" "$(many 31)"
check "the 32nd block is still read" "g1" "$R"
raw_note "$R" "$(many 39)"
check "the 40th block is not read" "" "$R"

# --- input fingerprints (1.3.0) ---------------------------------------------
# A committed spec names the paths a gate reads; the gate is then covered on
# ANY tree whose declared inputs are byte-identical. Every fixture here moves
# the tree (an unrelated commit) before checking, or the tree route would
# answer and prove nothing.

# A repository with sources, a spec naming them, and helpers for the cases.
fp_repo() { # [spec-lines...]  (default: "test src Cargo.toml" and "lint src")
    make_repo "$R" signer@example.org "$WORK/key"
    mkdir -p "$R/src" "$R/docs" "$R/tests"
    echo 'fn main() {}' > "$R/src/main.rs"; echo doc > "$R/docs/README.md"
    echo '[package]' > "$R/Cargo.toml"; echo 'x' > "$R/tests/t.sh"
    git -C "$R" add -A; git -C "$R" commit -q -m src
    if [ $# -gt 0 ]; then printf '%s\n' "$@"; else printf 'test src Cargo.toml\nlint src\n'; fi | write_spec "$R"
}
# Attest `test` (and any other gates in $2) under its fingerprint key.
attest_fp() { # gate [gates-in-payload] [inputs-override]
    local g=$1 gates=${2:-$1} fp inputs
    fp=$(fp_of "$R" "$g")
    inputs=${3:-"$g=$fp"}
    attach_input "$R" "$(payload_for "$R" "$gates" "$PLATFORM" "" "$inputs")" "$WORK/key" "$g" "$fp"
}

fp_repo; attest_fp test; move_tree "$R"
check "fp: tree moved, declared inputs unchanged: covered" "test" "$R"
check "fp: from a subdirectory, the same answer" "test" "$R/docs"

fp_repo
fp=$(fp_of "$R" test)
attach_input "$R" "$(payload_for "$R" other "$PLATFORM" "" "other=$fp")" "$WORK/key" other "$fp"
move_tree "$R"
check "fp: a gate the spec does not declare is never looked up" "" "$R"

fp_repo; attest_fp test
echo 'fn main() { changed }' > "$R/src/main.rs"; git -C "$R" commit -qam src2
check "fp: a declared file changed: nothing" "" "$R"

fp_repo; attest_fp test
printf '# a comment\ntest src Cargo.toml\nlint src\n' | write_spec "$R"
check "fp: the spec edited (comment only): nothing" "" "$R"

fp_repo; attest_fp test "test lint"; move_tree "$R"
check "fp: block lists test and lint, claims test only: test only" "test" "$R"

fp_repo
fp=$(fp_of "$R" test)
attach_note "$R" "$(payload_for "$R" "test lint" "$PLATFORM" "" "test=$fp")" "$WORK/key"
check "fp: the same block via the tree key, tree equal: both gates" "test lint" "$R"

fp_repo; attest_fp test lint; move_tree "$R"
check "fp: a claim for a gate absent from gates buys nothing" "" "$R"

fp_repo
fp=$(fp_of "$R" test)
attach_input "$R" "$(payload_for "$R" test "$PLATFORM" "" "test=$(printf 'a%.0s' $(seq 40))")" "$WORK/key" test "$fp"
move_tree "$R"
check "fp: block under K(fp1) whose payload claims fp2: nothing" "" "$R"

fp_repo
fp=$(fp_of "$R" test)
attach_input "$R" "$(payload_for "$R" test "$PLATFORM")" "$WORK/key" test "$fp"
move_tree "$R"
check "fp: block under K with no input line: nothing" "" "$R"

fp_repo
fp=$(fp_of "$R" test)
wrong=$(printf 'b%.0s' $(seq 40))
body=$(sign_block "$R" "$(payload_for "$R" test "$PLATFORM" "" "test=$wrong")" "$WORK/key")
raw_input_note "$R" "$(printf '%s' "$body" | sed "s/input test $wrong/input test $fp/")" test "$fp"
move_tree "$R"
check "fp: input line edited after signing: nothing" "" "$R"

fp_repo
fp=$(fp_of "$R" test)
attach_input "$R" "$(payload_for "$R" test "$PLATFORM" | sed "/^platform /a\\
input test $fp junk")" "$WORK/key" test "$fp"
move_tree "$R"
check "fp: an input line with a fourth field is not a claim" "" "$R"
fp_repo
fp=$(fp_of "$R" test)
attach_input "$R" "$(payload_for "$R" test "$PLATFORM" "" "test=${fp%?}")" "$WORK/key" test "$fp"
move_tree "$R"
check "fp: a 39-hex fingerprint is not a claim" "" "$R"

# `--anywhere` composes: platform and inputs are independent filters.
fp_repo
fp=$(fp_of "$R" test)
attach_input "$R" "$(payload_for "$R" test s390x-aix "" "test=$fp")" "$WORK/key" test "$fp"
move_tree "$R"
check "fp: foreign platform, matching inputs: nothing by default" "" "$R"
check "fp: foreign platform, matching inputs, --anywhere: covered" "test" "$R" --anywhere test
fp_repo
fp=$(fp_of "$R" test)
attach_input "$R" "$(payload_for "$R" test s390x-aix "" "test=$(printf 'c%.0s' $(seq 40))")" "$WORK/key" test "$fp"
move_tree "$R"
check "fp: --anywhere never rescues a wrong fingerprint" "" "$R" --anywhere test

# The grammar: any violation invalidates the WHOLE spec. The fixture computes
# the key the spec WOULD have used and proves nobody looks there.
bad_spec() { # name spec-file   (a file, not a variable — a variable cannot hold
    local name=$1 fp                #  a NUL — and not a pipe, which would run this in a
    fp_repo                         #  subshell and lose the pass/fail counters)
    write_spec "$R" < "$2"
    fp=$(fp_of "$R" test 2> /dev/null) || fp=$(printf 'd%.0s' $(seq 40))
    attach_input "$R" "$(payload_for "$R" test "$PLATFORM" "" "test=$fp")" "$WORK/key" test "$fp"
    move_tree "$R"
    check "fp: invalid spec — $name" "" "$R"
}
printf 'test src Cargo.toml tests/*.sh\n' > "$WORK/badspec"
bad_spec "a wildcard (ls-tree does not glob)" "$WORK/badspec"
printf 'test src :!docs\n' > "$WORK/badspec"
bad_spec "exclude magic" "$WORK/badspec"
printf 'test src :(glob)src/*.rs\n' > "$WORK/badspec"
bad_spec "glob magic" "$WORK/badspec"
printf 'test :/src\n' > "$WORK/badspec"
bad_spec "top magic" "$WORK/badspec"
printf 'test ./src\n' > "$WORK/badspec"
bad_spec "a ./ prefix" "$WORK/badspec"
printf 'test /src\n' > "$WORK/badspec"
bad_spec "an absolute path" "$WORK/badspec"
printf 'test src/\n' > "$WORK/badspec"
bad_spec "a trailing slash" "$WORK/badspec"
printf 'test src/../src\n' > "$WORK/badspec"
bad_spec "a .. component" "$WORK/badspec"
printf 'test src\r\n' > "$WORK/badspec"
bad_spec "a carriage return" "$WORK/badspec"
printf 'test src\n# \000\n' > "$WORK/badspec"
bad_spec "an embedded NUL" "$WORK/badspec"
printf 'test src\n# caf\303\251\n' > "$WORK/badspec"
bad_spec "a non-ASCII byte" "$WORK/badspec"
printf 'test\302\240src\n' > "$WORK/badspec"
bad_spec "a no-break space" "$WORK/badspec"
printf 'test src\n# \001\n' > "$WORK/badspec"
bad_spec "a control byte" "$WORK/badspec"
printf 'test src\nlint/x src\n' > "$WORK/badspec"
bad_spec "a gate name with a slash" "$WORK/badspec"
printf 'test src\nlint\n' > "$WORK/badspec"
bad_spec "a gate declaring no paths" "$WORK/badspec"
printf 'test src\ntest Cargo.toml\n' > "$WORK/badspec"
bad_spec "a duplicate gate" "$WORK/badspec"
printf 'test src\n'; for i in $(seq 64); do printf 'g%s src\n' "$i"; done > "$WORK/badspec"
bad_spec "65 gates" "$WORK/badspec"
printf 'test src'; for _ in $(seq 64); do printf ' Cargo.toml'; done; printf '\n' > "$WORK/badspec"
bad_spec "65 paths" "$WORK/badspec"
printf 'test src\n'; head -c 65528 /dev/zero | tr '\0' '\n' > "$WORK/badspec"
bad_spec "65537 bytes" "$WORK/badspec"
# 65536 bytes, mostly newlines, is valid.
fp_repo
{ printf 'test src Cargo.toml\n'; head -c 65516 /dev/zero | tr '\0' '\n'; } | write_spec "$R"
attest_fp test; move_tree "$R"
check "fp: a 65536-byte spec of mostly newlines is valid" "test" "$R"
# 64 gates and 64 paths are valid.
fp_repo
{ printf 'test src Cargo.toml\n'; for i in $(seq 63); do printf 'g%s src\n' "$i"; done; } | write_spec "$R"
attest_fp test; move_tree "$R"
check "fp: 64 gates are valid" "test" "$R"

# A declared path deleted after signing: that gate loses its fingerprint, the
# others keep theirs.
fp_repo
attest_fp test; attest_fp lint
git -C "$R" rm -q Cargo.toml; git -C "$R" commit -qm rm
check "fp: a declared path deleted: that gate loses its fingerprint, others keep it" "lint" "$R"

# Both spec locations present: the route is disabled.
fp_repo; attest_fp test
printf 'test src Cargo.toml\nlint src\n' | write_spec "$R" .forgejo
check "fp: both .forgejo and .github specs: nothing" "" "$R"
# .forgejo alone works; and moving the SAME content to the other location
# changes the fingerprint, which proves both paths are in the listing.
make_repo "$R" signer@example.org "$WORK/key"
mkdir -p "$R/src"; echo 'fn main() {}' > "$R/src/main.rs"; echo '[package]' > "$R/Cargo.toml"
git -C "$R" add -A; git -C "$R" commit -q -m src
printf 'test src Cargo.toml\n' | write_spec "$R" .forgejo
attest_fp test; move_tree "$R"
check "fp: a .forgejo spec works" "test" "$R"
git -C "$R" mv -q .forgejo/attest-inputs .github/attest-inputs 2> /dev/null || { mkdir -p "$R/.github"; git -C "$R" mv .forgejo/attest-inputs .github/attest-inputs; }
git -C "$R" commit -qm move
check "fp: the same spec at the other location is a different fingerprint" "" "$R"

# Modes, symlinks, directory boundaries, ancestor attributes.
fp_repo; attest_fp test
git -C "$R" update-index --chmod=+x Cargo.toml; git -C "$R" commit -qm chmod
check "fp: a declared file's mode changed: nothing" "" "$R"
if [ "$OS" != windows ]; then
    fp_repo
    ln -s main.rs "$R/src/link.rs"; git -C "$R" add -A; git -C "$R" commit -qm link
    attest_fp test
    rm "$R/src/link.rs"; ln -s ../Cargo.toml "$R/src/link.rs"; git -C "$R" add -A; git -C "$R" commit -qm retarget
    check "fp: a declared symlink retargeted: nothing" "" "$R"
fi
fp_repo "test tests"; attest_fp test
echo new > "$R/tests/new.sh"; git -C "$R" add -A; git -C "$R" commit -qm new
check "fp: a file added inside a declared directory: nothing" "" "$R"
fp_repo "test tests"; attest_fp test
mkdir -p "$R/testsuite"; echo new > "$R/testsuite/new.sh"; git -C "$R" add -A; git -C "$R" commit -qm new
check "fp: a directory that merely shares a prefix is not the declared one" "test" "$R"
fp_repo; attest_fp test
echo '* text=auto' > "$R/.gitattributes"; git -C "$R" add -A; git -C "$R" commit -qm attrs
check "fp: a root .gitattributes added: nothing" "" "$R"
make_repo "$R" signer@example.org "$WORK/key"
mkdir -p "$R/crates/foo/src"; echo 'fn main() {}' > "$R/crates/foo/src/main.rs"
git -C "$R" add -A; git -C "$R" commit -q -m src
printf 'test crates/foo/src\n' | write_spec "$R"
attest_fp test
echo '* eol=crlf' > "$R/crates/.gitattributes"; git -C "$R" add -A; git -C "$R" commit -qm attrs
check "fp: a .gitattributes at an ancestor of a declared path: nothing" "" "$R"

# Fault injection: a git that fails must never yield a fingerprint.
fp_repo; attest_fp test; move_tree "$R"
check_faulty "fp: ls-tree failing after one record: nothing" ls-tree "" "$R"
check_faulty "fp: cat-file failing to read the spec: nothing" cat-file "" "$R"

# A sha256 repository: 64-hex trees, fingerprints and keys.
if GIT_DEFAULT_HASH=sha256 git init -q "$WORK/probe256" 2> /dev/null; then
    rm -rf "$WORK/probe256"
    GIT_DEFAULT_HASH=sha256 fp_repo; attest_fp test; move_tree "$R"
    check "fp: a sha256 repository" "test" "$R"
fi

# Caps and budget. Strangers are signed by a key in no file.
fp_repo
fp=$(fp_of "$R" test)
stranger_block() { sign_block "$R" "$(payload_for "$R" "s$1" "$PLATFORM" "" "test=$fp")" "$WORK/other"; }
valid_block=$(sign_block "$R" "$(payload_for "$R" test "$PLATFORM" "" "test=$fp")" "$WORK/key")
blocks() { local i; for i in $(seq "$1"); do stranger_block "$i"; printf '\n\n'; done; printf '%s' "$valid_block"; }
raw_input_note "$R" "$(blocks 31)" test "$fp"; move_tree "$R"
check "fp: the 32nd block under a fingerprint key is read" "test" "$R"
raw_input_note "$R" "$(blocks 32)" test "$fp"
check "fp: the 33rd block under a fingerprint key is not" "" "$R"
# 64 distinct strangers across the tree note and the commit note spend the
# budget before the valid block under the key is reached.
fp_repo
fp=$(fp_of "$R" test)
valid_block=$(sign_block "$R" "$(payload_for "$R" test "$PLATFORM" "" "test=$fp")" "$WORK/key")
strangers() { local i; for i in $(seq "$1" "$2"); do stranger_block "$i"; [ "$i" -lt "$2" ] && printf '\n\n'; done; }
raw_note "$R" "$(strangers 1 32)"
raw_note "$R" "$(strangers 33 64)" HEAD
raw_input_note "$R" "$valid_block" test "$fp"
move_tree "$R"
raw_note "$R" "$(strangers 1 32)"; raw_note "$R" "$(strangers 33 64)" HEAD
check "fp: 64 verifications spend the budget before the key is reached" "" "$R"
raw_note "$R" "$(strangers 33 63)" HEAD
check "fp: 63 leave room for the valid block" "test" "$R"

# A 1.2.0-shaped payload (no input line) on a moved tree: nothing.
fp_repo
attach_note "$R" "$(payload_for "$R" test "$PLATFORM")" "$WORK/key"
move_tree "$R"
check "fp: a payload without input lines on a moved tree: nothing" "" "$R"

# Covered by both routes: listed once.
fp_repo
fp=$(fp_of "$R" test)
attach_note "$R" "$(payload_for "$R" test "$PLATFORM" "" "test=$fp")" "$WORK/key"
attach_input "$R" "$(payload_for "$R" test "$PLATFORM" "" "test=$fp")" "$WORK/key" test "$fp"
check "fp: covered by tree and by fingerprint, listed once" "test" "$R"

# --- gate names are literal, never globs ------------------------------------
# A signed gate called `pre-push-*` next to a FILE called pre-push-cargo-test
# must come out as `pre-push-*`, not as the file's name: word-splitting the
# gate list with globbing on would cover a gate nobody signed.
make_repo "$R" signer@example.org "$WORK/key"
echo x > "$R/pre-push-cargo-test"; git -C "$R" add -A; git -C "$R" commit -q -m decoy
attach_note "$R" "$(payload_for "$R" 'pre-push-*' "$PLATFORM")" "$WORK/key"
check "a wildcard gate name is not expanded against the working tree" 'pre-push-*' "$R"
check "...nor when admitted by --anywhere" 'pre-push-*' "$R" --platform s390x-aix --anywhere 'pre-push-*'

# --- the JSON shape the actions publish ------------------------------------
if [ "${SKIP_JSON:-}" != 1 ]; then
    make_repo "$R" signer@example.org "$WORK/key"
    attach_note "$R" "$(payload_for "$R" pre-push-cargo-test "$PLATFORM")" "$WORK/key"
    check "json array output" '["pre-push-cargo-test"]' "$R" --json
    make_repo "$R" signer@example.org "$WORK/key"
    check "json empty array when uncovered" '[]' "$R" --json

    # (defect 2) A gate whose name merely CONTAINS the one being asked about.
    # Substring matching skips the real suite here; array membership does not.
    attach_note "$R" "$(payload_for "$R" pre-push-cargo-test-slow "$PLATFORM")" "$WORK/key"
    check "prefix-colliding gate stays distinct" '["pre-push-cargo-test-slow"]' "$R" --json

    # "Signed" is not "well-formed". A control character in a gate name must
    # leave as \u00xx: a raw one makes the consumer's fromJSON throw, which
    # FAILS the job — the one outcome the contract says cannot happen.
    attach_note "$R" "$(payload_for "$R" "$(printf 'pre-push-cargo\001test')" "$PLATFORM")" "$WORK/key"
    check "control character in a gate name is escaped" '["pre-push-cargo\u0001test"]' "$R" --json

    # The exact bytes both actions append to $GITHUB_OUTPUT. `covered` is kept
    # only so workflows written against the old templates keep working.
    make_repo "$R" signer@example.org "$WORK/key"
    attach_note "$R" "$(payload_for "$R" "pre-push-cargo-test pre-push-clippy" "$PLATFORM")" "$WORK/key"
    check "github-output emits both forms" \
        'covered=pre-push-cargo-test pre-push-clippy gates=["pre-push-cargo-test","pre-push-clippy"]' \
        "$R" --github-output
    make_repo "$R" signer@example.org "$WORK/key"
    check "github-output when uncovered is still well-formed" \
        'covered= gates=[]' "$R" --github-output
fi

summary
