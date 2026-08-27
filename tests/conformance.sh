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

IMPL=${1:?usage: conformance.sh <implementation command>}
PASS=0; FAIL=0; FAILED_CASES=

ARCH=$(uname -m); case "$ARCH" in arm64 | aarch64) ARCH=aarch64 ;; esac
case "$(uname -s)" in Darwin) OS=macos ;; Linux) OS=linux ;; *) OS=windows ;; esac
PLATFORM=$ARCH-$OS

WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

ssh-keygen -q -t ed25519 -N '' -C signer@example.org -f "$WORK/key"
ssh-keygen -q -t ed25519 -N '' -C signer@example.org -f "$WORK/other"

# A repository with one commit, an allowed_signers naming `principal`, and
# optionally a note built from the given payload lines.
#
# `core.hooksPath=/dev/null` because this suite runs on a machine where amont's
# own hooks are installed globally via init.templateDir; without it the fixture
# commits are judged by the host's commit-msg policy.
make_repo() {
    local dir=$1 principal=$2 keyfile=$3
    rm -rf "$dir"; mkdir -p "$dir/.github"
    git init -q "$dir"
    git -C "$dir" config core.hooksPath /dev/null
    git -C "$dir" config user.email signer@example.org
    git -C "$dir" config user.name Signer
    printf '%s namespaces="amont-attest" %s\n' "$principal" "$(cat "$keyfile.pub")" \
        > "$dir/.github/allowed_signers"
    echo content > "$dir/file.txt"
    git -C "$dir" add -A
    git -C "$dir" commit -q -m init
}

# Sign `payload` with `keyfile` and attach it to the repo's HEAD tree.
attach_note() {
    local dir=$1 payload=$2 keyfile=$3
    # The payload's TRAILING NEWLINE is part of the signed bytes (SPEC.md).
    # Command substitution ate it when `payload` was captured, so it goes back
    # on here — signing the four lines without it produces a signature that is
    # valid over bytes no verifier will ever reconstruct.
    printf '%s\n' "$payload" > "$dir/.p"
    ssh-keygen -Y sign -n amont-attest -f "$keyfile" "$dir/.p" > /dev/null 2>&1
    # payload + its newline + a blank line + the armored signature.
    git -C "$dir" notes --ref amont-attest add -f \
        -m "$(printf '%s\n\n%s' "$payload" "$(cat "$dir/.p.sig")")" \
        "$(git -C "$dir" rev-parse 'HEAD^{tree}')" 2> /dev/null
    rm -f "$dir/.p" "$dir/.p.sig"
}

payload_for() { # dir gates platform [format]
    printf 'amont-attest-v2\ntree %s\ngates %s\nplatform %s\namont 1.23.0\n' \
        "$(git -C "$1" rev-parse 'HEAD^{tree}')" "$2" "$3" | sed "1s/.*/${4:-amont-attest-v2}/"
}

check() { # name expected-stdout dir [extra flags...]
    local name=$1 want=$2 dir=$3; shift 3
    local got rc
    # $IMPL is a command LINE ("git-attest covered") and must word-split;
    # the flags after it must not. Rebuilding the positional parameters does
    # both, and without `eval` — which would re-split the flags too.
    # shellcheck disable=SC2086
    got=$(cd "$dir" && set -- $IMPL "$@" && "$@" 2> /dev/null); rc=$?
    got=$(printf '%s' "$got" | tr -s '[:space:]' ' ' | sed 's/^ *//;s/ *$//')
    if [ "$got" = "$want" ] && [ "$rc" -eq 0 ]; then
        PASS=$((PASS + 1)); printf '  ok    %s\n' "$name"
    else
        FAIL=$((FAIL + 1)); FAILED_CASES="$FAILED_CASES\n    $name"
        printf '  FAIL  %s\n         want %-28s got %s (exit %s)\n' \
            "$name" "[$want]" "[$got]" "$rc"
    fi
}

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

# --- everything that must NOT cover ---------------------------------------
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

# The tree is what the signature covers, so an amend that preserves it keeps
# its attestation. This is the property that survives a forge's squash-merge.
git -C "$R" commit -q --amend -m "reworded, same tree"
check "survives a reword (same tree)" "pre-push-cargo-test" "$R"

# --- the JSON shape the actions publish ------------------------------------
if [ "${SKIP_JSON:-}" != 1 ]; then
    check "json array output" '["pre-push-cargo-test"]' "$R" --json
    make_repo "$R" signer@example.org "$WORK/key"
    check "json empty array when uncovered" '[]' "$R" --json

    # (defect 2) A gate whose name merely CONTAINS the one being asked about.
    # Substring matching skips the real suite here; array membership does not.
    attach_note "$R" "$(payload_for "$R" pre-push-cargo-test-slow "$PLATFORM")" "$WORK/key"
    check "prefix-colliding gate stays distinct" '["pre-push-cargo-test-slow"]' "$R" --json

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

printf '\n  %s passed, %s failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || { printf '  failing:%b\n' "$FAILED_CASES"; exit 1; }
