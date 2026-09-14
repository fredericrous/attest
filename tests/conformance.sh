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
ssh-keygen -q -t ed25519 -N '' -C second@example.org -f "$WORK/second"
ssh-keygen -q -t ed25519 -N '' -C signer@example.org -f "$WORK/other"

# A repository with one commit and an allowed_signers naming `principal` —
# and, when a second pair is given, a second signer after it.
#
# `core.hooksPath=/dev/null` because this suite runs on a machine where amont's
# own hooks are installed globally via init.templateDir; without it the fixture
# commits are judged by the host's commit-msg policy.
make_repo() { # dir principal keyfile [principal2 keyfile2]
    local dir=$1 principal=$2 keyfile=$3
    rm -rf "$dir"; mkdir -p "$dir/.github"
    git init -q "$dir"
    git -C "$dir" config core.hooksPath /dev/null
    git -C "$dir" config user.email signer@example.org
    git -C "$dir" config user.name Signer
    printf '%s namespaces="amont-attest" %s\n' "$principal" "$(cat "$keyfile.pub")" \
        > "$dir/.github/allowed_signers"
    [ $# -lt 5 ] || printf '%s namespaces="amont-attest" %s\n' "$4" "$(cat "$5.pub")" \
        >> "$dir/.github/allowed_signers"
    echo content > "$dir/file.txt"
    git -C "$dir" add -A
    git -C "$dir" commit -q -m init
}

# Sign `payload` with `keyfile` and attach it to the repo's HEAD tree — or to
# `target`, for a producer that keyed by commit.
attach_note() { # dir payload keyfile [target]
    local dir=$1 payload=$2 keyfile=$3 target=${4:-}
    [ -n "$target" ] || target=$(git -C "$dir" rev-parse 'HEAD^{tree}')
    # The payload's TRAILING NEWLINE is part of the signed bytes (SPEC.md).
    # Command substitution ate it when `payload` was captured, so it goes back
    # on here — signing the four lines without it produces a signature that is
    # valid over bytes no verifier will ever reconstruct.
    printf '%s\n' "$payload" > "$dir/.p"
    ssh-keygen -Y sign -n amont-attest -f "$keyfile" "$dir/.p" > /dev/null 2>&1
    # payload + its newline + a blank line + the armored signature.
    git -C "$dir" notes --ref amont-attest add -f \
        -m "$(printf '%s\n\n%s' "$payload" "$(cat "$dir/.p.sig")")" "$target" 2> /dev/null
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

# A usage error: exit 2 and NOTHING on stdout. The one exception to "always
# exit 0", because a typo in a flag is the author's mistake, not the
# repository's state — and a verifier that silently ignored `--platfrom any`
# would just never cover anything.
check_usage() { # name dir [flags...]
    local name=$1 dir=$2; shift 2
    local got rc
    # shellcheck disable=SC2086
    got=$(cd "$dir" && set -- $IMPL "$@" && "$@" 2> /dev/null); rc=$?
    if [ -z "$got" ] && [ "$rc" -eq 2 ]; then
        PASS=$((PASS + 1)); printf '  ok    %s\n' "$name"
    else
        FAIL=$((FAIL + 1)); FAILED_CASES="$FAILED_CASES\n    $name"
        printf '  FAIL  %s\n         want exit 2, nothing on stdout; got [%s] (exit %s)\n' \
            "$name" "$got" "$rc"
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

# --- the JSON shape the actions publish ------------------------------------
if [ "${SKIP_JSON:-}" != 1 ]; then
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

printf '\n  %s passed, %s failed\n' "$PASS" "$FAIL"
[ "$FAIL" -eq 0 ] || { printf '  failing:%b\n' "$FAILED_CASES"; exit 1; }
