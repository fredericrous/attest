# shellcheck shell=bash
# Shared by tests/conformance.sh, tests/compat.sh and tests/sign.sh. Sourced,
# not run. The caller sets WORK (a scratch directory it removes on exit) and
# IMPL (the implementation command line) before sourcing.

ARCH=$(uname -m); case "$ARCH" in arm64 | aarch64) ARCH=aarch64 ;; esac
case "$(uname -s)" in Darwin) OS=macos ;; Linux) OS=linux ;; *) OS=windows ;; esac
# shellcheck disable=SC2034  # used by the sourcing scripts
PLATFORM=$ARCH-$OS

PASS=0; FAIL=0; FAILED_CASES=

# Three ed25519 keys: the signer, a second signer for the same file, and a
# stranger whose key is in no file.
gen_keys() {
    ssh-keygen -q -t ed25519 -N '' -C signer@example.org -f "$WORK/key"
    ssh-keygen -q -t ed25519 -N '' -C second@example.org -f "$WORK/second"
    ssh-keygen -q -t ed25519 -N '' -C signer@example.org -f "$WORK/other"
}

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

payload_for() { # dir gates platform [format]
    printf 'amont-attest-v2\ntree %s\ngates %s\nplatform %s\namont 1.23.0\n' \
        "$(git -C "$1" rev-parse 'HEAD^{tree}')" "$2" "$3" | sed "1s/.*/${4:-amont-attest-v2}/"
}

# Sign `payload` with `keyfile` and print the BLOCK: payload, a blank line, the
# armored signature.
#
# The payload's TRAILING NEWLINE is part of the signed bytes (SPEC.md). Command
# substitution ate it when `payload` was captured, so it goes back on here —
# signing the lines without it produces a signature that is valid over bytes
# no verifier will ever reconstruct.
sign_block() { # dir payload keyfile
    printf '%s\n' "$2" > "$1/.p"
    rm -f "$1/.p.sig"
    ssh-keygen -Y sign -n amont-attest -f "$3" "$1/.p" > /dev/null 2>&1
    printf '%s\n\n%s' "$2" "$(cat "$1/.p.sig")"
    rm -f "$1/.p" "$1/.p.sig"
}

# A signed block as THE note on the HEAD tree (or `target`), replacing any.
attach_note() { # dir payload keyfile [target]
    local dir=$1 payload=$2 keyfile=$3 target=${4:-}
    [ -n "$target" ] || target=$(git -C "$dir" rev-parse 'HEAD^{tree}')
    git -C "$dir" notes --ref amont-attest add -f \
        -m "$(sign_block "$dir" "$payload" "$keyfile")" "$target" 2> /dev/null
}

# A signed block APPENDED to the note — the real producer path, and the shape
# every multi-block note in the wild has.
append_note() { # dir payload keyfile [target]
    local dir=$1 payload=$2 keyfile=$3 target=${4:-}
    [ -n "$target" ] || target=$(git -C "$dir" rev-parse 'HEAD^{tree}')
    git -C "$dir" notes --ref amont-attest append \
        -m "$(sign_block "$dir" "$payload" "$keyfile")" "$target" 2> /dev/null
}

# Arbitrary bytes as the note, verbatim: `-C` reuses a blob and runs no
# stripspace, which is how a note with two blank lines, a CRLF body or trailing
# garbage gets built.
raw_note() { # dir content [target]
    local dir=$1 content=$2 target=${3:-} blob
    [ -n "$target" ] || target=$(git -C "$dir" rev-parse 'HEAD^{tree}')
    blob=$(printf '%s' "$content" | git -C "$dir" hash-object -w --stdin)
    git -C "$dir" notes --ref amont-attest add -f -C "$blob" "$target" 2> /dev/null
}

# Run $IMPL in `dir` with the flags; stdout normalised to single spaces.
run_impl() { # dir [flags...]
    local dir=$1; shift
    # $IMPL is a command LINE ("git-attest covered") and must word-split;
    # the flags after it must not. Rebuilding the positional parameters does
    # both, and without `eval` — which would re-split the flags too.
    # shellcheck disable=SC2086
    GOT=$(cd "$dir" && set -- $IMPL "$@" && "$@" 2> /dev/null); RC=$?
    GOT=$(printf '%s' "$GOT" | tr -s '[:space:]' ' ' | sed 's/^ *//;s/ *$//')
}

ok()   { PASS=$((PASS + 1)); printf '  ok    %s\n' "$1"; }
fail() { FAIL=$((FAIL + 1)); FAILED_CASES="$FAILED_CASES\n    $1"; printf '  FAIL  %s\n         %s\n' "$1" "$2"; }

check() { # name expected-stdout dir [extra flags...]
    local name=$1 want=$2 dir=$3; shift 3
    run_impl "$dir" "$@"
    if [ "$GOT" = "$want" ] && [ "$RC" -eq 0 ]; then ok "$name"
    else fail "$name" "$(printf 'want %-28s got %s (exit %s)' "[$want]" "[$GOT]" "$RC")"; fi
}

# Any one of several acceptable outputs, `|`-separated. For a frozen verifier
# that may legitimately under-report.
check_one_of() { # name "alt1|alt2" dir [extra flags...]
    local name=$1 alts=$2 dir=$3; shift 3
    run_impl "$dir" "$@"
    case "|$alts|" in
        *"|$GOT|"*) [ "$RC" -eq 0 ] && { ok "$name"; return; } ;;
    esac
    fail "$name" "$(printf 'want one of %-20s got %s (exit %s)' "[$alts]" "[$GOT]" "$RC")"
}

# A usage error: exit 2 and NOTHING on stdout. The one exception to "always
# exit 0", because a typo in a flag is the author's mistake, not the
# repository's state — and a verifier that silently ignored `--platfrom any`
# would just never cover anything.
check_usage() { # name dir [flags...]
    local name=$1 dir=$2; shift 2
    run_impl "$dir" "$@"
    if [ -z "$GOT" ] && [ "$RC" -eq 2 ]; then ok "$name"
    else fail "$name" "$(printf 'want exit 2, nothing on stdout; got [%s] (exit %s)' "$GOT" "$RC")"; fi
}

summary() {
    printf '\n  %s passed, %s failed\n' "$PASS" "$FAIL"
    [ "$FAIL" -eq 0 ] || { printf '  failing:%b\n' "$FAILED_CASES"; exit 1; }
}
