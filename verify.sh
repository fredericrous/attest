#!/usr/bin/env bash
# The one copy of the attest verifier.
#
#   verify.sh [--signers PATH] [--principal ID] [--platform P|any]
#             [--json | --github-output] [--quiet]
#
# Prints the gate names a VALID attestation covers for the tree checked out
# here, space-separated, on stdout. Prints NOTHING when nothing is covered.
#
# `--json` prints them as a JSON array instead, and that is the form the
# actions publish. It exists because GitHub's `contains()` is a SUBSTRING test
# over a string and an ELEMENT test over an array: with a plain list,
# `contains(covered, 'pre-push-cargo-test')` is satisfied by an unrelated gate
# named `pre-push-cargo-test-slow`, and the real suite gets skipped on an
# attestation that never covered it. `contains(fromJSON(gates), ...)` cannot.
#
# EXIT 0 ALWAYS, covered or not. That is the contract, not an oversight: a
# verifier that can fail a build has turned a CI accelerator into a CI
# dependency, and every failure mode here — no note, no key, no ssh-keygen, a
# tree that moved — has the same correct answer, which is "run the tests".
# Usage errors exit 2, because those are the author's mistake, not the
# repository's state.
#
# The reason for every non-answer goes to STDERR unless --quiet. Silence is
# this design's worst property: when a skip does not happen, nothing tells you
# whether the attestation was absent, stale, signed by the wrong key, or minted
# on another platform. A CI log is exactly the place to spend four lines saying
# which.
#
# Depends on `git` and `ssh-keygen` only. See SPEC.md for the format.
set -u

FORMAT=amont-attest-v2
NOTES_REF=amont-attest
NAMESPACE=amont-attest

signers=; principal=; platform=; quiet=; mode=plain

while [ $# -gt 0 ]; do
    case "$1" in
        --signers)   signers=${2-};   shift 2 || exit 2 ;;
        --principal) principal=${2-}; shift 2 || exit 2 ;;
        --platform)  platform=${2-};  shift 2 || exit 2 ;;
        --json)          mode=json; shift ;;
        --github-output) mode=gha;  shift ;;
        --quiet)     quiet=1; shift ;;
        -h|--help)   sed -n '2,34p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) printf 'verify.sh: unknown argument %s\n' "$1" >&2; exit 2 ;;
    esac
done

# A producer writes its note to BOTH the tree and the commit, so the candidate
# loop below meets the same note twice and would otherwise report every
# rejection twice — which reads like two problems rather than one seen twice.
last_note=
note() {
    [ -n "$quiet" ] && return 0
    [ "$1" = "$last_note" ] && return 0
    last_note=$1
    printf 'attest: %s\n' "$1" >&2
}

# Gate names as a JSON array.
#
# Escaping rather than trusting the input: the names come from a signed
# document, but "signed" is not "well-formed", and a stray quote reaching a
# workflow output would be the one way a note could corrupt the YAML consuming
# it. Control characters go out as \u00xx, which JSON requires.
to_json() {
    printf '%s\n' "$1" | awk '{
        out = "["
        for (i = 1; i <= NF; i++) {
            g = $i
            gsub(/\\/, "\\\\", g)
            gsub(/"/, "\\\"", g)
            out = out (i > 1 ? "," : "") "\"" g "\""
        }
        print out "]"
    }'
}

# The ONE place gates reach stdout, in whichever shape the caller asked for.
# An empty argument means nothing is covered, and every mode has a well-formed
# way to say that — so a caller can parse the output unconditionally instead of
# guarding it.
#
# `--github-output` emits both forms, ready to append to $GITHUB_OUTPUT:
#
#   covered=pre-push-cargo-test        (legacy; a SUBSTRING match downstream)
#   gates=["pre-push-cargo-test"]      (use this one)
#
# Both live here rather than in the two action.yml files, so the escaping above
# has one implementation and `tests/conformance.sh` can reach it.
emit() {
    case $mode in
        plain) [ -z "$1" ] || printf '%s\n' "$1" ;;
        json)  to_json "$1" ;;
        gha)   printf 'covered=%s\n' "$1"; printf 'gates=%s\n' "$(to_json "$1")" ;;
    esac
}

uncovered() { note "$1"; emit ""; exit 0; }

command -v git        > /dev/null 2>&1 || uncovered "no git on PATH"
command -v ssh-keygen > /dev/null 2>&1 || uncovered "no ssh-keygen on PATH; nothing can be verified"

root=$(git rev-parse --show-toplevel 2> /dev/null) || uncovered "not a git repository"

# Resolved from the REPOSITORY ROOT, not the working directory. A workflow that
# sets `working-directory` (a monorepo matrix running inside `packages/<x>`)
# would otherwise find no signers, print nothing, and fail open forever —
# silently, with CI still green. That is the worst shape a fail-open can take.
if [ -z "$signers" ]; then
    for candidate in .forgejo/allowed_signers .github/allowed_signers; do
        [ -f "$root/$candidate" ] && { signers=$root/$candidate; break; }
    done
elif [ "${signers#/}" = "$signers" ]; then
    signers=$root/$signers
fi
[ -n "$signers" ] && [ -f "$signers" ] || uncovered \
    "no allowed_signers (looked for .forgejo/ and .github/allowed_signers at $root)"

# The identity to verify as. `ssh-keygen -Y verify` REQUIRES one and checks it
# against the principal column, so a wrong value rejects a perfectly good
# signature — quietly, since every rejection here means "run the tests".
#
# Defaulting to the file's first entry is what makes this safe to copy. The
# templates this replaces hardcoded `-I you@example.com`, so anyone who wrote
# their real address into allowed_signers — the obvious thing — got a gate that
# never fired and never said so.
if [ -z "$principal" ]; then
    principal=$(awk '!/^[[:space:]]*#/ && NF { print $1; exit }' "$signers")
    [ -n "$principal" ] || uncovered "$signers names no principal"
fi

# Best-effort: a repository that has never been pushed with attest enabled has
# no such ref, and that is not an error.
git fetch origin "+refs/notes/$NOTES_REF:refs/notes/$NOTES_REF" > /dev/null 2>&1

head_tree=$(git rev-parse 'HEAD^{tree}' 2> /dev/null) || uncovered "cannot resolve HEAD^{tree}"

if [ -z "$platform" ]; then
    case "$(uname -m)" in
        arm64 | aarch64) arch=aarch64 ;;
        *) arch=$(uname -m) ;;
    esac
    case "$(uname -s)" in
        Darwin) os=macos ;;
        Linux)  os=linux ;;
        *)      os=windows ;;
    esac
    platform=$arch-$os
fi

sig_file=$(mktemp "${TMPDIR:-/tmp}/attest-XXXXXX.sig") || uncovered "cannot create a temporary file"
trap 'rm -f "$sig_file"' EXIT

# Read a payload field BY PREFIX, never by line position: the payload has grown
# a line once already (v1 -> v2 added `platform`), and a positional reader
# silently mis-assigns every field after an insertion rather than failing.
#
# `exit` after the first match matters. Without it a payload carrying two
# `gates` lines yields a multi-line value, which would break the caller's
# `name=value` output format — the one place a malformed note could reach past
# this script.
field() { printf '%s\n' "$2" | awk -v k="$1" '$1 == k { sub(/^[^ ]* */, ""); print; exit }'; }

# The TREE first: it is what the signature covers, so it is the only key that
# survives a squash-merge, an amend or a rebase. HEAD and HEAD^2 follow for
# notes written by an older producer that keyed by commit only — HEAD^2 because
# a PR checkout is a merge commit whose second parent is the pushed tip.
tried=
for candidate in "$head_tree" HEAD HEAD^2; do
    object=$(git rev-parse --verify --quiet "$candidate" 2> /dev/null) || continue
    body=$(git notes --ref "$NOTES_REF" show "$object" 2> /dev/null) || continue
    tried=yes

    # Split on the first blank line. The payload's trailing newline is part of
    # the signed bytes, so it goes back on before verifying.
    payload=$(printf '%s\n' "$body" | sed -n '/^$/q;p')
    printf '%s\n' "$body" | sed -n "/^-----BEGIN SSH SIGNATURE-----\$/,\$p" > "$sig_file"
    [ -s "$sig_file" ] || { note "note on $candidate carries no signature block"; continue; }

    [ "$(printf '%s\n' "$payload" | sed -n 1p)" = "$FORMAT" ] || {
        note "note on $candidate is not $FORMAT (a newer producer wrote it; running the tests)"
        continue
    }

    tree=$(field tree "$payload")
    gates=$(field gates "$payload")
    ran_on=$(field platform "$payload")

    [ "$tree" = "$head_tree" ] || { note "attested tree $tree is not the checked-out tree $head_tree"; continue; }
    [ -n "$gates" ] || { note "attestation lists no gates"; continue; }

    # A pass is a pass ON SOMETHING: a macOS `cargo test` is no evidence about
    # the Windows leg. `--platform any` is the deliberate, committed statement
    # that a suite's result does not depend on where it ran.
    if [ "$platform" != any ] && [ "$platform" != "$ran_on" ]; then
        note "attested on $ran_on, this leg is $platform"
        continue
    fi

    if printf '%s\n' "$payload" | ssh-keygen -Y verify -f "$signers" \
        -I "$principal" -n "$NAMESPACE" -s "$sig_file" > /dev/null 2>&1; then
        note "covered by $principal: $gates"
        emit "$gates"
        exit 0
    fi
    note "signature on $candidate does not verify as $principal against $signers"
done

[ -n "$tried" ] || note "no attestation found for tree $head_tree"
emit ""
exit 0
