#!/usr/bin/env bash
# FROZEN COPY of verify.sh as released in 1.2.0 — DO NOT EDIT. `tests/compat-fields.sh`
# runs the additive-field fixtures against it to prove a 1.2.0 verifier ignores
# `input` lines and never reaches a fingerprint-keyed note.
# The one copy of the attest verifier.
#
#   verify.sh [--signers PATH] [--principal ID] [--platform P|OS|any]
#             [--anywhere NAMES] [--json | --github-output] [--quiet]
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
# repository's state — an unknown flag is refused rather than ignored, since a
# typo like `--platfrom any` that silently fell back to the default would just
# never cover anything.
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

signers=; principal=; platform=; anywhere=; quiet=; mode=plain

while [ $# -gt 0 ]; do
    case "$1" in
        --signers)   signers=${2-};   shift 2 || exit 2 ;;
        --principal) principal=${2-}; shift 2 || exit 2 ;;
        --platform)  platform=${2-};  shift 2 || exit 2 ;;
        --anywhere)  anywhere="$anywhere ${2-}"; shift 2 || exit 2 ;;
        --json)          mode=json; shift ;;
        --github-output) mode=gha;  shift ;;
        --quiet)     quiet=1; shift ;;
        -h|--help)   sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
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
# it. Control characters go out as \u00xx, which JSON requires — a raw one
# would make the consumer's `fromJSON` throw, and that FAILS the job, which is
# the one outcome this contract promises cannot happen.
#
# Character by character rather than gsub, because BSD awk, mawk and gawk do
# not agree on backslashes in a replacement string, and this must run on all
# three.
to_json() {
    printf '%s\n' "$1" | awk '
    BEGIN { for (i = 1; i < 32; i++) ctl[sprintf("%c", i)] = sprintf("\\u%04x", i) }
    {
        out = "["
        for (i = 1; i <= NF; i++) {
            g = $i; e = ""
            for (j = 1; j <= length(g); j++) {
                c = substr(g, j, 1)
                if (c == "\\")      e = e "\\\\"
                else if (c == "\"") e = e "\\\""
                else if (c in ctl)  e = e ctl[c]
                else                e = e c
            }
            out = out (i > 1 ? "," : "") "\"" e "\""
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
    [ -n "$signers" ] || uncovered "no allowed_signers (looked for .forgejo/ and .github/allowed_signers at $root)"
else
    [ "${signers#/}" = "$signers" ] && signers=$root/$signers
    [ -f "$signers" ] || uncovered "$signers does not exist"
fi

# The notes ref, from origin. A repository that has never been pushed with
# attest enabled has no such ref, and that is not an error — but a fetch that
# fails for any OTHER reason (no credentials because the checkout step set
# persist-credentials: false, a remote not named origin, no network) is the
# worst shape a fail-open can take: nothing covered, forever, with CI green and
# a log that reads as "no attestation". So the two are told apart, and only the
# second one is reported.
fetch_notes() {
    git fetch origin "+refs/notes/$NOTES_REF:refs/notes/$NOTES_REF" > /dev/null 2>&1 && return 0
    # ls-remote exits 2 when the ref simply is not there; anything else is the
    # remote being unreachable or refusing us.
    git ls-remote --exit-code origin "refs/notes/$NOTES_REF" > /dev/null 2>&1; rc=$?
    [ "$rc" -eq 2 ] && return 0
    git rev-parse --verify --quiet "refs/notes/$NOTES_REF" > /dev/null 2>&1 && return 0
    note "cannot fetch refs/notes/$NOTES_REF from origin and no local copy exists (no credentials on the checkout? remote not named origin?)"
}
fetch_notes

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

# No suffix after the Xs: stock macOS mktemp does not substitute a template
# whose Xs are not at the very end. It creates the literal `attest-XXXXXX.sig`,
# and the next run finds it there and fails with "File exists" — so one killed
# run on a self-hosted Mac would leave every later run uncovered, forever.
sig_file=$(mktemp "${TMPDIR:-/tmp}/attest-XXXXXX") || uncovered "cannot create a temporary file"
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

# How many blocks of one note are read. Every block costs two ssh-keygen runs,
# and the notes ref is writable by anyone with push access.
MAX_BLOCKS=32
CR=$(printf '\r')

# A note holds one or more BLOCKS — payload, blank line, armored signature —
# since 1.2.0, so a laptop and a CI job can both attest the same tree, each on
# its own platform. Blank lines separate blocks, which is exactly what
# `git notes append` writes. This prints one "pstart pend sstart send" line of
# line numbers per block, then the word `truncated` if MAX_BLOCKS was reached.
#
# The grammar (SPEC.md): skip blank lines; a payload runs to the first blank
# line; skip blank lines; the next line must be the BEGIN marker, or parsing
# STOPS and what was collected stands; the signature runs to END, and end of
# input closes an open one. Same state machine as split_blocks() in
# src/attest.rs.
blocks_of() {
    printf '%s\n' "$1" | awk -v max="$MAX_BLOCKS" \
        -v b='-----BEGIN SSH SIGNATURE-----' -v e='-----END SSH SIGNATURE-----' '
        function close_block() {
            if (n == max) { print "truncated"; stop = 1; exit }
            n++; print ps, pe, ss, NR
        }
        stop { next }
        s == ""  { if ($0 == "") next; ps = NR; pe = NR; s = "p"; next }
        s == "p" { if ($0 == "") { s = "w"; next } pe = NR; next }
        s == "w" { if ($0 == "") next; if ($0 != b) { stop = 1; exit } ss = NR; s = "g"; next }
        s == "g" { if ($0 == e) { close_block(); s = "" } next }
        END { if (!stop && s == "g") close_block() }'
}

# Names of $2 not already in $1, appended: first-appearance order, no repeats.
union() {
    printf '%s %s\n' "$1" "$2" | awk '{
        o = ""
        for (i = 1; i <= NF; i++) if (!($i in seen)) { seen[$i] = 1; o = o (o == "" ? "" : " ") $i }
        print o
    }'
}

# Those names of $1 that also appear in $2, in the order of $1.
intersect() {
    printf '%s\n%s\n' "$1" "$2" | awk '
        NR == 1 { for (i = 1; i <= NF; i++) g[i] = $i; n = NF; next }
        { for (i = 1; i <= NF; i++) in2[$i] = 1 }
        END { o = ""; for (i = 1; i <= n; i++) if (g[i] in in2) o = o (o == "" ? "" : " ") g[i]; print o }'
}

# Does an attestation minted on $2 satisfy the caller's $1? `any` takes all; a
# value with a dash is an exact <arch>-<os>; an OS alone is compared to the
# part after the LAST dash — never as a substring, so `inux` matches nothing.
platform_matches() {
    case $1 in
        any) return 0 ;;
        *-*) [ "$1" = "$2" ] ;;
        *)   case $2 in *-*) [ "$1" = "${2##*-}" ] ;; *) return 1 ;; esac ;;
    esac
}

# The TREE first: it is what the signature covers, so it is the only key that
# survives a squash-merge, an amend or a rebase. HEAD and HEAD^2 follow for
# notes written by an older producer that keyed by commit only — HEAD^2 because
# a PR checkout is a merge commit whose second parent is the pushed tip.
#
# A producer writes its note to BOTH the tree and the commit, so the loop meets
# the same note twice; it is judged once, by its oid.
covered=; seen=; tried=
for candidate in "$head_tree" HEAD HEAD^2; do
    object=$(git rev-parse --verify --quiet "$candidate" 2> /dev/null) || continue
    note_oid=$(git notes --ref "$NOTES_REF" list "$object" 2> /dev/null) || continue
    note_oid=${note_oid%% *}
    case " $seen " in *" $note_oid "*) continue ;; esac
    seen="$seen $note_oid"
    body=$(git notes --ref "$NOTES_REF" show "$object" 2> /dev/null) || continue
    tried=yes

    # LF only. Checked by the shell itself, before any tool sees the note:
    # the awk and sed of some environments (MSYS, hence Git Bash on Windows)
    # drop carriage returns on the way in, which would let a CRLF note parse
    # here and be refused by the binary.
    case $body in *"$CR"*) note "note on $candidate contains carriage returns; the format is LF-only"; continue ;; esac

    ranges=$(blocks_of "$body")
    [ -n "$ranges" ] || { note "note on $candidate carries no signature block"; continue; }
    nblocks=$(printf '%s\n' "$ranges" | awk '/^[0-9]/ { c++ } END { print c + 0 }')

    # A heredoc, not a pipe: a `printf | while` would run the loop in a
    # subshell and drop everything accumulated in $covered.
    n=0
    while read -r ps pe ss se; do
        [ -n "$ps" ] || continue
        if [ "$ps" = truncated ]; then
            note "note on $candidate has more than $MAX_BLOCKS blocks; the rest were ignored"
            continue
        fi
        n=$((n + 1))
        at=$candidate
        [ "$nblocks" -gt 1 ] && at="$candidate block $n"

        # The payload's trailing newline is part of the signed bytes; sed
        # prints whole lines, so it is there.
        payload=$(printf '%s\n' "$body" | sed -n "${ps},${pe}p")
        printf '%s\n' "$body" | sed -n "${ss},${se}p" > "$sig_file"

        [ "$(printf '%s\n' "$payload" | sed -n 1p)" = "$FORMAT" ] || {
            note "note on $at is not $FORMAT (a newer producer wrote it; running the tests)"
            continue
        }

        tree=$(field tree "$payload")
        gates=$(field gates "$payload")
        ran_on=$(field platform "$payload")

        # Every v2 field is required, `platform` included: a note that does
        # not say where it ran is not evidence about anywhere.
        if [ -z "$tree" ] || [ -z "$ran_on" ]; then
            note "note on $at is missing a required field (tree, platform)"
            continue
        fi
        [ "$tree" = "$head_tree" ] || { note "attested tree $tree is not the checked-out tree $head_tree"; continue; }
        [ -n "$gates" ] || { note "attestation lists no gates"; continue; }

        # WHO signed, read from the signature and the file rather than
        # guessed. `ssh-keygen -Y verify` requires a principal and checks it
        # against the principal column, so a guessed one rejects a perfectly
        # good signature — quietly. `find-principals` answers from the key that
        # actually signed, so a multi-signer file just works; `--principal`
        # narrows it to one identity.
        signer=$principal
        if [ -z "$signer" ]; then
            signer=$(ssh-keygen -Y find-principals -s "$sig_file" -f "$signers" 2> /dev/null | sed -n 1p)
            [ -n "$signer" ] || { note "signature on $at was not made by any key in $signers"; continue; }
        fi

        # The signature BEFORE the platform: `--anywhere` may only admit gates
        # from a block that actually verified.
        printf '%s\n' "$payload" | ssh-keygen -Y verify -f "$signers" \
            -I "$signer" -n "$NAMESPACE" -s "$sig_file" > /dev/null 2>&1 || {
            note "signature on $at does not verify as $signer against $signers"
            continue
        }

        # A pass is a pass ON SOMETHING: a macOS `cargo test` is no evidence
        # about the Windows leg. `--platform any` is the deliberate, committed
        # statement that the whole suite's result does not depend on where it
        # ran; `--anywhere` says it of the named gates only.
        if platform_matches "$platform" "$ran_on"; then
            covered=$(union "$covered" "$gates")
            note "covered by $signer on $ran_on: $gates"
            continue
        fi
        accepted=$(intersect "$gates" "$anywhere")
        covered=$(union "$covered" "$accepted")
        if [ -n "$accepted" ]; then
            note "attested on $ran_on by $signer, this leg is $platform; accepted anywhere: $accepted"
        else
            note "attested on $ran_on by $signer, this leg is $platform"
        fi
    done <<EOF
$ranges
EOF
done

[ -n "$tried" ] || note "no attestation found for tree $head_tree"
emit "$covered"
exit 0
