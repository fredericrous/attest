#!/usr/bin/env bash
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
INPUTS_REF=amont-attest-inputs
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

# A notes ref, from origin. A repository that has never been pushed with
# attest enabled has no such ref, and that is not an error — but a fetch that
# fails for any OTHER reason (no credentials because the checkout step set
# persist-credentials: false, a remote not named origin, no network) is the
# worst shape a fail-open can take: nothing covered, forever, with CI green and
# a log that reads as "no attestation". So the two are told apart, and only the
# second one is reported.
fetch_notes() { # ref
    git fetch origin "+refs/notes/$1:refs/notes/$1" > /dev/null 2>&1 && return 0
    # ls-remote exits 2 when the ref simply is not there; anything else is the
    # remote being unreachable or refusing us.
    git ls-remote --exit-code origin "refs/notes/$1" > /dev/null 2>&1; rc=$?
    [ "$rc" -eq 2 ] && return 0
    git rev-parse --verify --quiet "refs/notes/$1" > /dev/null 2>&1 && return 0
    note "cannot fetch refs/notes/$1 from origin and no local copy exists (no credentials on the checkout? remote not named origin?)"
}
fetch_notes "$NOTES_REF"
fetch_notes "$INPUTS_REF"

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
# whose Xs are not at the very end. It creates the literal name, and the next
# run finds it there and fails with "File exists" — so one killed run on a
# self-hosted Mac would leave every later run uncovered, forever.
tmp=$(mktemp -d "${TMPDIR:-/tmp}/attest-XXXXXX") || uncovered "cannot create a temporary directory"
trap 'rm -rf "$tmp"' EXIT
sig_file=$tmp/sig

# Read a payload field BY PREFIX, never by line position: the payload has grown
# a line once already (v1 -> v2 added `platform`), and a positional reader
# silently mis-assigns every field after an insertion rather than failing.
#
# `exit` after the first match matters. Without it a payload carrying two
# `gates` lines yields a multi-line value, which would break the caller's
# `name=value` output format — the one place a malformed note could reach past
# this script.
field() { printf '%s\n' "$2" | awk -v k="$1" '$1 == k { sub(/^[^ ]* */, ""); print; exit }'; }

# How many blocks of one note are read, and how many signatures one run
# verifies over every candidate. Every block costs two ssh-keygen runs, and
# the notes refs are writable by anyone with push access.
MAX_BLOCKS=32
MAX_VERIFICATIONS=64
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

# Is $1 one of the names in $2?
in_list() { case " $2 " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }

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

# ---------------------------------------------------------------------------
# Input fingerprints (1.3.0). SPEC.md, "Input fingerprints".
#
# A committed `.github/attest-inputs` (or `.forgejo/`) names the paths each
# gate reads. A gate's FINGERPRINT on a tree is `git hash-object` over the
# `git ls-tree -r -z --full-tree` listing of those paths (plus a few implicit
# ones, the spec file itself first). Equal fingerprints mean identical inputs,
# so an attestation covers the gate on any tree whose fingerprint is equal —
# a docs commit or another package no longer invalidates it. Producers attach
# their block, in a second notes ref, under a synthetic key derived from
# (gate, fingerprint), which is where this looks for it.
# ---------------------------------------------------------------------------

# The spec at HEAD's tree, parsed into "$tmp/spec.gates": one `gate<TAB>paths`
# line per gate. Read from the TREE (`cat-file`), never the working copy, into
# a FILE, never a variable: a variable cannot hold a NUL and drops trailing
# newlines, and the contract is checked on the raw bytes. Sets spec_ok=1 when
# there is a usable spec; says why when there is one and it is not.
spec_ok=
load_spec() {
    local present='' p n bad
    for p in .forgejo/attest-inputs .github/attest-inputs; do
        git -C "$root" cat-file -e "$head_tree:$p" 2> /dev/null && present="$present $p"
    done
    # shellcheck disable=SC2086  # the list is built from fixed names
    set -- $present
    [ $# -gt 0 ] || return 0
    if [ $# -gt 1 ]; then
        note "both .forgejo/attest-inputs and .github/attest-inputs exist; input fingerprints disabled"
        return 0
    fi
    p=$1
    if ! git -C "$root" cat-file blob "$head_tree:$p" > "$tmp/spec" 2> /dev/null; then
        note "cannot read $p from HEAD's tree; input fingerprints disabled"
        return 0
    fi
    n=$(wc -c < "$tmp/spec" | tr -d ' ')
    if [ "$n" -gt 65536 ]; then
        note "$p is larger than 65536 bytes; input fingerprints disabled"
        return 0
    fi
    # Every byte must be printable ASCII, space, tab or LF: delete exactly
    # those and anything left — a NUL, a CR, a control byte, anything
    # non-ASCII — is a violation.
    bad=$(LC_ALL=C tr -d ' \t\n!-~' < "$tmp/spec" | wc -c | tr -d ' ')
    if [ "$bad" -ne 0 ]; then
        note "$p contains a byte that is not printable ASCII, space, tab or LF; input fingerprints disabled"
        return 0
    fi
    # The grammar, one rule per message, any violation invalidating the WHOLE
    # spec: a line that silently dropped out would be one the author believes
    # is protecting something. Same rules as parse_spec() in src/attest.rs.
    if ! awk '
        function bad(why) { printf "line %d: %s\n", NR, why > "/dev/stderr"; exit 1 }
        { sub(/^[ \t]+/, ""); if ($0 == "" || substr($0, 1, 1) == "#") next }
        {
            g = $1
            if (g !~ /^[A-Za-z0-9][A-Za-z0-9._-]*$/ || length(g) > 64) bad("gate name `" g "` is not [A-Za-z0-9][A-Za-z0-9._-]* of at most 64 characters")
            if (g in seen) bad("gate `" g "` is declared twice")
            seen[g] = 1
            if (NF < 2) bad("gate `" g "` declares no paths")
            if (NF - 1 > 64) bad("gate `" g "` declares more than 64 paths")
            line = g
            for (i = 2; i <= NF; i++) {
                t = $i
                if (substr(t, 1, 1) == ":") bad("path `" t "` starts with `:` (pathspec magic is not allowed)")
                if (substr(t, 1, 1) == "/") bad("path `" t "` is absolute; paths are relative to the repository root")
                if (substr(t, 1, 2) == "./" || substr(t, 1, 3) == "../") bad("path `" t "` starts with `./` or `../`")
                if (substr(t, length(t), 1) == "/") bad("path `" t "` ends with `/`; name the directory without it")
                if (t ~ /[*?\[\]\\]/) bad("path `" t "` contains a wildcard; git ls-tree does not glob, only literal paths are accepted")
                m = split(t, c, "/")
                for (j = 1; j <= m; j++) if (c[j] == "" || c[j] == "." || c[j] == "..") bad("path `" t "` has an empty, `.` or `..` component")
                line = line (i == 2 ? "\t" : " ") t
            }
            print line
            if (++gates > 64) bad("declares more than 64 gates")
        }' "$tmp/spec" > "$tmp/spec.gates" 2> "$tmp/spec.err"; then
        note "$p $(sed -n 1p "$tmp/spec.err"); input fingerprints disabled"
        return 0
    fi
    spec_ok=1
}
load_spec

# The paths of gate $1 per the spec, space-separated, or nothing.
spec_paths() { awk -F '\t' -v g="$1" '$1 == g { print $2; exit }' "$tmp/spec.gates"; }

# The fingerprint of gate $1 on HEAD's tree, memoised in "$tmp/fp.<gate>":
# the oid, or an empty file when the gate has none here (not in the spec, a
# path that does not exist, git failing at any step). fp_head prints it.
fp_head() {
    local g=$1 paths tok listing_rc
    if [ ! -f "$tmp/fp.$g" ]; then
        : > "$tmp/fp.$g"
        paths=$(spec_paths "$g")
        if [ -n "$paths" ]; then
            # Every declared path must resolve — one `cat-file --batch-check`
            # for all of them, never a process per path.
            # shellcheck disable=SC2086  # declared paths never contain blanks (the grammar refuses them)
            set -- $paths
            if ! for tok in "$@"; do printf '%s:%s\n' "$head_tree" "$tok"; done \
                | git -C "$root" cat-file --batch-check 2> /dev/null \
                | awk -v want="$#" '/ missing$/ { m = 1 } { n++ } END { exit (m || n != want) }'; then
                :
            else
                # The implicit paths: both spec locations (so adding, removing
                # or editing either invalidates), .gitmodules, and
                # .gitattributes at the root and at every ancestor directory
                # of every declared path. Then the declared paths. The listing
                # goes to a FILE: a variable would strip the NULs, and the
                # exit status of ls-tree is checked before anything is hashed,
                # because a listing that ended early must never fingerprint.
                # shellcheck disable=SC2046,SC2086  # same: blank-free tokens, deliberately split
                set -- .forgejo/attest-inputs .github/attest-inputs .gitmodules \
                    $(for tok in $paths; do printf '.gitattributes\n'; d=${tok%/*}; while [ "$d" != "$tok" ]; do printf '%s/.gitattributes\n' "$d"; tok=$d; d=${tok%/*}; done; done | sort -u) \
                    $paths
                git -C "$root" ls-tree -r -z --full-tree "$head_tree" -- "$@" > "$tmp/listing" 2> /dev/null; listing_rc=$?
                if [ "$listing_rc" -eq 0 ] && [ -s "$tmp/listing" ]; then
                    git hash-object --stdin < "$tmp/listing" 2> /dev/null > "$tmp/fp.$g" || : > "$tmp/fp.$g"
                fi
            fi
        fi
    fi
    cat "$tmp/fp.$g"
}

# The fingerprint a block claims for gate $2 in payload $1: an `input <gate>
# <fp>` line of exactly three fields, first occurrence wins.
input_fp() {
    printf '%s\n' "$1" | awk -v g="$2" \
        'NF == 3 && $1 == "input" && $2 == g && $3 ~ /^[0-9a-f]+$/ && (length($3) == 40 || length($3) == 64) { print $3; exit }'
}

# The synthetic note key for (gate, fingerprint).
input_key() { printf 'amont-attest-input %s %s\n' "$1" "$2" | git hash-object --stdin 2> /dev/null; }

# The uniform rule, per gate: those names of $2 that the block covers, given
# whether its tree is the checked-out one ($1) and its payload ($3).
kept_gates() {
    local tree_matches=$1 gates=$2 payload=$3 g out='' claimed here
    for g in $gates; do
        if [ "$tree_matches" = yes ]; then
            out=$(union "$out" "$g")
        else
            claimed=$(input_fp "$payload" "$g")
            [ -n "$claimed" ] || continue
            here=$(fp_head "$g")
            [ -n "$here" ] && [ "$claimed" = "$here" ] && out=$(union "$out" "$g")
        fi
    done
    printf '%s\n' "$out"
}

# Judge every block of the note on object $2 in ref $1, labelled $3.
# Accumulates into $covered; a note seen before is skipped by its oid, a
# block seen before by its bytes (its verdict depends only on its content and
# HEAD, whichever note it appears in).
covered=; seen=; seen_blocks=; tried=; verifications=0; exhausted=
judge_note() {
    local nref=$1 object=$2 at=$3 note_oid body ranges nblocks n ps pe ss se where payload tree gates ran_on signer bh kept how accepted
    [ -z "$exhausted" ] || return 0
    note_oid=$(git notes --ref "$nref" list "$object" 2> /dev/null) || return 0
    note_oid=${note_oid%% *}
    in_list "$note_oid" "$seen" && return 0
    seen="$seen $note_oid"
    body=$(git notes --ref "$nref" show "$object" 2> /dev/null) || return 0
    tried=yes

    # LF only. Checked by the shell itself, before any tool sees the note:
    # the awk and sed of some environments (MSYS, hence Git Bash on Windows)
    # drop carriage returns on the way in, which would let a CRLF note parse
    # here and be refused by the binary.
    case $body in *"$CR"*) note "note on $at contains carriage returns; the format is LF-only"; return 0 ;; esac

    ranges=$(blocks_of "$body")
    [ -n "$ranges" ] || { note "note on $at carries no signature block"; return 0; }
    nblocks=$(printf '%s\n' "$ranges" | awk '/^[0-9]/ { c++ } END { print c + 0 }')

    # A heredoc, not a pipe: a `printf | while` would run the loop in a
    # subshell and drop everything accumulated in $covered.
    n=0
    while read -r ps pe ss se; do
        [ -n "$ps" ] || continue
        if [ "$ps" = truncated ]; then
            note "note on $at has more than $MAX_BLOCKS blocks; the rest were ignored"
            continue
        fi
        n=$((n + 1))
        where=$at
        [ "$nblocks" -gt 1 ] && where="$at block $n"

        # The payload's trailing newline is part of the signed bytes; sed
        # prints whole lines, so it is there.
        payload=$(printf '%s\n' "$body" | sed -n "${ps},${pe}p")
        printf '%s\n' "$body" | sed -n "${ss},${se}p" > "$sig_file"

        [ "$(printf '%s\n' "$payload" | sed -n 1p)" = "$FORMAT" ] || {
            note "note on $where is not $FORMAT (a newer producer wrote it; running the tests)"
            continue
        }

        tree=$(field tree "$payload")
        gates=$(field gates "$payload")
        ran_on=$(field platform "$payload")

        # Every v2 field is required, `platform` included: a note that does
        # not say where it ran is not evidence about anywhere.
        if [ -z "$tree" ] || [ -z "$ran_on" ]; then
            note "note on $where is missing a required field (tree, platform)"
            continue
        fi
        [ -n "$gates" ] || { note "attestation lists no gates"; continue; }

        # The same block reached through another key has the same verdict.
        bh=$(printf '%s\n' "$payload" | cat - "$sig_file" | git hash-object --stdin 2> /dev/null)
        in_list "$bh" "$seen_blocks" && continue
        seen_blocks="$seen_blocks $bh"
        if [ "$verifications" -ge "$MAX_VERIFICATIONS" ]; then
            note "the budget of $MAX_VERIFICATIONS signature verifications is spent; remaining candidates were not read"
            exhausted=1
            return 0
        fi
        verifications=$((verifications + 1))

        # WHO signed, read from the signature and the file rather than
        # guessed. `ssh-keygen -Y verify` requires a principal and checks it
        # against the principal column, so a guessed one rejects a perfectly
        # good signature — quietly. `find-principals` answers from the key that
        # actually signed, so a multi-signer file just works; `--principal`
        # narrows it to one identity.
        signer=$principal
        if [ -z "$signer" ]; then
            signer=$(ssh-keygen -Y find-principals -s "$sig_file" -f "$signers" 2> /dev/null | sed -n 1p)
            [ -n "$signer" ] || { note "signature on $where was not made by any key in $signers"; continue; }
        fi

        # The signature BEFORE anything the block's claims could buy it:
        # `--anywhere` and the input fingerprints may only admit gates from a
        # block that actually verified.
        printf '%s\n' "$payload" | ssh-keygen -Y verify -f "$signers" \
            -I "$signer" -n "$NAMESPACE" -s "$sig_file" > /dev/null 2>&1 || {
            note "signature on $where does not verify as $signer against $signers"
            continue
        }

        # The uniform rule, per gate: the tree is the checked-out tree, or the
        # block's fingerprint for that gate is the one computed here.
        if [ "$tree" = "$head_tree" ]; then
            kept=$(kept_gates yes "$gates" "$payload"); how=
        else
            kept=$(kept_gates no "$gates" "$payload"); how=" (by input fingerprint)"
        fi
        if [ -z "$kept" ]; then
            note "attested tree $tree is not the checked-out tree $head_tree and no input fingerprint of $where matches"
            continue
        fi

        # A pass is a pass ON SOMETHING: a macOS `cargo test` is no evidence
        # about the Windows leg. `--platform any` is the deliberate, committed
        # statement that the whole suite's result does not depend on where it
        # ran; `--anywhere` says it of the named gates only.
        if platform_matches "$platform" "$ran_on"; then
            covered=$(union "$covered" "$kept")
            note "covered by $signer on $ran_on$how: $kept"
            continue
        fi
        accepted=$(intersect "$kept" "$anywhere")
        covered=$(union "$covered" "$accepted")
        if [ -n "$accepted" ]; then
            note "attested on $ran_on by $signer$how, this leg is $platform; accepted anywhere: $accepted"
        else
            note "attested on $ran_on by $signer$how, this leg is $platform"
        fi
    done <<EOF
$ranges
EOF
}

# The TREE first: it is what the signature covers, so it is the only key that
# survives a squash-merge, an amend or a rebase. HEAD and HEAD^2 follow for
# notes written by an older producer that keyed by commit only — HEAD^2 because
# a PR checkout is a merge commit whose second parent is the pushed tip.
for candidate in "$head_tree" HEAD HEAD^2; do
    object=$(git rev-parse --verify --quiet "$candidate" 2> /dev/null) || continue
    judge_note "$NOTES_REF" "$object" "$candidate"
done

# Then, lazily, the fingerprint-keyed notes: only for gates the spec declares
# and nothing above covered. The common case (the tree matched) costs nothing.
if [ -n "$spec_ok" ]; then
    while IFS="$(printf '\t')" read -r g _; do
        [ -n "$g" ] || continue
        [ -z "$exhausted" ] || break
        in_list "$g" "$covered" && continue
        fp=$(fp_head "$g")
        if [ -z "$fp" ]; then
            note "gate $g: no fingerprint here (a declared path does not exist in this tree)"
            continue
        fi
        k=$(input_key "$g" "$fp") || continue
        [ -n "$k" ] || continue
        judge_note "$INPUTS_REF" "$k" "input $g $(printf '%s' "$fp" | cut -c1-12)"
    done < "$tmp/spec.gates"
fi

[ -n "$tried" ] || note "no attestation found for tree $head_tree"
emit "$covered"
exit 0
