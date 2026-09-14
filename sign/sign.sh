#!/usr/bin/env bash
# Attest, from CI, the gates that just passed on the tree checked out here.
#
#   sign/sign.sh --gates "NAMES" [--platform P] [--object REV] [--remote NAME]
#                [--producer NAME] [--attempts N] [--no-push] [--allow-dirty]
#                [--github-output] [--quiet]        < private-key
#
# Signs an `amont-attest-v2` block over HEAD's tree, APPENDS it to the note on
# that tree in refs/notes/amont-attest, and pushes the ref — so the next job
# that checks out the same tree (a re-run, the push to main after a merge) can
# skip what this one already ran. `verify.sh` is the other half.
#
# The private key arrives on STDIN and nowhere else: never argv, which is
# world-readable, and never a file the caller has to clean up. ed25519 only.
#
# EXIT 0 ALWAYS, whatever happened — no key (a fork PR has no secrets), a push
# refused, a key that will not load. Signing is an accelerator for the NEXT
# run and must never fail THIS one. Exit 2 only for a usage error: an unknown
# flag, `--gates` absent, a key on a terminal, an `--object` whose tree is not
# the checked-out one. With --github-output, four lines go to stdout:
#
#   status=<token>   one of: pushed local already-present no-key bad-key
#                    no-gates dirty sign-failed push-failed error
#   signed=<bool>    a new block for this tree exists locally after this run
#   pushed=<bool>    the remote holds a block for these gates
#   gates=<names>    the normalised, space-separated list that was (or would
#                    have been) signed
#   inputs=<p>/<w>   input fingerprints: <w> gates the committed spec declares
#                    among those signed, <p> of them published under their
#                    fingerprint key (see SPEC.md, "Input fingerprints")
#
# WHAT THIS REFUSES TO SIGN, because an attestation is only worth what it is
# honest about: a working tree with modified or untracked files (the checks
# did not run on HEAD^{tree} alone; --allow-dirty overrides, on your head), an
# `--object` whose tree differs from HEAD's (no override), and an empty gate
# list (not an error: it is what a workflow produces when every gate was
# skipped because it was already attested — and re-signing a skipped gate
# would launder another platform's result into this one).
#
# Depends on `git` and `ssh-keygen` only. See SPEC.md, "Producing".
set -u

FORMAT=amont-attest-v2
NOTES_REF=amont-attest
INPUTS_REF=amont-attest-inputs
NAMESPACE=amont-attest

gates=; have_gates=; platform=; object=; remote=origin; producer=attest-sign
attempts=5; push=1; allow_dirty=; gha=; quiet=
while [ $# -gt 0 ]; do
    case "$1" in
        --gates)     gates=${2-}; have_gates=1; shift 2 || exit 2 ;;
        --platform)  platform=${2-};  shift 2 || exit 2 ;;
        --object)    object=${2-};    shift 2 || exit 2 ;;
        --remote)    remote=${2-};    shift 2 || exit 2 ;;
        --producer)  producer=${2-};  shift 2 || exit 2 ;;
        --attempts)  attempts=${2-};  shift 2 || exit 2 ;;
        --no-push)      push=;        shift ;;
        --allow-dirty)  allow_dirty=1; shift ;;
        --github-output) gha=1;       shift ;;
        --quiet)     quiet=1;         shift ;;
        -h|--help)   sed -n '2,38p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) printf 'sign.sh: unknown argument %s\n' "$1" >&2; exit 2 ;;
    esac
done
[ -n "$have_gates" ] || { printf 'sign.sh: --gates is required\n' >&2; exit 2; }
case $attempts in '' | *[!0-9]*) printf 'sign.sh: --attempts wants a number\n' >&2; exit 2 ;; esac
if [ -t 0 ]; then
    printf 'sign.sh: the private key is read from stdin, which is a terminal; pipe or redirect it\n' >&2
    exit 2
fi

say() { [ -n "$quiet" ] || printf 'attest-sign: %s\n' "$1" >&2; }

# The ONE exit for every outcome: the five output lines, then 0.
inputs_wanted=0; inputs_published=0
finish() { # status signed pushed
    [ -z "$gha" ] || printf 'status=%s\nsigned=%s\npushed=%s\ngates=%s\ninputs=%s/%s\n' \
        "$1" "$2" "$3" "$gates" "$inputs_published" "$inputs_wanted"
    exit 0
}

# Whitespace inside the list is the one thing that could break the note: a
# newline would start a bogus payload line or, worse, the blank line that ends
# the payload. One space between names, none around.
gates=$(printf '%s' "$gates" | tr -s '[:space:]' ' ' | sed 's/^ *//;s/ *$//')
producer=$(printf '%s' "$producer" | tr -s '[:space:]' ' ' | sed 's/^ *//;s/ *$//')
[ -n "$producer" ] || producer=attest-sign

# Private things live under a 0700 directory that goes away on every exit,
# including the temporary notes ref the push loop works on. No suffix after
# the Xs (stock macOS mktemp does not substitute a template that has one).
umask 077
tmp=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/attest-sign-XXXXXX") || {
    say "cannot create a temporary directory"; finish error false false; }
# The temporary refs the push loop works on go with the directory.
# shellcheck disable=SC2329  # invoked by the trap
cleanup() {
    rm -rf "$tmp"
    git for-each-ref --format='%(refname)' "refs/notes/attest-sign-$$-*" 2> /dev/null | while read -r r; do
        git update-ref -d "$r" 2> /dev/null
    done
}
trap cleanup EXIT

# The key. A pasted secret routinely arrives with CRLF or without its final
# newline, and OpenSSH refuses both.
tr -d '\r' > "$tmp/key"
if [ ! -s "$tmp/key" ]; then
    say "no signing key on stdin (a fork PR has no secrets) — nothing signed"
    finish no-key false false
fi
[ -z "$(tail -c 1 "$tmp/key")" ] || printf '\n' >> "$tmp/key"
chmod 600 "$tmp/key"

# `-P ''` fails at once on a passphrase-protected key instead of prompting.
load_pub() { ssh-keygen -y -P '' -f "$tmp/key" 2> "$tmp/err"; }
if ! pub=$(load_pub); then
    # Windows OpenSSH judges key files by ACL, which MSYS chmod may not set.
    case "$(uname -s)" in
        MINGW* | MSYS* | CYGWIN*)
            if grep -qi 'permissions' "$tmp/err" 2> /dev/null; then
                icacls "$(cygpath -w "$tmp/key" 2> /dev/null || printf '%s' "$tmp/key")" \
                    /inheritance:r /grant:r "${USERNAME:-$USER}:R" > /dev/null 2>&1
                pub=$(load_pub) || pub=
            fi ;;
    esac
    if [ -z "${pub:-}" ]; then
        say "not a usable unencrypted OpenSSH private key (passphrase-protected? a .pub pasted by mistake?)"
        finish bad-key false false
    fi
fi
case $pub in
    "ssh-ed25519 "*) ;;
    *) say "only ed25519 keys are supported (this one is ${pub%% *})"; finish bad-key false false ;;
esac

if [ -z "$gates" ]; then
    say "no gates to sign"
    finish no-gates false false
fi

git rev-parse --show-toplevel > /dev/null 2>&1 || { say "not a git repository"; finish error false false; }
head_tree=$(git rev-parse 'HEAD^{tree}' 2> /dev/null) || { say "cannot resolve HEAD^{tree}"; finish error false false; }

# What the note attaches to: HEAD's tree by default, or a REV whose tree IS
# HEAD's tree (a commit, for consumers that key by commit). Anything else
# would sign content the checks never saw, and there is no flag for that.
[ -n "$object" ] || object=$head_tree
object_oid=$(git rev-parse --verify --quiet "$object" 2> /dev/null) || {
    printf 'sign.sh: --object %s does not name an object\n' "$object" >&2; exit 2; }
object_tree=$(git rev-parse --verify --quiet "$object^{tree}" 2> /dev/null) || {
    printf 'sign.sh: --object %s has no tree\n' "$object" >&2; exit 2; }
if [ "$object_tree" != "$head_tree" ]; then
    printf 'sign.sh: --object %s has tree %s, but the checks ran on HEAD^{tree} %s; only that tree may be signed\n' \
        "$object" "$object_tree" "$head_tree" >&2
    exit 2
fi

# The honesty guard. Modified OR untracked (non-ignored) files mean the checks
# ran on something other than HEAD^{tree}; ignored build output does not.
if [ -z "$allow_dirty" ] && [ -n "$(git status --porcelain 2> /dev/null)" ]; then
    say "the working tree has modified or untracked files, so the checks did not run on HEAD^{tree} alone; refusing to sign (--allow-dirty overrides)"
    finish dirty false false
fi

# Same normalisation table as verify.sh, kept identical by hand.
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

# ---------------------------------------------------------------------------
# Input fingerprints (1.3.0). SPEC.md, "Input fingerprints". The same reading
# of the same spec as verify.sh, kept identical by hand — the twin comment is
# there too. Read from the SIGNED tree, never the working copy (--allow-dirty
# exists), into a file, validated on the raw bytes, then parsed.
# ---------------------------------------------------------------------------
spec_ok=
load_spec() {
    local present='' p n bad
    for p in .forgejo/attest-inputs .github/attest-inputs; do
        git cat-file -e "$object_tree:$p" 2> /dev/null && present="$present $p"
    done
    # shellcheck disable=SC2086  # the list is built from fixed names
    set -- $present
    [ $# -gt 0 ] || return 0
    if [ $# -gt 1 ]; then
        say "both .forgejo/attest-inputs and .github/attest-inputs exist; no input fingerprints"
        return 0
    fi
    p=$1
    if ! git cat-file blob "$object_tree:$p" > "$tmp/spec" 2> /dev/null; then
        say "cannot read $p from the signed tree; no input fingerprints"
        return 0
    fi
    n=$(wc -c < "$tmp/spec" | tr -d ' ')
    if [ "$n" -gt 65536 ]; then
        say "$p is larger than 65536 bytes; no input fingerprints"
        return 0
    fi
    bad=$(LC_ALL=C tr -d ' \t\n!-~' < "$tmp/spec" | wc -c | tr -d ' ')
    if [ "$bad" -ne 0 ]; then
        say "$p contains a byte that is not printable ASCII, space, tab or LF; no input fingerprints"
        return 0
    fi
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
        say "$p $(sed -n 1p "$tmp/spec.err"); no input fingerprints"
        return 0
    fi
    spec_ok=1
}
load_spec

# The fingerprint of gate $1 on the signed tree, or nothing: the same
# listing, the same implicit paths, the same refusal to hash a listing that
# ended early as verify.sh's fp_head.
fingerprint() {
    local g=$1 paths tok listing_rc
    paths=$(awk -F '\t' -v g="$g" '$1 == g { print $2; exit }' "$tmp/spec.gates")
    [ -n "$paths" ] || return 1
    # shellcheck disable=SC2086  # declared paths never contain blanks (the grammar refuses them)
    set -- $paths
    for tok in "$@"; do printf '%s:%s\n' "$object_tree" "$tok"; done \
        | git cat-file --batch-check 2> /dev/null \
        | awk -v want="$#" '/ missing$/ { m = 1 } { n++ } END { exit (m || n != want) }' || return 1
    # shellcheck disable=SC2046,SC2086  # same: blank-free tokens, deliberately split
    set -- .forgejo/attest-inputs .github/attest-inputs .gitmodules \
        $(for tok in $paths; do printf '.gitattributes\n'; d=${tok%/*}; while [ "$d" != "$tok" ]; do printf '%s/.gitattributes\n' "$d"; tok=$d; d=${tok%/*}; done; done | sort -u) \
        $paths
    git ls-tree -r -z --full-tree "$object_tree" -- "$@" > "$tmp/listing" 2> /dev/null; listing_rc=$?
    [ "$listing_rc" -eq 0 ] && [ -s "$tmp/listing" ] || return 1
    git hash-object --stdin < "$tmp/listing" 2> /dev/null
}

# `gate<TAB>fp` per signed gate the spec declares, in spec order, into
# "$tmp/fps"; the payload's `input` lines come from it, and so do the keys.
: > "$tmp/fps"
if [ -n "$spec_ok" ]; then
    while IFS="$(printf '\t')" read -r g _; do
        [ -n "$g" ] || continue
        case " $gates " in *" $g "*) ;; *) continue ;; esac
        if fp=$(fingerprint "$g") && [ -n "$fp" ]; then
            printf '%s\t%s\n' "$g" "$fp" >> "$tmp/fps"
        else
            say "gate $g: no fingerprint (a declared path does not exist in the signed tree)"
        fi
    done < "$tmp/spec.gates"
fi
inputs_wanted=$(wc -l < "$tmp/fps" | tr -d ' ')

# The payload, in the exact shape SPEC.md gives — the `input` lines after
# `platform`, before `amont`, in spec order, so a re-run is byte-identical —
# then the block: payload, its trailing newline, a blank line, the armored
# signature.
{
    printf '%s\ntree %s\ngates %s\nplatform %s\n' "$FORMAT" "$object_tree" "$gates" "$platform"
    while IFS="$(printf '\t')" read -r g fp; do printf 'input %s %s\n' "$g" "$fp"; done < "$tmp/fps"
    printf 'amont %s\n' "$producer"
} > "$tmp/p"
ssh-keygen -Y sign -n "$NAMESPACE" -f "$tmp/key" "$tmp/p" > /dev/null 2>&1 || {
    say "ssh-keygen could not sign"; finish sign-failed false false; }
block=$(printf '%s\n\n%s' "$(cat "$tmp/p")" "$(cat "$tmp/p.sig")")

# `git notes` writes a commit on the notes ref and needs an identity; a bare
# runner has none, and this must not touch the repository's config.
gitw() {
    git -c "user.name=${GITHUB_ACTOR:-attest-sign}" \
        -c "user.email=${GITHUB_ACTOR:-attest-sign}@users.noreply.github.com" "$@"
}

# `append` creates the note when there is none and otherwise adds a blank line
# and the block — the exact multi-block shape verifiers read. Never `add -f`:
# that would erase every other producer's block.
#
# Attach the block under every object of ref $1, on the REMOTE's copy of that
# ref, and push. Remote work happens on a TEMPORARY ref, so the local ref —
# which may hold blocks nobody has pushed yet — is never fetched over, deleted,
# or left half-updated. Each attempt starts from what the remote has right
# now, appends what is missing, and pushes; a non-fast-forward rejection means
# another job attested the same tree in the meantime, and the loop goes again.
# Prints the outcome: pushed, already-present, push-failed or error.
publish() { # ref object...
    local ref=$1; shift
    local tref="attest-sign-$$-$ref" attempt=0 appended obj existing why
    while :; do
        attempt=$((attempt + 1))
        git update-ref -d "refs/notes/$tref" 2> /dev/null
        git fetch --quiet "$remote" "+refs/notes/$ref:refs/notes/$tref" 2> /dev/null
        appended=
        for obj in "$@"; do
            existing=$(git notes --ref "$tref" show "$obj" 2> /dev/null)
            case $existing in *"$block"*) continue ;; esac
            gitw notes --ref "$tref" append -m "$block" "$obj" 2> /dev/null || { echo error; return; }
            appended=1
        done
        if [ -z "$appended" ]; then
            git update-ref -d "refs/notes/$tref" 2> /dev/null
            echo already-present; return
        fi
        if git push --quiet "$remote" "refs/notes/$tref:refs/notes/$ref" 2> "$tmp/err"; then
            # The local ref follows what was just published.
            git update-ref "refs/notes/$ref" "refs/notes/$tref" 2> /dev/null
            git update-ref -d "refs/notes/$tref" 2> /dev/null
            echo pushed; return
        fi
        # A credential in a remote URL must not reach the log.
        why=$(sed -e 's#://[^/@]*@#://#g' "$tmp/err" | tr '\n' ' ' | sed 's/  */ /g')
        case $why in
            *non-fast-forward* | *"fetch first"* | *"stale info"* | *"cannot lock ref"* | *"failed to lock"*)
                if [ "$attempt" -ge "$attempts" ]; then
                    say "gave up on refs/notes/$ref after $attempt attempts: $why"
                    echo push-failed; return
                fi
                say "push of refs/notes/$ref rejected, another job attested this tree meanwhile; retrying"
                sleep $(( (RANDOM % 3) + attempt )) ;;
            *)
                say "push of refs/notes/$ref refused: $why"
                echo push-failed; return ;;
        esac
    done
}

# The same, locally only.
publish_local() { # ref object...
    local ref=$1; shift
    local appended obj existing
    appended=
    for obj in "$@"; do
        existing=$(git notes --ref "$ref" show "$obj" 2> /dev/null)
        case $existing in *"$block"*) continue ;; esac
        gitw notes --ref "$ref" append -m "$block" "$obj" 2> /dev/null || { echo error; return; }
        appended=1
    done
    [ -n "$appended" ] && echo local || echo already-present
}

# The keys of the inputs ref: one per fingerprinted gate.
input_keys() {
    while IFS="$(printf '\t')" read -r g fp; do
        printf 'amont-attest-input %s %s\n' "$g" "$fp" | git hash-object --stdin 2> /dev/null
    done < "$tmp/fps"
}
# shellcheck disable=SC2046  # oids, deliberately split
set -- $(input_keys)
keys_n=$#

# Each ref is published on its own, and a run whose inputs push failed
# earlier repairs the missing keys next time: `already-present` on the main
# ref never short-circuits the inputs ref.
if [ -z "$push" ]; then
    main=$(publish_local "$NOTES_REF" "$object_oid")
    if [ "$keys_n" -gt 0 ]; then
        case $(publish_local "$INPUTS_REF" "$@") in error) ;; *) inputs_published=$inputs_wanted ;; esac
    fi
    case $main in
        error) say "cannot write the note"; finish error false false ;;
        already-present) say "an identical block is already attached"; finish already-present false false ;;
        *) say "signed, not pushed: $gates on $platform"; finish local true false ;;
    esac
fi

main=$(publish "$NOTES_REF" "$object_oid")
if [ "$keys_n" -gt 0 ]; then
    case $(publish "$INPUTS_REF" "$@") in
        pushed | already-present) inputs_published=$inputs_wanted ;;
        *) say "the input fingerprints were not published; the next run will retry" ;;
    esac
fi
case $main in
    pushed)          say "signed and pushed: $gates on $platform"; finish pushed true true ;;
    already-present) say "an identical block is already on $remote"; finish already-present false true ;;
    push-failed)     finish push-failed false false ;;
    *)               say "cannot write the note"; finish error false false ;;
esac
