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

# The ONE exit for every outcome: the four output lines, then 0.
finish() { # status signed pushed
    [ -z "$gha" ] || printf 'status=%s\nsigned=%s\npushed=%s\ngates=%s\n' "$1" "$2" "$3" "$gates"
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
tmpref=
tmp=$(mktemp -d "${RUNNER_TEMP:-${TMPDIR:-/tmp}}/attest-sign-XXXXXX") || {
    say "cannot create a temporary directory"; finish error false false; }
trap 'rm -rf "$tmp"; [ -z "$tmpref" ] || git update-ref -d "refs/notes/$tmpref" 2> /dev/null' EXIT

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

# The payload, in the exact shape SPEC.md gives, then the block: payload, its
# trailing newline, a blank line, the armored signature.
printf '%s\ntree %s\ngates %s\nplatform %s\namont %s\n' \
    "$FORMAT" "$object_tree" "$gates" "$platform" "$producer" > "$tmp/p"
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
if [ -z "$push" ]; then
    existing=$(git notes --ref "$NOTES_REF" show "$object_oid" 2> /dev/null)
    case $existing in *"$block"*) say "an identical block is already attached"; finish already-present false false ;; esac
    gitw notes --ref "$NOTES_REF" append -m "$block" "$object_oid" 2> /dev/null || {
        say "cannot write the note"; finish error false false; }
    say "signed, not pushed: $gates on $platform"
    finish local true false
fi

# Remote work happens on a TEMPORARY ref, so the local refs/notes/amont-attest
# — which may hold blocks nobody has pushed yet — is never fetched over,
# deleted, or left half-updated. Each attempt starts from what the remote has
# right now, appends, and pushes; a non-fast-forward rejection means another
# job attested the same tree in the meantime, and the loop simply goes again.
tmpref="attest-sign-$$"
attempt=0
while :; do
    attempt=$((attempt + 1))
    git update-ref -d "refs/notes/$tmpref" 2> /dev/null
    git fetch --quiet "$remote" "+refs/notes/$NOTES_REF:refs/notes/$tmpref" 2> /dev/null
    existing=$(git notes --ref "$tmpref" show "$object_oid" 2> /dev/null)
    case $existing in
        *"$block"*) say "an identical block is already on $remote"; finish already-present false true ;;
    esac
    gitw notes --ref "$tmpref" append -m "$block" "$object_oid" 2> /dev/null || {
        say "cannot write the note"; finish error false false; }
    if git push --quiet "$remote" "refs/notes/$tmpref:refs/notes/$NOTES_REF" 2> "$tmp/err"; then
        # The local ref follows what was just published.
        git update-ref "refs/notes/$NOTES_REF" "refs/notes/$tmpref" 2> /dev/null
        say "signed and pushed: $gates on $platform"
        finish pushed true true
    fi
    # A credential in a remote URL must not reach the log.
    why=$(sed -e 's#://[^/@]*@#://#g' "$tmp/err" | tr '\n' ' ' | sed 's/  */ /g')
    case $why in
        *non-fast-forward* | *"fetch first"* | *"stale info"* | *"cannot lock ref"* | *"failed to lock"*)
            if [ "$attempt" -ge "$attempts" ]; then
                say "gave up after $attempt attempts: $why"
                finish push-failed false false
            fi
            say "push rejected, another job attested this tree meanwhile; retrying"
            sleep $(( (RANDOM % 3) + attempt )) ;;
        *)
            say "push refused: $why"
            finish push-failed false false ;;
    esac
done
