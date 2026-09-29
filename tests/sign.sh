#!/usr/bin/env bash
# The producer's contract, as fixtures: sign/sign.sh against a bare `origin`.
#
#   tests/sign.sh                # uses ./verify.sh to read back what was signed
#   ATTEST_IMPL="target/release/git-attest covered" tests/sign.sh
#                                # ...or any other verifier
#
# Every case asserts three things where they apply: the exit code (0 always,
# 2 for a usage error), the four --github-output lines, and what verify.sh
# then covers in a fresh clone — because "signed" is only worth what a
# verifier makes of it.
set -u

HERE=$(cd "$(dirname "$0")/.." && pwd)
SIGN="$HERE/sign/sign.sh"
VERIFY="$HERE/verify.sh"
# shellcheck disable=SC2034  # read by lib.sh
IMPL=${ATTEST_IMPL:-"bash $VERIFY --quiet"}
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
# The helper is sourced, which shellcheck follows only under -x; the hook
# runs without it, so the two findings that follow from that are silenced.
# shellcheck source=lib.sh disable=SC1091
. "$HERE/tests/lib.sh"
gen_keys

R=$WORK/r
ORIGIN=$WORK/origin.git

# A repository whose allowed_signers names `key` (the CI key here) and
# `second`, pushed to a fresh bare origin.
make_remote_repo() {
    rm -rf "$ORIGIN"; git init -q --bare "$ORIGIN"
    # Runners default to `master`; the branch pushed below is `main`, and a
    # clone of a bare repository whose HEAD names a missing branch checks out
    # nothing.
    git --git-dir="$ORIGIN" symbolic-ref HEAD refs/heads/main
    make_repo "$R" ci@example.org "$WORK/key" second@example.org "$WORK/second"
    git -C "$R" remote add origin "$ORIGIN"
    git -C "$R" push -q origin HEAD:refs/heads/main
}

# Run sign.sh in $R with the key on stdin; capture the output lines, stderr
# and the exit code.
sign() { # keyfile [flags...]
    local keyfile=$1; shift
    OUT=$(cd "$R" && bash "$SIGN" --github-output "$@" < "$keyfile" 2> "$WORK/err"); RC=$?
    ERR=$(cat "$WORK/err")
}

expect() { # name want-rc want-output-lines(joined by |)
    local name=$1 rc=$2 want=$3 got
    got=$(printf '%s' "$OUT" | tr '\n' '|')
    if [ "$RC" -eq "$rc" ] && [ "$got" = "$want" ]; then ok "$name"
    else fail "$name" "$(printf 'want exit %s [%s] got exit %s [%s]\n         stderr: %s' "$rc" "$want" "$RC" "$got" "$ERR")"; fi
}

assert_eq() { # name got want
    if [ "$2" = "$3" ]; then ok "$1"; else fail "$1" "want [$3] got [$2]"; fi
}

# What a fresh clone of origin covers.
covered_in_clone() { # [flags...]
    rm -rf "$WORK/clone"; git clone -q "$ORIGIN" "$WORK/clone"
    run_impl "$WORK/clone" "$@"
    printf '%s' "$GOT"
}

count_blocks() { grep -c '^-----BEGIN SSH SIGNATURE-----$'; }
remote_blocks() { git --git-dir="$ORIGIN" notes --ref amont-attest show "$(git -C "$R" rev-parse 'HEAD^{tree}')" 2> /dev/null | count_blocks; }
# The local MIRROR of origin's ref, and the unpushed blocks beside it.
local_blocks()  { git -C "$R" notes --ref amont-attest show "$(git -C "$R" rev-parse 'HEAD^{tree}')" 2> /dev/null | count_blocks; }
unpushed_blocks() { git -C "$R" notes --ref attest-local/amont-attest show "$(git -C "$R" rev-parse 'HEAD^{tree}')" 2> /dev/null | count_blocks; }
retried()       { case $ERR in *retrying*) return 0 ;; *) return 1 ;; esac; }

# --- the happy path -------------------------------------------------------
make_remote_repo
sign "$WORK/key" --gates "ci-fmt ci-shellcheck"
expect "signs and pushes" 0 "status=pushed|signed=true|pushed=true|gates=ci-fmt ci-shellcheck|inputs=0/0"
assert_eq "a fresh clone covers what CI signed" "$(covered_in_clone)" "ci-fmt ci-shellcheck"
assert_eq "the local ref follows the push" "$(local_blocks)" 1

# Re-run: the same block is recognised, nothing grows.
sign "$WORK/key" --gates "ci-fmt ci-shellcheck"
expect "a re-run finds its block already present" 0 "status=already-present|signed=false|pushed=true|gates=ci-fmt ci-shellcheck|inputs=0/0"
assert_eq "no duplicate block after a re-run" "$(remote_blocks)" 1

# Appends beside a developer's block on another platform: both verify.
make_remote_repo
append_note "$R" "$(payload_for "$R" pre-push-cargo-test s390x-aix)" "$WORK/second"
git -C "$R" push -q origin refs/notes/amont-attest:refs/notes/amont-attest
sign "$WORK/key" --gates ci-fmt
expect "appends beside an existing block" 0 "status=pushed|signed=true|pushed=true|gates=ci-fmt|inputs=0/0"
assert_eq "the developer's block survives" "$(remote_blocks)" 2
assert_eq "both blocks verify in a clone" "$(covered_in_clone --platform any)" "pre-push-cargo-test ci-fmt"

# --- local only ------------------------------------------------------------
# An unpushed block lives in refs/notes/attest-local/*, never in the mirror,
# so a verify run (which re-syncs the mirror with origin) cannot drop it.
make_remote_repo
sign "$WORK/key" --gates ci-fmt --no-push
expect "--no-push appends locally" 0 "status=local|signed=true|pushed=false|gates=ci-fmt|inputs=0/0"
assert_eq "the unpushed block is in attest-local" "$(unpushed_blocks)" 1
assert_eq "...not in the mirror" "$(local_blocks)" 0
if git --git-dir="$ORIGIN" rev-parse --verify --quiet refs/notes/amont-attest > /dev/null 2>&1; then
    fail "remote untouched by --no-push" "remote has the ref"
else
    ok "remote untouched by --no-push"
fi
check "the verifier ignores the unpushed block by default" "" "$R"
check "...and reads it with --include-local" "ci-fmt" "$R" --include-local
assert_eq "the unpushed block survives a verify run" "$(unpushed_blocks)" 1

# --- local blocks survive a failed push ------------------------------------
# An unpublished local block, then a push that cannot succeed: the local ref
# is byte-identical before and after, and the outcome is push-failed.
make_remote_repo
sign "$WORK/key" --gates ci-fmt --no-push > /dev/null 2>&1
before=$(git -C "$R" rev-parse refs/notes/attest-local/amont-attest)
git -C "$R" remote remove origin
sign "$WORK/key" --gates ci-shellcheck
expect "no origin at all: push-failed" 0 "status=push-failed|signed=false|pushed=false|gates=ci-shellcheck|inputs=0/0"
assert_eq "local ref untouched (no origin)" "$(git -C "$R" rev-parse refs/notes/attest-local/amont-attest)" "$before"
git -C "$R" remote add origin "file:///nonexistent/repo.git"
sign "$WORK/key" --gates ci-shellcheck
expect "unreachable origin: push-failed" 0 "status=push-failed|signed=false|pushed=false|gates=ci-shellcheck|inputs=0/0"
assert_eq "local ref untouched (unreachable)" "$(git -C "$R" rev-parse refs/notes/attest-local/amont-attest)" "$before"
if retried; then fail "an unreachable remote is not retried" "$ERR"; else ok "an unreachable remote is not retried"; fi
assert_eq "no temporary ref left behind" "$(git -C "$R" for-each-ref 'refs/notes/attest-sign-*')" ""

# --- the race: another job pushes between our fetch and our push -----------
# A one-shot pre-push hook in the fixture clone pushes a rival block from a
# second clone at exactly that moment. Deterministic, no sleeps.
make_remote_repo
rm -rf "$WORK/rival"; git clone -q "$ORIGIN" "$WORK/rival"
git -C "$WORK/rival" config user.email second@example.org
git -C "$WORK/rival" config user.name Rival
sign_block "$WORK/rival" "$(payload_for "$WORK/rival" pre-push-cargo-test s390x-aix)" "$WORK/second" > "$WORK/rival-block"
mkdir -p "$WORK/hooks"; : > "$WORK/hooks/armed"
cat > "$WORK/hooks/pre-push" <<EOF
#!/usr/bin/env bash
[ -e "$WORK/hooks/armed" ] || exit 0
rm -f "$WORK/hooks/armed"
cd "$WORK/rival" || exit 0
git notes --ref amont-attest append -m "\$(cat "$WORK/rival-block")" "\$(git rev-parse 'HEAD^{tree}')" > /dev/null 2>&1
git push -q origin refs/notes/amont-attest:refs/notes/amont-attest > /dev/null 2>&1
exit 0
EOF
chmod +x "$WORK/hooks/pre-push"
git -C "$R" config core.hooksPath "$WORK/hooks"
sign "$WORK/key" --gates ci-fmt
expect "a rejected push is retried and lands" 0 "status=pushed|signed=true|pushed=true|gates=ci-fmt|inputs=0/0"
if retried; then ok "the rejection was retried"; else fail "the rejection was retried" "$ERR"; fi
assert_eq "the rival's block and ours both landed" "$(remote_blocks)" 2
assert_eq "both verify after the race" "$(covered_in_clone --platform any)" "pre-push-cargo-test ci-fmt"
git -C "$R" config core.hooksPath /dev/null

# A refusal that is not a race is not retried.
make_remote_repo
mkdir -p "$ORIGIN/hooks"
printf '#!/usr/bin/env bash\necho "permission denied by policy" >&2\nexit 1\n' > "$ORIGIN/hooks/pre-receive"
chmod +x "$ORIGIN/hooks/pre-receive"
sign "$WORK/key" --gates ci-fmt --attempts 3
expect "a policy refusal is push-failed" 0 "status=push-failed|signed=false|pushed=false|gates=ci-fmt|inputs=0/0"
if retried; then fail "a policy refusal is not retried" "$ERR"; else ok "a policy refusal is not retried"; fi

# --- keys ------------------------------------------------------------------
make_remote_repo
sign /dev/null --gates ci-fmt
expect "empty stdin: no-key" 0 "status=no-key|signed=false|pushed=false|gates=ci-fmt|inputs=0/0"
printf 'not a key\n' > "$WORK/garbage"
sign "$WORK/garbage" --gates ci-fmt
expect "garbage key: bad-key" 0 "status=bad-key|signed=false|pushed=false|gates=ci-fmt|inputs=0/0"
ssh-keygen -q -t ed25519 -N secret -f "$WORK/locked"
sign "$WORK/locked" --gates ci-fmt
expect "passphrase-protected key: bad-key" 0 "status=bad-key|signed=false|pushed=false|gates=ci-fmt|inputs=0/0"
ssh-keygen -q -t ecdsa -N '' -f "$WORK/ecdsa"
sign "$WORK/ecdsa" --gates ci-fmt
expect "ecdsa key: bad-key" 0 "status=bad-key|signed=false|pushed=false|gates=ci-fmt|inputs=0/0"
assert_eq "nothing was pushed by a refused key" "$(remote_blocks)" 0
# A pasted secret: CRLF line endings and no final newline.
printf '%s' "$(sed 's/$/\r/' "$WORK/key")" > "$WORK/crlf-key"
sign "$WORK/crlf-key" --gates ci-fmt
expect "CRLF key without a final newline still loads" 0 "status=pushed|signed=true|pushed=true|gates=ci-fmt|inputs=0/0"

# --- gates -----------------------------------------------------------------
make_remote_repo
sign "$WORK/key" --gates ""
expect "empty --gates: no-gates, exit 0" 0 "status=no-gates|signed=false|pushed=false|gates=|inputs=0/0"
sign "$WORK/key" --gates "$(printf ' \n\t ')"
expect "whitespace-only --gates: no-gates" 0 "status=no-gates|signed=false|pushed=false|gates=|inputs=0/0"
sign "$WORK/key"
expect "missing --gates: usage error" 2 ""
sign "$WORK/key" --gates ci-fmt --platfrom any
expect "unknown flag: usage error" 2 ""
sign "$WORK/key" --gates "$(printf 'a\nb  "q"\t')"
expect "gates with newlines and quotes are normalised" 0 "status=pushed|signed=true|pushed=true|gates=a b \"q\"|inputs=0/0"
assert_eq "normalised gates verify" "$(covered_in_clone)" 'a b "q"'

# --- honesty guards --------------------------------------------------------
make_remote_repo
echo changed > "$R/file.txt"
sign "$WORK/key" --gates ci-fmt
expect "a modified tracked file: dirty" 0 "status=dirty|signed=false|pushed=false|gates=ci-fmt|inputs=0/0"
git -C "$R" checkout -q -- file.txt
echo new > "$R/new.txt"
sign "$WORK/key" --gates ci-fmt
expect "an untracked file: dirty" 0 "status=dirty|signed=false|pushed=false|gates=ci-fmt|inputs=0/0"
sign "$WORK/key" --gates ci-fmt --allow-dirty
expect "--allow-dirty signs anyway" 0 "status=pushed|signed=true|pushed=true|gates=ci-fmt|inputs=0/0"
rm -f "$R/new.txt"
make_remote_repo
echo 'build/' > "$R/.gitignore"; git -C "$R" add .gitignore; git -C "$R" commit -q -m ignore
git -C "$R" push -q origin HEAD:refs/heads/main
mkdir -p "$R/build"; echo out > "$R/build/artifact"
sign "$WORK/key" --gates ci-fmt
expect "ignored build output is not dirt" 0 "status=pushed|signed=true|pushed=true|gates=ci-fmt|inputs=0/0"

# The guard cannot be hidden by config, and a status that fails is not clean.
make_remote_repo
git -C "$R" config status.showUntrackedFiles no
echo new > "$R/hidden.txt"
sign "$WORK/key" --gates ci-fmt
expect "status.showUntrackedFiles=no does not hide an untracked file" 0 "status=dirty|signed=false|pushed=false|gates=ci-fmt|inputs=0/0"
rm -f "$R/hidden.txt"; git -C "$R" config --unset status.showUntrackedFiles
sub=$WORK/subrepo; rm -rf "$sub"; git init -q "$sub"; git -C "$sub" config core.hooksPath /dev/null
git -C "$sub" config user.email a@b.c; git -C "$sub" config user.name a
echo s > "$sub/s.txt"; git -C "$sub" add -A; git -C "$sub" commit -q -m s
if git -C "$R" -c protocol.file.allow=always submodule add -q "$sub" sub 2> /dev/null; then
    git -C "$R" commit -q -m submodule
    git -C "$R" config diff.ignoreSubmodules all
    echo changed > "$R/sub/s.txt"
    sign "$WORK/key" --gates ci-fmt
    expect "a modified submodule is dirt, whatever diff.ignoreSubmodules says" 0 "status=dirty|signed=false|pushed=false|gates=ci-fmt|inputs=0/0"
    git -C "$R" config --unset diff.ignoreSubmodules
fi
make_remote_repo
printf 'not an index' > "$R/.git/index"
sign "$WORK/key" --gates ci-fmt
expect "a failing git status refuses to sign, even with --allow-dirty" 0 "status=error|signed=false|pushed=false|gates=ci-fmt|inputs=0/0"
sign "$WORK/key" --gates ci-fmt --allow-dirty
expect "...--allow-dirty does not override a failing status" 0 "status=error|signed=false|pushed=false|gates=ci-fmt|inputs=0/0"

# A block that exists only locally survives a later successful push, in its
# own ref; the mirror and the remote hold only what was pushed.
make_remote_repo
sign "$WORK/key" --gates local-gate --no-push
expect "a local-only block first" 0 "status=local|signed=true|pushed=false|gates=local-gate|inputs=0/0"
sign "$WORK/key" --gates pushed-gate
expect "then a pushed one" 0 "status=pushed|signed=true|pushed=true|gates=pushed-gate|inputs=0/0"
assert_eq "the local-only block is still unpushed" "$(unpushed_blocks)" 1
assert_eq "the mirror holds only the pushed one" "$(local_blocks)" 1
assert_eq "the remote holds only the pushed one" "$(remote_blocks)" 1

# A push to another remote never enters origin's mirror.
make_remote_repo
rm -rf "$WORK/other.git"; git init -q --bare "$WORK/other.git"
git -C "$R" remote add other "$WORK/other.git"
sign "$WORK/key" --gates ci-fmt --remote other
expect "a push to another remote" 0 "status=pushed|signed=true|pushed=true|gates=ci-fmt|inputs=0/0"
assert_eq "...leaves origin's mirror alone" "$(local_blocks)" 0

# --- --object --------------------------------------------------------------
make_remote_repo
sign "$WORK/key" --gates ci-fmt --object HEAD
expect "--object HEAD attaches to the commit" 0 "status=pushed|signed=true|pushed=true|gates=ci-fmt|inputs=0/0"
if git -C "$R" notes --ref amont-attest show HEAD > /dev/null 2>&1; then ok "note is on the commit"; else fail "note is on the commit" ""; fi
assert_eq "a commit-keyed CI note verifies" "$(covered_in_clone)" ci-fmt
sign "$WORK/key" --gates ci-fmt --object HEAD:.github
expect "--object with another tree: usage error" 2 ""
sign "$WORK/key" --gates ci-fmt --object doesnotexist
expect "--object that does not resolve: usage error" 2 ""

# --- platform --------------------------------------------------------------
make_remote_repo
sign "$WORK/key" --gates ci-fmt --platform s390x-aix
expect "--platform is written as given" 0 "status=pushed|signed=true|pushed=true|gates=ci-fmt|inputs=0/0"
assert_eq "a foreign platform is not covered here" "$(covered_in_clone)" ""
assert_eq "...but is on its own platform" "$(covered_in_clone --platform s390x-aix)" ci-fmt

# --- input fingerprints (1.3.0) ---------------------------------------------
# A committed spec: the block carries `input <gate> <fp>` for each signed
# gate the spec declares, and is filed under K(gate, fp) in the inputs ref.
spec_repo() { # [spec lines...]
    make_remote_repo
    mkdir -p "$R/src" "$R/docs"; echo 'fn main() {}' > "$R/src/main.rs"; echo doc > "$R/docs/README.md"
    echo '[package]' > "$R/Cargo.toml"
    git -C "$R" add -A; git -C "$R" commit -q -m src
    if [ $# -gt 0 ]; then printf '%s\n' "$@"; else printf 'ci-fmt src Cargo.toml\nci-lint src\n'; fi | write_spec "$R"
    git -C "$R" push -q origin HEAD:refs/heads/main
}
remote_input_blocks() { # gate fp
    git --git-dir="$ORIGIN" notes --ref amont-attest-inputs show "$(input_key "$R" "$1" "$2")" 2> /dev/null | count_blocks
}

spec_repo
fp_fmt=$(fp_of "$R" ci-fmt); fp_lint=$(fp_of "$R" ci-lint)
sign "$WORK/key" --gates "ci-fmt ci-lint ci-other"
expect "spec: signs, with two fingerprints" 0 "status=pushed|signed=true|pushed=true|gates=ci-fmt ci-lint ci-other|inputs=2/2"
body=$(git --git-dir="$ORIGIN" notes --ref amont-attest show "$(git -C "$R" rev-parse 'HEAD^{tree}')")
assert_eq "spec: the payload carries input lines in spec order" \
    "$(printf '%s' "$body" | awk '$1 == "input" { print $2 }' | tr '\n' ' ')" "ci-fmt ci-lint "
assert_eq "spec: the fingerprint is the one SPEC.md defines" "$(printf '%s' "$body" | awk '$1 == "input" && $2 == "ci-fmt" { print $3 }')" "$fp_fmt"
assert_eq "spec: a gate the spec does not declare gets no input line" "$(printf '%s' "$body" | grep -c '^input ci-other ')" 0
assert_eq "spec: the block is under K(ci-fmt)" "$(remote_input_blocks ci-fmt "$fp_fmt")" 1
assert_eq "spec: the block is under K(ci-lint)" "$(remote_input_blocks ci-lint "$fp_lint")" 1
move_tree "$R"; git -C "$R" push -q origin HEAD:refs/heads/main
assert_eq "spec: a fresh clone covers after an unrelated commit" "$(covered_in_clone)" "ci-fmt ci-lint"

# A re-run appends nothing anywhere.
git -C "$R" checkout -q HEAD~1 2> /dev/null
sign "$WORK/key" --gates "ci-fmt ci-lint ci-other"
expect "spec: a re-run finds every key already present" 0 "status=already-present|signed=false|pushed=true|gates=ci-fmt ci-lint ci-other|inputs=2/2"
assert_eq "spec: no growth under K(ci-fmt)" "$(remote_input_blocks ci-fmt "$fp_fmt")" 1
git -C "$R" checkout -q main 2> /dev/null || git -C "$R" checkout -q -

# An invalid spec degrades to the object-keyed block.
spec_repo 'ci-fmt src/*.rs'
sign "$WORK/key" --gates ci-fmt
expect "spec: an invalid spec degrades to the tree-keyed block" 0 "status=pushed|signed=true|pushed=true|gates=ci-fmt|inputs=0/0"
case $ERR in *"no input fingerprints"*) ok "spec: ...and says why" ;; *) fail "spec: ...and says why" "$ERR" ;; esac

# A declared path that does not exist in the signed tree: that gate has none.
spec_repo 'ci-fmt src Cargo.toml' 'ci-lint nope'
sign "$WORK/key" --gates "ci-fmt ci-lint"
expect "spec: a gate whose path does not exist has no fingerprint" 0 "status=pushed|signed=true|pushed=true|gates=ci-fmt ci-lint|inputs=1/1"

# Both spec locations: none.
spec_repo
printf 'ci-fmt src\n' | write_spec "$R" .forgejo
sign "$WORK/key" --gates ci-fmt
expect "spec: both locations present, no fingerprints" 0 "status=pushed|signed=true|pushed=true|gates=ci-fmt|inputs=0/0"

# --object HEAD: the main-ref note is on the commit; the keys are the same.
spec_repo
fp_fmt=$(fp_of "$R" ci-fmt)
sign "$WORK/key" --gates ci-fmt --object HEAD
expect "spec: --object HEAD still files under the key" 0 "status=pushed|signed=true|pushed=true|gates=ci-fmt|inputs=1/1"
assert_eq "spec: ...and the key holds the block" "$(remote_input_blocks ci-fmt "$fp_fmt")" 1

# --no-push appends to both local refs.
spec_repo
fp_fmt=$(fp_of "$R" ci-fmt)
sign "$WORK/key" --gates ci-fmt --no-push
expect "spec: --no-push appends locally to both refs" 0 "status=local|signed=true|pushed=false|gates=ci-fmt|inputs=1/1"
assert_eq "spec: ...local inputs ref has the key" \
    "$(git -C "$R" notes --ref attest-local/amont-attest-inputs show "$(input_key "$R" ci-fmt "$fp_fmt")" 2> /dev/null | count_blocks)" 1

# Partial publication: the inputs ref refused, the main ref not. A later run
# repairs the keys without touching the main ref.
spec_repo
fp_fmt=$(fp_of "$R" ci-fmt)
mkdir -p "$ORIGIN/hooks"
# shellcheck disable=SC2016  # the hook's own $ref, not ours
printf '#!/usr/bin/env bash\nwhile read -r _ _ ref; do [ "$ref" = refs/notes/amont-attest-inputs ] && { echo "inputs ref refused by policy" >&2; exit 1; }; done\nexit 0\n' > "$ORIGIN/hooks/pre-receive"
chmod +x "$ORIGIN/hooks/pre-receive"
sign "$WORK/key" --gates ci-fmt
expect "spec: inputs ref refused, main ref published" 0 "status=pushed|signed=true|pushed=true|gates=ci-fmt|inputs=0/1"
assert_eq "spec: ...no key on the remote yet" "$(remote_input_blocks ci-fmt "$fp_fmt")" 0
rm -f "$ORIGIN/hooks/pre-receive"
sign "$WORK/key" --gates ci-fmt
expect "spec: the next run repairs the key" 0 "status=already-present|signed=false|pushed=true|gates=ci-fmt|inputs=1/1"
assert_eq "spec: ...and the key now holds the block" "$(remote_input_blocks ci-fmt "$fp_fmt")" 1
assert_eq "spec: ...while the main ref did not grow" "$(remote_blocks)" 1
assert_eq "spec: no temporary ref left behind" "$(git -C "$R" for-each-ref 'refs/notes/attest-sign-*')" ""

# A local-only block on the inputs ref survives a later push there too.
spec_repo
fp_fmt=$(fp_of "$R" ci-fmt); fp_lint=$(fp_of "$R" ci-lint)
sign "$WORK/key" --gates ci-lint --no-push
sign "$WORK/key" --gates ci-fmt
expect "inputs: a pushed block after a local-only one" 0 "status=pushed|signed=true|pushed=true|gates=ci-fmt|inputs=1/1"
assert_eq "inputs: the local-only key survived" \
    "$(git -C "$R" notes --ref attest-local/amont-attest-inputs show "$(input_key "$R" ci-lint "$fp_lint")" 2> /dev/null | count_blocks)" 1
assert_eq "inputs: the pushed key is there too" "$(remote_input_blocks ci-fmt "$fp_fmt")" 1

# --- origin's mirror (1.4.0) -------------------------------------------------
# refs/notes/amont-attest[-inputs] follow origin, which is the only place an
# attestation can be revoked. SPEC.md, "Lookup".

# The reasons, on stderr, from the verifier's explaining form.
explain_in() { # dir [flags...]
    local dir=$1; shift
    # shellcheck disable=SC2046,SC2086  # the command line word-splits on purpose
    ERR=$(cd "$dir" && set -- $(explain_impl) "$@" && "$@" 2>&1 > /dev/null < /dev/null)
}
gha_in() { # dir [flags...] -> the notes= and inputs_notes= lines, joined
    run_impl "$1" --github-output "${@:2}"
    printf '%s' "$GOT" | tr ' ' '\n' | grep -E '^(inputs_)?notes=' | tr '\n' ' ' | sed 's/ $//'
}
has_ref() { git -C "$1" rev-parse --verify --quiet "$2" > /dev/null 2>&1; }

# Revocation: a pushed gate, then origin's ref deleted. The signer's clone and
# a fresh one both cover nothing, and the signer's next push brings nothing back.
make_remote_repo
sign "$WORK/key" --gates ci-fmt
git --git-dir="$ORIGIN" update-ref -d refs/notes/amont-attest
check "revoked on origin: the signer's clone covers nothing" "" "$R"
if has_ref "$R" refs/notes/amont-attest; then fail "...and its mirror is gone" "still there"; else ok "...and its mirror is gone"; fi
assert_eq "revoked on origin: a fresh clone covers nothing" "$(covered_in_clone)" ""
sign "$WORK/key" --gates ci-other
assert_eq "the signer's next push does not bring it back" "$(covered_in_clone)" "ci-other"

# A 1.3.1-style clone: its local ref holds what origin used to have, origin
# has nothing. The mirror is deleted, loudly, with a restore command that works.
make_remote_repo
append_note "$R" "$(payload_for "$R" ci-fmt "$PLATFORM")" "$WORK/key"
old=$(git -C "$R" rev-parse refs/notes/amont-attest)
check "a stale mirror with nothing on origin covers nothing" "" "$R"
make_remote_repo
append_note "$R" "$(payload_for "$R" ci-fmt "$PLATFORM")" "$WORK/key"
old=$(git -C "$R" rev-parse refs/notes/amont-attest)
explain_in "$R"
want="attest: origin has no refs/notes/amont-attest; deleted the local mirror (was $old); restore: git update-ref refs/notes/amont-attest $old"
case $ERR in *"$want"*) ok "the deletion is announced with its restore command" ;; *) fail "the deletion is announced with its restore command" "$ERR" ;; esac
git -C "$R" update-ref refs/notes/amont-attest "$old"
assert_eq "...and the restore command brings the ref back" "$(git -C "$R" rev-parse refs/notes/amont-attest)" "$old"

# Origin reachable, neither ref there: both absent, both mirrors deleted.
make_remote_repo
append_note "$R" "$(payload_for "$R" ci-fmt "$PLATFORM")" "$WORK/key"
git -C "$R" notes --ref amont-attest-inputs add -m x HEAD 2> /dev/null
assert_eq "origin with neither ref" "$(gha_in "$R")" "notes=absent inputs_notes=absent"
if has_ref "$R" refs/notes/amont-attest || has_ref "$R" refs/notes/amont-attest-inputs; then
    fail "...both mirrors deleted" "one survived"
else
    ok "...both mirrors deleted"
fi
# Only the main ref on origin: that one fetched, the other absent.
make_remote_repo
sign "$WORK/key" --gates ci-fmt > /dev/null 2>&1
git -C "$R" notes --ref amont-attest-inputs add -m x HEAD 2> /dev/null
assert_eq "origin with only the main ref" "$(gha_in "$R")" "notes=fetched inputs_notes=absent"

# Origin configured but unreachable: a populated mirror is NOT judged, and
# the reason is exact (and identical in both implementations).
make_remote_repo
sign "$WORK/key" --gates ci-fmt > /dev/null 2>&1
git -C "$R" remote set-url origin "file:///nonexistent/attest-origin.git"
check "an unreachable origin: the mirror is not judged" "" "$R"
assert_eq "...notes says so" "$(gha_in "$R")" "notes=unreachable inputs_notes=unreachable"
explain_in "$R"
want="attest: cannot fetch refs/notes/amont-attest from origin (no credentials? persist-credentials: false?); local mirror not judged, running everything
attest: cannot fetch refs/notes/amont-attest-inputs from origin (no credentials? persist-credentials: false?); local mirror not judged, running everything"
assert_eq "...with the exact reasons first" "$(printf '%s\n' "$ERR" | head -2)" "$want"
if has_ref "$R" refs/notes/amont-attest; then ok "...and the mirror is kept for when origin answers"; else fail "...and the mirror is kept" "deleted"; fi

# An unpushed block beside an ignored one says how to include it.
make_remote_repo
sign "$WORK/key" --gates ci-fmt --no-push > /dev/null 2>&1
explain_in "$R"
case $ERR in *"attest: refs/notes/attest-local/amont-attest holds unpushed blocks, ignored without --include-local"*) ok "ignored unpushed blocks are named" ;; *) fail "ignored unpushed blocks are named" "$ERR" ;; esac

# A stalled http origin — connection accepted, nothing ever sent back — is
# bounded: at most two remote calls, each cut off after 10 s of silence.
PY=$(command -v python3 || command -v python || true)
if [ -n "$PY" ] && [ "$OS" != windows ]; then
    "$PY" -c '
import socket, sys, time
s = socket.socket(); s.bind(("127.0.0.1", 0)); s.listen(16)
print(s.getsockname()[1], flush=True)
conns = []
while True:
    c, _ = s.accept(); conns.append(c)
' > "$WORK/port" &
    listener=$!
    for _ in 1 2 3 4 5 6 7 8 9 10; do [ -s "$WORK/port" ] && break; sleep 1; done
    make_remote_repo
    git -C "$R" remote set-url origin "http://127.0.0.1:$(cat "$WORK/port")/repo.git"
    t0=$(date +%s)
    got=$(gha_in "$R")
    t=$(( $(date +%s) - t0 ))
    kill "$listener" 2> /dev/null; wait "$listener" 2> /dev/null
    assert_eq "a stalled http origin is unreachable" "$got" "notes=unreachable inputs_notes=unreachable"
    if [ "$t" -le 30 ]; then ok "...within 30 s (took ${t} s)"; else fail "...within 30 s" "took ${t} s"; fi
else
    printf '  SKIP  a stalled http origin (no python here, or Windows)\n'
fi

# Never a prompt: every remote call runs with prompts off and ssh in batch
# mode. The faulty-git wrapper records what fetch and ls-remote saw.
make_remote_repo
git -C "$R" remote set-url origin "file:///nonexistent/attest-origin.git"
case "$IMPL" in bash*) native= ;; *) native=1 ;; esac
if [ -n "$native" ] && [ "$OS" = windows ]; then
    printf '  SKIP  remote calls never prompt (the faulty-git wrapper cannot reach a native binary on Windows)\n'
else
    mkdir -p "$WORK/fault"; tr -d '\r' < "$HERE/tests/fault/git" > "$WORK/fault/git"; chmod +x "$WORK/fault/git"
    : > "$WORK/fault.log"
    ATTEST_REAL_GIT=$(command -v git) ATTEST_FAULT=env ATTEST_FAULT_LOG="$WORK/fault.log" GIT_SSH_COMMAND='' \
        PATH="$WORK/fault:$PATH" run_impl "$R"
    seen=$(sort -u "$WORK/fault.log" | tr '\n' '|')
    assert_eq "remote calls never prompt" "$seen" "0|ssh -o BatchMode=yes -o ConnectTimeout=10|"
fi

# The mirror cannot be deleted (a read-only .git): it is not judged either.
# The premise is checked first — root, reftable and packed refs all delete
# anyway — and the case says SKIP rather than passing for the wrong reason.
make_remote_repo
append_note "$R" "$(payload_for "$R" ci-fmt "$PLATFORM")" "$WORK/key"
git -C "$R" update-ref refs/notes/attest-scratch HEAD
restore_perm() { chmod u+w "$R/.git/refs/notes" 2> /dev/null; }
trap 'restore_perm; rm -rf "$WORK"' EXIT
trap 'restore_perm; exit 130' INT TERM
chmod a-w "$R/.git/refs/notes" 2> /dev/null
if [ "$OS" != windows ] && ! git -C "$R" update-ref -d refs/notes/attest-scratch 2> /dev/null; then
    assert_eq "an undeletable mirror is not judged" "$(gha_in "$R")" "notes=undeletable inputs_notes=absent"
    check "...and covers nothing" "" "$R"
else
    printf '  SKIP  an undeletable mirror (a read-only refs dir still deletes here)\n'
fi
restore_perm
trap 'rm -rf "$WORK"' EXIT

summary
