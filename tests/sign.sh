#!/usr/bin/env bash
# The producer's contract, as fixtures: sign/sign.sh against a bare `origin`.
#
#   tests/sign.sh                # uses ./verify.sh to read back what was signed
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
IMPL="bash $VERIFY --quiet"
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
local_blocks()  { git -C "$R" notes --ref amont-attest show "$(git -C "$R" rev-parse 'HEAD^{tree}')" 2> /dev/null | count_blocks; }
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
make_remote_repo
sign "$WORK/key" --gates ci-fmt --no-push
expect "--no-push appends locally" 0 "status=local|signed=true|pushed=false|gates=ci-fmt|inputs=0/0"
assert_eq "local note written" "$(local_blocks)" 1
if git --git-dir="$ORIGIN" rev-parse --verify --quiet refs/notes/amont-attest > /dev/null 2>&1; then
    fail "remote untouched by --no-push" "remote has the ref"
else
    ok "remote untouched by --no-push"
fi
check "verify.sh reads the local block" "ci-fmt" "$R"

# --- local blocks survive a failed push ------------------------------------
# An unpublished local block, then a push that cannot succeed: the local ref
# is byte-identical before and after, and the outcome is push-failed.
make_remote_repo
sign "$WORK/key" --gates ci-fmt --no-push > /dev/null 2>&1
before=$(git -C "$R" rev-parse refs/notes/amont-attest)
git -C "$R" remote remove origin
sign "$WORK/key" --gates ci-shellcheck
expect "no origin at all: push-failed" 0 "status=push-failed|signed=false|pushed=false|gates=ci-shellcheck|inputs=0/0"
assert_eq "local ref untouched (no origin)" "$(git -C "$R" rev-parse refs/notes/amont-attest)" "$before"
git -C "$R" remote add origin "file:///nonexistent/repo.git"
sign "$WORK/key" --gates ci-shellcheck
expect "unreachable origin: push-failed" 0 "status=push-failed|signed=false|pushed=false|gates=ci-shellcheck|inputs=0/0"
assert_eq "local ref untouched (unreachable)" "$(git -C "$R" rev-parse refs/notes/amont-attest)" "$before"
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
    "$(git -C "$R" notes --ref amont-attest-inputs show "$(input_key "$R" ci-fmt "$fp_fmt")" 2> /dev/null | count_blocks)" 1

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

summary
