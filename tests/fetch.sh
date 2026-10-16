#!/usr/bin/env bash
# fetch.sh, the actions' way to the pinned binary, against a release served
# from file://, and the shell scripts' deprecation line.
#
#   tests/fetch.sh
#
# Each failure case asserts the exit code (1), that stdout names no binary,
# and the reason on stderr's last line, which the actions quote in their
# warning. RELEASE itself is checked against the targets release builds.
set -u

HERE=$(cd "$(dirname "$0")/.." && pwd)
FETCH="$HERE/fetch.sh"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT
# shellcheck disable=SC2034  # read by lib.sh
IMPL=unused
# shellcheck source=lib.sh disable=SC1091
. "$HERE/tests/lib.sh"

V=9.9.9
T=test-target
NAME=git-attest-$V-$T
REL=$WORK/rel
# curl wants file:///C:/... on Windows; `pwd -W` exists only in Git Bash.
url_of() { (cd "$1" && p=$(pwd -W 2> /dev/null || pwd) && case $p in /*) echo "file://$p" ;; *) echo "file:///$p" ;; esac); }

sha_of() {
    if command -v sha256sum > /dev/null 2>&1; then sha256sum < "$1"; else shasum -a 256 < "$1"; fi | awk '{print $1}'
}

# A release whose stub binary answers --version with `$1` and exits `$2`.
make_release() { # version-line exit-code
    rm -rf "$REL" && mkdir -p "$REL/v$V" "$WORK/build/$NAME"
    # shellcheck disable=SC2016  # the stub's own $1
    printf '#!/bin/sh\n[ "$1" = --version ] && echo "%s"\nexit %s\n' "$1" "$2" > "$WORK/build/$NAME/git-attest"
    chmod +x "$WORK/build/$NAME/git-attest"
    (cd "$WORK/build" && tar czf "$REL/v$V/$NAME.tar.gz" "$NAME")
    rm -rf "$WORK/build"
}

write_release() { # sha
    printf '# test\nversion %s\n%s %s\n' "$V" "$T" "$1" > "$WORK/RELEASE"
}

CACHE=$WORK/cache
run_fetch() {
    ATTEST_RELEASE_FILE=$WORK/RELEASE ATTEST_RELEASE_URL="$(url_of "$WORK")/rel" \
        ATTEST_TARGET=$T ATTEST_CACHE=$CACHE RUNNER_TEMP=$WORK \
        bash "$FETCH" > "$WORK/out" 2> "$WORK/err"
}

expect_ok() { # name
    if run_fetch && [ -x "$(cat "$WORK/out")" ] && [ "$("$(cat "$WORK/out")" --version)" = "git-attest $V" ]; then
        ok "$1"
    else
        fail "$1" "stdout: $(cat "$WORK/out") stderr: $(cat "$WORK/err")"
    fi
}

expect_fail() { # name reason-substring
    if run_fetch; then
        fail "$1" "exit 0, stdout: $(cat "$WORK/out")"
    elif [ -s "$WORK/out" ]; then
        fail "$1" "a failure named a binary: $(cat "$WORK/out")"
    else
        case "$(tail -n 1 "$WORK/err")" in
            "attest: "*"$2"*) ok "$1" ;;
            *) fail "$1" "last stderr line: $(tail -n 1 "$WORK/err")" ;;
        esac
    fi
}

echo "--- fetch.sh ---"

make_release "git-attest $V" 0
GOOD=$(sha_of "$REL/v$V/$NAME.tar.gz")
write_release "$GOOD"
expect_ok "a pinned archive downloads, checks and runs"
CACHED=$CACHE/$V-$T-$GOOD/$NAME.tar.gz
if [ -f "$CACHED" ]; then ok "and is cached under version, target and digest"; else fail "cached" "no $CACHED"; fi

mv "$REL" "$REL.away"
expect_ok "a cache hit needs no download"
printf 'tampered' >> "$CACHED"
expect_fail "a tampered cache is refused, and with no release nothing runs" "could not download"
if grep -q "cached $NAME.tar.gz does not match RELEASE" "$WORK/err"; then ok "and the log says the cache was refused"; else fail "cache refusal line" "$(cat "$WORK/err")"; fi
mv "$REL.away" "$REL"
printf 'tampered' >> "$CACHED" 2> /dev/null || true
expect_ok "a tampered cache is replaced from the release"
if [ "$(sha_of "$CACHED")" = "$GOOD" ]; then ok "and the cache holds the pinned bytes again"; else fail "cache repaired" "$(sha_of "$CACHED")"; fi

rm -rf "$CACHE"
write_release "$(printf '%064d' 0)"
expect_fail "an archive whose digest is not RELEASE's is refused" "RELEASE pins $(printf '%064d' 0), so it is refused"
if [ -d "$CACHE" ] && [ -n "$(ls -A "$CACHE")" ]; then fail "refused archive cached" "$(ls -R "$CACHE")"; else ok "and is never cached"; fi

printf 'version %s\nother-target %s\n' "$V" "$GOOD" > "$WORK/RELEASE"
expect_fail "a target RELEASE does not pin has no binary" "pins no git-attest $V archive for $T"

write_release "not-a-digest"
expect_fail "a malformed digest is refused" "is not a sha256"

printf '%s %s\n' "$T" "$GOOD" > "$WORK/RELEASE"
expect_fail "a RELEASE with no version is refused" "no usable version"

rm -f "$WORK/RELEASE"
expect_fail "no RELEASE file, no binary" "no RELEASE file"

write_release "$GOOD"
rm -f "$REL/v$V/$NAME.tar.gz"
expect_fail "a release without the asset is a failed download" "could not download"

make_release "git-attest $V" 1
rm -rf "$CACHE"; write_release "$(sha_of "$REL/v$V/$NAME.tar.gz")"
expect_fail "a binary that will not run is refused" "does not run here"

make_release "git-attest 0.0.1" 0
rm -rf "$CACHE"; write_release "$(sha_of "$REL/v$V/$NAME.tar.gz")"
expect_fail "a binary of another version is refused" "not git-attest $V"

echo "--- RELEASE ---"

# The committed file pins exactly the targets release.yaml builds.
built=$(sed -n 's/.*target: *\([a-z0-9_-]*\),.*/\1/p' "$HERE/.github/workflows/build.yaml" | sort)
pinned=$(awk '$1 != "version" && $1 !~ /^#/ && NF { print $1 }' "$HERE/RELEASE" | sort)
if [ -n "$built" ] && [ "$built" = "$pinned" ]; then ok "RELEASE pins every target build.yaml builds"; else fail "RELEASE targets" "built: $built / pinned: $pinned"; fi
bad=$(awk '$1 != "version" && $1 !~ /^#/ && NF && $2 !~ /^[0-9a-f]+$/ { print $1 }' "$HERE/RELEASE")
lens=$(awk '$1 != "version" && $1 !~ /^#/ && NF { print length($2) }' "$HERE/RELEASE" | sort -u)
if [ -z "$bad" ] && [ "$lens" = 64 ]; then ok "every digest is a sha256"; else fail "RELEASE digests" "bad: $bad lengths: $lens"; fi
if awk '$1 == "version" { print $2 }' "$HERE/RELEASE" | grep -Eqx '[0-9]+\.[0-9]+\.[0-9]+'; then ok "RELEASE names a version"; else fail "RELEASE version" "$(grep version "$HERE/RELEASE")"; fi

echo "--- deprecation ---"

R=$WORK/repo
git init -q "$R" && git -C "$R" -c core.hooksPath=/dev/null -c user.email=t@example.org -c user.name=t commit -q --allow-empty -m init
unset ATTEST_NO_DEPRECATION
quiet_out=$(cd "$R" && GITHUB_ACTIONS='' bash "$HERE/verify.sh" --quiet 2> "$WORK/err")
if grep -q '^attest: verify.sh is deprecated' "$WORK/err"; then ok "verify.sh says it is deprecated, even under --quiet"; else fail "verify.sh deprecation" "$(cat "$WORK/err")"; fi
(cd "$R" && GITHUB_ACTIONS=true bash "$HERE/verify.sh" --quiet > /dev/null 2> "$WORK/err")
if grep -q '^::warning title=attest::verify.sh is deprecated' "$WORK/err"; then ok "as a warning annotation under GitHub Actions"; else fail "verify.sh annotation" "$(cat "$WORK/err")"; fi
plain_out=$(cd "$R" && ATTEST_NO_DEPRECATION=1 bash "$HERE/verify.sh" --quiet 2> "$WORK/err")
if [ ! -s "$WORK/err" ] && [ "$quiet_out" = "$plain_out" ]; then ok "ATTEST_NO_DEPRECATION silences it, and stdout is the same either way"; else fail "verify.sh silenced" "$(cat "$WORK/err")"; fi
sign_out=$(cd "$R" && GITHUB_ACTIONS='' bash "$HERE/sign/sign.sh" --gates x --github-output < /dev/null 2> "$WORK/err")
if grep -q '^attest: sign.sh is deprecated' "$WORK/err"; then ok "sign.sh says it is deprecated"; else fail "sign.sh deprecation" "$(cat "$WORK/err")"; fi
case $sign_out in status=no-key*) ok "and its stdout is unchanged" ;; *) fail "sign.sh stdout" "$sign_out" ;; esac

summary
