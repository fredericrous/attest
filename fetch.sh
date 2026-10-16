#!/usr/bin/env bash
# Print the path of the git-attest binary that RELEASE pins, for this runner.
#
#   fetch.sh
#
# The actions run it first and use the binary it names; on any failure they
# warn and fall back to verify.sh / sign.sh, so a flaky download can never
# fail a job or silently disable a gate (the actions' header says why).
#
# What it does, in order: map this runner to a release target (Linux x86_64
# takes the static musl build, so an old glibc or an Alpine `container:` job
# still runs it); take an archive from the cache, or download
# git-attest-<version>-<target>.tar.gz from that release; refuse it unless its
# sha256 is the one RELEASE names; extract it into a private directory; prove
# the binary runs. The digest is checked on a private COPY of the archive,
# after every cache hit as after every download, and only that copy is
# extracted: a cache on a persistent runner is never trusted, only reused.
#
# Exit 0 and one line on stdout, the binary's path. Exit 1 on any failure,
# whose LAST line on stderr is `attest: <reason>`, ready to quote in a
# warning.
#
# Test-only overrides (tests/fetch.sh): ATTEST_RELEASE_FILE (default: RELEASE
# beside this script), ATTEST_RELEASE_URL (the download base, default
# https://github.com/fredericrous/attest/releases/download), ATTEST_TARGET,
# ATTEST_CACHE (default: $RUNNER_TOOL_CACHE/git-attest).
set -uf

fail() {
    printf 'attest: %s\n' "$1" >&2
    exit 1
}

# Git Bash hands Windows paths (D:\a\_temp) to scripts; turn them into the
# POSIX form every tool below expects.
posix() {
    case $1 in
        [A-Za-z]:[\\/]*) if command -v cygpath > /dev/null 2>&1; then cygpath -u "$1"; return; fi ;;
    esac
    printf '%s\n' "$1"
}

sha256() {
    if command -v sha256sum > /dev/null 2>&1; then
        sha256sum < "$1" | awk '{print $1}'
    elif command -v shasum > /dev/null 2>&1; then
        shasum -a 256 < "$1" | awk '{print $1}'
    else
        return 1
    fi
}

# The release targets (release.yaml builds these six). Anything else has no
# asset, and the shell scripts serve it.
target() {
    case "$(uname -s)" in
        Linux)
            case "$(uname -m)" in
                x86_64 | amd64) echo x86_64-unknown-linux-musl ;;
                aarch64 | arm64) echo aarch64-unknown-linux-gnu ;;
            esac ;;
        Darwin)
            case "$(uname -m)" in
                arm64 | aarch64) echo aarch64-apple-darwin ;;
                x86_64) echo x86_64-apple-darwin ;;
            esac ;;
        MINGW* | MSYS* | CYGWIN* | Windows_NT)
            case "$(uname -m)" in
                x86_64 | amd64) echo x86_64-pc-windows-msvc ;;
            esac ;;
    esac
}

here=$(cd "$(dirname "$0")" && pwd)
release=${ATTEST_RELEASE_FILE:-$here/RELEASE}
[ -r "$release" ] || fail "no RELEASE file at $release"

version=$(awk '$1 == "version" { print $2; exit }' "$release")
printf '%s\n' "$version" | grep -Eqx '[0-9]+\.[0-9]+\.[0-9]+' \
    || fail "RELEASE names no usable version: '$version'"

tgt=${ATTEST_TARGET:-$(target)}
[ -n "$tgt" ] || fail "no git-attest release for $(uname -s) $(uname -m)"
want=$(awk -v t="$tgt" '$1 == t { print $2; exit }' "$release")
[ -n "$want" ] || fail "RELEASE pins no git-attest $version archive for $tgt"
printf '%s\n' "$want" | grep -Eqx '[0-9a-f]{64}' \
    || fail "RELEASE's sha256 for $tgt is not a sha256: '$want'"

command -v curl > /dev/null 2>&1 || fail "curl is not installed"
command -v sha256sum > /dev/null 2>&1 || command -v shasum > /dev/null 2>&1 \
    || fail "neither sha256sum nor shasum is installed"

name=git-attest-$version-$tgt
base=${ATTEST_RELEASE_URL:-https://github.com/fredericrous/attest/releases/download}
url=$base/v$version/$name.tar.gz
tmp=$(posix "${RUNNER_TEMP:-${TMPDIR:-/tmp}}")
cache=$(posix "${ATTEST_CACHE:-${RUNNER_TOOL_CACHE:-$tmp}/git-attest}")/$version-$tgt-$want
cached=$cache/$name.tar.gz

work=$(mktemp -d "$tmp/git-attest.XXXXXX") || fail "cannot create a directory under $tmp"
copy=$work/$name.tar.gz

if [ -f "$cached" ] && cp "$cached" "$copy" 2> /dev/null && [ "$(sha256 "$copy")" = "$want" ]; then
    :
else
    if [ -f "$cached" ]; then
        printf 'attest: the cached %s.tar.gz does not match RELEASE; downloading it again\n' "$name" >&2
        rm -f "$cached"
    fi
    curl -fsSL --retry 3 --retry-delay 2 --connect-timeout 10 --max-time 120 -o "$copy" "$url" \
        || fail "could not download $url"
    got=$(sha256 "$copy")
    [ "$got" = "$want" ] \
        || fail "the downloaded $name.tar.gz has sha256 $got; RELEASE pins $want, so it is refused"
    # Best effort: a cache that cannot be written only costs the next run a
    # download.
    if mkdir -p "$cache" 2> /dev/null && cp "$copy" "$cached.$$" 2> /dev/null; then
        mv -f "$cached.$$" "$cached" 2> /dev/null || rm -f "$cached.$$"
    fi
fi

# From stdin: GNU tar reads `C:/...` as a remote host, and a relative name
# sidesteps every path dialect at once.
(cd "$work" && tar xzf - < "$copy") || fail "could not extract $name.tar.gz"
bin=$work/$name/git-attest
[ -f "$bin.exe" ] && bin=$bin.exe
[ -f "$bin" ] || fail "$name.tar.gz holds no git-attest binary"
ran=$("$bin" --version 2>&1) || fail "the git-attest $version binary does not run here: $ran"
[ "$ran" = "git-attest $version" ] || fail "the binary says '$ran', not git-attest $version"
printf '%s\n' "$bin"
