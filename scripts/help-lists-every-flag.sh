#!/usr/bin/env bash
# Every flag a parser accepts appears in that program's --help.
#
# The help of verify.sh and sign.sh is a line range of their header comment,
# and git-attest's is a string beside its parser: all three drift the moment a
# flag is added and the text is not. A flag nobody can discover is one nobody
# uses — or, worse, one somebody guesses wrong.
set -u
cd "$(dirname "$0")/.." || exit 1
rc=0

# The `--flag)` and `--a|--b)` arms of a shell script's argument loop.
shell_flags() { grep -oE '^ +(-[a-z]\|)?--[a-z-]+(\|--[a-z-]+)*\)' "$1" | tr -d ' )' | tr '|' '\n' | grep '^--' | grep -vx -- --help; }
# The "--flag" string patterns of git-attest's `parse`.
rust_flags() { sed -n '/^fn parse/,/^}/p' src/main.rs | grep -oE '"--[a-z-]+"' | tr -d '"'; }

check() { # program help-text flags...
    local prog=$1 help=$2 f; shift 2
    for f in "$@"; do
        case $help in
            *"$f"*) ;;
            *) printf 'help-lists-every-flag: %s accepts %s but its --help never mentions it\n' "$prog" "$f" >&2; rc=1 ;;
        esac
    done
}

# shellcheck disable=SC2046  # one flag per word
check verify.sh "$(bash verify.sh --help)" $(shell_flags verify.sh)
# shellcheck disable=SC2046
check sign/sign.sh "$(bash sign/sign.sh --help < /dev/null)" $(shell_flags sign/sign.sh)
if [ -x target/release/git-attest ] || cargo build -q --release; then
    # shellcheck disable=SC2046
    check git-attest "$(target/release/git-attest --help)" $(rust_flags)
else
    printf 'help-lists-every-flag: cannot build git-attest\n' >&2; rc=1
fi
exit "$rc"
