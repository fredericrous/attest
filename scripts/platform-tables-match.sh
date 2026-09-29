#!/usr/bin/env bash
# The platform table is byte-identical in verify.sh, sign/sign.sh and
# tests/lib.sh. Three hand-kept copies drift; a producer that names its
# platform one way and a verifier that expects another never meet, silently.
set -u
cd "$(dirname "$0")/.." || exit 1
table() { sed -n '/^# platform-table:start$/,/^# platform-table:end$/p' "$1"; }
ref=$(table verify.sh)
[ -n "$ref" ] || { echo "platform-tables-match: no marked table in verify.sh" >&2; exit 1; }
rc=0
for f in sign/sign.sh tests/lib.sh; do
    if [ "$(table "$f")" != "$ref" ]; then
        echo "platform-tables-match: $f differs from verify.sh:" >&2
        diff <(table verify.sh) <(table "$f") >&2
        rc=1
    fi
done
exit "$rc"
