#!/usr/bin/env bash
# NEGATIVE CONTROL — do not fix this file.
#
# This is the verifier amont's CI templates shipped, lifted verbatim from
# `templates/ci/github/rust.yaml` and wrapped so `conformance.sh` can drive it.
# It exists to prove the fixtures are not vacuous: the cases marked (defect N)
# in `conformance.sh` MUST fail here and pass against `verify.sh`.
#
# Flags are accepted and ignored — it never had any, which is itself part of
# what the suite measures.
set -u
while [ $# -gt 0 ]; do shift; done

command -v ssh-keygen > /dev/null || exit 0
git fetch origin '+refs/notes/amont-attest:refs/notes/amont-attest' 2> /dev/null || true
note=
for c in "$(git rev-parse 'HEAD^{tree}')" HEAD HEAD^2; do
    note=$(git notes --ref amont-attest show "$c" 2> /dev/null) && break
done
[ -n "$note" ] || exit 0
payload=$(printf '%s\n' "$note" | sed -n '/^$/q;p')
sig=$(printf '%s\n' "$note" | sed -n '/^-----BEGIN SSH SIGNATURE-----$/,$p')
[ -n "$sig" ] || exit 0
[ "$(printf '%s\n' "$payload" | sed -n 1p)" = amont-attest-v2 ] || exit 0
case "$(uname -m)" in arm64 | aarch64) arch=aarch64 ;; *) arch=$(uname -m) ;; esac
case "$(uname -s)" in Darwin) os=macos ;; Linux) os=linux ;; *) os=windows ;; esac
[ "$(printf '%s\n' "$payload" | awk '$1=="platform"{print $2}')" = "$arch-$os" ] || exit 0
tree=$(printf '%s\n' "$payload" | awk '$1=="tree"{print $2}')
[ -n "$tree" ] && [ "$tree" = "$(git rev-parse 'HEAD^{tree}')" ] || exit 0
printf '%s\n' "$sig" > /tmp/amont-attest.sig
printf '%s\n' "$payload" | ssh-keygen -Y verify \
    -f .github/allowed_signers -I you@example.com \
    -n amont-attest -s /tmp/amont-attest.sig > /dev/null 2>&1 || exit 0
printf '%s\n' "$payload" | awk '$1=="gates"{sub(/^gates */,""); print}'
