#!/bin/sh
set -eu

cli=$1
fixture=$2
work=${TMPDIR:-/tmp}/p101-tool-receipt-cli.$$

cleanup()
{
    rm -rf "$work"
}
trap cleanup EXIT HUP INT TERM
mkdir -p "$work"

"$fixture" "$work/valid.json"
"$cli" --help >"$work/help.out"
grep -q '^Usage:' "$work/help.out"
"$cli" -h >"$work/help-short.out"
grep -q '^Usage:' "$work/help-short.out"
# P101_BOUNDARY_CASE boundary:durable-tool-receipt:clean
"$cli" verify "$work/valid.json" >"$work/valid.out"
grep -q '^valid receipt:' "$work/valid.out"
"$cli" require-clean "$work/valid.json" >"$work/clean.out"

"$fixture" "$work/findings.json" findings
"$cli" verify "$work/findings.json" >"$work/findings.out"
if "$cli" require-clean "$work/findings.json" >"$work/findings-clean.out" 2>&1
then
    echo "findings receipt unexpectedly satisfied require-clean" >&2
    exit 1
else
    [ "$?" -eq 1 ]
fi
grep -q 'receipt outcome is not clean: findings' "$work/findings-clean.out"

sed 's/"fixture"/"gixture"/' "$work/valid.json" >"$work/tampered.json"
# P101_BOUNDARY_CASE boundary:durable-tool-receipt:binding_swap
if "$cli" verify "$work/tampered.json" >"$work/tampered.out" 2>&1; then
    echo "tampered receipt unexpectedly passed" >&2
    exit 1
fi
grep -q 'bad-digest' "$work/tampered.out"

sed 's/receipt-v4/receipt-v3/' "$work/valid.json" >"$work/old.json"
# P101_BOUNDARY_CASE boundary:durable-tool-receipt:stale_version
if "$cli" verify "$work/old.json" >"$work/old.out" 2>&1; then
    echo "old receipt unexpectedly passed" >&2
    exit 1
fi
grep -q 'bad-version' "$work/old.out"

printf '{"schema":' >"$work/truncated.json"
# P101_BOUNDARY_CASE boundary:durable-tool-receipt:typed_refusal
if "$cli" verify "$work/truncated.json" >"$work/truncated.out" 2>&1; then
    echo "truncated receipt unexpectedly passed" >&2
    exit 1
fi
grep -q 'invalid' "$work/truncated.out"

if "$cli" verify "$work/missing.json" >"$work/missing.out" 2>&1; then
    echo "missing receipt unexpectedly passed" >&2
    exit 1
fi
grep -q '^p101-tool-receipt:' "$work/missing.out"

if "$cli" >"$work/usage.out" 2>&1; then
    echo "invalid command unexpectedly passed" >&2
    exit 1
fi
grep -q '^Usage:' "$work/usage.out"
