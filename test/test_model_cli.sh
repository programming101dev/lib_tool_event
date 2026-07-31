#!/usr/bin/env sh
set -eu

tool=$1
resources=$2
calls=$3
work=$(mktemp -d "${TMPDIR:-/tmp}/p101-event-model-test.XXXXXX")
trap 'rm -rf "$work"' EXIT

"$tool" -r "$resources" -c "$calls" -o "$work/run-model.json"
grep -q '"schema": "p101-run-model-v1"' "$work/run-model.json"
grep -q '"kind":"call-return"' "$work/run-model.json"
grep -q '"kind":"resource-lifetime"' "$work/run-model.json"

"$tool" --help >/dev/null
if "$tool" -r "$resources" >/dev/null 2>&1; then
    echo "missing call stream was accepted" >&2
    exit 1
fi
sed '$d' "$calls" >"$work/incomplete.log"
if "$tool" -r "$resources" -c "$work/incomplete.log" >/dev/null 2>&1; then
    echo "incomplete call stream was accepted" >&2
    exit 1
fi
