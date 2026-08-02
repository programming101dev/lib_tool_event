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
"$tool" -r "$resources" -c "$calls" >/dev/null

"$tool" --help >/dev/null
if P101_TOOL_EVENT_TEST_FAIL_MODEL_CREATE=1 "$tool" -r "$resources" -c "$calls" >/dev/null 2>&1; then
    echo "injected model allocation failure was accepted" >&2
    exit 1
fi
if P101_TOOL_EVENT_TEST_FAIL_HEALTH=1 "$tool" -r "$resources" -c "$calls" >/dev/null 2>&1; then
    echo "injected health allocation failure was accepted" >&2
    exit 1
fi
if P101_TOOL_EVENT_TEST_FAIL_HEALTH=1 P101_TOOL_EVENT_TEST_ZERO_HEALTH_ERRNO=1 "$tool" -r "$resources" -c "$calls" >/dev/null 2>&1; then
    echo "injected zero-errno health failure was accepted" >&2
    exit 1
fi
if P101_TOOL_EVENT_TEST_FAIL_INGEST=1 "$tool" -r "$resources" -c "$calls" >/dev/null 2>&1; then
    echo "injected model-ingest allocation failure was accepted" >&2
    exit 1
fi
if P101_TOOL_EVENT_TEST_FAIL_FINISH=1 "$tool" -r "$resources" -c "$calls" >/dev/null 2>&1; then
    echo "injected model-finish allocation failure was accepted" >&2
    exit 1
fi
if "$tool" --unknown >/dev/null 2>&1; then
    echo "unknown option was accepted" >&2
    exit 1
fi
if "$tool" -r >/dev/null 2>&1; then
    echo "missing option value was accepted" >&2
    exit 1
fi
if "$tool" -r "" -c "$calls" >/dev/null 2>&1; then
    echo "empty option value was accepted" >&2
    exit 1
fi
if "$tool" -r "$resources" -r "$resources" -c "$calls" >/dev/null 2>&1; then
    echo "duplicate resource option was accepted" >&2
    exit 1
fi
if "$tool" -r "$resources" >/dev/null 2>&1; then
    echo "missing call stream was accepted" >&2
    exit 1
fi
if "$tool" -c "$calls" >/dev/null 2>&1; then
    echo "missing resource stream was accepted" >&2
    exit 1
fi
sed '$d' "$calls" >"$work/incomplete.log"
if "$tool" -r "$resources" -c "$work/incomplete.log" >/dev/null 2>&1; then
    echo "incomplete call stream was accepted" >&2
    exit 1
fi
sed '$d' "$resources" >"$work/incomplete-resources.log"
if "$tool" -r "$work/incomplete-resources.log" -c "$calls" >/dev/null 2>&1; then
    echo "incomplete resource stream was accepted" >&2
    exit 1
fi
if "$tool" -r "$work/missing.log" -c "$calls" >/dev/null 2>&1; then
    echo "missing resource stream was accepted" >&2
    exit 1
fi
if "$tool" -r "$resources" -c "$work/missing.log" >/dev/null 2>&1; then
    echo "missing call stream was accepted" >&2
    exit 1
fi
if "$tool" -r "$resources" -c "$calls" -o "$work/missing/run-model.json" >/dev/null 2>&1; then
    echo "unwritable output path was accepted" >&2
    exit 1
fi
printf 'P101CALL\t4\tbroken\n' >"$work/malformed.log"
if "$tool" -r "$resources" -c "$work/malformed.log" >/dev/null 2>&1; then
    echo "malformed event stream was accepted" >&2
    exit 1
fi
i=0
: >"$work/overlong.log"
while [ "$i" -lt 9000 ]; do
    printf 'x' >>"$work/overlong.log"
    i=$((i + 1))
done
printf '\n' >>"$work/overlong.log"
if "$tool" -r "$resources" -c "$work/overlong.log" >/dev/null 2>&1; then
    echo "overlong event stream was accepted" >&2
    exit 1
fi
if P101_TOOL_EVENT_TEST_READ_ERROR=1 "$tool" -r "$resources" -c "$calls" >/dev/null 2>&1; then
    echo "injected event-stream read failure was accepted" >&2
    exit 1
fi
{
    printf 'not-an-event\n'
    cat "$calls"
} >"$work/other-lines.log"
"$tool" -r "$resources" -c "$work/other-lines.log" >/dev/null
{
    head -n 1 "$calls"
    sed '$d' "$resources"
    tail -n 1 "$resources" | awk -F '\t' 'BEGIN {OFS="\t"} {$9 = 3; print}'
} >"$work/call-in-resource-stream.log"
"$tool" -r "$work/call-in-resource-stream.log" -c "$calls" >/dev/null
{
    head -n 1 "$calls"
    sed '$d' "$resources"
    sed -n '2p' "$calls"
    tail -n 1 "$calls" | awk -F '\t' 'BEGIN {OFS="\t"} {$9 = 4; print}'
} >"$work/resource-in-call-stream.log"
"$tool" -r "$resources" -c "$work/resource-in-call-stream.log" >/dev/null
if "$tool" -r "$resources" -c "$calls" >&- 2>/dev/null; then
    echo "closed output stream was accepted" >&2
    exit 1
fi
