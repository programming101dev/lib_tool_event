# Tool report format

`p101_tool_report_begin()`, `p101_tool_report_emit()`, and
`p101_tool_report_end()` form the shared lifecycle for a complete p101 finding
run. Tools retain their analysis and teaching policy; `lib_tool_event` owns the
stable report boundary.

## Admitted input

At begin time, a producer supplies:

- a stable tool name;
- a plain-language description of the files, facts, logs, or commands actually
  admitted by that run;
- a required `does_not_prove` statement naming the report's blind spots;
- one output selection: human, JSON, or both.

Each emitted finding is a validated `p101-tool-diagnostic-v1` record. At end
time, the producer supplies a typed outcome, the corresponding Unix exit
status, and optional non-negative counters with unique lowercase keys.

## Human output

Findings use the compiler-compatible diagnostic grammar. A final parseable
summary uses `key=value` fields. The report begins with escaped contract
metadata so human and JSON modes expose the same boundary:

```text
report: tool="audit-wrappers" admitted_inputs="Clang AST facts for selected translation units."
report: does_not_prove="Unscanned code is outside this report."
audit-wrappers: outcome=findings exit_status=1 findings=2 missed_wrappers=2
```

Human-only output goes to stdout. In dual mode it goes to stderr so stdout
remains valid JSON.

## JSON output

JSON output is one complete document:

```json
{"schema":"p101-tool-report-v1","tool":"audit-wrappers","admitted_inputs":"Clang AST facts for selected translation units.","does_not_prove":"Unscanned code is outside this report.","findings":[],"summary":{"findings":0,"missed_wrappers":0},"outcome":"clean","exit_status":0}
```

The `findings` elements use `p101-tool-diagnostic-v1`, so human and JSON modes
carry the same message and lesson route. JSON-only and dual output both write
the document to stdout.

## Common option

`p101_tool_report_parse_output_option()` accepts only the exact public forms:

```text
-d:human
-d:json
-d:human,json
```

There is no separate `-j` or `--json` spelling. Rejecting aliases keeps every
tool's command line and teaching material aligned.

## Boundary and blind spots

The report lifecycle serializes evidence; it does not discover findings,
choose severity, prove that admitted inputs are complete, or prove the
producer's `does_not_prove` statement is sufficient. A clean report means only
that the named tool found no findings in its admitted inputs.

## Evidence

`test/test_report.c` verifies exact option parsing, dual-stream routing,
diagnostic reuse, counters, outcome, and exit status. `cmake -S . -B build -DP101_BUILD_LEVEL=2 && cmake --build build` runs the
focused suite and `cmake --build build` runs the strict repository pipeline.
