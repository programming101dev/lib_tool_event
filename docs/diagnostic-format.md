# Tool diagnostic format

`p101_tool_diagnostic_write()` is the shared serialization boundary for p101
source findings. A tool supplies a normalized diagnostic record and retains
ownership of the policy that produced it; `lib_tool_event` owns the stable text
and JSON encodings.

## Admitted input

The renderer accepts a typed finding, severity, source path, line, column,
optional function identity, and human-readable message. The finding must exist
in the generated lesson catalog. The shared initializer resolves its stable
diagnostic identifier and exact playground lesson route; callers cannot supply
a private or stale lesson path. The message is required and is emitted in both
formats.

`playgrounds/lessons/manifest.json` is the single editable source of truth for
finding IDs, lesson IDs, lesson paths, and lesson URLs. The checked generator
`scripts/generators/generate-tool-lesson-catalog.sh` produces
`p101_tool_support/lesson_catalog.h` and its implementation. Native consumers use
the common `p101_tool_rule_definition_lookup()` function; they do not parse the
JSON or duplicate its strings.

Consumers whose finding identity is selected at runtime use
`p101_tool_diagnostic_initialize_id`; consumers with a compile-time identity
use `p101_tool_diagnostic_initialize`. Both resolve the same generated catalog.
Tool messages describe the observed symptom. Repair instructions belong in the
linked playground lesson, not in a second tool-owned answer.

## Text output

The default output follows the grammar understood by editors and by parsers for
compiler, clang-tidy, and cppcheck diagnostics:

```text
path:line:column: severity: message [diagnostic-id]
path:line:column: note: learn more: lesson-id (lesson-url) [diagnostic-id]
```

The second record is emitted when a lesson route is present. Control characters
in paths, function identities, and messages are escaped so every diagnostic
occupies complete physical lines.

## JSON output

The JSON renderer writes exactly one `p101-tool-diagnostic-v1` object without a
trailing newline. A caller can therefore place the object in an existing JSON
array or use one object per line. The object contains the same message as the
text record plus structured severity, location, diagnostic identity, and lesson
identity, path, and URL.

`p101_tool_diagnostic_parse_outputs()` gives tools one shared interpretation of
`human`, `json`, and `human,json`. When both are selected,
`p101_tool_diagnostic_write_outputs()` fans the same record out to separate
human and JSON streams so neither representation corrupts the other.

The consolidated tools expose that choice as `-d:human`, `-d:json`, or
`-d:human,json`. Human output is the default. In dual mode, JSON is written to
stdout and human diagnostics to stderr, allowing a person to see findings while
automation consumes a valid JSON document.

Complete tool runs place these objects in the shared `p101-tool-report-v1`
envelope described in [report-format.md](report-format.md). The diagnostic
object is the finding record; the report adds admitted inputs, blind spots,
counters, outcome, and exit status.

```json
{"schema":"p101-tool-diagnostic-v1","id":"P101-WRAP-001","severity":"error","location":{"path":"src/main.c","line":12,"column":7,"function":"main"},"message":"missed-wrapper: malloc -> p101_malloc","lesson":{"id":"P101-LESSON-WRAPPER-BOUNDARIES","path":"lessons/wrapper-boundaries.md","url":"https://github.com/programming101dev/playgrounds/blob/main/lessons/wrapper-boundaries.md"}}
```

## Boundary and blind spots

The renderer does not discover findings, select severity, or prove that a
source location is correct. Those remain producer responsibilities. The
generated lookup proves only that the selected finding has one declared route
in the admitted manifest; it does not prove that the lesson is correct or that
the tool selected the right finding. Its serialization contract is
deterministic and parseable.

## Evidence

`test/test_diagnostic.c` checks exact compiler-style output, control-character
escaping, the shared message in JSON, typed lookup, the playground route, and
invalid input. `scripts/tests/test-tool-lesson-catalog.py` checks deterministic
generation, drift detection, and duplicate-route rejection. Run `cmake -S . -B build -DP101_BUILD_LEVEL=2 && cmake --build build`
for the library tests, or `cmake --build build` for the repository's strict analysis
pipeline.
