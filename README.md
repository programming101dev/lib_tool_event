# lib_tool_event

`lib_tool_event` owns the Programming 101 runtime event protocol. It provides the
byte-safe line reader, the versioned TSV parser, execution-context metadata,
generic resource records, and the policy-free lifecycle replay mechanism shared
by runtime tools.

Descriptor/allocation release and replacement classification also lives here in
`p101_tool_event/ownership.h`. Resource tracker and correlated report retain
different presentation state, but no longer carry independent definitions of
stray release, duplicate release, bad replacement, or exec inheritance.
`p101_tool_event/summary.h` is the single bounded parser for resource-summary JSON
consumed by launchers.

Serialization is shared too: `lib_env` supplies observation metadata and calls
`p101_tool_event_write()`, so producers and consumers cannot drift into different
escaping or field-order rules. A complete bounded record is published with one
append write, and `lib_env` serializes sequence assignment with publication.
Event-write failures
are sticky on the environment, queryable through
`p101_env_event_log_failed()`, and reported when the environment is destroyed.

It does not decide whether a finding should fail a course gate or how a report
should explain it. Those policies remain in consumers such as
`p101-resource-tracker`, `p101-report`, and `p101-trace`.

Event format v4 uses this common prefix:

```text
MAGIC<TAB>4<TAB>pid<TAB>context<TAB>sequence<TAB>monotonic-ns<TAB>wall-ns<TAB>...
```

Version 4 is the only supported protocol version. Other versions are rejected
rather than interpreted under weaker assumptions.

`p101_tool_event_fingerprint_file()` supplies the bounded file fingerprint used by
lightweight run receipts. It records bytes, physical lines, final-newline state,
and an FNV-1a 64-bit fingerprint. That fingerprint is a reproducible change
detector, not a cryptographic authenticity proof.

The protocol sees only records emitted by p101 wrappers or user code using the
observation API. Direct libc calls and third-party internals are outside its
admitted inputs.
