# p101 event format v3

The p101 runtime event protocol is a line-oriented, tab-separated teaching
format. It is deliberately readable with ordinary text tools while
`lib_tool_event` supplies the authoritative bounded reader, serializer, parser, and
policy-free lifecycle replay.

Each v3 record starts with:

```text
MAGIC<TAB>3<TAB>pid<TAB>context<TAB>sequence<TAB>monotonic-ns<TAB>wall-unix-ns<TAB>...
```

`context` distinguishes independent observation contexts in one process.
Sequence numbers are monotonic within a context. A timestamp is `-` when the
producer cannot provide it. The parser also accepts v2 records, assigning them
context zero; v1 is not supported.

Text fields escape backslash, tab, newline, and carriage return as `\\`, `\t`,
`\n`, and `\r`. A physical line, including its terminator, may not exceed
`P101_TOOL_EVENT_LINE_MAX_BYTES`. Embedded NUL bytes and overlong lines are
malformed.

## Records

```text
P101FD        ... OPEN|CLOSE fd line function file
P101ALLOC     ... ALLOC|FREE|REALLOC ptr new-ptr size line function file
P101FORK      ... child-pid line function file
P101SPAWN     ... child-pid line function file target
P101EXEC      ... fd cloexec line function file target
P101EXECFAIL  ... line function file target
P101CALL      ... ENTER|EXIT line function call args result file
P101RESOURCE  ... ACQUIRE|RELEASE|REPLACE|TRANSFER class id related-id size metadata line function file
```

The ellipsis is the common v3 prefix shown above. Optional text values are `-`.
Pointer and generic resource identities are opaque strings. POSIX spawn file
actions are opaque, so consumers must not infer a fork-equivalent descriptor
table from a spawn record. An exec wrapper emits descriptor snapshots before
the native call; `P101EXECFAIL` tells consumers that an attempted exec returned
and did not create a new program image.

Generic resource policy is intentionally outside this contract. `class`
identifies the domain, `id` identifies a resource within a PID,
`related-id` supports replace/transfer, and `size` is zero when meaningless.
Context records where an operation happened and may change across a transfer.
Tools decide which resource classes and findings matter to their users.

## API and ownership

- `p101_tool_event_read_line()` performs byte-safe physical-line input.
- `p101_tool_event_parse_line()` validates and parses in place; string fields point
  into the caller-owned mutable line until that line is reused.
- `p101_tool_event_write()` performs authoritative escaping and serialization.
- `p101_tool_event_fingerprint_file()` computes the bounded, non-cryptographic file
  fingerprint used by run receipts without changing the event records.
- `p101_tool_event_lifecycle_*()` copies identities it retains and replays generic
  acquire/release lifecycles without assigning severity or exit policy.

## Separate control streams

`P101FAULT` records belong to the fault-injection control stream used by
`p101-error-path-walk`; they are not runtime event records parsed by
`lib_tool_event`.

## Blind spots

The protocol sees only records emitted by p101 wrappers or user code using the
observation API. Direct libc calls, third-party internals, and kernel-internal
activity remain invisible. Context IDs and timestamps improve correlation, but
this is not a kernel audit trail and cannot establish a total order across
independently buffered processes.
