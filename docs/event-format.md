# p101 event format v5

The p101 runtime event protocol is a line-oriented, tab-separated teaching
format. It is deliberately readable with ordinary text tools while
`lib_tool_event` supplies the authoritative bounded reader, serializer, parser, and
policy-free lifecycle replay.

Each v5 record starts with:

```text
MAGIC<TAB>5<TAB>run-id<TAB>pid<TAB>context<TAB>sequence<TAB>monotonic-ns<TAB>wall-unix-ns<TAB>...
```

`run-id` binds every record to one capture. Consumers reject a stream that
mixes run identities. `context` distinguishes independent observation contexts in one process.
Sequence numbers are monotonic within a context. A timestamp is `-` when the
producer cannot provide it. Version 5 is the only supported protocol version;
all other versions are rejected.

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
P101COMPLETE  ... events-attempted write-failed write-errno
```

The ellipsis is the common v5 prefix shown above. Optional text values are `-`.
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

`P101COMPLETE` is the producer's end-of-stream receipt for one observation
context. `events-attempted` excludes the completion record itself.
`write-failed` is zero or one, and `write-errno` is zero unless a prior event
write failed. A v5 stream without a completion record is incomplete evidence,
not evidence of a clean run. Abrupt termination can legitimately prevent this
record; consumers must report that limitation rather than silently accepting
the prefix they happened to read.

Completeness is evaluated independently for every `(pid, context)` producer
observed in a stream. Every producer must emit exactly one clean completion
record. A receipt from one context cannot make a truncated sibling context look
complete. Records after a context's completion, duplicate/non-monotonic
sequences, and a completion count that disagrees with the number of observed
records are stream-integrity failures. Sequence gaps are allowed because one
context sequence is shared across filtered resource and call streams.

`lib_env` serializes sequence assignment and publication for one environment,
and `p101_tool_event_write()` publishes a complete bounded record with one
append write. This prevents threads sharing an environment from interleaving a
record or reversing its sequence order. After `fork()`, the p101 fork wrapper
resets the child's inherited emission lock; the child must still obey the usual
POSIX async-signal-safe restrictions until `exec()` or `_Exit()`.

## API and ownership

- `p101_tool_event_read_line()` performs byte-safe physical-line input.
- `p101_tool_event_parse_line()` validates and parses in place; string fields point
  into the caller-owned mutable line until that line is reused.
- `p101_tool_event_write()` performs authoritative escaping and serialization.
- `p101_tool_event_stream_health_*()` recognizes completion receipts without
  imposing a consumer's exit-status or severity policy.
- `p101_tool_event_fingerprint_file()` computes the bounded, non-cryptographic file
  fingerprint used by run receipts without changing the event records.
- `p101_tool_event_lifecycle_*()` copies identities it retains and replays generic
  acquire/release lifecycles without assigning severity or exit policy. One
  lifecycle model admits exactly one run identity.

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
