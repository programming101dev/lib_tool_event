# lib_tool_event

`lib_tool_event` owns the Programming 101 runtime event protocol. It provides the
byte-safe line reader, the versioned TSV parser, execution-context metadata,
generic resource records, and the policy-free lifecycle replay mechanism shared
by runtime tools.

The repository also installs the smaller `p101_record` library. Its
`<p101_record/record.h>` API only splits, unescapes, and validates bounded
tab-delimited fields; it has no event kinds, schema versions, or lifecycle
policy. This is an intentional boundary: fact-stream consumers such as
`lib_c_facts` can reuse the text-record mechanics without depending on the
runtime event protocol. Event producers and analyzers use `p101_tool_event`,
which remains the sole owner of the P101 event schema.

`p101_tool_event/model.h` adds the shared policy-free causal model. Consumers
ingest validated event records, finish the model once, and then inspect
call-parent, call-return, call-caused-event, resource-lifetime, and
process-child-event edges or serialize `p101-run-model-v1`. The model owns
copies of admitted record text, is bounded to 1,048,576 nodes and edges, and
does not assign severity or teaching policy.

The installed `p101-event-model` command is the narrow command-line boundary
for that mechanism:

```sh
p101-event-model -r resources.log -c calls.log -o run-model.json
```

It validates both complete protocol-v5 streams and serializes exactly one
model. It does not emit findings. `p101 analyze` launches this builder once and
applies resource, synchronization, and trace policies to the resulting model
without reparsing TSV.

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
should explain it. Those policies remain in the runtime policy modules and
their report views.

Event format v5 uses this common prefix:

```text
MAGIC<TAB>5<TAB>run-id<TAB>pid<TAB>context<TAB>sequence<TAB>monotonic-ns<TAB>wall-ns<TAB>...
```

Version 5 is the only supported protocol version. Every record is bound to one
capture run. Stream-health validation rejects mixed run identities, so reused
process IDs and context counters cannot silently combine separate executions.
Other versions are rejected rather than interpreted under weaker assumptions.

`p101_tool_event_fingerprint_file()` supplies the bounded file fingerprint used by
lightweight run receipts. It records bytes, physical lines, final-newline state,
and an FNV-1a 64-bit fingerprint. That fingerprint is a reproducible change
detector, not a cryptographic authenticity proof.

`p101_tool_run_receipt_write_json()` supplies the shared machine-readable
`p101-tool-run-receipt-v2` envelope. Tools retain ordinary Unix exit statuses,
while receipts distinguish `clean`, `findings`, `refused`, `incomplete`,
`unsupported`, and `tool-error`. Non-clean receipts also carry a typed failure
reason, the stage that failed, and the first actionable diagnostic. A receipt
binds the tool and input identities, executed-check counts, an optional input fingerprint, and a required
`does_not_prove` limitation. It records a bounded observation; it is not an
authenticity or completeness proof.

The protocol sees only records emitted by p101 wrappers or user code using the
observation API. Direct libc calls and third-party internals are outside its
admitted inputs.

The model is exercised by `test/test_model.c`, including allocation failures,
retry after partial construction, JSON escaping, output failure, and every
event domain. `test/test_model_cli.sh` proves the command-line boundary accepts
complete streams and rejects incomplete ones. Run `./test.sh`; use
`./build.sh -q` for the strict repository pipeline.
