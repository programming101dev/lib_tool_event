#ifndef P101_TOOL_EVENT_RECEIPT_H
#define P101_TOOL_EVENT_RECEIPT_H

#include <p101_error/error.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C"
{
#endif

    enum
    {
        P101_TOOL_EVENT_RECEIPT_DEFAULT_MAX_BYTES   = 64 * 1024 * 1024,
        P101_TOOL_EVENT_RECEIPT_DEFAULT_MAX_RECORDS = 1000000,
        P101_TOOL_EVENT_RECEIPT_TEXT_MAX_BYTES      = 4096
    };

    typedef enum
    {
        P101_TOOL_OUTCOME_CLEAN = 0,
        P101_TOOL_OUTCOME_FINDINGS,
        P101_TOOL_OUTCOME_REFUSED,
        P101_TOOL_OUTCOME_INCOMPLETE,
        P101_TOOL_OUTCOME_UNSUPPORTED,
        P101_TOOL_OUTCOME_TOOL_ERROR
    } p101_tool_outcome;

    struct p101_tool_event_fingerprint
    {
        size_t   bytes;
        size_t   records;
        uint64_t fnv1a64;
        int      final_newline;
    };

    struct p101_tool_run_receipt
    {
        const char       *tool_name;
        const char       *tool_version;
        const char       *input_schema;
        const char       *input_identity;
        p101_tool_outcome outcome;
        size_t            checks_attempted;
        size_t            checks_completed;
        const char       *does_not_prove;
    };

    /*
     * Compute a bounded, reproducible file fingerprint for a run receipt.
     *
     * FNV-1a is intentionally a lightweight change detector, not a
     * cryptographic authenticity proof. `records` counts physical lines,
     * including an unterminated final line.
     */
    int         p101_tool_event_fingerprint_file(struct p101_error *err, const char *path, size_t maximum_bytes, size_t maximum_records, struct p101_tool_event_fingerprint *fingerprint);
    const char *p101_tool_outcome_name(p101_tool_outcome outcome);
    int         p101_tool_outcome_exit_status(p101_tool_outcome outcome);
    int         p101_tool_run_receipt_write_json(struct p101_error *err, FILE *stream, const struct p101_tool_run_receipt *receipt, const struct p101_tool_event_fingerprint *fingerprint);

#ifdef __cplusplus
}
#endif

#endif
