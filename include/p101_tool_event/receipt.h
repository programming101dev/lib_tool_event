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

    typedef enum
    {
        P101_TOOL_FAILURE_NONE = 0,
        P101_TOOL_FAILURE_FINDINGS_PRESENT,
        P101_TOOL_FAILURE_INPUT_REFUSED,
        P101_TOOL_FAILURE_EVIDENCE_INCOMPLETE,
        P101_TOOL_FAILURE_UNSUPPORTED_INPUT,
        P101_TOOL_FAILURE_TOOL_ERROR
    } p101_tool_failure_reason;

    struct p101_tool_event_fingerprint
    {
        size_t   bytes;
        size_t   records;
        uint64_t fnv1a64;
        int      final_newline;
    };

    struct p101_tool_run_receipt
    {
        const char              *tool_name;
        const char              *tool_version;
        const char              *input_schema;
        const char              *input_identity;
        const char              *policy_schema;
        const char              *policy_identity;
        const char              *run_identity;
        p101_tool_outcome        outcome;
        p101_tool_failure_reason failure_reason;
        const char              *failed_stage;
        const char              *first_diagnostic;
        size_t                   checks_attempted;
        size_t                   checks_completed;
        const char              *does_not_prove;
    };

    typedef enum
    {
        P101_TOOL_RECEIPT_VALID = 0,
        P101_TOOL_RECEIPT_INVALID,
        P101_TOOL_RECEIPT_BAD_VERSION,
        P101_TOOL_RECEIPT_BAD_DIGEST
    } p101_tool_receipt_validation_status;

    struct p101_tool_run_receipt_validation
    {
        p101_tool_receipt_validation_status status;
        p101_tool_outcome                   outcome;
        p101_tool_failure_reason            failure_reason;
        size_t                              checks_attempted;
        size_t                              checks_completed;
        int                                 fingerprint_present;
        uint64_t                            receipt_digest;
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
    const char *p101_tool_failure_reason_name(p101_tool_failure_reason reason);
    const char *p101_tool_receipt_validation_status_name(p101_tool_receipt_validation_status status);
    int         p101_tool_outcome_exit_status(p101_tool_outcome outcome);
    uint64_t    p101_tool_run_receipt_digest(const struct p101_tool_run_receipt *receipt, const struct p101_tool_event_fingerprint *fingerprint);
    int         p101_tool_run_receipt_write_json(struct p101_error *err, FILE *stream, const struct p101_tool_run_receipt *receipt, const struct p101_tool_event_fingerprint *fingerprint);
    int         p101_tool_run_receipt_validate_json(struct p101_error *err, const char *text, struct p101_tool_run_receipt_validation *validation);
    int         p101_tool_run_receipt_validate_file(struct p101_error *err, const char *path, size_t maximum_bytes, struct p101_tool_run_receipt_validation *validation);

#ifdef __cplusplus
}
#endif

#endif
