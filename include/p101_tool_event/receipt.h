#ifndef P101_TOOL_EVENT_RECEIPT_H
#define P101_TOOL_EVENT_RECEIPT_H

#include <p101_error/error.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

    enum
    {
        P101_TOOL_EVENT_RECEIPT_DEFAULT_MAX_BYTES   = 64 * 1024 * 1024,
        P101_TOOL_EVENT_RECEIPT_DEFAULT_MAX_RECORDS = 1000000
    };

    struct p101_tool_event_fingerprint
    {
        size_t   bytes;
        size_t   records;
        uint64_t fnv1a64;
        int      final_newline;
    };

    /*
     * Compute a bounded, reproducible file fingerprint for a run receipt.
     *
     * FNV-1a is intentionally a lightweight change detector, not a
     * cryptographic authenticity proof. `records` counts physical lines,
     * including an unterminated final line.
     */
    int p101_tool_event_fingerprint_file(struct p101_error *err, const char *path, size_t maximum_bytes, size_t maximum_records, struct p101_tool_event_fingerprint *fingerprint);

#ifdef __cplusplus
}
#endif

#endif
