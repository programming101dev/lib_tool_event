#ifndef P101_TOOL_EVENT_REPORT_H
#define P101_TOOL_EVENT_REPORT_H

#include <p101_tool_event/diagnostic.h>
#include <p101_tool_event/receipt.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define P101_TOOL_REPORT_SCHEMA_NAME "p101-tool-report-v1"

    struct p101_tool_report_options
    {
        const char  *tool_name;
        const char  *admitted_inputs;
        const char  *does_not_prove;
        unsigned int outputs;
        bool         human_summary;
    };

    struct p101_tool_report_counter
    {
        const char *name;
        size_t      value;
    };

    struct p101_tool_report
    {
        struct p101_tool_report_options options;
        FILE                           *human_stream;
        FILE                           *json_stream;
        size_t                          finding_count;
        bool                            first_json_finding;
        bool                            active;
    };

    /* Parse the exact common CLI form: -d:human, -d:json, or -d:human,json. */
    int p101_tool_report_parse_output_option(const char *argument, unsigned int *outputs);

    /*
     * Begin a report on caller-supplied standard streams. Human-only and
     * JSON-only output use standard_output. Dual output uses standard_error
     * for human diagnostics and standard_output for JSON.
     */
    int p101_tool_report_begin(struct p101_tool_report *report, FILE *standard_output, FILE *standard_error, const struct p101_tool_report_options *options);
    int p101_tool_report_emit(struct p101_tool_report *report, const struct p101_tool_diagnostic *diagnostic);
    int p101_tool_report_end(struct p101_tool_report *report, p101_tool_outcome outcome, int exit_status, const struct p101_tool_report_counter counters[], size_t counter_count);

#ifdef __cplusplus
}
#endif

#endif
