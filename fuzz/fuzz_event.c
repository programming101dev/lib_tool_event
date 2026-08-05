#include <p101_error/error.h>
#include <p101_tool_event/event.h>
#include <p101_tool_event/lifecycle.h>
#include <p101_tool_event/summary.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size);

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    char                         *line;
    struct p101_tool_event_record record;
    p101_tool_event_parse_status  status;

    if(size >= P101_TOOL_EVENT_LINE_MAX_BYTES)
    {
        return 0;
    }

    line = (char *)malloc(size + 1U);
    if(line == NULL)
    {
        return 0;
    }
    memcpy(line, data, size);
    line[size] = '\0';

    status = p101_tool_event_parse_line(line, &record);
    if(status == P101_TOOL_EVENT_PARSE_OK && record.record_kind == P101_TOOL_EVENT_RECORD_RESOURCE)
    {
        struct p101_error                      *err;
        struct p101_tool_event_lifecycle_model *model;

        model = NULL;
        err   = p101_error_create(false);
        model = p101_tool_event_lifecycle_create(err);
        if(model != NULL)
        {
            (void)p101_tool_event_lifecycle_ingest(err, model, &record);
            (void)p101_tool_event_lifecycle_finish(err, model);
        }
        p101_tool_event_lifecycle_destroy(&model);
        p101_error_destroy(err);
    }

    {
        struct p101_tool_event_policy_summary   policy_summary;
        struct p101_tool_event_resource_summary resource_summary;
        size_t                                  parsed_size;

        (void)p101_tool_event_parse_policy_summary_json_n((const char *)data, size, "p101-resource-policy-findings-v1", &policy_summary);
        (void)p101_tool_event_parse_resource_summary_json_n((const char *)data, size, &resource_summary);
        (void)p101_tool_event_parse_json_size_n((const char *)data, size, "findings", &parsed_size);
    }

    free(line);
    return 0;
}
