#ifndef P101_TOOL_EVENT_SUMMARY_H
#define P101_TOOL_EVENT_SUMMARY_H

#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif

    struct p101_tool_event_resource_summary
    {
        size_t records;
        size_t fd_leaks;
        size_t allocation_leaks;
        size_t bad_releases;
        size_t exec_inheritances;
        size_t generic_resource_leaks;
        size_t generic_bad_releases;
        size_t malformed;
        size_t bad_version;
        size_t refused;
        bool   log_complete;
        bool   parsed;
    };

    bool   p101_tool_event_parse_resource_summary_json(const char *text, struct p101_tool_event_resource_summary *summary);
    bool   p101_tool_event_parse_json_size(const char *text, const char *key, size_t *value);
    size_t p101_tool_event_resource_summary_finding_count(const struct p101_tool_event_resource_summary *summary);

#ifdef __cplusplus
}
#endif

#endif
