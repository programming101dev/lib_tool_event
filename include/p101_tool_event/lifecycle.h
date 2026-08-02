#ifndef P101_TOOL_EVENT_LIFECYCLE_H
#define P101_TOOL_EVENT_LIFECYCLE_H

#include <p101_tool_event/event.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif

    typedef enum
    {
        P101_TOOL_EVENT_LIFECYCLE_FINDING_LEAK = 0,
        P101_TOOL_EVENT_LIFECYCLE_FINDING_DOUBLE_RELEASE,
        P101_TOOL_EVENT_LIFECYCLE_FINDING_STRAY_RELEASE,
        P101_TOOL_EVENT_LIFECYCLE_FINDING_BAD_REPLACE,
        P101_TOOL_EVENT_LIFECYCLE_FINDING_DUPLICATE_ACQUIRE
    } p101_tool_event_lifecycle_finding_kind;

    struct p101_tool_event_lifecycle_entry
    {
        long                        pid;
        p101_tool_event_record_kind origin_kind;
        size_t                      acquired_context_id;
        size_t                      released_context_id;
        char                       *resource_class;
        char                       *resource_id;
        size_t                      acquired_sequence;
        size_t                      released_sequence;
        size_t                      acquired_monotonic_ns;
        size_t                      released_monotonic_ns;
        size_t                      size;
        int                         acquired_line_number;
        int                         released_line_number;
        char                       *acquired_function_name;
        char                       *released_function_name;
        char                       *acquired_file_name;
        char                       *released_file_name;
        bool                        acquired_monotonic_ns_available;
        bool                        released_monotonic_ns_available;
        bool                        live;
        bool                        exec_pending;
    };

    struct p101_tool_event_lifecycle_finding
    {
        p101_tool_event_lifecycle_finding_kind kind;
        p101_tool_event_record_kind            origin_kind;
        long                                   pid;
        size_t                                 context_id;
        size_t                                 previous_context_id;
        char                                  *resource_class;
        char                                  *resource_id;
        size_t                                 sequence;
        size_t                                 previous_sequence;
        int                                    line_number;
        int                                    previous_line_number;
        char                                  *function_name;
        char                                  *previous_function_name;
        char                                  *file_name;
        char                                  *previous_file_name;
        size_t                                 monotonic_ns;
        bool                                   monotonic_ns_available;
    };

    struct p101_tool_event_lifecycle_model;

    struct p101_tool_event_lifecycle_model         *p101_tool_event_lifecycle_create(struct p101_error *err);
    void                                            p101_tool_event_lifecycle_destroy(struct p101_tool_event_lifecycle_model **model);
    int                                             p101_tool_event_lifecycle_ingest(struct p101_error *err, struct p101_tool_event_lifecycle_model *model, const struct p101_tool_event_record *record);
    int                                             p101_tool_event_lifecycle_finish(struct p101_error *err, struct p101_tool_event_lifecycle_model *model);
    size_t                                          p101_tool_event_lifecycle_entry_count(const struct p101_tool_event_lifecycle_model *model);
    const struct p101_tool_event_lifecycle_entry   *p101_tool_event_lifecycle_entry_at(const struct p101_tool_event_lifecycle_model *model, size_t index);
    size_t                                          p101_tool_event_lifecycle_finding_count(const struct p101_tool_event_lifecycle_model *model);
    const struct p101_tool_event_lifecycle_finding *p101_tool_event_lifecycle_finding_at(const struct p101_tool_event_lifecycle_model *model, size_t index);

#ifdef __cplusplus
}
#endif

#endif
