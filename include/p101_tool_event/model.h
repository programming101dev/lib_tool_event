#ifndef P101_TOOL_EVENT_MODEL_H
#define P101_TOOL_EVENT_MODEL_H

#include <p101_tool_event/event.h>
#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C"
{
#endif

    typedef enum
    {
        P101_TOOL_MODEL_NODE_CALL = 0,
        P101_TOOL_MODEL_NODE_RESOURCE
    } p101_tool_model_node_domain;

    typedef enum
    {
        P101_TOOL_MODEL_EDGE_CALL_PARENT = 0,
        P101_TOOL_MODEL_EDGE_CALL_RETURN,
        P101_TOOL_MODEL_EDGE_CALL_CAUSED_EVENT,
        P101_TOOL_MODEL_EDGE_RESOURCE_LIFETIME,
        P101_TOOL_MODEL_EDGE_PROCESS_CHILD_EVENT
    } p101_tool_model_edge_kind;

    struct p101_tool_model_node
    {
        p101_tool_model_node_domain   domain;
        p101_tool_event_record_kind   record_kind;
        p101_tool_event_call_kind     call_kind;
        p101_tool_event_fd_kind       fd_kind;
        p101_tool_event_alloc_kind    alloc_kind;
        p101_tool_event_resource_kind resource_kind;
        long                          pid;
        long                          child_pid;
        size_t                        context_id;
        size_t                        sequence;
        size_t                        monotonic_ns;
        size_t                        wall_unix_ns;
        bool                          monotonic_ns_available;
        bool                          wall_unix_ns_available;
        int                           fd;
        bool                          cloexec;
        size_t                        size;
        int                           line_number;
        const char                   *function_name;
        const char                   *file_name;
        const char                   *call_name;
        const char                   *arguments;
        const char                   *result;
        const char                   *ptr;
        const char                   *new_ptr;
        const char                   *target;
        const char                   *resource_class;
        const char                   *resource_id;
        const char                   *related_id;
        const char                   *metadata;
    };

    struct p101_tool_model_edge
    {
        p101_tool_model_edge_kind kind;
        size_t                    from;
        size_t                    to;
    };

    struct p101_tool_model;

    struct p101_tool_model            *p101_tool_model_create(struct p101_error *err);
    void                               p101_tool_model_destroy(struct p101_tool_model **model);
    int                                p101_tool_model_ingest(struct p101_error *err, struct p101_tool_model *model, const struct p101_tool_event_record *record);
    int                                p101_tool_model_finish(struct p101_error *err, struct p101_tool_model *model);
    size_t                             p101_tool_model_node_count(const struct p101_tool_model *model);
    const struct p101_tool_model_node *p101_tool_model_node_at(const struct p101_tool_model *model, size_t index);
    size_t                             p101_tool_model_edge_count(const struct p101_tool_model *model);
    const struct p101_tool_model_edge *p101_tool_model_edge_at(const struct p101_tool_model *model, size_t index);
    int                                p101_tool_model_write_json(struct p101_error *err, FILE *stream, const struct p101_tool_model *model);

#ifdef __cplusplus
}
#endif

#endif
