#ifndef P101_TOOL_EVENT_MODEL_H
#define P101_TOOL_EVENT_MODEL_H

#include <p101_tool_event/event.h>
#include <p101_tool_event/model_types.h>
#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C"
{
#endif

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
