#ifndef P101_TOOL_EVENT_MODEL_INTERNAL_H
#define P101_TOOL_EVENT_MODEL_INTERNAL_H

#include <p101_tool_event/model.h>

struct p101_tool_model_owned_node
{
    struct p101_tool_model_node value;
    char                       *function_name;
    char                       *file_name;
    char                       *call_name;
    char                       *arguments;
    char                       *result;
    char                       *ptr;
    char                       *new_ptr;
    char                       *target;
    char                       *resource_class;
    char                       *resource_id;
    char                       *related_id;
    char                       *metadata;
};

struct p101_tool_model
{
    struct p101_tool_model_owned_node *nodes;
    size_t                             node_count;
    size_t                             node_capacity;
    struct p101_tool_model_edge       *edges;
    size_t                             edge_count;
    size_t                             edge_capacity;
    int                                finished;
};

#endif
