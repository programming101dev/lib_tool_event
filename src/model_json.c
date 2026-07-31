#include "model_internal.h"
#include <errno.h>
#include <p101_error/error.h>
#include <stdio.h>

enum
{
    JSON_CONTROL_CHARACTER_LIMIT = 0x20U
};

static void        write_json_string(FILE *stream, const char *text);
static void        write_source(FILE *stream, const struct p101_tool_model_node *node);
static void        write_time(FILE *stream, const struct p101_tool_model_node *node);
static void        write_resource_fields(FILE *stream, const struct p101_tool_model_node *node);
static void        write_node(FILE *stream, const struct p101_tool_model_node *node);
static void        write_nodes(FILE *stream, const struct p101_tool_model *model);
static void        write_edges(FILE *stream, const struct p101_tool_model *model);
static const char *node_kind_name(const struct p101_tool_model_node *node);
static const char *edge_kind_name(p101_tool_model_edge_kind kind);
static void        write_node_id(FILE *stream, const struct p101_tool_model_node *node);
static const char *fd_kind_name(p101_tool_event_fd_kind kind);
static const char *alloc_kind_name(p101_tool_event_alloc_kind kind);
static const char *resource_operation_name(p101_tool_event_resource_kind kind);

int p101_tool_model_write_json(struct p101_error *err, FILE *stream, const struct p101_tool_model *model)
{
    size_t calls;
    size_t resources;

    if(stream == NULL || model == NULL || model->finished == 0)
    {
        P101_ERROR_RAISE_ERRNO(err, EINVAL);
        return -1;
    }
    calls     = 0U;
    resources = 0U;
    for(size_t index = 0U; index < model->node_count; index++)
    {
        if(model->nodes[index].value.domain == P101_TOOL_MODEL_NODE_CALL)
        {
            calls++;
        }
        else
        {
            resources++;
        }
    }
    (void)fprintf(stream,
                  "{\n"
                  "  \"schema\": \"p101-run-model-v1\",\n"
                  "  \"event_schema\": \"%s\",\n"
                  "  \"identity_policy\": \"pid-context-event-sequence-kind\",\n"
                  "  \"ordering\": \"causal-edges-with-per-context-sequence-and-observed-timestamps\",\n"
                  "  \"summary\": {\"call_nodes\": %zu, \"resource_nodes\": %zu},\n",
                  P101_TOOL_EVENT_SCHEMA_NAME,
                  calls,
                  resources);
    write_nodes(stream, model);
    (void)fputs(",\n", stream);
    write_edges(stream, model);
    (void)fputs("\n}\n", stream);
    if(fflush(stream) != 0)
    {
        P101_ERROR_RAISE_ERRNO(err, EIO);
        return -1;
    }
    return 0;
}

static const char *node_kind_name(const struct p101_tool_model_node *node)
{
#ifdef __clang__
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wcovered-switch-default"
#endif
    // GCOVR_EXCL_BR_START: model nodes are constructed only from admitted
    // protocol enum values; the defensive default is not an executable input.
    switch(node->record_kind)
    {
        case P101_TOOL_EVENT_RECORD_FD:
        {
            return fd_kind_name(node->fd_kind);
        }
        case P101_TOOL_EVENT_RECORD_ALLOC:
        {
            return alloc_kind_name(node->alloc_kind);
        }
        case P101_TOOL_EVENT_RECORD_FORK:
        {
            return "fork";
        }
        case P101_TOOL_EVENT_RECORD_SPAWN:
        {
            return "spawn";
        }
        case P101_TOOL_EVENT_RECORD_EXEC:
        {
            return "exec";
        }
        case P101_TOOL_EVENT_RECORD_EXEC_FAIL:
        {
            return "exec-fail";
        }
        case P101_TOOL_EVENT_RECORD_CALL:
        {
            return node->call_kind == P101_TOOL_EVENT_CALL_ENTER ? "call-enter" : "call-exit";
        }
        case P101_TOOL_EVENT_RECORD_RESOURCE:
        {
            return "resource";
        }
        // GCOVR_EXCL_START
        case P101_TOOL_EVENT_RECORD_COMPLETE:
        {
            return "complete";
        }
        default:
        {
            return "unknown";
        }
        // GCOVR_EXCL_STOP
    }
    // GCOVR_EXCL_BR_STOP
#ifdef __clang__
    #pragma clang diagnostic pop
#endif
}

static const char *edge_kind_name(p101_tool_model_edge_kind kind)
{
#ifdef __clang__
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wcovered-switch-default"
#endif
    // GCOVR_EXCL_BR_START: edges are created only by the typed model builder.
    switch(kind)
    {
        case P101_TOOL_MODEL_EDGE_CALL_PARENT:
        {
            return "call-parent";
        }
        case P101_TOOL_MODEL_EDGE_CALL_RETURN:
        {
            return "call-return";
        }
        case P101_TOOL_MODEL_EDGE_CALL_CAUSED_EVENT:
        {
            return "call-caused-event";
        }
        case P101_TOOL_MODEL_EDGE_RESOURCE_LIFETIME:
        {
            return "resource-lifetime";
        }
        case P101_TOOL_MODEL_EDGE_PROCESS_CHILD_EVENT:
        {
            return "process-child-event";
        }
        // GCOVR_EXCL_START
        default:
        {
            return "unknown";
        }
        // GCOVR_EXCL_STOP
    }
    // GCOVR_EXCL_BR_STOP
#ifdef __clang__
    #pragma clang diagnostic pop
#endif
}

static void write_node_id(FILE *stream, const struct p101_tool_model_node *node)
{
    const char *domain;

    domain = node->domain == P101_TOOL_MODEL_NODE_CALL ? "call" : "resource";
    (void)fprintf(stream, "\"%s:%ld:%zu:%zu:%s\"", domain, node->pid, node->context_id, node->sequence, node_kind_name(node));
}

static void write_nodes(FILE *stream, const struct p101_tool_model *model)
{
    (void)fputs("  \"nodes\": [\n", stream);
    for(size_t index = 0U; index < model->node_count; index++)
    {
        if(index > 0U)
        {
            (void)fputs(",\n", stream);
        }
        write_node(stream, &model->nodes[index].value);
    }
    (void)fputs("\n  ]", stream);
}

static void write_node(FILE *stream, const struct p101_tool_model_node *node)
{
    (void)fputs("    {\"id\":", stream);
    write_node_id(stream, node);
    (void)fprintf(stream, ",\"domain\":\"%s\",\"kind\":", node->domain == P101_TOOL_MODEL_NODE_CALL ? "call" : "resource");
    write_json_string(stream, node_kind_name(node));
    (void)fprintf(stream, ",\"pid\":%ld,\"context\":%zu,\"sequence\":%zu", node->pid, node->context_id, node->sequence);
    if(node->domain == P101_TOOL_MODEL_NODE_CALL)
    {
        (void)fputs(",\"name\":", stream);
        write_json_string(stream, node->call_name);
        (void)fputs(",\"arguments\":", stream);
        write_json_string(stream, node->arguments);
        (void)fputs(",\"result\":", stream);
        write_json_string(stream, node->result);
    }
    else
    {
        write_resource_fields(stream, node);
    }
    (void)fputc(',', stream);
    write_time(stream, node);
    (void)fputc(',', stream);
    write_source(stream, node);
    (void)fputc('}', stream);
}

static void write_resource_fields(FILE *stream, const struct p101_tool_model_node *node)
{
    if(node->record_kind == P101_TOOL_EVENT_RECORD_FD)
    {
        (void)fprintf(stream, ",\"resource_class\":\"fd\",\"resource_identity\":\"%d\"", node->fd);
    }
    else if(node->record_kind == P101_TOOL_EVENT_RECORD_ALLOC)
    {
        (void)fputs(",\"resource_class\":\"allocation\",\"resource_identity\":", stream);
        write_json_string(stream, node->ptr);
        if(node->alloc_kind == P101_TOOL_EVENT_ALLOC_REALLOC)
        {
            (void)fputs(",\"related_identity\":", stream);
            write_json_string(stream, node->new_ptr);
        }
        (void)fprintf(stream, ",\"size\":%zu", node->size);
    }
    else if(node->record_kind == P101_TOOL_EVENT_RECORD_FORK || node->record_kind == P101_TOOL_EVENT_RECORD_SPAWN)
    {
        (void)fprintf(stream, ",\"child_pid\":%ld", node->child_pid);
        if(node->record_kind == P101_TOOL_EVENT_RECORD_SPAWN)
        {
            (void)fputs(",\"target\":", stream);
            write_json_string(stream, node->target);
        }
    }
    else if(node->record_kind == P101_TOOL_EVENT_RECORD_EXEC || node->record_kind == P101_TOOL_EVENT_RECORD_EXEC_FAIL)
    {
        if(node->record_kind == P101_TOOL_EVENT_RECORD_EXEC)
        {
            (void)fprintf(stream, ",\"resource_class\":\"fd\",\"resource_identity\":\"%d\"", node->fd);
        }
        (void)fputs(",\"target\":", stream);
        write_json_string(stream, node->target);
        if(node->record_kind == P101_TOOL_EVENT_RECORD_EXEC)
        {
            (void)fprintf(stream, ",\"cloexec\":%s", (int)node->cloexec ? "true" : "false");
        }
    }
    else
    {
        (void)fputs(",\"operation\":", stream);
        write_json_string(stream, resource_operation_name(node->resource_kind));
        (void)fputs(",\"resource_class\":", stream);
        write_json_string(stream, node->resource_class);
        (void)fputs(",\"resource_identity\":", stream);
        write_json_string(stream, node->resource_id);
        (void)fputs(",\"related_identity\":", stream);
        write_json_string(stream, node->related_id);
        (void)fputs(",\"metadata\":", stream);
        write_json_string(stream, node->metadata);
        (void)fprintf(stream, ",\"size\":%zu", node->size);
    }
}

static void write_edges(FILE *stream, const struct p101_tool_model *model)
{
    (void)fputs("  \"edges\": [\n", stream);
    for(size_t index = 0U; index < model->edge_count; index++)
    {
        const struct p101_tool_model_edge *edge;

        edge = &model->edges[index];
        if(index > 0U)
        {
            (void)fputs(",\n", stream);
        }
        (void)fputs("    {\"kind\":", stream);
        write_json_string(stream, edge_kind_name(edge->kind));
        (void)fputs(",\"from\":", stream);
        write_node_id(stream, &model->nodes[edge->from].value);
        (void)fputs(",\"to\":", stream);
        write_node_id(stream, &model->nodes[edge->to].value);
        (void)fputc('}', stream);
    }
    (void)fputs("\n  ]", stream);
}

static void write_time(FILE *stream, const struct p101_tool_model_node *node)
{
    (void)fputs("\"monotonic_ns\":", stream);
    if(node->monotonic_ns_available)
    {
        (void)fprintf(stream, "%zu", node->monotonic_ns);
    }
    else
    {
        (void)fputs("null", stream);
    }
    (void)fputs(",\"wall_unix_ns\":", stream);
    if(node->wall_unix_ns_available)
    {
        (void)fprintf(stream, "%zu", node->wall_unix_ns);
    }
    else
    {
        (void)fputs("null", stream);
    }
}

static void write_source(FILE *stream, const struct p101_tool_model_node *node)
{
    (void)fputs("\"source\":{\"file\":", stream);
    write_json_string(stream, node->file_name);
    (void)fprintf(stream, ",\"line\":%d,\"function\":", node->line_number);
    write_json_string(stream, node->function_name);
    (void)fputc('}', stream);
}

static void write_json_string(FILE *stream, const char *text)
{
    const unsigned char *cursor;

    (void)fputc('"', stream);
    cursor = (const unsigned char *)text;
    while(*cursor != '\0')
    {
        if(*cursor == '"' || *cursor == '\\')
        {
            (void)fputc('\\', stream);
            (void)fputc((int)*cursor, stream);
        }
        else if(*cursor == '\n')
        {
            (void)fputs("\\n", stream);
        }
        else if(*cursor == '\r')
        {
            (void)fputs("\\r", stream);
        }
        else if(*cursor == '\t')
        {
            (void)fputs("\\t", stream);
        }
        else if(*cursor < JSON_CONTROL_CHARACTER_LIMIT)
        {
            (void)fprintf(stream, "\\u%04x", (unsigned int)*cursor);
        }
        else
        {
            (void)fputc((int)*cursor, stream);
        }
        cursor++;
    }
    (void)fputc('"', stream);
}

static const char *fd_kind_name(p101_tool_event_fd_kind kind)
{
    return kind == P101_TOOL_EVENT_FD_OPEN ? "fd-open" : "fd-close";
}

static const char *alloc_kind_name(p101_tool_event_alloc_kind kind)
{
#ifdef __clang__
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wcovered-switch-default"
#endif
    // GCOVR_EXCL_BR_START: allocation kinds come from validated event records.
    switch(kind)
    {
        case P101_TOOL_EVENT_ALLOC_ALLOC:
        {
            return "alloc";
        }
        case P101_TOOL_EVENT_ALLOC_FREE:
        {
            return "free";
        }
        case P101_TOOL_EVENT_ALLOC_REALLOC:
        {
            return "realloc";
        }
        // GCOVR_EXCL_START
        default:
        {
            return "unknown";
        }
        // GCOVR_EXCL_STOP
    }
    // GCOVR_EXCL_BR_STOP
#ifdef __clang__
    #pragma clang diagnostic pop
#endif
}

static const char *resource_operation_name(p101_tool_event_resource_kind kind)
{
#ifdef __clang__
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wcovered-switch-default"
#endif
    // GCOVR_EXCL_BR_START: resource kinds come from validated event records.
    switch(kind)
    {
        case P101_TOOL_EVENT_RESOURCE_ACQUIRE:
        {
            return "acquire";
        }
        case P101_TOOL_EVENT_RESOURCE_RELEASE:
        {
            return "release";
        }
        case P101_TOOL_EVENT_RESOURCE_REPLACE:
        {
            return "replace";
        }
        case P101_TOOL_EVENT_RESOURCE_TRANSFER:
        {
            return "transfer";
        }
        // GCOVR_EXCL_START
        default:
        {
            return "unknown";
        }
        // GCOVR_EXCL_STOP
    }
    // GCOVR_EXCL_BR_STOP
#ifdef __clang__
    #pragma clang diagnostic pop
#endif
}
