#include "model_internal.h"
#include <errno.h>
#include <p101_error/error.h>
#include <stdio.h>

#ifdef P101_TOOL_EVENT_TESTING
    #include <stdarg.h>
    #include <stdint.h>

static size_t test_write_failure_after = SIZE_MAX;
static size_t test_successful_writes;

static int test_write_should_fail(void);
static int test_fprintf(FILE *stream, const char *format, ...) P101_ATTR_PRINTF(2, 3);
static int test_fputc(int character, FILE *stream);
static int test_fputs(const char *text, FILE *stream);
static int test_fflush(FILE *stream);

void p101_tool_event_test_model_fail_write_after(size_t successful_writes)
{
    test_write_failure_after = successful_writes;
    test_successful_writes   = 0U;
}

static int test_write_should_fail(void)
{
    if(test_successful_writes == test_write_failure_after)
    {
        test_write_failure_after = SIZE_MAX;
        errno                    = EIO;
        return 1;
    }
    test_successful_writes++;
    return 0;
}

static int test_fprintf(FILE *stream, const char *format, ...)
{
    int     result;
    va_list arguments;

    if(test_write_should_fail() != 0)
    {
        return -1;
    }
    va_start(arguments, format);
    result = vfprintf(stream, format, arguments);
    va_end(arguments);
    return result;
}

static int test_fputc(int character, FILE *stream)
{
    return test_write_should_fail() != 0 ? EOF : fputc(character, stream);
}

static int test_fputs(const char *text, FILE *stream)
{
    return test_write_should_fail() != 0 ? EOF : fputs(text, stream);
}

static int test_fflush(FILE *stream)
{
    return test_write_should_fail() != 0 ? EOF : fflush(stream);
}

    #define fprintf test_fprintf
    #define fputc test_fputc
    #define fputs test_fputs
    #define fflush test_fflush
#endif

enum
{
    JSON_CONTROL_CHARACTER_LIMIT = 0x20U
};

static int         write_json_string(FILE *stream, const char *text);
static int         write_json_string_contents(FILE *stream, const char *text);
static int         write_source(FILE *stream, const struct p101_tool_model_node *node);
static int         write_time(FILE *stream, const struct p101_tool_model_node *node);
static int         write_resource_fields(FILE *stream, const struct p101_tool_model_node *node);
static int         write_node(FILE *stream, const struct p101_tool_model_node *node);
static int         write_nodes(FILE *stream, const struct p101_tool_model *model);
static int         write_edges(FILE *stream, const struct p101_tool_model *model);
static const char *node_kind_name(const struct p101_tool_model_node *node);
static const char *edge_kind_name(p101_tool_model_edge_kind kind);
static int         write_node_id(FILE *stream, const struct p101_tool_model_node *node);
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
    if(fprintf(stream,
               "{\n"
               "  \"schema\": \"p101-run-model-v1\",\n"
               "  \"event_schema\": \"%s\",\n"
               "  \"identity_policy\": \"run-pid-context-event-sequence-kind\",\n"
               "  \"ordering\": \"causal-edges-with-per-context-sequence-and-observed-timestamps\",\n"
               "  \"summary\": {\"call_nodes\": %zu, \"resource_nodes\": %zu},\n",
               P101_TOOL_EVENT_SCHEMA_NAME,
               calls,
               resources) < 0 ||
       write_nodes(stream, model) != 0 || fputs(",\n", stream) == EOF || write_edges(stream, model) != 0 || fputs("\n}\n", stream) == EOF || fflush(stream) != 0)
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

static int write_node_id(FILE *stream, const struct p101_tool_model_node *node)
{
    const char *domain;

    domain = node->domain == P101_TOOL_MODEL_NODE_CALL ? "call" : "resource";
    if(fputc('"', stream) == EOF || fprintf(stream, "%s:", domain) < 0 || write_json_string_contents(stream, node->run_id) != 0 || fprintf(stream, ":%ld:%zu:%zu:%s\"", node->pid, node->context_id, node->sequence, node_kind_name(node)) < 0)
    {
        return -1;
    }
    return 0;
}

static int write_nodes(FILE *stream, const struct p101_tool_model *model)
{
    if(fputs("  \"nodes\": [\n", stream) == EOF)
    {
        return -1;
    }
    for(size_t index = 0U; index < model->node_count; index++)
    {
        if((index > 0U && fputs(",\n", stream) == EOF) || write_node(stream, &model->nodes[index].value) != 0)
        {
            return -1;
        }
    }
    return fputs("\n  ]", stream) == EOF ? -1 : 0;
}

static int write_node(FILE *stream, const struct p101_tool_model_node *node)
{
    if(fputs("    {\"id\":", stream) == EOF || write_node_id(stream, node) != 0 || fprintf(stream, ",\"domain\":\"%s\",\"kind\":", node->domain == P101_TOOL_MODEL_NODE_CALL ? "call" : "resource") < 0 || write_json_string(stream, node_kind_name(node)) != 0 ||
       fputs(",\"run_id\":", stream) == EOF || write_json_string(stream, node->run_id) != 0 || fprintf(stream, ",\"pid\":%ld,\"context\":%zu,\"sequence\":%zu", node->pid, node->context_id, node->sequence) < 0)
    {
        return -1;
    }
    if(node->domain == P101_TOOL_MODEL_NODE_CALL)
    {
        if(fputs(",\"name\":", stream) == EOF || write_json_string(stream, node->call_name) != 0 || fputs(",\"arguments\":", stream) == EOF || write_json_string(stream, node->arguments) != 0 || fputs(",\"result\":", stream) == EOF ||
           write_json_string(stream, node->result) != 0)
        {
            return -1;
        }
    }
    else if(write_resource_fields(stream, node) != 0)
    {
        return -1;
    }
    return fputc(',', stream) == EOF || write_time(stream, node) != 0 || fputc(',', stream) == EOF || write_source(stream, node) != 0 || fputc('}', stream) == EOF ? -1 : 0;
}

static int write_resource_fields(FILE *stream, const struct p101_tool_model_node *node)
{
    if(node->record_kind == P101_TOOL_EVENT_RECORD_FD)
    {
        return fprintf(stream, ",\"resource_class\":\"fd\",\"resource_identity\":\"%d\"", node->fd) < 0 ? -1 : 0;
    }
    if(node->record_kind == P101_TOOL_EVENT_RECORD_ALLOC)
    {
        if(fputs(",\"resource_class\":\"allocation\",\"resource_identity\":", stream) == EOF || write_json_string(stream, node->ptr) != 0)
        {
            return -1;
        }
        if(node->alloc_kind == P101_TOOL_EVENT_ALLOC_REALLOC)
        {
            if(fputs(",\"related_identity\":", stream) == EOF || write_json_string(stream, node->new_ptr) != 0)
            {
                return -1;
            }
        }
        return fprintf(stream, ",\"size\":%zu", node->size) < 0 ? -1 : 0;
    }
    if(node->record_kind == P101_TOOL_EVENT_RECORD_FORK || node->record_kind == P101_TOOL_EVENT_RECORD_SPAWN)
    {
        if(fprintf(stream, ",\"child_pid\":%ld", node->child_pid) < 0)
        {
            return -1;
        }
        if(node->record_kind == P101_TOOL_EVENT_RECORD_SPAWN)
        {
            return fputs(",\"target\":", stream) == EOF || write_json_string(stream, node->target) != 0 ? -1 : 0;
        }
        return 0;
    }
    if(node->record_kind == P101_TOOL_EVENT_RECORD_EXEC || node->record_kind == P101_TOOL_EVENT_RECORD_EXEC_FAIL)
    {
        if(node->record_kind == P101_TOOL_EVENT_RECORD_EXEC && fprintf(stream, ",\"resource_class\":\"fd\",\"resource_identity\":\"%d\"", node->fd) < 0)
        {
            return -1;
        }
        if(fputs(",\"target\":", stream) == EOF || write_json_string(stream, node->target) != 0)
        {
            return -1;
        }
        return node->record_kind == P101_TOOL_EVENT_RECORD_EXEC && fprintf(stream, ",\"cloexec\":%s", (int)node->cloexec ? "true" : "false") < 0 ? -1 : 0;
    }

    return fputs(",\"operation\":", stream) == EOF || write_json_string(stream, resource_operation_name(node->resource_kind)) != 0 || fputs(",\"resource_class\":", stream) == EOF || write_json_string(stream, node->resource_class) != 0 ||
                   fputs(",\"resource_identity\":", stream) == EOF || write_json_string(stream, node->resource_id) != 0 || fputs(",\"related_identity\":", stream) == EOF || write_json_string(stream, node->related_id) != 0 ||
                   fputs(",\"metadata\":", stream) == EOF || write_json_string(stream, node->metadata) != 0 || fprintf(stream, ",\"size\":%zu", node->size) < 0 ?
               -1 :
               0;
}

static int write_edges(FILE *stream, const struct p101_tool_model *model)
{
    if(fputs("  \"edges\": [\n", stream) == EOF)
    {
        return -1;
    }
    for(size_t index = 0U; index < model->edge_count; index++)
    {
        const struct p101_tool_model_edge *edge;

        edge = &model->edges[index];
        if((index > 0U && fputs(",\n", stream) == EOF) || fputs("    {\"kind\":", stream) == EOF || write_json_string(stream, edge_kind_name(edge->kind)) != 0 || fputs(",\"from\":", stream) == EOF ||
           write_node_id(stream, &model->nodes[edge->from].value) != 0 || fputs(",\"to\":", stream) == EOF || write_node_id(stream, &model->nodes[edge->to].value) != 0 || fputc('}', stream) == EOF)
        {
            return -1;
        }
    }
    return fputs("\n  ]", stream) == EOF ? -1 : 0;
}

static int write_time(FILE *stream, const struct p101_tool_model_node *node)
{
    if(fputs("\"monotonic_ns\":", stream) == EOF)
    {
        return -1;
    }
    if(node->monotonic_ns_available)
    {
        if(fprintf(stream, "%zu", node->monotonic_ns) < 0)
        {
            return -1;
        }
    }
    else if(fputs("null", stream) == EOF)
    {
        return -1;
    }
    if(fputs(",\"wall_unix_ns\":", stream) == EOF)
    {
        return -1;
    }
    if(node->wall_unix_ns_available)
    {
        return fprintf(stream, "%zu", node->wall_unix_ns) < 0 ? -1 : 0;
    }
    return fputs("null", stream) == EOF ? -1 : 0;
}

static int write_source(FILE *stream, const struct p101_tool_model_node *node)
{
    return fputs("\"source\":{\"file\":", stream) == EOF || write_json_string(stream, node->file_name) != 0 || fprintf(stream, ",\"line\":%d,\"function\":", node->line_number) < 0 || write_json_string(stream, node->function_name) != 0 ||
                   fputc('}', stream) == EOF ?
               -1 :
               0;
}

static int write_json_string(FILE *stream, const char *text)
{
    if(fputc('"', stream) == EOF || write_json_string_contents(stream, text) != 0)
    {
        return -1;
    }
    return fputc('"', stream) == EOF ? -1 : 0;
}

static int write_json_string_contents(FILE *stream, const char *text)
{
    const unsigned char *cursor;

    cursor = (const unsigned char *)text;
    while(*cursor != '\0')
    {
        if(*cursor == '"' || *cursor == '\\')
        {
            if(fputc('\\', stream) == EOF || fputc((int)*cursor, stream) == EOF)
            {
                return -1;
            }
        }
        else if(*cursor == '\n')
        {
            if(fputs("\\n", stream) == EOF)
            {
                return -1;
            }
        }
        else if(*cursor == '\r')
        {
            if(fputs("\\r", stream) == EOF)
            {
                return -1;
            }
        }
        else if(*cursor == '\t')
        {
            if(fputs("\\t", stream) == EOF)
            {
                return -1;
            }
        }
        else if(*cursor < JSON_CONTROL_CHARACTER_LIMIT)
        {
            if(fprintf(stream, "\\u%04x", (unsigned int)*cursor) < 0)
            {
                return -1;
            }
        }
        else if(fputc((int)*cursor, stream) == EOF)
        {
            return -1;
        }
        cursor++;
    }
    return 0;
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
