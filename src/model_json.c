#include "model_internal.h"
#include <errno.h>
#include <p101_error/error.h>
#include <p101_record/record.h>
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

static int         write_json_string(FILE *stream, const char *text);
static int         write_json_string_contents(FILE *stream, const char *text);
static int         write_source(FILE *stream, const struct p101_tool_model_node *node);
static int         write_time(FILE *stream, const struct p101_tool_model_node *node);
static int         write_resource_fields(FILE *stream, const struct p101_tool_model_node *node);
static int         write_node(FILE *stream, const struct p101_tool_model_node *node);
static int         write_nodes(FILE *stream, const struct p101_tool_model *model);
static int         write_edges(FILE *stream, const struct p101_tool_model *model);
static int         write_lifecycle(FILE *stream, const struct p101_tool_model *model);
static int         write_lifecycle_entry(FILE *stream, const struct p101_tool_event_lifecycle_entry *entry);
static int         write_lifecycle_finding(FILE *stream, const struct p101_tool_event_lifecycle_finding *finding);
static int         write_lifecycle_location(FILE *stream, size_t context, size_t sequence, size_t monotonic_ns, bool monotonic_available, const char *file_name, int line_number, const char *function_name);
static const char *node_kind_name(const struct p101_tool_model_node *node);
static const char *edge_kind_name(p101_tool_model_edge_kind kind);
static const char *lifecycle_finding_kind_name(p101_tool_event_lifecycle_finding_kind kind);
static int         write_node_id(FILE *stream, const struct p101_tool_model_node *node);
static const char *fd_kind_name(p101_tool_event_fd_kind kind);
static const char *alloc_kind_name(p101_tool_event_alloc_kind kind);
static const char *resource_operation_name(p101_tool_event_resource_kind kind);

int p101_tool_model_write_json(struct p101_error *err, FILE *stream, const struct p101_tool_model *model)
{
    int    p101_single_result_;
    int    operation_status;
    size_t calls;
    size_t resources;

    if(stream == NULL || model == NULL || model->finished == 0)
    {
        P101_ERROR_RAISE_ERRNO(err, EINVAL);
        p101_single_result_ = -1;
        goto p101_single_exit_;
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
    operation_status = fprintf(stream,
                               "{\n"
                               "  \"schema\": \"p101-run-model-v1\",\n"
                               "  \"event_schema\": \"%s\",\n"
                               "  \"identity_policy\": \"run-pid-context-event-sequence-kind\",\n"
                               "  \"ordering\": \"causal-edges-with-per-context-sequence-and-observed-timestamps\",\n"
                               "  \"summary\": {\"call_nodes\": %zu, \"resource_nodes\": %zu},\n",
                               P101_TOOL_EVENT_SCHEMA_NAME,
                               calls,
                               resources);
    if(operation_status < 0)
    {
        goto write_failed;
    }
    operation_status = write_nodes(stream, model);
    if(operation_status != 0)
    {
        goto write_failed;
    }
    operation_status = fputs(",\n", stream);
    if(operation_status == EOF)
    {
        goto write_failed;
    }
    operation_status = write_edges(stream, model);
    if(operation_status != 0)
    {
        goto write_failed;
    }
    operation_status = fputs(",\n", stream);
    if(operation_status == EOF)
    {
        goto write_failed;
    }
    operation_status = write_lifecycle(stream, model);
    if(operation_status != 0)
    {
        goto write_failed;
    }
    operation_status = fputs("\n}\n", stream);
    if(operation_status == EOF)
    {
        goto write_failed;
    }
    operation_status = fflush(stream);
    if(operation_status != 0)
    {
        goto write_failed;
    }
    p101_single_result_ = 0;
    goto p101_single_exit_;

write_failed:
    P101_ERROR_RAISE_ERRNO(err, EIO);
    p101_single_result_ = -1;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static int write_lifecycle(FILE *stream, const struct p101_tool_model *model)
{
    int    p101_single_result_;
    int    operation_status;
    size_t entry_count;
    size_t finding_count;

    entry_count      = p101_tool_event_lifecycle_entry_count(model->lifecycle);
    finding_count    = p101_tool_event_lifecycle_finding_count(model->lifecycle);
    operation_status = fputs("  \"lifecycle\": {\n    \"entries\": [\n", stream);
    if(operation_status == EOF)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    for(size_t index = 0U; index < entry_count; index++)
    {
        const struct p101_tool_event_lifecycle_entry *entry;

        entry = p101_tool_event_lifecycle_entry_at(model->lifecycle, index);
        // GCOVR_EXCL_START: index is bounded by the count returned by the same
        // lifecycle model, so a null entry would violate the library invariant.
        if(entry == NULL)
        {
            p101_single_result_ = -1;
            goto p101_single_exit_;
        }
        // GCOVR_EXCL_STOP
        if(index > 0U)
        {
            operation_status = fputs(",\n", stream);
            if(operation_status == EOF)
            {
                p101_single_result_ = -1;
                goto p101_single_exit_;
            }
        }
        operation_status = write_lifecycle_entry(stream, entry);
        if(operation_status != 0)
        {
            p101_single_result_ = -1;
            goto p101_single_exit_;
        }
    }
    operation_status = fputs("\n    ],\n    \"findings\": [\n", stream);
    if(operation_status == EOF)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    for(size_t index = 0U; index < finding_count; index++)
    {
        const struct p101_tool_event_lifecycle_finding *finding;

        finding = p101_tool_event_lifecycle_finding_at(model->lifecycle, index);
        // GCOVR_EXCL_START: index is bounded by the count returned by the same
        // lifecycle model, so a null finding would violate the library invariant.
        if(finding == NULL)
        {
            p101_single_result_ = -1;
            goto p101_single_exit_;
        }
        // GCOVR_EXCL_STOP
        if(index > 0U)
        {
            operation_status = fputs(",\n", stream);
            if(operation_status == EOF)
            {
                p101_single_result_ = -1;
                goto p101_single_exit_;
            }
        }
        operation_status = write_lifecycle_finding(stream, finding);
        if(operation_status != 0)
        {
            p101_single_result_ = -1;
            goto p101_single_exit_;
        }
    }
    operation_status    = fputs("\n    ]\n  }", stream);
    p101_single_result_ = operation_status == EOF ? -1 : 0;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static int write_lifecycle_entry(FILE *stream, const struct p101_tool_event_lifecycle_entry *entry)
{
    int         p101_single_result_;
    int         operation_status;
    const char *live_text;

    live_text = "false";
    if(entry->live)
    {
        live_text = "true";
    }
    operation_status = fputs("      {\"pid\":", stream);
    if(operation_status == EOF)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    operation_status = fprintf(stream, "%ld,\"resource_class\":", entry->pid);
    if(operation_status < 0)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    operation_status = write_json_string(stream, entry->resource_class);
    if(operation_status != 0)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    operation_status = fputs(",\"identity\":", stream);
    if(operation_status == EOF)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    operation_status = write_json_string(stream, entry->resource_id);
    if(operation_status != 0)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    operation_status = fprintf(stream, ",\"size\":%zu,\"live\":%s,\"acquired\":", entry->size, live_text);
    if(operation_status < 0)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    operation_status =
        write_lifecycle_location(stream, entry->acquired_context_id, entry->acquired_sequence, entry->acquired_monotonic_ns, entry->acquired_monotonic_ns_available, entry->acquired_file_name, entry->acquired_line_number, entry->acquired_function_name);
    if(operation_status != 0)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    operation_status = fputs(",\"released\":", stream);
    if(operation_status == EOF)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    if(entry->live)
    {
        operation_status = fputs("null", stream);
        if(operation_status == EOF)
        {
            p101_single_result_ = -1;
            goto p101_single_exit_;
        }
    }
    else
    {
        operation_status =
            write_lifecycle_location(stream, entry->released_context_id, entry->released_sequence, entry->released_monotonic_ns, entry->released_monotonic_ns_available, entry->released_file_name, entry->released_line_number, entry->released_function_name);
        if(operation_status != 0)
        {
            p101_single_result_ = -1;
            goto p101_single_exit_;
        }
    }
    operation_status    = fputc('}', stream);
    p101_single_result_ = operation_status == EOF ? -1 : 0;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static int write_lifecycle_finding(FILE *stream, const struct p101_tool_event_lifecycle_finding *finding)
{
    int         p101_single_result_;
    int         operation_status;
    const char *kind_name;

    operation_status = fputs("      {\"kind\":", stream);
    if(operation_status == EOF)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    kind_name        = lifecycle_finding_kind_name(finding->kind);
    operation_status = write_json_string(stream, kind_name);
    if(operation_status != 0)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    operation_status = fprintf(stream, ",\"pid\":%ld,\"resource_class\":", finding->pid);
    if(operation_status < 0)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    operation_status = write_json_string(stream, finding->resource_class);
    if(operation_status != 0)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    operation_status = fputs(",\"identity\":", stream);
    if(operation_status == EOF)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    operation_status = write_json_string(stream, finding->resource_id);
    if(operation_status != 0)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    operation_status = fputs(",\"at\":", stream);
    if(operation_status == EOF)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    operation_status = write_lifecycle_location(stream, finding->context_id, finding->sequence, finding->monotonic_ns, finding->monotonic_ns_available, finding->file_name, finding->line_number, finding->function_name);
    if(operation_status != 0)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    operation_status = fputs(",\"previous\":", stream);
    if(operation_status == EOF)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    if(finding->previous_sequence == 0U)
    {
        operation_status = fputs("null", stream);
        if(operation_status == EOF)
        {
            p101_single_result_ = -1;
            goto p101_single_exit_;
        }
    }
    else
    {
        operation_status = write_lifecycle_location(stream, finding->previous_context_id, finding->previous_sequence, 0U, false, finding->previous_file_name, finding->previous_line_number, finding->previous_function_name);
        if(operation_status != 0)
        {
            p101_single_result_ = -1;
            goto p101_single_exit_;
        }
    }
    operation_status    = fputc('}', stream);
    p101_single_result_ = operation_status == EOF ? -1 : 0;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static int write_lifecycle_location(FILE *stream, size_t context, size_t sequence, size_t monotonic_ns, bool monotonic_available, const char *file_name, int line_number, const char *function_name)
{
    int p101_single_result_;
    int operation_status;

    operation_status = fprintf(stream, "{\"context\":%zu,\"sequence\":%zu,\"monotonic_ns\":", context, sequence);
    if(operation_status < 0)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    if(monotonic_available)
    {
        operation_status = fprintf(stream, "%zu", monotonic_ns);
        if(operation_status < 0)
        {
            p101_single_result_ = -1;
            goto p101_single_exit_;
        }
    }
    else
    {
        operation_status = fputs("null", stream);
        if(operation_status == EOF)
        {
            p101_single_result_ = -1;
            goto p101_single_exit_;
        }
    }
    /*
     * Lifecycle construction normalizes missing source text to "?"; locations
     * therefore never receive null names.
     */
    operation_status = fputs(",\"source\":{\"file\":", stream);
    if(operation_status == EOF)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    operation_status = write_json_string(stream, file_name);
    if(operation_status != 0)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    operation_status = fprintf(stream, ",\"line\":%d,\"function\":", line_number);
    if(operation_status < 0)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    operation_status = write_json_string(stream, function_name);
    if(operation_status != 0)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    operation_status    = fputs("}}", stream);
    p101_single_result_ = operation_status == EOF ? -1 : 0;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static const char *lifecycle_finding_kind_name(p101_tool_event_lifecycle_finding_kind kind)
{
    const char *p101_single_result_;
#ifdef __clang__
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wcovered-switch-default"
#endif
    // GCOVR_EXCL_BR_START: every valid finding kind is exercised; the remaining
    // edge is the defensive fallback for a value outside the closed enum.
    switch(kind)
    {
        case P101_TOOL_EVENT_LIFECYCLE_FINDING_LEAK:
            p101_single_result_ = "leak";
            goto p101_single_exit_;
        case P101_TOOL_EVENT_LIFECYCLE_FINDING_DOUBLE_RELEASE:
            p101_single_result_ = "double-release";
            goto p101_single_exit_;
        case P101_TOOL_EVENT_LIFECYCLE_FINDING_STRAY_RELEASE:
            p101_single_result_ = "stray-release";
            goto p101_single_exit_;
        case P101_TOOL_EVENT_LIFECYCLE_FINDING_BAD_REPLACE:
            p101_single_result_ = "bad-replace";
            goto p101_single_exit_;
        case P101_TOOL_EVENT_LIFECYCLE_FINDING_DUPLICATE_ACQUIRE:
            p101_single_result_ = "duplicate-acquire";
            goto p101_single_exit_;
        case P101_TOOL_EVENT_LIFECYCLE_FINDING_EXEC_INHERIT:
            p101_single_result_ = "exec-inherit";
            goto p101_single_exit_;
        default:
            p101_single_result_ = "unknown";
            goto p101_single_exit_;    // GCOVR_EXCL_LINE -- exhaustive enum defensive fallback.
    }
        // GCOVR_EXCL_BR_STOP
#ifdef __clang__
    #pragma clang diagnostic pop
#endif

p101_single_exit_:
    return p101_single_result_;
}

static const char *node_kind_name(const struct p101_tool_model_node *node)
{
    const char *p101_single_result_;
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
            p101_single_result_ = fd_kind_name(node->fd_kind);
            goto p101_single_exit_;
        }
        case P101_TOOL_EVENT_RECORD_ALLOC:
        {
            p101_single_result_ = alloc_kind_name(node->alloc_kind);
            goto p101_single_exit_;
        }
        case P101_TOOL_EVENT_RECORD_FORK:
        {
            p101_single_result_ = "fork";
            goto p101_single_exit_;
        }
        case P101_TOOL_EVENT_RECORD_SPAWN:
        {
            p101_single_result_ = "spawn";
            goto p101_single_exit_;
        }
        case P101_TOOL_EVENT_RECORD_EXEC:
        {
            p101_single_result_ = "exec";
            goto p101_single_exit_;
        }
        case P101_TOOL_EVENT_RECORD_EXEC_FAIL:
        {
            p101_single_result_ = "exec-fail";
            goto p101_single_exit_;
        }
        case P101_TOOL_EVENT_RECORD_CALL:
        {
            p101_single_result_ = node->call_kind == P101_TOOL_EVENT_CALL_ENTER ? "call-enter" : "call-exit";
            goto p101_single_exit_;
        }
        case P101_TOOL_EVENT_RECORD_RESOURCE:
        {
            p101_single_result_ = "resource";
            goto p101_single_exit_;
        }
        // GCOVR_EXCL_START
        case P101_TOOL_EVENT_RECORD_COMPLETE:
        {
            p101_single_result_ = "complete";
            goto p101_single_exit_;
        }
        default:
        {
            p101_single_result_ = "unknown";
            goto p101_single_exit_;
        }
            // GCOVR_EXCL_STOP
    }
        // GCOVR_EXCL_BR_STOP
#ifdef __clang__
    #pragma clang diagnostic pop
#endif

p101_single_exit_:
    return p101_single_result_;
}

static const char *edge_kind_name(p101_tool_model_edge_kind kind)
{
    const char *p101_single_result_;
#ifdef __clang__
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wcovered-switch-default"
#endif
    // GCOVR_EXCL_BR_START: edges are created only by the typed model builder.
    switch(kind)
    {
        case P101_TOOL_MODEL_EDGE_CALL_PARENT:
        {
            p101_single_result_ = "call-parent";
            goto p101_single_exit_;
        }
        case P101_TOOL_MODEL_EDGE_CALL_RETURN:
        {
            p101_single_result_ = "call-return";
            goto p101_single_exit_;
        }
        case P101_TOOL_MODEL_EDGE_CALL_CAUSED_EVENT:
        {
            p101_single_result_ = "call-caused-event";
            goto p101_single_exit_;
        }
        case P101_TOOL_MODEL_EDGE_RESOURCE_LIFETIME:
        {
            p101_single_result_ = "resource-lifetime";
            goto p101_single_exit_;
        }
        case P101_TOOL_MODEL_EDGE_PROCESS_CHILD_EVENT:
        {
            p101_single_result_ = "process-child-event";
            goto p101_single_exit_;
        }
        // GCOVR_EXCL_START
        default:
        {
            p101_single_result_ = "unknown";
            goto p101_single_exit_;
        }
            // GCOVR_EXCL_STOP
    }
        // GCOVR_EXCL_BR_STOP
#ifdef __clang__
    #pragma clang diagnostic pop
#endif

p101_single_exit_:
    return p101_single_result_;
}

static int write_node_id(FILE *stream, const struct p101_tool_model_node *node)
{
    int         p101_single_result_;
    int         operation_status;
    const char *domain;
    const char *kind_name;

    domain           = node->domain == P101_TOOL_MODEL_NODE_CALL ? "call" : "resource";
    operation_status = fputc('"', stream);
    if(operation_status == EOF)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    operation_status = fprintf(stream, "%s:", domain);
    if(operation_status < 0)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    operation_status = write_json_string_contents(stream, node->run_id);
    if(operation_status != 0)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    kind_name        = node_kind_name(node);
    operation_status = fprintf(stream, ":%ld:%zu:%zu:%s\"", node->pid, node->context_id, node->sequence, kind_name);
    if(operation_status < 0)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    p101_single_result_ = 0;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static int write_nodes(FILE *stream, const struct p101_tool_model *model)
{
    int p101_single_result_;
    int operation_status;

    operation_status = fputs("  \"nodes\": [\n", stream);
    if(operation_status == EOF)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    for(size_t index = 0U; index < model->node_count; index++)
    {
        if(index > 0U)
        {
            operation_status = fputs(",\n", stream);
            if(operation_status == EOF)
            {
                p101_single_result_ = -1;
                goto p101_single_exit_;
            }
        }
        operation_status = write_node(stream, &model->nodes[index].value);
        if(operation_status != 0)
        {
            p101_single_result_ = -1;
            goto p101_single_exit_;
        }
    }
    operation_status    = fputs("\n  ]", stream);
    p101_single_result_ = operation_status == EOF ? -1 : 0;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static int write_node(FILE *stream, const struct p101_tool_model_node *node)
{
    int         p101_single_result_;
    int         operation_status;
    const char *domain;
    const char *kind_name;

    operation_status = fputs("    {\"id\":", stream);
    if(operation_status == EOF)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    operation_status = write_node_id(stream, node);
    if(operation_status != 0)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    domain           = node->domain == P101_TOOL_MODEL_NODE_CALL ? "call" : "resource";
    operation_status = fprintf(stream, ",\"domain\":\"%s\",\"kind\":", domain);
    if(operation_status < 0)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    kind_name        = node_kind_name(node);
    operation_status = write_json_string(stream, kind_name);
    if(operation_status != 0)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    operation_status = fputs(",\"run_id\":", stream);
    if(operation_status == EOF)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    operation_status = write_json_string(stream, node->run_id);
    if(operation_status != 0)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    operation_status = fprintf(stream, ",\"pid\":%ld,\"context\":%zu,\"sequence\":%zu", node->pid, node->context_id, node->sequence);
    if(operation_status < 0)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    if(node->domain == P101_TOOL_MODEL_NODE_CALL)
    {
        operation_status = fputs(",\"name\":", stream);
        if(operation_status == EOF)
        {
            p101_single_result_ = -1;
            goto p101_single_exit_;
        }
        operation_status = write_json_string(stream, node->call_name);
        if(operation_status != 0)
        {
            p101_single_result_ = -1;
            goto p101_single_exit_;
        }
        operation_status = fputs(",\"arguments\":", stream);
        if(operation_status == EOF)
        {
            p101_single_result_ = -1;
            goto p101_single_exit_;
        }
        operation_status = write_json_string(stream, node->arguments);
        if(operation_status != 0)
        {
            p101_single_result_ = -1;
            goto p101_single_exit_;
        }
        operation_status = fputs(",\"result\":", stream);
        if(operation_status == EOF)
        {
            p101_single_result_ = -1;
            goto p101_single_exit_;
        }
        operation_status = write_json_string(stream, node->result);
        if(operation_status != 0)
        {
            p101_single_result_ = -1;
            goto p101_single_exit_;
        }
    }
    else
    {
        operation_status = write_resource_fields(stream, node);
        if(operation_status != 0)
        {
            p101_single_result_ = -1;
            goto p101_single_exit_;
        }
    }
    operation_status = fputc(',', stream);
    if(operation_status == EOF)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    operation_status = write_time(stream, node);
    if(operation_status != 0)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    operation_status = fputc(',', stream);
    if(operation_status == EOF)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    operation_status = write_source(stream, node);
    if(operation_status != 0)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    operation_status    = fputc('}', stream);
    p101_single_result_ = operation_status == EOF ? -1 : 0;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static int write_resource_fields(FILE *stream, const struct p101_tool_model_node *node)
{
    int         p101_single_result_;
    int         operation_status;
    const char *operation_name;
    const char *cloexec_text;

    if(node->record_kind == P101_TOOL_EVENT_RECORD_FD)
    {
        operation_status    = fprintf(stream, ",\"resource_class\":\"fd\",\"resource_identity\":\"%d\"", node->fd);
        p101_single_result_ = operation_status < 0 ? -1 : 0;
        goto p101_single_exit_;
    }
    if(node->record_kind == P101_TOOL_EVENT_RECORD_ALLOC)
    {
        operation_status = fputs(",\"resource_class\":\"allocation\",\"resource_identity\":", stream);
        if(operation_status == EOF)
        {
            p101_single_result_ = -1;
            goto p101_single_exit_;
        }
        operation_status = write_json_string(stream, node->ptr);
        if(operation_status != 0)
        {
            p101_single_result_ = -1;
            goto p101_single_exit_;
        }
        if(node->alloc_kind == P101_TOOL_EVENT_ALLOC_REALLOC)
        {
            operation_status = fputs(",\"related_identity\":", stream);
            if(operation_status == EOF)
            {
                p101_single_result_ = -1;
                goto p101_single_exit_;
            }
            operation_status = write_json_string(stream, node->new_ptr);
            if(operation_status != 0)
            {
                p101_single_result_ = -1;
                goto p101_single_exit_;
            }
        }
        operation_status    = fprintf(stream, ",\"size\":%zu", node->size);
        p101_single_result_ = operation_status < 0 ? -1 : 0;
        goto p101_single_exit_;
    }
    if(node->record_kind == P101_TOOL_EVENT_RECORD_FORK || node->record_kind == P101_TOOL_EVENT_RECORD_SPAWN)
    {
        operation_status = fprintf(stream, ",\"child_pid\":%ld", node->child_pid);
        if(operation_status < 0)
        {
            p101_single_result_ = -1;
            goto p101_single_exit_;
        }
        if(node->record_kind == P101_TOOL_EVENT_RECORD_SPAWN)
        {
            operation_status = fputs(",\"target\":", stream);
            if(operation_status == EOF)
            {
                p101_single_result_ = -1;
                goto p101_single_exit_;
            }
            operation_status    = write_json_string(stream, node->target);
            p101_single_result_ = operation_status != 0 ? -1 : 0;
            goto p101_single_exit_;
        }
        p101_single_result_ = 0;
        goto p101_single_exit_;
    }
    if(node->record_kind == P101_TOOL_EVENT_RECORD_EXEC || node->record_kind == P101_TOOL_EVENT_RECORD_EXEC_FAIL)
    {
        if(node->record_kind == P101_TOOL_EVENT_RECORD_EXEC)
        {
            operation_status = fprintf(stream, ",\"resource_class\":\"fd\",\"resource_identity\":\"%d\"", node->fd);
            if(operation_status < 0)
            {
                p101_single_result_ = -1;
                goto p101_single_exit_;
            }
        }
        operation_status = fputs(",\"target\":", stream);
        if(operation_status == EOF)
        {
            p101_single_result_ = -1;
            goto p101_single_exit_;
        }
        operation_status = write_json_string(stream, node->target);
        if(operation_status != 0)
        {
            p101_single_result_ = -1;
            goto p101_single_exit_;
        }
        p101_single_result_ = 0;
        if(node->record_kind == P101_TOOL_EVENT_RECORD_EXEC)
        {
            cloexec_text        = (int)node->cloexec ? "true" : "false";
            operation_status    = fprintf(stream, ",\"cloexec\":%s", cloexec_text);
            p101_single_result_ = operation_status < 0 ? -1 : 0;
        }
        goto p101_single_exit_;
    }

    operation_status = fputs(",\"operation\":", stream);
    if(operation_status == EOF)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    operation_name   = resource_operation_name(node->resource_kind);
    operation_status = write_json_string(stream, operation_name);
    if(operation_status != 0)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    operation_status = fputs(",\"resource_class\":", stream);
    if(operation_status == EOF)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    operation_status = write_json_string(stream, node->resource_class);
    if(operation_status != 0)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    operation_status = fputs(",\"resource_identity\":", stream);
    if(operation_status == EOF)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    operation_status = write_json_string(stream, node->resource_id);
    if(operation_status != 0)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    operation_status = fputs(",\"related_identity\":", stream);
    if(operation_status == EOF)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    operation_status = write_json_string(stream, node->related_id);
    if(operation_status != 0)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    operation_status = fputs(",\"metadata\":", stream);
    if(operation_status == EOF)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    operation_status = write_json_string(stream, node->metadata);
    if(operation_status != 0)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    operation_status    = fprintf(stream, ",\"size\":%zu", node->size);
    p101_single_result_ = operation_status < 0 ? -1 : 0;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static int write_edges(FILE *stream, const struct p101_tool_model *model)
{
    int         p101_single_result_;
    int         operation_status;
    const char *kind_name;

    operation_status = fputs("  \"edges\": [\n", stream);
    if(operation_status == EOF)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    for(size_t index = 0U; index < model->edge_count; index++)
    {
        const struct p101_tool_model_edge *edge;

        edge = &model->edges[index];
        if(index > 0U)
        {
            operation_status = fputs(",\n", stream);
            if(operation_status == EOF)
            {
                p101_single_result_ = -1;
                goto p101_single_exit_;
            }
        }
        operation_status = fputs("    {\"kind\":", stream);
        if(operation_status == EOF)
        {
            p101_single_result_ = -1;
            goto p101_single_exit_;
        }
        kind_name        = edge_kind_name(edge->kind);
        operation_status = write_json_string(stream, kind_name);
        if(operation_status != 0)
        {
            p101_single_result_ = -1;
            goto p101_single_exit_;
        }
        operation_status = fputs(",\"from\":", stream);
        if(operation_status == EOF)
        {
            p101_single_result_ = -1;
            goto p101_single_exit_;
        }
        operation_status = write_node_id(stream, &model->nodes[edge->from].value);
        if(operation_status != 0)
        {
            p101_single_result_ = -1;
            goto p101_single_exit_;
        }
        operation_status = fputs(",\"to\":", stream);
        if(operation_status == EOF)
        {
            p101_single_result_ = -1;
            goto p101_single_exit_;
        }
        operation_status = write_node_id(stream, &model->nodes[edge->to].value);
        if(operation_status != 0)
        {
            p101_single_result_ = -1;
            goto p101_single_exit_;
        }
        operation_status = fputc('}', stream);
        if(operation_status == EOF)
        {
            p101_single_result_ = -1;
            goto p101_single_exit_;
        }
    }
    operation_status    = fputs("\n  ]", stream);
    p101_single_result_ = operation_status == EOF ? -1 : 0;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static int write_time(FILE *stream, const struct p101_tool_model_node *node)
{
    int p101_single_result_;
    int operation_status;

    operation_status = fputs("\"monotonic_ns\":", stream);
    if(operation_status == EOF)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    if(node->monotonic_ns_available)
    {
        operation_status = fprintf(stream, "%zu", node->monotonic_ns);
        if(operation_status < 0)
        {
            p101_single_result_ = -1;
            goto p101_single_exit_;
        }
    }
    else
    {
        operation_status = fputs("null", stream);
        if(operation_status == EOF)
        {
            p101_single_result_ = -1;
            goto p101_single_exit_;
        }
    }
    operation_status = fputs(",\"wall_unix_ns\":", stream);
    if(operation_status == EOF)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    if(node->wall_unix_ns_available)
    {
        operation_status    = fprintf(stream, "%zu", node->wall_unix_ns);
        p101_single_result_ = operation_status < 0 ? -1 : 0;
        goto p101_single_exit_;
    }
    operation_status    = fputs("null", stream);
    p101_single_result_ = operation_status == EOF ? -1 : 0;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static int write_source(FILE *stream, const struct p101_tool_model_node *node)
{
    int p101_single_result_;
    int operation_status;

    operation_status = fputs("\"source\":{\"file\":", stream);
    if(operation_status == EOF)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    operation_status = write_json_string(stream, node->file_name);
    if(operation_status != 0)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    operation_status = fprintf(stream, ",\"line\":%d,\"function\":", node->line_number);
    if(operation_status < 0)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    operation_status = write_json_string(stream, node->function_name);
    if(operation_status != 0)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    operation_status    = fputc('}', stream);
    p101_single_result_ = operation_status == EOF ? -1 : 0;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static int write_json_string(FILE *stream, const char *text)
{
    int p101_single_result_;

    p101_single_result_ = p101_record_write_json_string(stream, text);
    return p101_single_result_;
}

static int write_json_string_contents(FILE *stream, const char *text)
{
    int p101_single_result_;

    p101_single_result_ = p101_record_write_json_string_contents(stream, text);
    return p101_single_result_;
}

static const char *fd_kind_name(p101_tool_event_fd_kind kind)
{
    return kind == P101_TOOL_EVENT_FD_OPEN ? "fd-open" : "fd-close";
}

static const char *alloc_kind_name(p101_tool_event_alloc_kind kind)
{
    const char *p101_single_result_;
#ifdef __clang__
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wcovered-switch-default"
#endif
    // GCOVR_EXCL_BR_START: allocation kinds come from validated event records.
    switch(kind)
    {
        case P101_TOOL_EVENT_ALLOC_ALLOC:
        {
            p101_single_result_ = "alloc";
            goto p101_single_exit_;
        }
        case P101_TOOL_EVENT_ALLOC_FREE:
        {
            p101_single_result_ = "free";
            goto p101_single_exit_;
        }
        case P101_TOOL_EVENT_ALLOC_REALLOC:
        {
            p101_single_result_ = "realloc";
            goto p101_single_exit_;
        }
        // GCOVR_EXCL_START
        default:
        {
            p101_single_result_ = "unknown";
            goto p101_single_exit_;
        }
            // GCOVR_EXCL_STOP
    }
        // GCOVR_EXCL_BR_STOP
#ifdef __clang__
    #pragma clang diagnostic pop
#endif

p101_single_exit_:
    return p101_single_result_;
}

static const char *resource_operation_name(p101_tool_event_resource_kind kind)
{
    const char *p101_single_result_;
#ifdef __clang__
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wcovered-switch-default"
#endif
    // GCOVR_EXCL_BR_START: resource kinds come from validated event records.
    switch(kind)
    {
        case P101_TOOL_EVENT_RESOURCE_ACQUIRE:
        {
            p101_single_result_ = "acquire";
            goto p101_single_exit_;
        }
        case P101_TOOL_EVENT_RESOURCE_RELEASE:
        {
            p101_single_result_ = "release";
            goto p101_single_exit_;
        }
        case P101_TOOL_EVENT_RESOURCE_REPLACE:
        {
            p101_single_result_ = "replace";
            goto p101_single_exit_;
        }
        case P101_TOOL_EVENT_RESOURCE_TRANSFER:
        {
            p101_single_result_ = "transfer";
            goto p101_single_exit_;
        }
        // GCOVR_EXCL_START
        default:
        {
            p101_single_result_ = "unknown";
            goto p101_single_exit_;
        }
            // GCOVR_EXCL_STOP
    }
        // GCOVR_EXCL_BR_STOP
#ifdef __clang__
    #pragma clang diagnostic pop
#endif

p101_single_exit_:
    return p101_single_result_;
}
