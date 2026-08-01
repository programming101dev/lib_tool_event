#include <errno.h>
#include <p101_error/error.h>
#include <p101_tool_event/model.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int failures;

extern void p101_tool_event_test_model_fail_allocation_after(size_t successful_allocations);
extern void p101_tool_event_test_model_set_allocation_failure_errno(int errnum);
extern void p101_tool_event_test_model_fail_write_after(size_t successful_writes);

#define EXPECT(condition)                                                                                                                                                                                                                                          \
    do                                                                                                                                                                                                                                                             \
    {                                                                                                                                                                                                                                                              \
        if(!(condition))                                                                                                                                                                                                                                           \
        {                                                                                                                                                                                                                                                          \
            (void)fprintf(stderr, "EXPECT failed at %s:%d: %s\n", __FILE__, __LINE__, #condition);                                                                                                                                                                 \
            failures++;                                                                                                                                                                                                                                            \
        }                                                                                                                                                                                                                                                          \
    } while(0)

static struct p101_tool_event_record base_record(p101_tool_event_record_kind kind, size_t sequence)
{
    struct p101_tool_event_record record;

    memset(&record, 0, sizeof(record));
    record.version                = P101_TOOL_EVENT_LOG_VERSION;
    record.record_kind            = kind;
    record.pid                    = 41;
    record.context_id             = 7U;
    record.sequence               = sequence;
    record.function_name          = "demo";
    record.file_name              = "demo.c";
    record.line_number            = 12;
    record.monotonic_ns           = sequence * 10U;
    record.wall_unix_ns           = sequence * 20U;
    record.monotonic_ns_available = 1;
    record.wall_unix_ns_available = sequence % 2U == 0U ? 1 : 0;
    return record;
}

static void ingest_record(struct p101_error *err, struct p101_tool_model *model, struct p101_tool_event_record *record)
{
    EXPECT(p101_tool_model_ingest(err, model, record) == 0);
}

static void ingest_call(struct p101_error *err, struct p101_tool_model *model, size_t sequence, p101_tool_event_call_kind kind)
{
    struct p101_tool_event_record record;

    record           = base_record(P101_TOOL_EVENT_RECORD_CALL, sequence);
    record.call_kind = kind;
    record.call_name = "p101_open";
    record.arguments = kind == P101_TOOL_EVENT_CALL_ENTER ? "path=x" : "";
    record.result    = kind == P101_TOOL_EVENT_CALL_EXIT ? "3" : "";
    EXPECT(p101_tool_model_ingest(err, model, &record) == 0);
}

static void ingest_fd(struct p101_error *err, struct p101_tool_model *model, size_t sequence, p101_tool_event_fd_kind kind)
{
    struct p101_tool_event_record record;

    record         = base_record(P101_TOOL_EVENT_RECORD_FD, sequence);
    record.fd_kind = kind;
    record.fd      = 3;
    EXPECT(p101_tool_model_ingest(err, model, &record) == 0);
}

static void test_model_graph_and_json(void)
{
    struct p101_error      *err;
    struct p101_tool_model *model;
    FILE                   *stream;
    char                    text[4096];
    size_t                  bytes;

    err   = p101_error_create(false);
    model = p101_tool_model_create(err);
    EXPECT(err != NULL);
    EXPECT(model != NULL);
    ingest_call(err, model, 1U, P101_TOOL_EVENT_CALL_ENTER);
    ingest_fd(err, model, 2U, P101_TOOL_EVENT_FD_OPEN);
    ingest_fd(err, model, 3U, P101_TOOL_EVENT_FD_CLOSE);
    ingest_call(err, model, 4U, P101_TOOL_EVENT_CALL_EXIT);
    EXPECT(p101_tool_model_finish(err, model) == 0);
    EXPECT(p101_tool_model_finish(err, model) == 0);
    EXPECT(p101_tool_model_node_count(model) == 4U);
    EXPECT(p101_tool_model_edge_count(model) == 4U);
    EXPECT(p101_tool_model_node_at(model, 4U) == NULL);
    EXPECT(p101_tool_model_edge_at(model, 4U) == NULL);
    EXPECT(p101_tool_model_node_at(model, 0U)->domain == P101_TOOL_MODEL_NODE_CALL);
    EXPECT(p101_tool_model_edge_at(model, 0U)->kind == P101_TOOL_MODEL_EDGE_CALL_RETURN);

    stream = tmpfile();
    EXPECT(stream != NULL);
    EXPECT(p101_tool_model_write_json(err, stream, model) == 0);
    rewind(stream);
    bytes       = fread(text, 1U, sizeof(text) - 1U, stream);
    text[bytes] = '\0';
    EXPECT(strstr(text, "\"schema\": \"p101-run-model-v1\"") != NULL);
    EXPECT(strstr(text, "\"kind\":\"resource-lifetime\"") != NULL);
    EXPECT(strstr(text, "\"arguments\":\"path=x\"") != NULL);
    fclose(stream);

    EXPECT(p101_tool_model_ingest(err, model, NULL) == -1);
    EXPECT(p101_error_is_errno(err, EINVAL));
    p101_error_reset(err);
    {
        struct p101_tool_event_record finished_record;

        finished_record = base_record(P101_TOOL_EVENT_RECORD_EXEC_FAIL, 5U);
        EXPECT(p101_tool_model_ingest(err, model, &finished_record) == -1);
        EXPECT(p101_error_is_errno(err, EINVAL));
    }
    p101_tool_model_destroy(&model);
    EXPECT(model == NULL);
    p101_error_destroy(err);
}

static void test_invalid_operations(void)
{
    struct p101_error      *err;
    struct p101_tool_model *model;
    FILE                   *stream;

    err    = p101_error_create(false);
    model  = p101_tool_model_create(err);
    stream = tmpfile();
    EXPECT(p101_tool_model_node_count(NULL) == 0U);
    EXPECT(p101_tool_model_edge_count(NULL) == 0U);
    EXPECT(p101_tool_model_node_at(NULL, 0U) == NULL);
    EXPECT(p101_tool_model_edge_at(NULL, 0U) == NULL);
    p101_tool_model_destroy(NULL);
    EXPECT(p101_tool_model_finish(err, NULL) == -1);
    EXPECT(p101_error_is_errno(err, EINVAL));
    p101_error_reset(err);
    EXPECT(p101_tool_model_write_json(err, stream, model) == -1);
    EXPECT(p101_error_is_errno(err, EINVAL));
    p101_error_reset(err);
    EXPECT(p101_tool_model_write_json(err, NULL, model) == -1);
    EXPECT(p101_error_is_errno(err, EINVAL));
    p101_error_reset(err);
    EXPECT(p101_tool_model_write_json(err, stream, NULL) == -1);
    EXPECT(p101_error_is_errno(err, EINVAL));
    p101_error_reset(err);
    EXPECT(p101_tool_model_ingest(err, NULL, NULL) == -1);
    EXPECT(p101_error_is_errno(err, EINVAL));
    fclose(stream);
    p101_tool_model_destroy(&model);
    p101_error_destroy(err);
}

static void test_all_event_kinds_and_growth(void)
{
    struct p101_error            *err;
    struct p101_tool_model       *model;
    struct p101_tool_event_record record;
    FILE                         *stream;
    char                          text[16384];
    size_t                        bytes;

    err   = p101_error_create(false);
    model = p101_tool_model_create(err);
    ingest_call(err, model, 1U, P101_TOOL_EVENT_CALL_ENTER);

    record           = base_record(P101_TOOL_EVENT_RECORD_CALL, 2U);
    record.call_kind = P101_TOOL_EVENT_CALL_ENTER;
    record.call_name = "p101_inner";
    record.arguments = "quote=\" slash=\\ newline=\n";
    record.result    = "";
    ingest_record(err, model, &record);

    ingest_fd(err, model, 3U, P101_TOOL_EVENT_FD_OPEN);
    ingest_fd(err, model, 4U, P101_TOOL_EVENT_FD_CLOSE);

    record            = base_record(P101_TOOL_EVENT_RECORD_ALLOC, 5U);
    record.alloc_kind = P101_TOOL_EVENT_ALLOC_ALLOC;
    record.ptr        = "0x1";
    record.size       = 8U;
    ingest_record(err, model, &record);
    record            = base_record(P101_TOOL_EVENT_RECORD_ALLOC, 6U);
    record.alloc_kind = P101_TOOL_EVENT_ALLOC_REALLOC;
    record.ptr        = "0x1";
    record.new_ptr    = "0x2";
    record.size       = 16U;
    ingest_record(err, model, &record);
    record            = base_record(P101_TOOL_EVENT_RECORD_ALLOC, 7U);
    record.alloc_kind = P101_TOOL_EVENT_ALLOC_FREE;
    record.ptr        = "0x2";
    ingest_record(err, model, &record);

    record                = base_record(P101_TOOL_EVENT_RECORD_RESOURCE, 8U);
    record.resource_kind  = P101_TOOL_EVENT_RESOURCE_ACQUIRE;
    record.resource_class = "mutex";
    record.resource_id    = "A";
    record.related_id     = "";
    record.metadata       = "line\nreturn\rtab\tcontrol\001";
    record.size           = 1U;
    ingest_record(err, model, &record);
    record                = base_record(P101_TOOL_EVENT_RECORD_RESOURCE, 9U);
    record.resource_kind  = P101_TOOL_EVENT_RESOURCE_REPLACE;
    record.resource_class = "mutex";
    record.resource_id    = "A";
    record.related_id     = "B";
    record.metadata       = "";
    ingest_record(err, model, &record);
    record                = base_record(P101_TOOL_EVENT_RECORD_RESOURCE, 10U);
    record.resource_kind  = P101_TOOL_EVENT_RESOURCE_TRANSFER;
    record.resource_class = "mutex";
    record.resource_id    = "B";
    record.related_id     = "C";
    record.metadata       = "";
    ingest_record(err, model, &record);
    record                = base_record(P101_TOOL_EVENT_RECORD_RESOURCE, 11U);
    record.resource_kind  = P101_TOOL_EVENT_RESOURCE_RELEASE;
    record.resource_class = "mutex";
    record.resource_id    = "C";
    record.related_id     = "";
    record.metadata       = "";
    ingest_record(err, model, &record);

    record           = base_record(P101_TOOL_EVENT_RECORD_FORK, 12U);
    record.child_pid = 42;
    ingest_record(err, model, &record);
    record           = base_record(P101_TOOL_EVENT_RECORD_SPAWN, 13U);
    record.child_pid = 43;
    record.target    = "worker";
    ingest_record(err, model, &record);
    record         = base_record(P101_TOOL_EVENT_RECORD_EXEC, 14U);
    record.fd      = 9;
    record.cloexec = 1;
    record.target  = "child";
    ingest_record(err, model, &record);
    record                        = base_record(P101_TOOL_EVENT_RECORD_EXEC_FAIL, 15U);
    record.target                 = "missing";
    record.monotonic_ns_available = 0;
    ingest_record(err, model, &record);

    record           = base_record(P101_TOOL_EVENT_RECORD_CALL, 16U);
    record.call_kind = P101_TOOL_EVENT_CALL_EXIT;
    record.call_name = "p101_inner";
    record.arguments = "";
    record.result    = "0";
    ingest_record(err, model, &record);
    ingest_call(err, model, 17U, P101_TOOL_EVENT_CALL_EXIT);
    record        = base_record(P101_TOOL_EVENT_RECORD_EXEC_FAIL, 18U);
    record.target = "after-call";
    ingest_record(err, model, &record);

    record           = base_record(P101_TOOL_EVENT_RECORD_CALL, 1U);
    record.pid       = 42;
    record.call_kind = P101_TOOL_EVENT_CALL_ENTER;
    record.call_name = "child_call";
    record.arguments = "";
    record.result    = "";
    ingest_record(err, model, &record);
    record         = base_record(P101_TOOL_EVENT_RECORD_FD, 1U);
    record.pid     = 43;
    record.fd_kind = P101_TOOL_EVENT_FD_OPEN;
    record.fd      = 6;
    ingest_record(err, model, &record);

    EXPECT(p101_tool_model_finish(err, model) == 0);
    EXPECT(p101_tool_model_edge_count(model) > 15U);
    stream = tmpfile();
    EXPECT(stream != NULL);
    EXPECT(p101_tool_model_write_json(err, stream, model) == 0);
    rewind(stream);
    bytes       = fread(text, 1U, sizeof(text) - 1U, stream);
    text[bytes] = '\0';
    EXPECT(strstr(text, "\"kind\":\"spawn\"") != NULL);
    EXPECT(strstr(text, "\"kind\":\"exec-fail\"") != NULL);
    EXPECT(strstr(text, "\"operation\":\"transfer\"") != NULL);
    EXPECT(strstr(text, "\\nreturn\\rtab\\tcontrol\\u0001") != NULL);
    EXPECT(strstr(text, "\"cloexec\":true") != NULL);
    EXPECT(strstr(text, "\"kind\":\"call-parent\"") != NULL);
    EXPECT(strstr(text, "\"kind\":\"process-child-event\"") != NULL);
    fclose(stream);

    for(size_t successful_writes = 0U; successful_writes < 4096U; successful_writes++)
    {
        int result;

        stream = tmpfile();
        EXPECT(stream != NULL);
        p101_tool_event_test_model_fail_write_after(successful_writes);
        result = p101_tool_model_write_json(err, stream, model);
        fclose(stream);
        if(result == 0)
        {
            EXPECT(successful_writes > 0U);
            p101_tool_event_test_model_fail_write_after(SIZE_MAX);
            break;
        }
        EXPECT(p101_error_is_errno(err, EIO));
        p101_error_reset(err);
        if(successful_writes == 4095U)
        {
            EXPECT(0);
        }
    }

    p101_tool_model_destroy(&model);
    p101_error_destroy(err);
}

static void test_empty_complete_and_capacity_growth(void)
{
    struct p101_error            *err;
    struct p101_tool_model       *model;
    struct p101_tool_event_record record;
    FILE                         *stream;

    err    = p101_error_create(false);
    model  = p101_tool_model_create(err);
    record = base_record(P101_TOOL_EVENT_RECORD_COMPLETE, 1U);
    EXPECT(p101_tool_model_ingest(err, model, &record) == 0);
    for(size_t index = 1U; index <= 40U; index++)
    {
        record        = base_record(P101_TOOL_EVENT_RECORD_EXEC_FAIL, index);
        record.target = NULL;
        ingest_record(err, model, &record);
    }
    EXPECT(p101_tool_model_finish(err, model) == 0);
    EXPECT(p101_tool_model_node_count(model) == 40U);
    stream = tmpfile();
    EXPECT(stream != NULL);
    EXPECT(p101_tool_model_write_json(err, stream, model) == 0);
    fclose(stream);
    p101_tool_model_destroy(&model);

    model = p101_tool_model_create(err);
    EXPECT(p101_tool_model_finish(err, model) == 0);
    stream = tmpfile();
    EXPECT(stream != NULL);
    EXPECT(p101_tool_model_write_json(err, stream, model) == 0);
    fclose(stream);
    p101_tool_model_destroy(&model);
    p101_error_destroy(err);
}

static void test_model_allocation_and_output_failures(void)
{
    struct p101_error            *err;
    struct p101_tool_model       *model;
    struct p101_tool_event_record record;
    FILE                         *stream;

    err = p101_error_create(false);
    p101_tool_event_test_model_fail_allocation_after(0U);
    EXPECT(p101_tool_model_create(err) == NULL);
    EXPECT(p101_error_is_errno(err, ENOMEM));
    p101_error_reset(err);

    model         = p101_tool_model_create(err);
    record        = base_record(P101_TOOL_EVENT_RECORD_EXEC_FAIL, 1U);
    record.target = "target";
    p101_tool_event_test_model_fail_allocation_after(0U);
    EXPECT(p101_tool_model_ingest(err, model, &record) == -1);
    EXPECT(p101_error_is_errno(err, ENOMEM));
    p101_error_reset(err);

    p101_tool_event_test_model_fail_allocation_after(1U);
    EXPECT(p101_tool_model_ingest(err, model, &record) == -1);
    EXPECT(p101_error_is_errno(err, ENOMEM));
    p101_error_reset(err);
    EXPECT(p101_tool_model_ingest(err, model, &record) == 0);
    p101_tool_event_test_model_fail_allocation_after(0U);
    EXPECT(p101_tool_model_finish(err, model) == -1);
    EXPECT(p101_error_is_errno(err, ENOMEM));
    p101_error_reset(err);
    EXPECT(p101_tool_model_finish(err, model) == 0);

    stream = tmpfile();
    EXPECT(stream != NULL);
    EXPECT(close(fileno(stream)) == 0);
    EXPECT(p101_tool_model_write_json(err, stream, model) == -1);
    EXPECT(p101_error_is_errno(err, EIO));
    fclose(stream);
    p101_tool_model_destroy(&model);

    model = p101_tool_model_create(err);
    ingest_call(err, model, 1U, P101_TOOL_EVENT_CALL_ENTER);
    ingest_call(err, model, 2U, P101_TOOL_EVENT_CALL_EXIT);
    p101_tool_event_test_model_fail_allocation_after(1U);
    EXPECT(p101_tool_model_finish(err, model) == -1);
    EXPECT(p101_error_is_errno(err, ENOMEM));
    p101_error_reset(err);
    EXPECT(p101_tool_model_edge_count(model) == 0U);
    EXPECT(p101_tool_model_finish(err, model) == 0);
    p101_tool_model_destroy(&model);

    p101_tool_event_test_model_set_allocation_failure_errno(0);
    p101_tool_event_test_model_fail_allocation_after(0U);
    EXPECT(p101_tool_model_create(err) == NULL);
    EXPECT(p101_error_is_errno(err, ENOMEM));
    p101_error_reset(err);

    model  = p101_tool_model_create(err);
    record = base_record(P101_TOOL_EVENT_RECORD_EXEC_FAIL, 50U);
    p101_tool_event_test_model_fail_allocation_after(0U);
    EXPECT(p101_tool_model_ingest(err, model, &record) == -1);
    EXPECT(p101_error_is_errno(err, ENOMEM));
    p101_error_reset(err);
    p101_tool_model_destroy(&model);

    model = p101_tool_model_create(err);
    p101_tool_event_test_model_fail_allocation_after(1U);
    EXPECT(p101_tool_model_ingest(err, model, &record) == -1);
    EXPECT(p101_error_is_errno(err, ENOMEM));
    p101_error_reset(err);
    p101_tool_model_destroy(&model);

    model = p101_tool_model_create(err);
    EXPECT(p101_tool_model_ingest(err, model, &record) == 0);
    p101_tool_event_test_model_fail_allocation_after(0U);
    EXPECT(p101_tool_model_finish(err, model) == -1);
    EXPECT(p101_error_is_errno(err, ENOMEM));
    p101_error_reset(err);
    p101_tool_model_destroy(&model);

    model = p101_tool_model_create(err);
    ingest_call(err, model, 1U, P101_TOOL_EVENT_CALL_ENTER);
    ingest_call(err, model, 2U, P101_TOOL_EVENT_CALL_EXIT);
    p101_tool_event_test_model_fail_allocation_after(1U);
    EXPECT(p101_tool_model_finish(err, model) == -1);
    EXPECT(p101_error_is_errno(err, ENOMEM));
    p101_error_reset(err);
    p101_tool_model_destroy(&model);
    p101_tool_event_test_model_set_allocation_failure_errno(ENOMEM);

    for(size_t successful_allocations = 0U; successful_allocations <= 12U; successful_allocations++)
    {
        model = p101_tool_model_create(err);
        EXPECT(model != NULL);
        record                = base_record(P101_TOOL_EVENT_RECORD_RESOURCE, successful_allocations + 10U);
        record.resource_kind  = P101_TOOL_EVENT_RESOURCE_ACQUIRE;
        record.function_name  = "function";
        record.file_name      = "file";
        record.call_name      = "call";
        record.arguments      = "arguments";
        record.result         = "result";
        record.ptr            = "ptr";
        record.new_ptr        = "new-ptr";
        record.target         = "target";
        record.resource_class = "class";
        record.resource_id    = "id";
        record.related_id     = "related";
        record.metadata       = "metadata";
        p101_tool_event_test_model_fail_allocation_after(successful_allocations);
        EXPECT(p101_tool_model_ingest(err, model, &record) == -1);
        EXPECT(p101_error_is_errno(err, ENOMEM));
        p101_error_reset(err);
        p101_tool_model_destroy(&model);
    }

    p101_error_destroy(err);
}

static void test_lifetime_uses_earliest_observed_sequence(void)
{
    struct p101_error      *err;
    struct p101_tool_model *model;
    size_t                  lifetime_edges;

    err   = p101_error_create(false);
    model = p101_tool_model_create(err);
    ingest_fd(err, model, 1U, P101_TOOL_EVENT_FD_OPEN);
    ingest_fd(err, model, 4U, P101_TOOL_EVENT_FD_CLOSE);
    ingest_fd(err, model, 3U, P101_TOOL_EVENT_FD_CLOSE);
    EXPECT(p101_tool_model_finish(err, model) == 0);
    lifetime_edges = 0U;
    for(size_t index = 0U; index < p101_tool_model_edge_count(model); index++)
    {
        const struct p101_tool_model_edge *edge;

        edge = p101_tool_model_edge_at(model, index);
        if(edge->kind == P101_TOOL_MODEL_EDGE_RESOURCE_LIFETIME)
        {
            EXPECT(edge->from == 0U);
            EXPECT(edge->to == 2U);
            lifetime_edges++;
        }
    }
    EXPECT(lifetime_edges == 1U);
    p101_tool_model_destroy(&model);
    p101_error_destroy(err);
}

static void expect_first_edge_allocation_failure(struct p101_error *err, struct p101_tool_model *model)
{
    p101_tool_event_test_model_fail_allocation_after(1U);
    EXPECT(p101_tool_model_finish(err, model) == -1);
    EXPECT(p101_error_is_errno(err, ENOMEM));
    p101_error_reset(err);
    p101_tool_model_destroy(&model);
}

static void test_model_edge_allocation_failures(void)
{
    struct p101_error            *err;
    struct p101_tool_model       *model;
    struct p101_tool_event_record record;

    err = p101_error_create(false);

    model = p101_tool_model_create(err);
    ingest_call(err, model, 1U, P101_TOOL_EVENT_CALL_ENTER);
    ingest_call(err, model, 2U, P101_TOOL_EVENT_CALL_ENTER);
    expect_first_edge_allocation_failure(err, model);

    model = p101_tool_model_create(err);
    ingest_call(err, model, 1U, P101_TOOL_EVENT_CALL_ENTER);
    ingest_fd(err, model, 2U, P101_TOOL_EVENT_FD_OPEN);
    expect_first_edge_allocation_failure(err, model);

    model = p101_tool_model_create(err);
    ingest_fd(err, model, 1U, P101_TOOL_EVENT_FD_OPEN);
    ingest_fd(err, model, 2U, P101_TOOL_EVENT_FD_CLOSE);
    expect_first_edge_allocation_failure(err, model);

    model            = p101_tool_model_create(err);
    record           = base_record(P101_TOOL_EVENT_RECORD_FORK, 1U);
    record.child_pid = 99;
    ingest_record(err, model, &record);
    record     = base_record(P101_TOOL_EVENT_RECORD_EXEC_FAIL, 2U);
    record.pid = 99;
    ingest_record(err, model, &record);
    expect_first_edge_allocation_failure(err, model);

    p101_error_destroy(err);
}

static void test_model_branch_shapes(void)
{
    static char *const            null_pointers[] = {"", "-", "0", "0x0", "(nil)", "NULL"};
    struct p101_error            *err;
    struct p101_tool_model       *model;
    struct p101_tool_event_record record;
    size_t                        sequence;

    err   = p101_error_create(false);
    model = p101_tool_model_create(err);

    /* Grow the edge store, not merely the node store. */
    for(sequence = 1U; sequence <= 40U; sequence++)
    {
        record           = base_record(P101_TOOL_EVENT_RECORD_CALL, sequence);
        record.call_kind = P101_TOOL_EVENT_CALL_ENTER;
        record.call_name = "nested";
        record.arguments = "";
        record.result    = "";
        ingest_record(err, model, &record);
    }
    EXPECT(p101_tool_model_finish(err, model) == 0);
    EXPECT(p101_tool_model_edge_count(model) == 39U);
    p101_tool_model_destroy(&model);

    model            = p101_tool_model_create(err);
    record           = base_record(P101_TOOL_EVENT_RECORD_CALL, 10U);
    record.call_kind = P101_TOOL_EVENT_CALL_ENTER;
    record.call_name = "outer";
    record.arguments = "";
    record.result    = "";
    ingest_record(err, model, &record);
    record           = base_record(P101_TOOL_EVENT_RECORD_CALL, 30U);
    record.call_kind = P101_TOOL_EVENT_CALL_ENTER;
    record.call_name = "future";
    ingest_record(err, model, &record);
    record         = base_record(P101_TOOL_EVENT_RECORD_FD, 20U);
    record.fd_kind = P101_TOOL_EVENT_FD_OPEN;
    record.fd      = 3;
    ingest_record(err, model, &record);
    record           = base_record(P101_TOOL_EVENT_RECORD_CALL, 21U);
    record.call_kind = P101_TOOL_EVENT_CALL_EXIT;
    record.call_name = "not-an-enter";
    record.result    = "0";
    ingest_record(err, model, &record);
    record         = base_record(P101_TOOL_EVENT_RECORD_FD, 22U);
    record.fd_kind = P101_TOOL_EVENT_FD_CLOSE;
    record.fd      = 4;
    ingest_record(err, model, &record);
    record.sequence = 23U;
    record.fd       = 3;
    ingest_record(err, model, &record);
    record.sequence = 24U;
    ingest_record(err, model, &record);
    record.sequence = 25U;
    record.fd_kind  = P101_TOOL_EVENT_FD_OPEN;
    record.fd       = 9;
    ingest_record(err, model, &record);

    record                = base_record(P101_TOOL_EVENT_RECORD_RESOURCE, 26U);
    record.resource_kind  = P101_TOOL_EVENT_RESOURCE_ACQUIRE;
    record.resource_class = "mutex";
    record.resource_id    = "one";
    record.related_id     = "";
    record.metadata       = "";
    ingest_record(err, model, &record);
    record.resource_kind  = P101_TOOL_EVENT_RESOURCE_RELEASE;
    record.sequence       = 27U;
    record.resource_class = "condition";
    ingest_record(err, model, &record);
    record.sequence       = 28U;
    record.resource_class = "mutex";
    ingest_record(err, model, &record);

    sequence = 40U;
    for(size_t index = 0U; index < sizeof(null_pointers) / sizeof(null_pointers[0]); index++)
    {
        record            = base_record(P101_TOOL_EVENT_RECORD_ALLOC, sequence++);
        record.alloc_kind = P101_TOOL_EVENT_ALLOC_REALLOC;
        record.ptr        = "old";
        record.new_ptr    = null_pointers[index];
        ingest_record(err, model, &record);
    }
    record            = base_record(P101_TOOL_EVENT_RECORD_ALLOC, sequence);
    record.alloc_kind = P101_TOOL_EVENT_ALLOC_REALLOC;
    record.ptr        = "old";
    record.new_ptr    = "0x123";
    ingest_record(err, model, &record);

    EXPECT(p101_tool_model_finish(err, model) == 0);
    p101_tool_model_destroy(&model);

    /* Exercise unsuccessful matching after a call was already consumed and
     * after a same-name call from a different context. */
    model            = p101_tool_model_create(err);
    record           = base_record(P101_TOOL_EVENT_RECORD_CALL, 1U);
    record.call_kind = P101_TOOL_EVENT_CALL_ENTER;
    record.call_name = "matched";
    record.arguments = "";
    record.result    = "";
    ingest_record(err, model, &record);
    record.call_kind = P101_TOOL_EVENT_CALL_EXIT;
    record.sequence  = 2U;
    ingest_record(err, model, &record);
    record.sequence = 3U;
    ingest_record(err, model, &record);
    record.call_kind  = P101_TOOL_EVENT_CALL_ENTER;
    record.sequence   = 4U;
    record.context_id = 99U;
    ingest_record(err, model, &record);
    record.call_kind  = P101_TOOL_EVENT_CALL_EXIT;
    record.sequence   = 5U;
    record.context_id = 7U;
    ingest_record(err, model, &record);
    EXPECT(p101_tool_model_finish(err, model) == 0);
    p101_tool_model_destroy(&model);

    /* Ingestion order and event sequence are separate. The innermost
     * enclosing call is selected by sequence, not array position. */
    model            = p101_tool_model_create(err);
    record           = base_record(P101_TOOL_EVENT_RECORD_CALL, 20U);
    record.call_kind = P101_TOOL_EVENT_CALL_ENTER;
    record.call_name = "later";
    record.arguments = "";
    record.result    = "";
    ingest_record(err, model, &record);
    record.sequence  = 10U;
    record.call_name = "earlier";
    ingest_record(err, model, &record);
    record        = base_record(P101_TOOL_EVENT_RECORD_EXEC_FAIL, 30U);
    record.target = "child";
    ingest_record(err, model, &record);
    EXPECT(p101_tool_model_finish(err, model) == 0);
    p101_tool_model_destroy(&model);
    p101_error_destroy(err);
}

int main(void)
{
    test_model_graph_and_json();
    test_invalid_operations();
    test_all_event_kinds_and_growth();
    test_empty_complete_and_capacity_growth();
    test_model_allocation_and_output_failures();
    test_lifetime_uses_earliest_observed_sequence();
    test_model_edge_allocation_failures();
    test_model_branch_shapes();
    return failures == 0 ? 0 : 1;
}
