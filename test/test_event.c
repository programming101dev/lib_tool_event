#include <errno.h>
#include <p101_error/error.h>
#include <p101_tool_event/event.h>
#include <p101_tool_event/lifecycle.h>
#include <p101_tool_event/ownership.h>
#include <p101_tool_event/receipt.h>
#include <p101_tool_event/summary.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures;

enum
{
    WRITE_THREAD_COUNT    = 4,
    WRITES_PER_THREAD     = 250,
    EXPECTED_THREAD_LINES = WRITE_THREAD_COUNT * WRITES_PER_THREAD
};

struct write_thread
{
    FILE *stream;
    int   failed;
};

#define EXPECT(condition)                                                                                                                                                                                                                                          \
    do                                                                                                                                                                                                                                                             \
    {                                                                                                                                                                                                                                                              \
        if(!(condition))                                                                                                                                                                                                                                           \
        {                                                                                                                                                                                                                                                          \
            failures++;                                                                                                                                                                                                                                            \
        }                                                                                                                                                                                                                                                          \
    } while(0)

static void test_v4_call(void)
{
    char                          line[] = "P101CALL\t4\t42\t7\t9\t100\t200\tENTER\t12\tmain\topen\tpath=x\t-\tmain.c\n";
    struct p101_tool_event_record record;

    EXPECT(p101_tool_event_parse_line(line, &record) == P101_TOOL_EVENT_PARSE_OK);
    EXPECT(record.record_kind == P101_TOOL_EVENT_RECORD_CALL);
    EXPECT(record.pid == 42);
    EXPECT(record.context_id == 7U);
    EXPECT(record.sequence == 9U);
    EXPECT(strcmp(record.call_name, "open") == 0);
}

static void test_old_version_is_rejected(void)
{
    char                          line[] = "P101FD\t2\t42\t9\t100\t200\tOPEN\t3\t12\tmain\tmain.c\n";
    struct p101_tool_event_record record;

    EXPECT(p101_tool_event_parse_line(line, &record) == P101_TOOL_EVENT_PARSE_BAD_VERSION);
}

static void test_generic_lifecycle(void)
{
    char                                    acquire[] = "P101RESOURCE\t4\t42\t7\t1\t100\t200\tACQUIRE\tmmap\t0x1000\t-\t4096\tprivate\t12\tmain\tmain.c\n";
    char                                    release[] = "P101RESOURCE\t4\t42\t7\t2\t110\t210\tRELEASE\tmmap\t0x1000\t-\t0\t-\t13\tmain\tmain.c\n";
    struct p101_tool_event_record           record;
    struct p101_error                      *err;
    struct p101_tool_event_lifecycle_model *model;

    err   = p101_error_create(false);
    model = p101_tool_event_lifecycle_create(err);
    EXPECT(model != NULL);
    EXPECT(p101_tool_event_parse_line(acquire, &record) == P101_TOOL_EVENT_PARSE_OK);
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == 0);
    EXPECT(p101_tool_event_parse_line(release, &record) == P101_TOOL_EVENT_PARSE_OK);
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == 0);
    EXPECT(p101_tool_event_lifecycle_entry_count(model) == 1U);
    EXPECT(!p101_tool_event_lifecycle_entry_at(model, 0U)->live);
    EXPECT(strcmp(p101_tool_event_lifecycle_entry_at(model, 0U)->acquired_file_name, "main.c") == 0);
    EXPECT(strcmp(p101_tool_event_lifecycle_entry_at(model, 0U)->released_function_name, "main") == 0);
    EXPECT(p101_tool_event_lifecycle_entry_at(model, 0U)->released_line_number == 13);
    EXPECT(p101_tool_event_lifecycle_finding_count(model) == 0U);
    p101_tool_event_lifecycle_destroy(&model);
    p101_error_destroy(err);
}

static void test_lifecycle_bad_replace_has_source(void)
{
    char                                            acquire[] = "P101RESOURCE\t4\t42\t7\t1\t100\t200\tACQUIRE\tmapping\t0x1000\t-\t4096\t-\t12\tmap_file\tmain.c\n";
    char                                            replace[] = "P101RESOURCE\t4\t42\t7\t2\t110\t210\tREPLACE\tmapping\t0x1000\t-\t8192\t-\t20\tgrow_map\tresize.c\n";
    struct p101_tool_event_record                   record;
    struct p101_error                              *err;
    struct p101_tool_event_lifecycle_model         *model;
    const struct p101_tool_event_lifecycle_finding *finding;

    err   = p101_error_create(false);
    model = p101_tool_event_lifecycle_create(err);
    EXPECT(model != NULL);
    EXPECT(p101_tool_event_parse_line(acquire, &record) == P101_TOOL_EVENT_PARSE_OK);
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == 0);
    EXPECT(p101_tool_event_parse_line(replace, &record) == P101_TOOL_EVENT_PARSE_OK);
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == 0);
    EXPECT(p101_tool_event_lifecycle_finding_count(model) == 1U);
    finding = p101_tool_event_lifecycle_finding_at(model, 0U);
    EXPECT(finding != NULL);
    EXPECT(finding->kind == P101_TOOL_EVENT_LIFECYCLE_FINDING_BAD_REPLACE);
    EXPECT(strcmp(finding->file_name, "resize.c") == 0);
    EXPECT(strcmp(finding->function_name, "grow_map") == 0);
    EXPECT(finding->line_number == 20);
    EXPECT(p101_tool_event_lifecycle_entry_at(model, 0U)->live);
    p101_tool_event_lifecycle_destroy(&model);
    p101_error_destroy(err);
}

static void test_lifecycle_duplicate_acquire(void)
{
    char                                            first[]  = "P101RESOURCE\t4\t42\t7\t1\t100\t200\tACQUIRE\tmapping\t0x1000\t-\t4096\t-\t12\tmap_file\tmain.c\n";
    char                                            second[] = "P101RESOURCE\t4\t42\t8\t2\t110\t210\tACQUIRE\tmapping\t0x1000\t-\t8192\t-\t20\tmap_again\tother.c\n";
    struct p101_tool_event_record                   record;
    struct p101_error                              *err;
    struct p101_tool_event_lifecycle_model         *model;
    const struct p101_tool_event_lifecycle_finding *finding;

    err   = p101_error_create(false);
    model = p101_tool_event_lifecycle_create(err);
    EXPECT(model != NULL);
    EXPECT(p101_tool_event_parse_line(first, &record) == P101_TOOL_EVENT_PARSE_OK);
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == 0);
    EXPECT(p101_tool_event_parse_line(second, &record) == P101_TOOL_EVENT_PARSE_OK);
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == 0);
    EXPECT(p101_tool_event_lifecycle_entry_count(model) == 2U);
    EXPECT(p101_tool_event_lifecycle_finding_count(model) == 1U);
    finding = p101_tool_event_lifecycle_finding_at(model, 0U);
    EXPECT(finding != NULL);
    EXPECT(finding->kind == P101_TOOL_EVENT_LIFECYCLE_FINDING_DUPLICATE_ACQUIRE);
    EXPECT(finding->previous_sequence == 1U);
    EXPECT(finding->sequence == 2U);
    p101_tool_event_lifecycle_destroy(&model);
    p101_error_destroy(err);
}

static void test_lifecycle_leak_has_no_duplicate_previous_evidence(void)
{
    char                                            acquire[] = "P101RESOURCE\t4\t42\t7\t1\t100\t200\tACQUIRE\tmapping\t0x1000\t-\t4096\t-\t12\tmap_file\tmain.c\n";
    struct p101_tool_event_record                   record;
    struct p101_error                              *err;
    struct p101_tool_event_lifecycle_model         *model;
    const struct p101_tool_event_lifecycle_finding *finding;

    err   = p101_error_create(false);
    model = p101_tool_event_lifecycle_create(err);
    EXPECT(model != NULL);
    EXPECT(p101_tool_event_parse_line(acquire, &record) == P101_TOOL_EVENT_PARSE_OK);
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == 0);
    EXPECT(p101_tool_event_lifecycle_finish(err, model) == 0);
    EXPECT(p101_tool_event_lifecycle_finding_count(model) == 1U);
    finding = p101_tool_event_lifecycle_finding_at(model, 0U);
    EXPECT(finding != NULL);
    EXPECT(finding->kind == P101_TOOL_EVENT_LIFECYCLE_FINDING_LEAK);
    EXPECT(finding->previous_sequence == 0U);
    EXPECT(finding->previous_file_name == NULL);
    EXPECT(strcmp(finding->file_name, "main.c") == 0);
    p101_tool_event_lifecycle_destroy(&model);
    p101_error_destroy(err);
}

static void test_lifecycle_normalizes_fd_and_allocation_records(void)
{
    struct p101_error                      *err;
    struct p101_tool_event_lifecycle_model *model;
    struct p101_tool_event_record           record;

    err   = p101_error_create(false);
    model = p101_tool_event_lifecycle_create(err);
    memset(&record, 0, sizeof(record));
    record.record_kind   = P101_TOOL_EVENT_RECORD_FD;
    record.fd_kind       = P101_TOOL_EVENT_FD_OPEN;
    record.pid           = 42;
    record.fd            = 7;
    record.sequence      = 1U;
    record.function_name = "open_it";
    record.file_name     = "main.c";
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == 0);
    record.fd_kind  = P101_TOOL_EVENT_FD_CLOSE;
    record.sequence = 2U;
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == 0);

    record.record_kind = P101_TOOL_EVENT_RECORD_ALLOC;
    record.alloc_kind  = P101_TOOL_EVENT_ALLOC_ALLOC;
    record.ptr         = "0x100";
    record.size        = 64U;
    record.sequence    = 3U;
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == 0);
    record.alloc_kind = P101_TOOL_EVENT_ALLOC_REALLOC;
    record.new_ptr    = "0x200";
    record.size       = 128U;
    record.sequence   = 4U;
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == 0);
    record.alloc_kind = P101_TOOL_EVENT_ALLOC_FREE;
    record.ptr        = "0x200";
    record.new_ptr    = NULL;
    record.sequence   = 5U;
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == 0);
    EXPECT(p101_tool_event_lifecycle_finish(err, model) == 0);
    EXPECT(p101_tool_event_lifecycle_finding_count(model) == 0U);
    EXPECT(p101_tool_event_lifecycle_entry_count(model) == 3U);
    p101_tool_event_lifecycle_destroy(&model);
    p101_error_destroy(err);
}

static void test_lifecycle_applies_and_rolls_back_cloexec(void)
{
    struct p101_error                      *err;
    struct p101_tool_event_lifecycle_model *model;
    struct p101_tool_event_record           record;

    err   = p101_error_create(false);
    model = p101_tool_event_lifecycle_create(err);
    memset(&record, 0, sizeof(record));
    record.record_kind   = P101_TOOL_EVENT_RECORD_FD;
    record.fd_kind       = P101_TOOL_EVENT_FD_OPEN;
    record.pid           = 42;
    record.fd            = 7;
    record.sequence      = 1U;
    record.function_name = "open_it";
    record.file_name     = "main.c";
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == 0);

    record.record_kind   = P101_TOOL_EVENT_RECORD_EXEC;
    record.cloexec       = 1;
    record.sequence      = 2U;
    record.function_name = "exec_it";
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == 0);
    EXPECT(!p101_tool_event_lifecycle_entry_at(model, 0U)->live);

    record.record_kind = P101_TOOL_EVENT_RECORD_EXEC_FAIL;
    record.sequence    = 3U;
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == 0);
    EXPECT(p101_tool_event_lifecycle_entry_at(model, 0U)->live);

    record.record_kind = P101_TOOL_EVENT_RECORD_EXEC;
    record.sequence    = 4U;
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == 0);
    EXPECT(p101_tool_event_lifecycle_finish(err, model) == 0);
    EXPECT(p101_tool_event_lifecycle_finding_count(model) == 0U);
    p101_tool_event_lifecycle_destroy(&model);
    p101_error_destroy(err);
}

static void test_lifecycle_clones_descriptors_at_fork(void)
{
    struct p101_error                      *err;
    struct p101_tool_event_lifecycle_model *model;
    struct p101_tool_event_record           record;

    err   = p101_error_create(false);
    model = p101_tool_event_lifecycle_create(err);
    memset(&record, 0, sizeof(record));
    record.record_kind   = P101_TOOL_EVENT_RECORD_FD;
    record.fd_kind       = P101_TOOL_EVENT_FD_OPEN;
    record.pid           = 42;
    record.context_id    = 7U;
    record.fd            = 9;
    record.sequence      = 1U;
    record.function_name = "open_it";
    record.file_name     = "main.c";
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == 0);

    record.record_kind   = P101_TOOL_EVENT_RECORD_FORK;
    record.child_pid     = 43;
    record.sequence      = 2U;
    record.function_name = "fork_it";
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == 0);
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == 0);
    EXPECT(p101_tool_event_lifecycle_entry_count(model) == 2U);

    record.record_kind = P101_TOOL_EVENT_RECORD_FD;
    record.fd_kind     = P101_TOOL_EVENT_FD_CLOSE;
    record.pid         = 43;
    record.sequence    = 3U;
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == 0);
    record.pid      = 42;
    record.sequence = 4U;
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == 0);
    EXPECT(p101_tool_event_lifecycle_finish(err, model) == 0);
    EXPECT(p101_tool_event_lifecycle_finding_count(model) == 0U);
    p101_tool_event_lifecycle_destroy(&model);
    p101_error_destroy(err);
}

static void test_shared_ownership_semantics(void)
{
    EXPECT(p101_tool_event_ownership_classify_release(P101_TOOL_EVENT_OWNERSHIP_LIVE) == P101_TOOL_EVENT_OWNERSHIP_RELEASE_OK);
    EXPECT(p101_tool_event_ownership_classify_release(P101_TOOL_EVENT_OWNERSHIP_NEVER) == P101_TOOL_EVENT_OWNERSHIP_RELEASE_STRAY);
    EXPECT(p101_tool_event_ownership_classify_release(P101_TOOL_EVENT_OWNERSHIP_RELEASED) == P101_TOOL_EVENT_OWNERSHIP_RELEASE_DUPLICATE);
    EXPECT(p101_tool_event_ownership_classify_replace(true, P101_TOOL_EVENT_OWNERSHIP_NEVER) == P101_TOOL_EVENT_OWNERSHIP_REPLACE_NEW);
    EXPECT(p101_tool_event_ownership_classify_replace(false, P101_TOOL_EVENT_OWNERSHIP_LIVE) == P101_TOOL_EVENT_OWNERSHIP_REPLACE_OK);
    EXPECT(p101_tool_event_ownership_classify_replace(false, P101_TOOL_EVENT_OWNERSHIP_RELEASED) == P101_TOOL_EVENT_OWNERSHIP_REPLACE_BAD);
    EXPECT(p101_tool_event_ownership_exec_inherits(P101_TOOL_EVENT_OWNERSHIP_LIVE, false));
    EXPECT(!p101_tool_event_ownership_exec_inherits(P101_TOOL_EVENT_OWNERSHIP_LIVE, true));
    EXPECT(!p101_tool_event_ownership_exec_inherits(P101_TOOL_EVENT_OWNERSHIP_RELEASED, false));
}

static void test_shared_resource_summary_parser(void)
{
    static const char                       json[] = "{\"schema\":\"p101-resource-tracker-findings-v3\",\"records\":9,\"fd_leaks\":1,\"allocation_leaks\":2,\"bad_releases\":3,\"exec_inheritances\":4,\"generic_resource_leaks\":5,\"generic_bad_releases\":6,"
                                                     "\"malformed\":0,\"bad_version\":0,\"refused\":0,\"log_health\":{\"complete\":true,\"producers\":1},\"findings\":[]}";
    struct p101_tool_event_resource_summary summary;

    EXPECT(p101_tool_event_parse_resource_summary_json(json, &summary));
    EXPECT(summary.records == 9U);
    EXPECT(summary.generic_resource_leaks == 5U);
    EXPECT(summary.log_complete);
    EXPECT(p101_tool_event_resource_summary_finding_count(&summary) == 21U);
    EXPECT(!p101_tool_event_parse_resource_summary_json("{\"records\":1}", &summary));
    EXPECT(!p101_tool_event_parse_resource_summary_json("prefix \"records\":1 \"fd_leaks\":0 \"allocation_leaks\":0 \"bad_releases\":0", &summary));
}

static void test_lifecycle_cross_context_release(void)
{
    char                                    acquire[] = "P101RESOURCE\t4\t42\t7\t1\t100\t200\tACQUIRE\tlock\tshared\t-\t0\t-\t12\tmain\tmain.c\n";
    char                                    release[] = "P101RESOURCE\t4\t42\t8\t2\t110\t210\tRELEASE\tlock\tshared\t-\t0\t-\t13\tworker\tworker.c\n";
    struct p101_tool_event_record           record;
    struct p101_error                      *err;
    struct p101_tool_event_lifecycle_model *model;

    err   = p101_error_create(false);
    model = p101_tool_event_lifecycle_create(err);
    EXPECT(model != NULL);
    EXPECT(p101_tool_event_parse_line(acquire, &record) == P101_TOOL_EVENT_PARSE_OK);
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == 0);
    EXPECT(p101_tool_event_parse_line(release, &record) == P101_TOOL_EVENT_PARSE_OK);
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == 0);
    EXPECT(!p101_tool_event_lifecycle_entry_at(model, 0U)->live);
    EXPECT(p101_tool_event_lifecycle_entry_at(model, 0U)->acquired_context_id == 7U);
    EXPECT(p101_tool_event_lifecycle_entry_at(model, 0U)->released_context_id == 8U);
    EXPECT(p101_tool_event_lifecycle_finding_count(model) == 0U);
    p101_tool_event_lifecycle_destroy(&model);
    p101_error_destroy(err);
}

static void test_lifecycle_finding_owns_text(void)
{
    char                                    release[] = "P101RESOURCE\t4\t42\t8\t2\t110\t210\tRELEASE\tlock\tshared\t-\t0\t-\t13\tworker\tworker.c\n";
    struct p101_tool_event_record           record;
    struct p101_error                      *err;
    struct p101_tool_event_lifecycle_model *model;

    err   = p101_error_create(false);
    model = p101_tool_event_lifecycle_create(err);
    EXPECT(model != NULL);
    EXPECT(p101_tool_event_parse_line(release, &record) == P101_TOOL_EVENT_PARSE_OK);
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == 0);
    EXPECT(p101_tool_event_lifecycle_finding_count(model) == 1U);
    memset(release, 'x', sizeof(release) - 1U);
    EXPECT(strcmp(p101_tool_event_lifecycle_finding_at(model, 0U)->resource_class, "lock") == 0);
    EXPECT(strcmp(p101_tool_event_lifecycle_finding_at(model, 0U)->resource_id, "shared") == 0);
    p101_tool_event_lifecycle_destroy(&model);
    p101_error_destroy(err);
}

static void test_write_round_trip(void)
{
    char                          line[P101_TOOL_EVENT_LINE_MAX_BYTES];
    struct p101_tool_event_record record;
    struct p101_tool_event_output written;
    FILE                         *stream;

    stream = tmpfile();
    EXPECT(stream != NULL);
    if(stream == NULL)
    {
        return;
    }

    memset(&written, 0, sizeof(written));
    written.version                = P101_TOOL_EVENT_LOG_VERSION;
    written.record_kind            = P101_TOOL_EVENT_RECORD_RESOURCE;
    written.resource_kind          = P101_TOOL_EVENT_RESOURCE_ACQUIRE;
    written.pid                    = 99;
    written.context_id             = 7U;
    written.sequence               = 3U;
    written.monotonic_ns           = 100U;
    written.wall_unix_ns           = 200U;
    written.monotonic_ns_available = 1;
    written.wall_unix_ns_available = 1;
    written.resource_class         = "mapping";
    written.resource_id            = "0x1";
    written.related_id             = "-";
    written.size                   = 4096U;
    written.metadata               = "read\\twrite";
    written.line_number            = 42;
    written.function_name          = "map_file";
    written.file_name              = "demo.c";

    errno = EDOM;
    EXPECT(p101_tool_event_write(stream, &written) == 0);
    EXPECT(errno == EDOM);
    rewind(stream);
    EXPECT(fgets(line, sizeof(line), stream) != NULL);
    EXPECT(p101_tool_event_parse_line(line, &record) == P101_TOOL_EVENT_PARSE_OK);
    EXPECT(record.version == P101_TOOL_EVENT_LOG_VERSION);
    EXPECT(record.context_id == 7U);
    EXPECT(strcmp(record.metadata, "read\\twrite") == 0);
    EXPECT(record.related_id != NULL);
    EXPECT(strcmp(record.related_id, "-") == 0);
    fclose(stream);
}

static void test_completion_round_trip(void)
{
    char                          line[P101_TOOL_EVENT_LINE_MAX_BYTES];
    struct p101_tool_event_output written;
    struct p101_tool_event_record record;
    FILE                         *stream;

    stream = tmpfile();
    EXPECT(stream != NULL);
    if(stream == NULL)
    {
        return;
    }

    memset(&written, 0, sizeof(written));
    written.version          = P101_TOOL_EVENT_LOG_VERSION;
    written.record_kind      = P101_TOOL_EVENT_RECORD_COMPLETE;
    written.pid              = 99;
    written.context_id       = 7U;
    written.sequence         = 4U;
    written.events_attempted = 3U;
    written.write_failed     = 1;
    written.write_errno      = ENOSPC;

    EXPECT(p101_tool_event_write(stream, &written) == 0);
    rewind(stream);
    EXPECT(fgets(line, sizeof(line), stream) != NULL);
    EXPECT(p101_tool_event_parse_line(line, &record) == P101_TOOL_EVENT_PARSE_OK);
    EXPECT(record.record_kind == P101_TOOL_EVENT_RECORD_COMPLETE);
    EXPECT(record.events_attempted == 3U);
    EXPECT(record.write_failed == 1);
    EXPECT(record.write_errno == ENOSPC);
    {
        struct p101_tool_event_stream_health health = {0};

        EXPECT(p101_tool_event_stream_health_observe(&health, &record) == 0);
        EXPECT(health.completion_records == 1U);
        EXPECT(health.producer_write_failures == 1U);
        EXPECT(health.last_write_errno == ENOSPC);
        EXPECT(!p101_tool_event_stream_health_is_complete(&health));

        p101_tool_event_stream_health_destroy(&health);
        EXPECT(!p101_tool_event_stream_health_is_complete(&health));
        record.version     = P101_TOOL_EVENT_LOG_VERSION;
        record.record_kind = P101_TOOL_EVENT_RECORD_FD;
        EXPECT(p101_tool_event_stream_health_observe(&health, &record) == 0);
        EXPECT(!p101_tool_event_stream_health_is_complete(&health));

        p101_tool_event_stream_health_destroy(&health);
        record.version          = P101_TOOL_EVENT_LOG_VERSION;
        record.record_kind      = P101_TOOL_EVENT_RECORD_COMPLETE;
        record.write_failed     = 0;
        record.write_errno      = 0;
        record.events_attempted = 0U;
        EXPECT(p101_tool_event_stream_health_observe(&health, &record) == 0);
        EXPECT(p101_tool_event_stream_health_is_complete(&health));
        p101_tool_event_stream_health_destroy(&health);
    }
    {
        struct p101_tool_event_stream_health health = {0};

        memset(&record, 0, sizeof(record));
        record.version     = P101_TOOL_EVENT_LOG_VERSION;
        record.record_kind = P101_TOOL_EVENT_RECORD_FD;
        record.pid         = 100;
        record.context_id  = 1U;
        record.sequence    = 1U;
        EXPECT(p101_tool_event_stream_health_observe(&health, &record) == 0);
        record.record_kind      = P101_TOOL_EVENT_RECORD_COMPLETE;
        record.sequence         = 2U;
        record.events_attempted = 1U;
        EXPECT(p101_tool_event_stream_health_observe(&health, &record) == 0);

        record.record_kind = P101_TOOL_EVENT_RECORD_FD;
        record.pid         = 101;
        record.context_id  = 2U;
        record.sequence    = 1U;
        EXPECT(p101_tool_event_stream_health_observe(&health, &record) == 0);
        EXPECT(health.producer_count == 2U);
        EXPECT(p101_tool_event_stream_health_incomplete_producers(&health) == 1U);
        EXPECT(!p101_tool_event_stream_health_is_complete(&health));

        record.record_kind      = P101_TOOL_EVENT_RECORD_COMPLETE;
        record.sequence         = 2U;
        record.events_attempted = 1U;
        EXPECT(p101_tool_event_stream_health_observe(&health, &record) == 0);
        EXPECT(p101_tool_event_stream_health_incomplete_producers(&health) == 0U);
        EXPECT(p101_tool_event_stream_health_is_complete(&health));

        record.record_kind = P101_TOOL_EVENT_RECORD_FD;
        record.sequence    = 3U;
        EXPECT(p101_tool_event_stream_health_observe(&health, &record) == 0);
        EXPECT(health.records_after_completion == 1U);
        EXPECT(!p101_tool_event_stream_health_is_complete(&health));
        p101_tool_event_stream_health_destroy(&health);
    }
    {
        struct p101_tool_event_stream_health health = {0};

        memset(&record, 0, sizeof(record));
        record.version     = P101_TOOL_EVENT_LOG_VERSION;
        record.record_kind = P101_TOOL_EVENT_RECORD_FD;
        record.pid         = 102;
        record.context_id  = 3U;
        record.sequence    = 2U;
        EXPECT(p101_tool_event_stream_health_observe(&health, &record) == 0);
        record.sequence = 1U;
        EXPECT(p101_tool_event_stream_health_observe(&health, &record) == 0);
        record.sequence = 2U;
        EXPECT(p101_tool_event_stream_health_observe(&health, &record) == 0);
        record.record_kind      = P101_TOOL_EVENT_RECORD_COMPLETE;
        record.sequence         = 3U;
        record.events_attempted = 99U;
        EXPECT(p101_tool_event_stream_health_observe(&health, &record) == 0);
        EXPECT(health.nonmonotonic_sequences == 1U);
        EXPECT(health.duplicate_sequences == 1U);
        EXPECT(health.attempted_count_mismatches == 1U);
        EXPECT(!p101_tool_event_stream_health_is_complete(&health));
        p101_tool_event_stream_health_destroy(&health);
    }
    fclose(stream);

    {
        char invalid[] = "P101COMPLETE\t4\t99\t7\t4\t-\t-\t3\t0\t28\n";

        EXPECT(p101_tool_event_parse_line(invalid, &record) == P101_TOOL_EVENT_PARSE_MALFORMED);
    }
}

static void *write_records(void *data)
{
    struct write_thread          *thread;
    struct p101_tool_event_output record;

    thread = (struct write_thread *)data;
    memset(&record, 0, sizeof(record));
    record.version                = P101_TOOL_EVENT_LOG_VERSION;
    record.record_kind            = P101_TOOL_EVENT_RECORD_RESOURCE;
    record.resource_kind          = P101_TOOL_EVENT_RESOURCE_ACQUIRE;
    record.pid                    = 99;
    record.context_id             = 7U;
    record.monotonic_ns           = 100U;
    record.wall_unix_ns           = 200U;
    record.monotonic_ns_available = 1;
    record.wall_unix_ns_available = 1;
    record.resource_class         = "thread-record";
    record.resource_id            = "shared";
    record.related_id             = "-";
    record.metadata               = "concurrency-test";
    record.line_number            = 42;
    record.function_name          = "write_records";
    record.file_name              = "test_event.c";

    for(size_t i = 0U; i < WRITES_PER_THREAD; i++)
    {
        record.sequence = i + 1U;
        if(p101_tool_event_write(thread->stream, &record) != 0)
        {
            thread->failed = 1;
            break;
        }
    }
    return NULL;
}

static void test_concurrent_writes_are_complete_records(void)
{
    char                          line[P101_TOOL_EVENT_LINE_MAX_BYTES];
    pthread_t                     threads[WRITE_THREAD_COUNT];
    struct write_thread           contexts[WRITE_THREAD_COUNT];
    struct p101_tool_event_record record;
    FILE                         *stream;
    size_t                        lines;

    stream = tmpfile();
    EXPECT(stream != NULL);
    if(stream == NULL)
    {
        return;
    }

    memset(contexts, 0, sizeof(contexts));
    for(size_t i = 0U; i < WRITE_THREAD_COUNT; i++)
    {
        contexts[i].stream = stream;
        EXPECT(pthread_create(&threads[i], NULL, write_records, &contexts[i]) == 0);
    }
    for(size_t i = 0U; i < WRITE_THREAD_COUNT; i++)
    {
        EXPECT(pthread_join(threads[i], NULL) == 0);
        EXPECT(contexts[i].failed == 0);
    }

    rewind(stream);
    lines = 0U;
    while(fgets(line, sizeof(line), stream) != NULL)
    {
        EXPECT(p101_tool_event_parse_line(line, &record) == P101_TOOL_EVENT_PARSE_OK);
        lines++;
    }
    EXPECT(lines == EXPECTED_THREAD_LINES);
    fclose(stream);
}

static void test_file_fingerprint(void)
{
    struct p101_error                 *err;
    struct p101_tool_event_fingerprint fingerprint;

    err = p101_error_create(false);
    EXPECT(p101_tool_event_fingerprint_file(err, P101_TOOL_EVENT_FINGERPRINT_FIXTURE, P101_TOOL_EVENT_RECEIPT_DEFAULT_MAX_BYTES, P101_TOOL_EVENT_RECEIPT_DEFAULT_MAX_RECORDS, &fingerprint) == 0);
    EXPECT(p101_error_has_no_error(err));
    EXPECT(fingerprint.bytes == 4U);
    EXPECT(fingerprint.records == 2U);
    EXPECT(fingerprint.final_newline != 0);
    EXPECT(fingerprint.fnv1a64 == UINT64_C(0x78ed6781f136a14e));

    EXPECT(p101_tool_event_fingerprint_file(err, P101_TOOL_EVENT_FINGERPRINT_FIXTURE, 3U, 2U, &fingerprint) == -1);
    EXPECT(p101_error_is_errno(err, EFBIG));
    p101_error_destroy(err);
}

int main(void)
{
    test_v4_call();
    test_old_version_is_rejected();
    test_generic_lifecycle();
    test_lifecycle_cross_context_release();
    test_lifecycle_finding_owns_text();
    test_lifecycle_bad_replace_has_source();
    test_lifecycle_duplicate_acquire();
    test_lifecycle_leak_has_no_duplicate_previous_evidence();
    test_lifecycle_normalizes_fd_and_allocation_records();
    test_lifecycle_applies_and_rolls_back_cloexec();
    test_lifecycle_clones_descriptors_at_fork();
    test_shared_ownership_semantics();
    test_shared_resource_summary_parser();
    test_write_round_trip();
    test_completion_round_trip();
    test_concurrent_writes_are_complete_records();
    test_file_fingerprint();
    return failures == 0 ? 0 : 1;
}
