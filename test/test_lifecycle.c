#include <errno.h>
#include <p101_error/error.h>
#include <p101_tool_event/lifecycle.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures;

extern void p101_tool_event_test_lifecycle_fail_allocation_after(size_t successful_allocations);
extern void p101_tool_event_test_lifecycle_force_format_failure(void);

#define EXPECT(condition)                                                                                                                                                                                                                                          \
    do                                                                                                                                                                                                                                                             \
    {                                                                                                                                                                                                                                                              \
        if(!(condition))                                                                                                                                                                                                                                           \
        {                                                                                                                                                                                                                                                          \
            failures++;                                                                                                                                                                                                                                            \
        }                                                                                                                                                                                                                                                          \
    } while(0)

static void initialize_resource(struct p101_tool_event_record *record, p101_tool_event_resource_kind kind, const char *resource_class, const char *resource_id)
{
    memset(record, 0, sizeof(*record));
    record->record_kind            = P101_TOOL_EVENT_RECORD_RESOURCE;
    record->resource_kind          = kind;
    record->pid                    = 1;
    record->context_id             = 2U;
    record->sequence               = 3U;
    record->monotonic_ns           = 4U;
    record->monotonic_ns_available = 1;
    record->resource_class         = (char *)resource_class;
    record->resource_id            = (char *)resource_id;
    record->size                   = 5U;
    record->line_number            = 6;
    record->function_name          = "function";
    record->file_name              = "file.c";
}

static struct p101_tool_event_lifecycle_model *new_model(struct p101_error **err)
{
    *err = p101_error_create(false);
    return p101_tool_event_lifecycle_create(*err);
}

static void test_public_boundaries(void)
{
    struct p101_error                      *err;
    struct p101_tool_event_lifecycle_model *model;
    struct p101_tool_event_record           record;

    model = new_model(&err);
    initialize_resource(&record, P101_TOOL_EVENT_RESOURCE_ACQUIRE, "class", "id");
    EXPECT(p101_tool_event_lifecycle_ingest(err, NULL, &record) == -1);
    p101_error_reset(err);
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, NULL) == -1);
    p101_error_reset(err);
    record.record_kind = P101_TOOL_EVENT_RECORD_CALL;
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == -1);
    p101_error_reset(err);
    record.record_kind = (p101_tool_event_record_kind)99;
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == -1);
    p101_error_reset(err);
    initialize_resource(&record, P101_TOOL_EVENT_RESOURCE_ACQUIRE, NULL, "id");
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == -1);
    p101_error_reset(err);
    initialize_resource(&record, P101_TOOL_EVENT_RESOURCE_ACQUIRE, "class", NULL);
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == -1);
    p101_error_reset(err);
    initialize_resource(&record, (p101_tool_event_resource_kind)99, "class", "id");
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == -1);
    p101_error_reset(err);
    EXPECT(p101_tool_event_lifecycle_finish(err, NULL) == -1);

    EXPECT(p101_tool_event_lifecycle_entry_count(NULL) == 0U);
    EXPECT(p101_tool_event_lifecycle_entry_at(NULL, 0U) == NULL);
    EXPECT(p101_tool_event_lifecycle_entry_at(model, 0U) == NULL);
    EXPECT(p101_tool_event_lifecycle_finding_count(NULL) == 0U);
    EXPECT(p101_tool_event_lifecycle_finding_at(NULL, 0U) == NULL);
    EXPECT(p101_tool_event_lifecycle_finding_at(model, 0U) == NULL);

    p101_tool_event_lifecycle_destroy(NULL);
    {
        struct p101_tool_event_lifecycle_model *null_model = NULL;

        p101_tool_event_lifecycle_destroy(&null_model);
    }
    p101_tool_event_lifecycle_destroy(&model);
    p101_error_destroy(err);
}

static void test_release_and_replace_findings(void)
{
    struct p101_error                      *err;
    struct p101_tool_event_lifecycle_model *model;
    struct p101_tool_event_record           record;

    model = new_model(&err);
    initialize_resource(&record, P101_TOOL_EVENT_RESOURCE_RELEASE, "class", "stray");
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == 0);
    EXPECT(p101_tool_event_lifecycle_finding_at(model, 0U)->kind == P101_TOOL_EVENT_LIFECYCLE_FINDING_STRAY_RELEASE);

    initialize_resource(&record, P101_TOOL_EVENT_RESOURCE_ACQUIRE, "class", "id");
    record.function_name = NULL;
    record.file_name     = NULL;
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == 0);
    record.resource_kind = P101_TOOL_EVENT_RESOURCE_RELEASE;
    record.sequence++;
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == 0);
    record.sequence++;
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == 0);
    EXPECT(p101_tool_event_lifecycle_finding_at(model, 1U)->kind == P101_TOOL_EVENT_LIFECYCLE_FINDING_DOUBLE_RELEASE);

    initialize_resource(&record, P101_TOOL_EVENT_RESOURCE_REPLACE, "class", "missing");
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == 0);
    EXPECT(p101_tool_event_lifecycle_finding_at(model, 2U)->kind == P101_TOOL_EVENT_LIFECYCLE_FINDING_BAD_REPLACE);

    initialize_resource(&record, P101_TOOL_EVENT_RESOURCE_ACQUIRE, "class", "old");
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == 0);
    record.resource_kind = P101_TOOL_EVENT_RESOURCE_REPLACE;
    record.related_id    = "new";
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == 0);
    EXPECT(!p101_tool_event_lifecycle_entry_at(model, 1U)->live);
    EXPECT(p101_tool_event_lifecycle_entry_at(model, 2U)->live);

    record.resource_kind = P101_TOOL_EVENT_RESOURCE_TRANSFER;
    record.resource_id   = "new";
    record.related_id    = "final";
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == 0);
    EXPECT(p101_tool_event_lifecycle_finish(err, model) == 0);
    EXPECT(p101_tool_event_lifecycle_finish(err, model) == 0);
    p101_tool_event_lifecycle_destroy(&model);
    p101_error_destroy(err);
}

static void ingest_allocation(struct p101_error *err, struct p101_tool_event_lifecycle_model *model, p101_tool_event_alloc_kind kind, const char *ptr, const char *new_ptr)
{
    struct p101_tool_event_record record;

    memset(&record, 0, sizeof(record));
    record.record_kind   = P101_TOOL_EVENT_RECORD_ALLOC;
    record.alloc_kind    = kind;
    record.pid           = 2;
    record.ptr           = (char *)ptr;
    record.new_ptr       = (char *)new_ptr;
    record.function_name = "allocation";
    record.file_name     = "alloc.c";
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == 0);
}

static void test_allocation_shapes(void)
{
    static const char *const                nulls[] = {NULL, "-", "(nil)", "0x0"};
    struct p101_error                      *err;
    struct p101_tool_event_lifecycle_model *model;

    model = new_model(&err);
    for(size_t index = 0U; index < sizeof(nulls) / sizeof(nulls[0]); index++)
    {
        ingest_allocation(err, model, P101_TOOL_EVENT_ALLOC_ALLOC, nulls[index], NULL);
        ingest_allocation(err, model, P101_TOOL_EVENT_ALLOC_FREE, nulls[index], NULL);
        ingest_allocation(err, model, P101_TOOL_EVENT_ALLOC_REALLOC, nulls[index], nulls[index]);
    }
    ingest_allocation(err, model, P101_TOOL_EVENT_ALLOC_REALLOC, NULL, "new-a");
    ingest_allocation(err, model, P101_TOOL_EVENT_ALLOC_REALLOC, "missing-a", NULL);
    ingest_allocation(err, model, P101_TOOL_EVENT_ALLOC_REALLOC, "missing-b", "new-b");
    ingest_allocation(err, model, P101_TOOL_EVENT_ALLOC_ALLOC, "live-a", NULL);
    ingest_allocation(err, model, P101_TOOL_EVENT_ALLOC_REALLOC, "live-a", NULL);
    ingest_allocation(err, model, P101_TOOL_EVENT_ALLOC_REALLOC, "live-a", "live-b");
    ingest_allocation(err, model, P101_TOOL_EVENT_ALLOC_FREE, "live-b", NULL);
    p101_tool_event_lifecycle_destroy(&model);
    p101_error_destroy(err);
}

static void test_fork_and_exec_edges(void)
{
    struct p101_error                      *err;
    struct p101_tool_event_lifecycle_model *model;
    struct p101_tool_event_record           record;
    char                                    long_id[64];

    model = new_model(&err);
    memset(&record, 0, sizeof(record));
    record.record_kind = P101_TOOL_EVENT_RECORD_FORK;
    record.pid         = -1;
    record.child_pid   = 2;
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == 0);
    record.pid       = 1;
    record.child_pid = -1;
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == 0);
    record.child_pid = 1;
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == 0);

    initialize_resource(&record, P101_TOOL_EVENT_RESOURCE_ACQUIRE, "not-fd", "x");
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == 0);
    initialize_resource(&record, P101_TOOL_EVENT_RESOURCE_ACQUIRE, "fd", "7");
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == 0);
    record.resource_kind = P101_TOOL_EVENT_RESOURCE_RELEASE;
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == 0);

    memset(long_id, 'x', sizeof(long_id) - 1U);
    long_id[sizeof(long_id) - 1U] = '\0';
    initialize_resource(&record, P101_TOOL_EVENT_RESOURCE_ACQUIRE, "fd", long_id);
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == 0);
    record.record_kind = P101_TOOL_EVENT_RECORD_FORK;
    record.pid         = 1;
    record.child_pid   = 2;
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == -1);
    p101_error_reset(err);

    memset(&record, 0, sizeof(record));
    record.record_kind = P101_TOOL_EVENT_RECORD_EXEC;
    record.pid         = 1;
    record.fd          = 999;
    record.cloexec     = 0;
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == 0);
    record.cloexec = 1;
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == 0);
    record.record_kind = P101_TOOL_EVENT_RECORD_EXEC_FAIL;
    record.pid         = 999;
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == 0);

    p101_tool_event_lifecycle_destroy(&model);
    p101_error_destroy(err);
}

static void test_capacity_growth(void)
{
    struct p101_error                      *err;
    struct p101_tool_event_lifecycle_model *model;
    struct p101_tool_event_record           record;
    char                                    id[32];

    model = new_model(&err);
    for(size_t index = 0U; index < 64U; index++)
    {
        (void)snprintf(id, sizeof(id), "id-%zu", index);
        initialize_resource(&record, P101_TOOL_EVENT_RESOURCE_ACQUIRE, "class", id);
        EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == 0);
    }
    (void)snprintf(id, sizeof(id), "id-overflow");
    initialize_resource(&record, P101_TOOL_EVENT_RESOURCE_ACQUIRE, "class", id);
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == -1);
    p101_error_reset(err);
    for(size_t index = 0U; index < 64U; index++)
    {
        (void)snprintf(id, sizeof(id), "missing-%zu", index);
        initialize_resource(&record, P101_TOOL_EVENT_RESOURCE_RELEASE, "class", id);
        EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == 0);
    }
    (void)snprintf(id, sizeof(id), "missing-overflow");
    initialize_resource(&record, P101_TOOL_EVENT_RESOURCE_RELEASE, "class", id);
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == -1);
    EXPECT(p101_tool_event_lifecycle_entry_count(model) == 64U);
    EXPECT(p101_tool_event_lifecycle_finding_count(model) == 64U);
    EXPECT(p101_tool_event_lifecycle_entry_at(model, 64U) == NULL);
    EXPECT(p101_tool_event_lifecycle_finding_at(model, 64U) == NULL);
    p101_tool_event_lifecycle_destroy(&model);
    p101_error_destroy(err);
}

static void test_format_failures(void)
{
    struct p101_error                      *err;
    struct p101_tool_event_lifecycle_model *model;
    struct p101_tool_event_record           record;

    model = new_model(&err);
    memset(&record, 0, sizeof(record));
    record.record_kind = P101_TOOL_EVENT_RECORD_FD;
    record.fd_kind     = P101_TOOL_EVENT_FD_OPEN;
    record.fd          = 3;
    p101_tool_event_test_lifecycle_force_format_failure();
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == -1);
    p101_error_reset(err);

    record.record_kind = P101_TOOL_EVENT_RECORD_EXEC;
    record.cloexec     = 1;
    p101_tool_event_test_lifecycle_force_format_failure();
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == -1);
    p101_tool_event_lifecycle_destroy(&model);
    p101_error_destroy(err);
}

static void test_create_allocation_failure(void)
{
    struct p101_error *err;

    err = p101_error_create(false);
    p101_tool_event_test_lifecycle_fail_allocation_after(0U);
    EXPECT(p101_tool_event_lifecycle_create(err) == NULL);
    EXPECT(p101_error_is_errno(err, ENOMEM));
    p101_error_destroy(err);
}

static void test_entry_allocation_failures(void)
{
    for(size_t failure = 0U; failure < 5U; failure++)
    {
        struct p101_error                      *err;
        struct p101_tool_event_lifecycle_model *model;
        struct p101_tool_event_record           record;

        model = new_model(&err);
        initialize_resource(&record, P101_TOOL_EVENT_RESOURCE_ACQUIRE, "class", "id");
        p101_tool_event_test_lifecycle_fail_allocation_after(failure);
        EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == -1);
        EXPECT(p101_error_has_error(err));
        p101_tool_event_lifecycle_destroy(&model);
        p101_error_destroy(err);
    }
}

static void test_release_allocation_failures(void)
{
    for(size_t failure = 0U; failure < 2U; failure++)
    {
        struct p101_error                      *err;
        struct p101_tool_event_lifecycle_model *model;
        struct p101_tool_event_record           record;

        model = new_model(&err);
        initialize_resource(&record, P101_TOOL_EVENT_RESOURCE_ACQUIRE, "class", "id");
        EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == 0);
        record.resource_kind = P101_TOOL_EVENT_RESOURCE_RELEASE;
        p101_tool_event_test_lifecycle_fail_allocation_after(failure);
        EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == -1);
        p101_tool_event_lifecycle_destroy(&model);
        p101_error_destroy(err);
    }
}

static void test_finding_allocation_failures(void)
{
    for(size_t failure = 0U; failure < 5U; failure++)
    {
        struct p101_error                      *err;
        struct p101_tool_event_lifecycle_model *model;
        struct p101_tool_event_record           record;

        model = new_model(&err);
        initialize_resource(&record, P101_TOOL_EVENT_RESOURCE_RELEASE, "class", "missing");
        record.function_name = NULL;
        record.file_name     = NULL;
        p101_tool_event_test_lifecycle_fail_allocation_after(failure);
        EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == -1);
        p101_tool_event_lifecycle_destroy(&model);
        p101_error_destroy(err);
    }

    for(size_t failure = 0U; failure < 7U; failure++)
    {
        struct p101_error                      *err;
        struct p101_tool_event_lifecycle_model *model;
        struct p101_tool_event_record           record;

        model = new_model(&err);
        initialize_resource(&record, P101_TOOL_EVENT_RESOURCE_ACQUIRE, "class", "id");
        EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == 0);
        record.resource_kind = P101_TOOL_EVENT_RESOURCE_RELEASE;
        EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == 0);
        p101_tool_event_test_lifecycle_fail_allocation_after(failure);
        EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == -1);
        p101_tool_event_lifecycle_destroy(&model);
        p101_error_destroy(err);
    }
}

static void test_failure_propagation(void)
{
    struct p101_error                      *err;
    struct p101_tool_event_lifecycle_model *model;
    struct p101_tool_event_record           record;

    model = new_model(&err);
    initialize_resource(&record, P101_TOOL_EVENT_RESOURCE_ACQUIRE, "class", "duplicate");
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == 0);
    p101_tool_event_test_lifecycle_fail_allocation_after(0U);
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == -1);
    p101_tool_event_lifecycle_destroy(&model);
    p101_error_destroy(err);

    model = new_model(&err);
    initialize_resource(&record, P101_TOOL_EVENT_RESOURCE_ACQUIRE, "class", "old");
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == 0);
    record.resource_kind = P101_TOOL_EVENT_RESOURCE_REPLACE;
    record.related_id    = "new";
    p101_tool_event_test_lifecycle_fail_allocation_after(0U);
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == -1);
    p101_tool_event_lifecycle_destroy(&model);
    p101_error_destroy(err);

    model = new_model(&err);
    memset(&record, 0, sizeof(record));
    record.record_kind   = P101_TOOL_EVENT_RECORD_ALLOC;
    record.alloc_kind    = P101_TOOL_EVENT_ALLOC_REALLOC;
    record.pid           = 1;
    record.ptr           = "missing";
    record.new_ptr       = "new";
    record.function_name = "reallocate";
    record.file_name     = "alloc.c";
    p101_tool_event_test_lifecycle_fail_allocation_after(0U);
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == -1);
    p101_tool_event_lifecycle_destroy(&model);
    p101_error_destroy(err);

    model = new_model(&err);
    ingest_allocation(err, model, P101_TOOL_EVENT_ALLOC_ALLOC, "old", NULL);
    p101_tool_event_test_lifecycle_fail_allocation_after(0U);
    memset(&record, 0, sizeof(record));
    record.record_kind = P101_TOOL_EVENT_RECORD_ALLOC;
    record.alloc_kind  = P101_TOOL_EVENT_ALLOC_REALLOC;
    record.pid         = 2;
    record.ptr         = "old";
    record.new_ptr     = "new";
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == -1);
    p101_tool_event_lifecycle_destroy(&model);
    p101_error_destroy(err);

    model = new_model(&err);
    memset(&record, 0, sizeof(record));
    record.record_kind   = P101_TOOL_EVENT_RECORD_FD;
    record.fd_kind       = P101_TOOL_EVENT_FD_OPEN;
    record.pid           = 1;
    record.fd            = 3;
    record.function_name = "open";
    record.file_name     = "fd.c";
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == 0);
    record.record_kind = P101_TOOL_EVENT_RECORD_FORK;
    record.child_pid   = 2;
    p101_tool_event_test_lifecycle_fail_allocation_after(0U);
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == -1);
    p101_error_reset(err);
    record.record_kind = P101_TOOL_EVENT_RECORD_EXEC_FAIL;
    record.pid         = 1;
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == 0);
    p101_tool_event_lifecycle_destroy(&model);
    p101_error_destroy(err);

    model = new_model(&err);
    memset(&record, 0, sizeof(record));
    record.record_kind   = P101_TOOL_EVENT_RECORD_FD;
    record.fd_kind       = P101_TOOL_EVENT_FD_OPEN;
    record.pid           = 1;
    record.fd            = 3;
    record.function_name = "open";
    record.file_name     = "fd.c";
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == 0);
    record.record_kind = P101_TOOL_EVENT_RECORD_EXEC;
    record.cloexec     = 1;
    p101_tool_event_test_lifecycle_fail_allocation_after(0U);
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == -1);
    p101_tool_event_lifecycle_destroy(&model);
    p101_error_destroy(err);

    model = new_model(&err);
    initialize_resource(&record, P101_TOOL_EVENT_RESOURCE_ACQUIRE, "class", "leak");
    EXPECT(p101_tool_event_lifecycle_ingest(err, model, &record) == 0);
    p101_tool_event_test_lifecycle_fail_allocation_after(0U);
    EXPECT(p101_tool_event_lifecycle_finish(err, model) == -1);
    p101_tool_event_lifecycle_destroy(&model);
    p101_error_destroy(err);
}

int main(void)
{
    test_public_boundaries();
    test_release_and_replace_findings();
    test_allocation_shapes();
    test_fork_and_exec_edges();
    test_capacity_growth();
    test_format_failures();
    test_create_allocation_failure();
    test_entry_allocation_failures();
    test_release_allocation_failures();
    test_finding_allocation_failures();
    test_failure_propagation();
    return failures == 0 ? 0 : 1;
}
