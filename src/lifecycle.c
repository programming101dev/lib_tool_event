#include <errno.h>
#include <p101_tool_event/lifecycle.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

enum
{
    INITIAL_CAPACITY     = 16,
    FD_IDENTIFIER_LENGTH = 32,
#ifdef P101_TOOL_EVENT_TESTING
    MAX_LIFECYCLE_ENTRIES  = 64,
    MAX_LIFECYCLE_FINDINGS = 64
#else
    MAX_LIFECYCLE_ENTRIES  = 1048576,
    MAX_LIFECYCLE_FINDINGS = 1048576
#endif
};

/* Records own mutable views into parsed lines, so normalized literals use
 * arrays with compatible pointer types. They are never modified here. */
static char fd_resource_class[]         = "fd";            // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)
static char allocation_resource_class[] = "allocation";    // NOLINT(cppcoreguidelines-avoid-non-const-global-variables)

struct p101_tool_event_lifecycle_model
{
    char                                      run_id[P101_TOOL_EVENT_RUN_ID_MAX_BYTES + 1U];
    struct p101_tool_event_lifecycle_entry   *entries;
    size_t                                    entry_count;
    size_t                                    entry_capacity;
    struct p101_tool_event_lifecycle_finding *findings;
    size_t                                    finding_count;
    size_t                                    finding_capacity;
    int                                       finished;
};

static char                                   *copy_text(struct p101_error *err, const char *text);
static struct p101_tool_event_lifecycle_entry *find_latest(struct p101_tool_event_lifecycle_model *model, long pid, const char *resource_class, const char *resource_id, bool live_only);
static int                                     add_entry(struct p101_error *err, struct p101_tool_event_lifecycle_model *model, const struct p101_tool_event_record *record, const char *resource_id);
static int                                     ensure_finding_capacity(struct p101_error *err, struct p101_tool_event_lifecycle_model *model);
static int                                     add_leak_finding(struct p101_error *err, struct p101_tool_event_lifecycle_model *model, const struct p101_tool_event_lifecycle_entry *entry);
static int   add_finding(struct p101_error *err, struct p101_tool_event_lifecycle_model *model, p101_tool_event_lifecycle_finding_kind kind, const struct p101_tool_event_record *record, const struct p101_tool_event_lifecycle_entry *previous);
static void  destroy_finding(struct p101_tool_event_lifecycle_finding *finding);
static bool  take_stray_release(struct p101_tool_event_lifecycle_model *model, long pid, const char *resource_class, const char *resource_id, struct p101_tool_event_lifecycle_finding *finding);
static int   reconcile_stray_releases(struct p101_error *err, struct p101_tool_event_lifecycle_model *model, long pid, const char *resource_class, const char *resource_id);
static int   release_entry(struct p101_error *err, struct p101_tool_event_lifecycle_model *model, const struct p101_tool_event_record *record);
static int   ingest_resource(struct p101_error *err, struct p101_tool_event_lifecycle_model *model, const struct p101_tool_event_record *record);
static int   ingest_fd(struct p101_error *err, struct p101_tool_event_lifecycle_model *model, const struct p101_tool_event_record *record);
static int   ingest_allocation(struct p101_error *err, struct p101_tool_event_lifecycle_model *model, const struct p101_tool_event_record *record);
static int   ingest_fork(struct p101_error *err, struct p101_tool_event_lifecycle_model *model, const struct p101_tool_event_record *record);
static int   ingest_exec(struct p101_error *err, struct p101_tool_event_lifecycle_model *model, const struct p101_tool_event_record *record);
static void  rollback_exec(struct p101_tool_event_lifecycle_model *model, long pid);
static bool  pointer_is_null_text(const char *text);
static void *lifecycle_allocate(size_t size);
static void *lifecycle_reallocate(void *memory, size_t size);
static int   format_fd_identifier(char *identifier, size_t size, int fd);

#ifdef P101_TOOL_EVENT_TESTING
static size_t allocations_before_failure = SIZE_MAX;
static int    force_format_failure;

void p101_tool_event_test_lifecycle_fail_allocation_after(size_t successful_allocations)
{
    allocations_before_failure = successful_allocations;
}

void p101_tool_event_test_lifecycle_force_format_failure(void)
{
    force_format_failure = 1;
}

static bool allocation_should_fail(void)
{
    if(allocations_before_failure == SIZE_MAX)
    {
        return false;
    }
    if(allocations_before_failure > 0U)
    {
        allocations_before_failure--;
        return false;
    }
    allocations_before_failure = SIZE_MAX;
    errno                      = ENOMEM;
    return true;
}
#endif

static void *lifecycle_allocate(size_t size)
{
#ifdef P101_TOOL_EVENT_TESTING
    if(allocation_should_fail())
    {
        return NULL;
    }
#endif
    return malloc(size);
}

static void *lifecycle_reallocate(void *memory, size_t size)
{
#ifdef P101_TOOL_EVENT_TESTING
    if(allocation_should_fail())
    {
        return NULL;
    }
#endif
    return realloc(memory, size);
}

static int format_fd_identifier(char *identifier, size_t size, int fd)
{
#ifdef P101_TOOL_EVENT_TESTING
    if(force_format_failure != 0)
    {
        force_format_failure = 0;
        return -1;
    }
#endif
    return snprintf(identifier, size, "%d", fd);
}

struct p101_tool_event_lifecycle_model *p101_tool_event_lifecycle_create(struct p101_error *err)
{
    struct p101_tool_event_lifecycle_model *model;

    model = (struct p101_tool_event_lifecycle_model *)lifecycle_allocate(sizeof(*model));
    if(model == NULL)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
    }
    else
    {
        memset(model, 0, sizeof(*model));
    }
    return model;
}

void p101_tool_event_lifecycle_destroy(struct p101_tool_event_lifecycle_model **model)
{
    if(model == NULL || *model == NULL)
    {
        return;
    }

    for(size_t i = 0U; i < (*model)->entry_count; i++)
    {
        free((*model)->entries[i].resource_class);
        free((*model)->entries[i].resource_id);
        free((*model)->entries[i].acquired_function_name);
        free((*model)->entries[i].released_function_name);
        free((*model)->entries[i].acquired_file_name);
        free((*model)->entries[i].released_file_name);
    }
    for(size_t i = 0U; i < (*model)->finding_count; i++)
    {
        destroy_finding(&(*model)->findings[i]);
    }
    free((*model)->entries);
    free((*model)->findings);
    free(*model);
    *model = NULL;
}

int p101_tool_event_lifecycle_ingest(struct p101_error *err, struct p101_tool_event_lifecycle_model *model, const struct p101_tool_event_record *record)
{
    int result;

    if(model == NULL || record == NULL || record->version != P101_TOOL_EVENT_LOG_VERSION || record->run_id == NULL || record->run_id[0] == '\0' || strlen(record->run_id) > P101_TOOL_EVENT_RUN_ID_MAX_BYTES)
    {
        P101_ERROR_RAISE_CHECK(err);
        return -1;
    }
    if(model->run_id[0] != '\0' && strcmp(model->run_id, record->run_id) != 0)
    {
        P101_ERROR_RAISE_CHECK(err);
        return -1;
    }

    model->finished = 0;
#ifdef __clang__
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wcovered-switch-default"
#endif
    switch(record->record_kind)
    {
        case P101_TOOL_EVENT_RECORD_RESOURCE:
            result = ingest_resource(err, model, record);
            break;    // GCOVR_EXCL_LINE
        case P101_TOOL_EVENT_RECORD_FD:
            result = ingest_fd(err, model, record);
            break;    // GCOVR_EXCL_LINE
        case P101_TOOL_EVENT_RECORD_ALLOC:
            result = ingest_allocation(err, model, record);
            break;
        case P101_TOOL_EVENT_RECORD_FORK:
            result = ingest_fork(err, model, record);
            break;
        case P101_TOOL_EVENT_RECORD_EXEC:
            result = ingest_exec(err, model, record);
            break;
        case P101_TOOL_EVENT_RECORD_EXEC_FAIL:
            rollback_exec(model, record->pid);
            result = 0;
            break;
        case P101_TOOL_EVENT_RECORD_SPAWN:
        case P101_TOOL_EVENT_RECORD_CALL:
        case P101_TOOL_EVENT_RECORD_COMPLETE:
            P101_ERROR_RAISE_CHECK(err);
            result = -1;
            break;
        default:
            P101_ERROR_RAISE_CHECK(err);    // GCOVR_EXCL_LINE -- exhaustive enum has no other valid value.
            result = -1;                    // GCOVR_EXCL_LINE
            break;                          // GCOVR_EXCL_LINE
    }
#ifdef __clang__
    #pragma clang diagnostic pop
#endif
    if(result == 0 && model->run_id[0] == '\0')
    {
        (void)memcpy(model->run_id, record->run_id, strlen(record->run_id) + 1U);
    }
    return result;
}

static int ingest_resource(struct p101_error *err, struct p101_tool_event_lifecycle_model *model, const struct p101_tool_event_record *record)
{
    int result;

    if(record->resource_class == NULL || record->resource_id == NULL)
    {
        P101_ERROR_RAISE_CHECK(err);
        return -1;
    }

#ifdef __clang__
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wcovered-switch-default"
#endif
    switch(record->resource_kind)
    {
        case P101_TOOL_EVENT_RESOURCE_ACQUIRE:
        {
            const struct p101_tool_event_lifecycle_entry *previous;

            previous = find_latest(model, record->pid, record->resource_class, record->resource_id, true);
            result   = 0;
            if(previous != NULL)
            {
                result = add_finding(err, model, P101_TOOL_EVENT_LIFECYCLE_FINDING_DUPLICATE_ACQUIRE, record, previous);
            }
            if(result == 0)
            {
                result = add_entry(err, model, record, record->resource_id);
            }
            break;
        }
        case P101_TOOL_EVENT_RESOURCE_RELEASE:
            result = release_entry(err, model, record);
            break;
        case P101_TOOL_EVENT_RESOURCE_REPLACE:
        case P101_TOOL_EVENT_RESOURCE_TRANSFER:
            if(record->related_id == NULL)
            {
                result = add_finding(err, model, P101_TOOL_EVENT_LIFECYCLE_FINDING_BAD_REPLACE, record, find_latest(model, record->pid, record->resource_class, record->resource_id, false));
            }
            else
            {
                result = release_entry(err, model, record);
                if(result == 0)
                {
                    result = add_entry(err, model, record, record->related_id);
                }
            }
            break;
        default:
            P101_ERROR_RAISE_CHECK(err);
            result = -1;
            break;
    }
#ifdef __clang__
    #pragma clang diagnostic pop
#endif
    return result;
}

static int ingest_fd(struct p101_error *err, struct p101_tool_event_lifecycle_model *model, const struct p101_tool_event_record *record)
{
    struct p101_tool_event_record normalized;
    char                          identifier[FD_IDENTIFIER_LENGTH];

    if(format_fd_identifier(identifier, sizeof(identifier), record->fd) < 0)
    {
        P101_ERROR_RAISE_CHECK(err);
        return -1;
    }
    normalized                = *record;
    normalized.resource_kind  = record->fd_kind == P101_TOOL_EVENT_FD_OPEN ? P101_TOOL_EVENT_RESOURCE_ACQUIRE : P101_TOOL_EVENT_RESOURCE_RELEASE;
    normalized.resource_class = fd_resource_class;
    normalized.resource_id    = identifier;
    normalized.related_id     = NULL;
    normalized.size           = 0U;
    return ingest_resource(err, model, &normalized);
}

static int ingest_allocation(struct p101_error *err, struct p101_tool_event_lifecycle_model *model, const struct p101_tool_event_record *record)
{
    struct p101_tool_event_record                 normalized;
    const struct p101_tool_event_lifecycle_entry *entry;
    int                                           result;

    normalized                = *record;
    normalized.resource_class = allocation_resource_class;
    normalized.related_id     = NULL;

    if(record->alloc_kind == P101_TOOL_EVENT_ALLOC_ALLOC)
    {
        if(pointer_is_null_text(record->ptr))
        {
            return 0;
        }
        normalized.resource_kind = P101_TOOL_EVENT_RESOURCE_ACQUIRE;
        normalized.resource_id   = record->ptr;
        return ingest_resource(err, model, &normalized);
    }
    if(record->alloc_kind == P101_TOOL_EVENT_ALLOC_FREE)
    {
        if(pointer_is_null_text(record->ptr))
        {
            return 0;
        }
        normalized.resource_kind = P101_TOOL_EVENT_RESOURCE_RELEASE;
        normalized.resource_id   = record->ptr;
        return ingest_resource(err, model, &normalized);
    }

    if(pointer_is_null_text(record->ptr))
    {
        if(pointer_is_null_text(record->new_ptr))
        {
            return 0;
        }
        normalized.resource_kind = P101_TOOL_EVENT_RESOURCE_ACQUIRE;
        normalized.resource_id   = record->new_ptr;
        return ingest_resource(err, model, &normalized);
    }

    entry = find_latest(model, record->pid, "allocation", record->ptr, true);
    if(entry == NULL)
    {
        normalized.resource_kind = P101_TOOL_EVENT_RESOURCE_REPLACE;
        normalized.resource_id   = record->ptr;
        result                   = add_finding(err, model, P101_TOOL_EVENT_LIFECYCLE_FINDING_BAD_REPLACE, &normalized, find_latest(model, record->pid, "allocation", record->ptr, false));
        if(result != 0 || pointer_is_null_text(record->new_ptr))
        {
            return result;
        }
        normalized.resource_kind = P101_TOOL_EVENT_RESOURCE_ACQUIRE;
        normalized.resource_id   = record->new_ptr;
        return ingest_resource(err, model, &normalized);
    }
    if(pointer_is_null_text(record->new_ptr))
    {
        return 0;
    }

    normalized.resource_kind = P101_TOOL_EVENT_RESOURCE_RELEASE;
    normalized.resource_id   = record->ptr;
    result                   = ingest_resource(err, model, &normalized);
    if(result == 0)
    {
        normalized.resource_kind = P101_TOOL_EVENT_RESOURCE_ACQUIRE;
        normalized.resource_id   = record->new_ptr;
        result                   = ingest_resource(err, model, &normalized);
    }
    return result;
}

static int ingest_fork(struct p101_error *err, struct p101_tool_event_lifecycle_model *model, const struct p101_tool_event_record *record)
{
    size_t inherited_count;

    if(record->pid < 0 || record->child_pid < 0 || record->pid == record->child_pid)
    {
        return 0;
    }

    /*
     * A fork gives the child its own copy of every live descriptor. Clone
     * only the entries that existed before this record: add_entry() may grow
     * the array and must not make this loop chase entries it just added.
     *
     * The parent emits the relationship after fork returns. A fast child can
     * therefore release an inherited descriptor before this record reaches a
     * shared stream. Reconcile any provisional stray release after cloning;
     * emitting a second fork marker from the child would violate per-context
     * sequence uniqueness.
     */
    inherited_count = model->entry_count;
    for(size_t index = 0U; index < inherited_count; index++)
    {
        const struct p101_tool_event_lifecycle_entry *entry;
        struct p101_tool_event_record                 inherited;
        char                                          identifier[FD_IDENTIFIER_LENGTH];
        size_t                                        identifier_length;

        entry = &model->entries[index];
        if(entry->pid != record->pid || !entry->live || strcmp(entry->resource_class, "fd") != 0)
        {
            continue;
        }
        if(find_latest(model, record->child_pid, entry->resource_class, entry->resource_id, false) != NULL)
        {
            continue;
        }

        identifier_length = 0U;
        while(identifier_length + 1U < sizeof(identifier) && entry->resource_id[identifier_length] != '\0')
        {
            identifier[identifier_length] = entry->resource_id[identifier_length];
            identifier_length++;
        }
        if(entry->resource_id[identifier_length] != '\0')
        {
            P101_ERROR_RAISE_CHECK(err);
            return -1;
        }
        identifier[identifier_length] = '\0';

        inherited                = *record;
        inherited.record_kind    = entry->origin_kind;
        inherited.pid            = record->child_pid;
        inherited.context_id     = record->context_id;
        inherited.resource_class = fd_resource_class;
        inherited.resource_id    = identifier;
        inherited.size           = entry->size;
        if(add_entry(err, model, &inherited, identifier) != 0)
        {
            return -1;
        }
        if(reconcile_stray_releases(err, model, record->child_pid, fd_resource_class, identifier) != 0)
        {
            return -1;
        }
    }
    return 0;
}

static bool pointer_is_null_text(const char *text)
{
    return (text == NULL || strcmp(text, "-") == 0 || strcmp(text, "(nil)") == 0 || strcmp(text, "0x0") == 0) != 0;
}

static int ingest_exec(struct p101_error *err, struct p101_tool_event_lifecycle_model *model, const struct p101_tool_event_record *record)
{
    struct p101_tool_event_lifecycle_entry *entry;
    struct p101_tool_event_record           normalized;
    char                                    identifier[FD_IDENTIFIER_LENGTH];

    if(record->cloexec == 0)
    {
        return 0;
    }
    if(format_fd_identifier(identifier, sizeof(identifier), record->fd) < 0)
    {
        P101_ERROR_RAISE_CHECK(err);
        return -1;
    }
    entry = find_latest(model, record->pid, "fd", identifier, true);
    if(entry == NULL)
    {
        return 0;
    }

    normalized                = *record;
    normalized.resource_kind  = P101_TOOL_EVENT_RESOURCE_RELEASE;
    normalized.resource_class = fd_resource_class;
    normalized.resource_id    = identifier;
    if(release_entry(err, model, &normalized) != 0)
    {
        return -1;
    }
    entry->exec_pending = true;
    return 0;
}

static void rollback_exec(struct p101_tool_event_lifecycle_model *model, long pid)
{
    for(size_t index = 0U; index < model->entry_count; index++)
    {
        struct p101_tool_event_lifecycle_entry *entry;

        entry = &model->entries[index];
        if(entry->pid != pid || !entry->exec_pending)
        {
            continue;
        }
        free(entry->released_function_name);
        free(entry->released_file_name);
        entry->released_function_name          = NULL;
        entry->released_file_name              = NULL;
        entry->released_context_id             = 0U;
        entry->released_sequence               = 0U;
        entry->released_monotonic_ns           = 0U;
        entry->released_monotonic_ns_available = false;
        entry->released_line_number            = 0;
        entry->live                            = true;
        entry->exec_pending                    = false;
    }
}

int p101_tool_event_lifecycle_finish(struct p101_error *err, struct p101_tool_event_lifecycle_model *model)
{
    if(model == NULL)
    {
        P101_ERROR_RAISE_CHECK(err);
        return -1;
    }
    if(model->finished != 0)
    {
        return 0;
    }

    for(size_t i = 0U; i < model->entry_count; i++)
    {
        struct p101_tool_event_lifecycle_entry *entry;

        entry               = &model->entries[i];
        entry->exec_pending = false;
        if(!entry->live)
        {
            continue;
        }
        if(add_leak_finding(err, model, entry) != 0)
        {
            return -1;
        }
    }
    model->finished = 1;
    return 0;
}

size_t p101_tool_event_lifecycle_entry_count(const struct p101_tool_event_lifecycle_model *model)
{
    return model == NULL ? 0U : model->entry_count;
}

const struct p101_tool_event_lifecycle_entry *p101_tool_event_lifecycle_entry_at(const struct p101_tool_event_lifecycle_model *model, size_t index)
{
    return model == NULL || index >= model->entry_count ? NULL : &model->entries[index];
}

size_t p101_tool_event_lifecycle_finding_count(const struct p101_tool_event_lifecycle_model *model)
{
    return model == NULL ? 0U : model->finding_count;
}

const struct p101_tool_event_lifecycle_finding *p101_tool_event_lifecycle_finding_at(const struct p101_tool_event_lifecycle_model *model, size_t index)
{
    return model == NULL || index >= model->finding_count ? NULL : &model->findings[index];
}

static char *copy_text(struct p101_error *err, const char *text)
{
    char  *copy;
    size_t length;

    length = strlen(text);
    copy   = (char *)lifecycle_allocate(length + 1U);
    if(copy == NULL)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
        return NULL;
    }
    memcpy(copy, text, length + 1U);
    return copy;
}

static struct p101_tool_event_lifecycle_entry *find_latest(struct p101_tool_event_lifecycle_model *model, long pid, const char *resource_class, const char *resource_id, bool live_only)
{
    for(size_t i = model->entry_count; i > 0U; i--)
    {
        struct p101_tool_event_lifecycle_entry *entry;

        entry = &model->entries[i - 1U];
        if(entry->pid == pid && strcmp(entry->resource_class, resource_class) == 0 && strcmp(entry->resource_id, resource_id) == 0 && (!live_only || entry->live))
        {
            return entry;
        }
    }
    return NULL;
}

static int add_entry(struct p101_error *err, struct p101_tool_event_lifecycle_model *model, const struct p101_tool_event_record *record, const char *resource_id)
{
    struct p101_tool_event_lifecycle_entry *entry;

    if(model->entry_count >= MAX_LIFECYCLE_ENTRIES)
    {
        P101_ERROR_RAISE_ERRNO(err, EFBIG);
        return -1;
    }
    if(model->entry_count == model->entry_capacity)
    {
        size_t                                  capacity;
        struct p101_tool_event_lifecycle_entry *grown;

        capacity = INITIAL_CAPACITY;
        if(model->entry_capacity != 0U)
        {
            capacity = model->entry_capacity * 2U;
        }
        grown = (struct p101_tool_event_lifecycle_entry *)lifecycle_reallocate(model->entries, capacity * sizeof(*grown));
        if(grown == NULL)
        {
            P101_ERROR_RAISE_ERRNO(err, errno);
            return -1;
        }
        model->entries        = grown;
        model->entry_capacity = capacity;
    }

    entry = &model->entries[model->entry_count];
    memset(entry, 0, sizeof(*entry));
    entry->resource_class         = copy_text(err, record->resource_class);
    entry->resource_id            = copy_text(err, resource_id);
    entry->acquired_function_name = copy_text(err, record->function_name == NULL ? "?" : record->function_name);
    entry->acquired_file_name     = copy_text(err, record->file_name == NULL ? "?" : record->file_name);
    if(entry->resource_class == NULL || entry->resource_id == NULL || entry->acquired_function_name == NULL || entry->acquired_file_name == NULL)
    {
        free(entry->resource_class);
        free(entry->resource_id);
        free(entry->acquired_function_name);
        free(entry->acquired_file_name);
        return -1;
    }
    entry->pid                             = record->pid;
    entry->origin_kind                     = record->record_kind;
    entry->acquired_context_id             = record->context_id;
    entry->acquired_sequence               = record->sequence;
    entry->acquired_monotonic_ns           = record->monotonic_ns;
    entry->acquired_monotonic_ns_available = record->monotonic_ns_available != 0;
    entry->size                            = record->size;
    entry->acquired_line_number            = record->line_number;
    entry->live                            = true;
    model->entry_count++;
    return 0;
}

static int ensure_finding_capacity(struct p101_error *err, struct p101_tool_event_lifecycle_model *model)
{
    if(model->finding_count >= MAX_LIFECYCLE_FINDINGS)
    {
        P101_ERROR_RAISE_ERRNO(err, EFBIG);
        return -1;
    }
    if(model->finding_count == model->finding_capacity)
    {
        size_t                                    capacity;
        struct p101_tool_event_lifecycle_finding *grown;

        capacity = INITIAL_CAPACITY;
        if(model->finding_capacity != 0U)
        {
            capacity = model->finding_capacity * 2U;
        }
        grown = (struct p101_tool_event_lifecycle_finding *)lifecycle_reallocate(model->findings, capacity * sizeof(*grown));
        if(grown == NULL)
        {
            P101_ERROR_RAISE_ERRNO(err, errno);
            return -1;
        }
        model->findings         = grown;
        model->finding_capacity = capacity;
    }
    return 0;
}

static int add_leak_finding(struct p101_error *err, struct p101_tool_event_lifecycle_model *model, const struct p101_tool_event_lifecycle_entry *entry)
{
    struct p101_tool_event_lifecycle_finding *finding;
    char                                     *resource_class;
    char                                     *resource_id;
    char                                     *function_name;
    char                                     *file_name;

    if(ensure_finding_capacity(err, model) != 0)
    {
        return -1;
    }

    resource_class = copy_text(err, entry->resource_class);
    resource_id    = copy_text(err, entry->resource_id);
    function_name  = copy_text(err, entry->acquired_function_name);
    file_name      = copy_text(err, entry->acquired_file_name);
    if(resource_class == NULL || resource_id == NULL || function_name == NULL || file_name == NULL)
    {
        free(resource_class);
        free(resource_id);
        free(function_name);
        free(file_name);
        return -1;
    }

    finding = &model->findings[model->finding_count++];
    memset(finding, 0, sizeof(*finding));
    finding->kind           = P101_TOOL_EVENT_LIFECYCLE_FINDING_LEAK;
    finding->origin_kind    = entry->origin_kind;
    finding->pid            = entry->pid;
    finding->context_id     = entry->acquired_context_id;
    finding->resource_class = resource_class;
    finding->resource_id    = resource_id;
    finding->sequence       = entry->acquired_sequence;
    finding->line_number    = entry->acquired_line_number;
    finding->function_name  = function_name;
    finding->file_name      = file_name;
    return 0;
}

static int add_finding(struct p101_error *err, struct p101_tool_event_lifecycle_model *model, p101_tool_event_lifecycle_finding_kind kind, const struct p101_tool_event_record *record, const struct p101_tool_event_lifecycle_entry *previous)
{
    struct p101_tool_event_lifecycle_finding *finding;
    const char                               *resource_class;
    const char                               *resource_id;
    char                                     *resource_class_copy;
    char                                     *resource_id_copy;
    const char                               *previous_function_name;
    const char                               *previous_file_name;

    if(ensure_finding_capacity(err, model) != 0)
    {
        return -1;
    }

    resource_class      = previous == NULL ? record->resource_class : previous->resource_class;
    resource_id         = previous == NULL ? record->resource_id : previous->resource_id;
    resource_class_copy = copy_text(err, resource_class);
    resource_id_copy    = copy_text(err, resource_id);
    if(resource_class_copy == NULL || resource_id_copy == NULL)
    {
        free(resource_class_copy);
        free(resource_id_copy);
        return -1;
    }

    finding                         = &model->findings[model->finding_count++];
    finding->kind                   = kind;
    finding->origin_kind            = previous == NULL ? record->record_kind : previous->origin_kind;
    finding->pid                    = record->pid;
    finding->context_id             = record->context_id;
    finding->previous_context_id    = previous == NULL ? 0U : previous->acquired_context_id;
    finding->resource_class         = resource_class_copy;
    finding->resource_id            = resource_id_copy;
    finding->sequence               = record->sequence;
    finding->previous_sequence      = 0U;
    finding->line_number            = record->line_number;
    finding->monotonic_ns           = record->monotonic_ns;
    finding->monotonic_ns_available = record->monotonic_ns_available != 0;
    finding->function_name          = copy_text(err, record->function_name == NULL ? "?" : record->function_name);
    finding->file_name              = copy_text(err, record->file_name == NULL ? "?" : record->file_name);
    finding->previous_line_number   = 0;
    finding->previous_function_name = NULL;
    finding->previous_file_name     = NULL;
    if(previous != NULL)
    {
        finding->previous_sequence      = previous->released_sequence == 0U ? previous->acquired_sequence : previous->released_sequence;
        finding->previous_context_id    = previous->released_sequence == 0U ? previous->acquired_context_id : previous->released_context_id;
        finding->previous_line_number   = previous->released_sequence == 0U ? previous->acquired_line_number : previous->released_line_number;
        previous_function_name          = previous->released_sequence == 0U ? previous->acquired_function_name : previous->released_function_name;
        previous_file_name              = previous->released_sequence == 0U ? previous->acquired_file_name : previous->released_file_name;
        finding->previous_function_name = copy_text(err, previous_function_name);
        finding->previous_file_name     = copy_text(err, previous_file_name);
    }
    if(finding->function_name == NULL || finding->file_name == NULL || (previous != NULL && (finding->previous_function_name == NULL || finding->previous_file_name == NULL)))
    {
        free(finding->resource_class);
        free(finding->resource_id);
        free(finding->function_name);
        free(finding->file_name);
        free(finding->previous_function_name);
        free(finding->previous_file_name);
        memset(finding, 0, sizeof(*finding));
        model->finding_count--;
        return -1;
    }
    return 0;
}

static void destroy_finding(struct p101_tool_event_lifecycle_finding *finding)
{
    free(finding->resource_class);
    free(finding->resource_id);
    free(finding->function_name);
    free(finding->previous_function_name);
    free(finding->file_name);
    free(finding->previous_file_name);
    memset(finding, 0, sizeof(*finding));
}

static bool take_stray_release(struct p101_tool_event_lifecycle_model *model, long pid, const char *resource_class, const char *resource_id, struct p101_tool_event_lifecycle_finding *finding)
{
    for(size_t index = 0U; index < model->finding_count; index++)
    {
        const struct p101_tool_event_lifecycle_finding *candidate;

        candidate = &model->findings[index];
        if(candidate->kind != P101_TOOL_EVENT_LIFECYCLE_FINDING_STRAY_RELEASE || candidate->pid != pid || strcmp(candidate->resource_class, resource_class) != 0 || strcmp(candidate->resource_id, resource_id) != 0)
        {
            continue;
        }

        *finding = *candidate;
        if(index + 1U < model->finding_count)
        {
            memmove(&model->findings[index], &model->findings[index + 1U], (model->finding_count - index - 1U) * sizeof(*model->findings));
        }
        model->finding_count--;
        memset(&model->findings[model->finding_count], 0, sizeof(*model->findings));
        return true;
    }
    return false;
}

static int reconcile_stray_releases(struct p101_error *err, struct p101_tool_event_lifecycle_model *model, long pid, const char *resource_class, const char *resource_id)
{
    struct p101_tool_event_lifecycle_finding finding;

    while(take_stray_release(model, pid, resource_class, resource_id, &finding))
    {
        struct p101_tool_event_record release;
        int                           result;

        memset(&release, 0, sizeof(release));
        release.record_kind            = finding.origin_kind;
        release.pid                    = finding.pid;
        release.context_id             = finding.context_id;
        release.sequence               = finding.sequence;
        release.monotonic_ns           = finding.monotonic_ns;
        release.monotonic_ns_available = (int)finding.monotonic_ns_available;
        release.resource_kind          = P101_TOOL_EVENT_RESOURCE_RELEASE;
        release.resource_class         = finding.resource_class;
        release.resource_id            = finding.resource_id;
        release.line_number            = finding.line_number;
        release.function_name          = finding.function_name;
        release.file_name              = finding.file_name;
        result                         = release_entry(err, model, &release);
        destroy_finding(&finding);
        if(result != 0)
        {
            return -1;
        }
    }
    return 0;
}

static int release_entry(struct p101_error *err, struct p101_tool_event_lifecycle_model *model, const struct p101_tool_event_record *record)
{
    struct p101_tool_event_lifecycle_entry       *entry;
    const struct p101_tool_event_lifecycle_entry *previous;

    entry = find_latest(model, record->pid, record->resource_class, record->resource_id, true);
    if(entry != NULL)
    {
        char *function_name;
        char *file_name;

        function_name = copy_text(err, record->function_name == NULL ? "?" : record->function_name);
        file_name     = copy_text(err, record->file_name == NULL ? "?" : record->file_name);
        if(function_name == NULL || file_name == NULL)
        {
            free(function_name);
            free(file_name);
            return -1;
        }
        entry->live                            = false;
        entry->released_sequence               = record->sequence;
        entry->released_context_id             = record->context_id;
        entry->released_monotonic_ns           = record->monotonic_ns;
        entry->released_monotonic_ns_available = record->monotonic_ns_available != 0;
        entry->released_line_number            = record->line_number;
        entry->released_function_name          = function_name;
        entry->released_file_name              = file_name;
        return 0;
    }

    previous = find_latest(model, record->pid, record->resource_class, record->resource_id, false);
    return add_finding(err, model, previous == NULL ? P101_TOOL_EVENT_LIFECYCLE_FINDING_STRAY_RELEASE : P101_TOOL_EVENT_LIFECYCLE_FINDING_DOUBLE_RELEASE, record, previous);
}
