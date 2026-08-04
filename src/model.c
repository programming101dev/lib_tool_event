#include "model_internal.h"
#include <errno.h>
#include <p101_error/error.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

enum
{
    INITIAL_CAPACITY = 32,
    MODEL_LIMIT      = 1048576
};

static char  *copy_text(struct p101_error *err, const char *text);
static int    reserve_nodes(struct p101_error *err, struct p101_tool_model *model);
static int    reserve_edges(struct p101_error *err, struct p101_tool_model *model);
static int    add_edge(struct p101_error *err, struct p101_tool_model *model, p101_tool_model_edge_kind kind, size_t from, size_t to);
static void   copy_record(struct p101_tool_model_owned_node *node, const struct p101_tool_event_record *record);
static int    copy_record_text(struct p101_error *err, struct p101_tool_model_owned_node *node, const struct p101_tool_event_record *record);
static void   free_node(struct p101_tool_model_owned_node *node);
static int    same_context(const struct p101_tool_model_node *left, const struct p101_tool_model_node *right);
static size_t find_active_enter(const struct p101_tool_model *model, const size_t *matched_exit, size_t node_index, int require_name);
static size_t find_enclosing_call(const struct p101_tool_model *model, const size_t *matched_exit, size_t resource_index);
static size_t find_lifetime_end(const struct p101_tool_model *model, size_t birth_index);
static int    is_lifetime_birth(const struct p101_tool_model_node *node);
static int    lifetime_matches(const struct p101_tool_model_node *birth, const struct p101_tool_model_node *death);
static int    pointer_is_null(const char *text);
static int    build_call_edges(struct p101_error *err, struct p101_tool_model *model, size_t *matched_exit);
static int    build_resource_edges(struct p101_error *err, struct p101_tool_model *model, const size_t *matched_exit);
static int    build_lifecycle(struct p101_error *err, struct p101_tool_model *model);
static void   record_from_node(const struct p101_tool_model_owned_node *owned, struct p101_tool_event_record *record);
static void  *model_allocate(size_t size);
static void  *model_callocate(size_t count, size_t size);
static void  *model_reallocate(void *memory, size_t size);

#ifdef P101_TOOL_EVENT_TESTING
static size_t model_allocations_before_failure = SIZE_MAX;
static int    model_allocation_failure_errno   = ENOMEM;

void p101_tool_event_test_model_fail_allocation_after(size_t successful_allocations)
{
    model_allocations_before_failure = successful_allocations;
}

void p101_tool_event_test_model_set_allocation_failure_errno(int errnum)
{
    model_allocation_failure_errno = errnum;
}

static int model_allocation_should_fail(void)
{
    if(model_allocations_before_failure == SIZE_MAX)
    {
        return 0;
    }
    if(model_allocations_before_failure > 0U)
    {
        model_allocations_before_failure--;
        return 0;
    }
    model_allocations_before_failure = SIZE_MAX;
    errno                            = model_allocation_failure_errno;
    return 1;
}
#endif

static void *model_allocate(size_t size)
{
#ifdef P101_TOOL_EVENT_TESTING
    if(model_allocation_should_fail() != 0)
    {
        return NULL;
    }
#endif
    return malloc(size);
}

static void *model_callocate(size_t count, size_t size)
{
#ifdef P101_TOOL_EVENT_TESTING
    if(model_allocation_should_fail() != 0)
    {
        return NULL;
    }
#endif
    return calloc(count, size);
}

static void *model_reallocate(void *memory, size_t size)
{
#ifdef P101_TOOL_EVENT_TESTING
    if(model_allocation_should_fail() != 0)
    {
        return NULL;
    }
#endif
    return realloc(memory, size);
}

struct p101_tool_model *p101_tool_model_create(struct p101_error *err)
{
    struct p101_tool_model *model;

    model = (struct p101_tool_model *)model_callocate(1U, sizeof(*model));
    if(model == NULL)
    {
        P101_ERROR_RAISE_ERRNO(err, errno == 0 ? ENOMEM : errno);
    }
    return model;
}

void p101_tool_model_destroy(struct p101_tool_model **model)
{
    if(model == NULL || *model == NULL)
    {
        return;
    }
    for(size_t index = 0U; index < (*model)->node_count; index++)
    {
        free_node(&(*model)->nodes[index]);
    }
    free((*model)->nodes);
    free((*model)->edges);
    free((*model)->run_id);
    p101_tool_event_lifecycle_destroy(&(*model)->lifecycle);
    free(*model);
    *model = NULL;
}

int p101_tool_model_ingest(struct p101_error *err, struct p101_tool_model *model, const struct p101_tool_event_record *record)
{
    int                                p101_single_result_;
    struct p101_tool_model_owned_node *node;

    if(model == NULL || record == NULL || model->finished != 0 || record->version != P101_TOOL_EVENT_LOG_VERSION || record->run_id == NULL || record->run_id[0] == '\0' || strlen(record->run_id) > P101_TOOL_EVENT_RUN_ID_MAX_BYTES)
    {
        P101_ERROR_RAISE_ERRNO(err, EINVAL);
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    if(model->run_id == NULL)
    {
        model->run_id = copy_text(err, record->run_id);
        if(model->run_id == NULL)
        {
            p101_single_result_ = -1;
            goto p101_single_exit_;
        }
    }
    else if(strcmp(model->run_id, record->run_id) != 0)
    {
        P101_ERROR_RAISE_ERRNO(err, EINVAL);
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    if(record->record_kind == P101_TOOL_EVENT_RECORD_COMPLETE)
    {
        p101_single_result_ = 0;
        goto p101_single_exit_;
    }
    if(reserve_nodes(err, model) != 0)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    node = &model->nodes[model->node_count];
    memset(node, 0, sizeof(*node));
    copy_record(node, record);
    if(copy_record_text(err, node, record) != 0)
    {
        free_node(node);
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    model->node_count++;
    p101_single_result_ = 0;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

int p101_tool_model_finish(struct p101_error *err, struct p101_tool_model *model)
{
    int     p101_single_result_;
    size_t *matched_exit;
    int     result;

    if(model == NULL)
    {
        P101_ERROR_RAISE_ERRNO(err, EINVAL);
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    if(model->finished != 0)
    {
        p101_single_result_ = 0;
        goto p101_single_exit_;
    }
    /*
     * A previous allocation failure may have left a partial edge set. Edges
     * own no storage, so rebuilding from the admitted nodes is safe.
     */
    model->edge_count = 0U;
    p101_tool_event_lifecycle_destroy(&model->lifecycle);
    matched_exit = NULL;
    result       = -1;
    if(model->node_count > 0U)
    {
        matched_exit = (size_t *)model_allocate(model->node_count * sizeof(*matched_exit));
        if(matched_exit == NULL)
        {
            P101_ERROR_RAISE_ERRNO(err, errno == 0 ? ENOMEM : errno);
            goto done;
        }
        for(size_t index = 0U; index < model->node_count; index++)
        {
            matched_exit[index] = SIZE_MAX;
        }
    }
    if(build_call_edges(err, model, matched_exit) != 0 || build_resource_edges(err, model, matched_exit) != 0 || build_lifecycle(err, model) != 0)
    {
        model->edge_count = 0U;
        goto done;
    }
    model->finished = 1;
    result          = 0;

done:
    free(matched_exit);
    p101_single_result_ = result;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static int build_lifecycle(struct p101_error *err, struct p101_tool_model *model)
{
    int p101_single_result_;
    model->lifecycle = p101_tool_event_lifecycle_create(err);
    if(model->lifecycle == NULL)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    for(size_t index = 0U; index < model->node_count; index++)
    {
        const struct p101_tool_model_owned_node *node;
        struct p101_tool_event_record            record;

        node = &model->nodes[index];
        if(node->value.domain != P101_TOOL_MODEL_NODE_RESOURCE)
        {
            continue;
        }
        if(node->value.record_kind == P101_TOOL_EVENT_RECORD_SPAWN)
        {
            continue;
        }
        record_from_node(node, &record);
        if(p101_tool_event_lifecycle_ingest(err, model->lifecycle, &record) != 0)
        {
            p101_tool_event_lifecycle_destroy(&model->lifecycle);
            p101_single_result_ = -1;
            goto p101_single_exit_;
        }
    }
    if(p101_tool_event_lifecycle_finish(err, model->lifecycle) != 0)
    {
        p101_tool_event_lifecycle_destroy(&model->lifecycle);
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    p101_single_result_ = 0;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static void record_from_node(const struct p101_tool_model_owned_node *owned, struct p101_tool_event_record *record)
{
    const struct p101_tool_model_node *node;

    node = &owned->value;
    memset(record, 0, sizeof(*record));
    record->version                = P101_TOOL_EVENT_LOG_VERSION;
    record->record_kind            = node->record_kind;
    record->call_kind              = node->call_kind;
    record->fd_kind                = node->fd_kind;
    record->alloc_kind             = node->alloc_kind;
    record->resource_kind          = node->resource_kind;
    record->run_id                 = owned->run_id;
    record->pid                    = node->pid;
    record->child_pid              = node->child_pid;
    record->context_id             = node->context_id;
    record->sequence               = node->sequence;
    record->monotonic_ns           = node->monotonic_ns;
    record->wall_unix_ns           = node->wall_unix_ns;
    record->monotonic_ns_available = (int)node->monotonic_ns_available;
    record->wall_unix_ns_available = (int)node->wall_unix_ns_available;
    record->fd                     = node->fd;
    record->cloexec                = (int)node->cloexec;
    record->size                   = node->size;
    record->line_number            = node->line_number;
    record->function_name          = owned->function_name;
    record->file_name              = owned->file_name;
    record->call_name              = owned->call_name;
    record->arguments              = owned->arguments;
    record->result                 = owned->result;
    record->ptr                    = owned->ptr;
    record->new_ptr                = owned->new_ptr;
    record->target                 = owned->target;
    record->resource_class         = owned->resource_class;
    record->resource_id            = owned->resource_id;
    record->related_id             = owned->related_id;
    record->metadata               = owned->metadata;
}

size_t p101_tool_model_node_count(const struct p101_tool_model *model)
{
    return model == NULL ? 0U : model->node_count;
}

const struct p101_tool_model_node *p101_tool_model_node_at(const struct p101_tool_model *model, size_t index)
{
    const struct p101_tool_model_node *p101_single_result_;
    if(model == NULL || index >= model->node_count)
    {
        p101_single_result_ = NULL;
        goto p101_single_exit_;
    }
    p101_single_result_ = &model->nodes[index].value;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

size_t p101_tool_model_edge_count(const struct p101_tool_model *model)
{
    return model == NULL ? 0U : model->edge_count;
}

const struct p101_tool_model_edge *p101_tool_model_edge_at(const struct p101_tool_model *model, size_t index)
{
    const struct p101_tool_model_edge *p101_single_result_;
    if(model == NULL || index >= model->edge_count)
    {
        p101_single_result_ = NULL;
        goto p101_single_exit_;
    }
    p101_single_result_ = &model->edges[index];
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static char *copy_text(struct p101_error *err, const char *text)
{
    char       *p101_single_result_;
    const char *source;
    char       *copy;
    size_t      length;

    source = text == NULL ? "" : text;
    length = strlen(source);
    copy   = (char *)model_allocate(length + 1U);
    if(copy == NULL)
    {
        P101_ERROR_RAISE_ERRNO(err, errno == 0 ? ENOMEM : errno);
        p101_single_result_ = NULL;
        goto p101_single_exit_;
    }
    memcpy(copy, source, length + 1U);
    p101_single_result_ = copy;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static int reserve_nodes(struct p101_error *err, struct p101_tool_model *model)
{
    int                                p101_single_result_;
    struct p101_tool_model_owned_node *nodes;
    size_t                             capacity;

    if(model->node_count < model->node_capacity)
    {
        p101_single_result_ = 0;
        goto p101_single_exit_;
    }
    // GCOVR_EXCL_START: reaching the million-node hard limit is intentionally
    // outside the bounded unit corpus; growth and allocation failure are tested.
    if(model->node_capacity >= MODEL_LIMIT)
    {
        P101_ERROR_RAISE_ERRNO(err, EOVERFLOW);
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    // GCOVR_EXCL_STOP
    capacity = model->node_capacity == 0U ? INITIAL_CAPACITY : model->node_capacity * 2U;
    nodes    = (struct p101_tool_model_owned_node *)model_reallocate(model->nodes, capacity * sizeof(*nodes));
    if(nodes == NULL)
    {
        P101_ERROR_RAISE_ERRNO(err, errno == 0 ? ENOMEM : errno);
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    model->nodes         = nodes;
    model->node_capacity = capacity;
    p101_single_result_  = 0;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static int reserve_edges(struct p101_error *err, struct p101_tool_model *model)
{
    int                          p101_single_result_;
    struct p101_tool_model_edge *edges;
    size_t                       capacity;

    if(model->edge_count < model->edge_capacity)
    {
        p101_single_result_ = 0;
        goto p101_single_exit_;
    }
    // GCOVR_EXCL_START: reaching the million-edge hard limit is intentionally
    // outside the bounded unit corpus; growth and allocation failure are tested.
    if(model->edge_capacity >= MODEL_LIMIT)
    {
        P101_ERROR_RAISE_ERRNO(err, EOVERFLOW);
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    // GCOVR_EXCL_STOP
    capacity = model->edge_capacity == 0U ? INITIAL_CAPACITY : model->edge_capacity * 2U;
    edges    = (struct p101_tool_model_edge *)model_reallocate(model->edges, capacity * sizeof(*edges));
    if(edges == NULL)
    {
        P101_ERROR_RAISE_ERRNO(err, errno == 0 ? ENOMEM : errno);
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    model->edges         = edges;
    model->edge_capacity = capacity;
    p101_single_result_  = 0;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static int add_edge(struct p101_error *err, struct p101_tool_model *model, p101_tool_model_edge_kind kind, size_t from, size_t to)
{
    int p101_single_result_;
    if(reserve_edges(err, model) != 0)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    model->edges[model->edge_count].kind = kind;
    model->edges[model->edge_count].from = from;
    model->edges[model->edge_count].to   = to;
    model->edge_count++;
    p101_single_result_ = 0;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static void copy_record(struct p101_tool_model_owned_node *node, const struct p101_tool_event_record *record)
{
    node->value.domain                 = record->record_kind == P101_TOOL_EVENT_RECORD_CALL ? P101_TOOL_MODEL_NODE_CALL : P101_TOOL_MODEL_NODE_RESOURCE;
    node->value.record_kind            = record->record_kind;
    node->value.call_kind              = record->call_kind;
    node->value.fd_kind                = record->fd_kind;
    node->value.alloc_kind             = record->alloc_kind;
    node->value.resource_kind          = record->resource_kind;
    node->value.pid                    = record->pid;
    node->value.child_pid              = record->child_pid;
    node->value.context_id             = record->context_id;
    node->value.sequence               = record->sequence;
    node->value.monotonic_ns           = record->monotonic_ns;
    node->value.wall_unix_ns           = record->wall_unix_ns;
    node->value.monotonic_ns_available = record->monotonic_ns_available != 0;
    node->value.wall_unix_ns_available = record->wall_unix_ns_available != 0;
    node->value.fd                     = record->fd;
    node->value.cloexec                = record->cloexec != 0;
    node->value.size                   = record->size;
    node->value.line_number            = record->line_number;
}

static int copy_record_text(struct p101_error *err, struct p101_tool_model_owned_node *node, const struct p101_tool_event_record *record)
{
    int result;

#define COPY_FIELD(field)                                                                                                                                                                                                                                          \
    do                                                                                                                                                                                                                                                             \
    {                                                                                                                                                                                                                                                              \
        node->field = copy_text(err, record->field);                                                                                                                                                                                                               \
        if(node->field == NULL)                                                                                                                                                                                                                                    \
        {                                                                                                                                                                                                                                                          \
            result = -1;                                                                                                                                                                                                                                           \
            goto done;                                                                                                                                                                                                                                             \
        }                                                                                                                                                                                                                                                          \
        node->value.field = node->field;                                                                                                                                                                                                                           \
    } while(0)

    result = 0;
    COPY_FIELD(run_id);
    COPY_FIELD(function_name);
    COPY_FIELD(file_name);
    COPY_FIELD(call_name);
    COPY_FIELD(arguments);
    COPY_FIELD(result);
    COPY_FIELD(ptr);
    COPY_FIELD(new_ptr);
    COPY_FIELD(target);
    COPY_FIELD(resource_class);
    COPY_FIELD(resource_id);
    COPY_FIELD(related_id);
    COPY_FIELD(metadata);
#undef COPY_FIELD
done:
    return result;
}

static void free_node(struct p101_tool_model_owned_node *node)
{
    free(node->run_id);
    free(node->function_name);
    free(node->file_name);
    free(node->call_name);
    free(node->arguments);
    free(node->result);
    free(node->ptr);
    free(node->new_ptr);
    free(node->target);
    free(node->resource_class);
    free(node->resource_id);
    free(node->related_id);
    free(node->metadata);
    memset(node, 0, sizeof(*node));
}

static int same_context(const struct p101_tool_model_node *left, const struct p101_tool_model_node *right)
{
    /*
     * Ingestion rejects mixed run identifiers, so every node in one model
     * already has the same run identity. Rechecking it here added an
     * unreachable branch without strengthening the causal match.
     */
    return left->pid == right->pid && left->context_id == right->context_id;
}

static size_t find_active_enter(const struct p101_tool_model *model, const size_t *matched_exit, size_t node_index, int require_name)
{
    size_t                             p101_single_result_;
    const struct p101_tool_model_node *current;

    current = &model->nodes[node_index].value;
    for(size_t cursor = node_index; cursor > 0U; cursor--)
    {
        size_t                             candidate_index;
        const struct p101_tool_model_node *candidate;

        candidate_index = cursor - 1U;
        candidate       = &model->nodes[candidate_index].value;
        if(candidate->record_kind == P101_TOOL_EVENT_RECORD_CALL && candidate->call_kind == P101_TOOL_EVENT_CALL_ENTER && matched_exit[candidate_index] == SIZE_MAX && same_context(candidate, current) != 0 &&
           (require_name == 0 || strcmp(candidate->call_name, current->call_name) == 0))
        {
            p101_single_result_ = candidate_index;
            goto p101_single_exit_;
        }
    }
    p101_single_result_ = SIZE_MAX;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static size_t find_enclosing_call(const struct p101_tool_model *model, const size_t *matched_exit, size_t resource_index)
{
    const struct p101_tool_model_node *resource;
    size_t                             match;

    resource = &model->nodes[resource_index].value;
    match    = SIZE_MAX;
    for(size_t index = 0U; index < model->node_count; index++)
    {
        const struct p101_tool_model_node *enter;
        size_t                             exit_index;

        enter = &model->nodes[index].value;
        if(enter->record_kind != P101_TOOL_EVENT_RECORD_CALL || enter->call_kind != P101_TOOL_EVENT_CALL_ENTER || same_context(enter, resource) == 0 || enter->sequence > resource->sequence)
        {
            continue;
        }
        exit_index = matched_exit[index];
        if(exit_index != SIZE_MAX && model->nodes[exit_index].value.sequence < resource->sequence)
        {
            continue;
        }
        if(match == SIZE_MAX || model->nodes[match].value.sequence < enter->sequence)
        {
            match = index;
        }
    }
    return match;
}

static size_t find_lifetime_end(const struct p101_tool_model *model, size_t birth_index)
{
    size_t                             p101_single_result_;
    const struct p101_tool_model_node *birth;
    size_t                             match;

    birth = &model->nodes[birth_index].value;
    if(is_lifetime_birth(birth) == 0)
    {
        p101_single_result_ = SIZE_MAX;
        goto p101_single_exit_;
    }
    match = SIZE_MAX;
    for(size_t index = 0U; index < model->node_count; index++)
    {
        const struct p101_tool_model_node *death;

        death = &model->nodes[index].value;
        if(death->sequence > birth->sequence && death->pid == birth->pid && lifetime_matches(birth, death) != 0 && (match == SIZE_MAX || death->sequence < model->nodes[match].value.sequence))
        {
            match = index;
        }
    }
    p101_single_result_ = match;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static int is_lifetime_birth(const struct p101_tool_model_node *node)
{
    int p101_single_result_;
    if(node->record_kind == P101_TOOL_EVENT_RECORD_FD)
    {
        p101_single_result_ = node->fd_kind == P101_TOOL_EVENT_FD_OPEN;
        goto p101_single_exit_;
    }
    if(node->record_kind == P101_TOOL_EVENT_RECORD_ALLOC)
    {
        p101_single_result_ = node->alloc_kind == P101_TOOL_EVENT_ALLOC_ALLOC || (node->alloc_kind == P101_TOOL_EVENT_ALLOC_REALLOC && pointer_is_null(node->new_ptr) == 0);
        goto p101_single_exit_;
    }
    if(node->record_kind == P101_TOOL_EVENT_RECORD_RESOURCE)
    {
        p101_single_result_ = node->resource_kind == P101_TOOL_EVENT_RESOURCE_ACQUIRE || ((node->resource_kind == P101_TOOL_EVENT_RESOURCE_REPLACE || node->resource_kind == P101_TOOL_EVENT_RESOURCE_TRANSFER) && node->related_id[0] != '\0');
        goto p101_single_exit_;
    }
    p101_single_result_ = 0;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static int lifetime_matches(const struct p101_tool_model_node *birth, const struct p101_tool_model_node *death)
{
    int         p101_single_result_;
    const char *birth_id;

    if(birth->record_kind == P101_TOOL_EVENT_RECORD_FD)
    {
        p101_single_result_ = death->record_kind == P101_TOOL_EVENT_RECORD_FD && death->fd_kind == P101_TOOL_EVENT_FD_CLOSE && death->fd == birth->fd;
        goto p101_single_exit_;
    }
    if(birth->record_kind == P101_TOOL_EVENT_RECORD_ALLOC)
    {
        birth_id = birth->alloc_kind == P101_TOOL_EVENT_ALLOC_REALLOC ? birth->new_ptr : birth->ptr;
        p101_single_result_ =
            (death->record_kind == P101_TOOL_EVENT_RECORD_ALLOC && ((death->alloc_kind == P101_TOOL_EVENT_ALLOC_FREE && strcmp(death->ptr, birth_id) == 0) || (death->alloc_kind == P101_TOOL_EVENT_ALLOC_REALLOC && strcmp(death->ptr, birth_id) == 0)));
        goto p101_single_exit_;
    }
    birth_id            = birth->resource_kind == P101_TOOL_EVENT_RESOURCE_ACQUIRE ? birth->resource_id : birth->related_id;
    p101_single_result_ = (death->record_kind == P101_TOOL_EVENT_RECORD_RESOURCE && strcmp(death->resource_class, birth->resource_class) == 0 &&
                           ((death->resource_kind == P101_TOOL_EVENT_RESOURCE_RELEASE && strcmp(death->resource_id, birth_id) == 0) ||
                            ((death->resource_kind == P101_TOOL_EVENT_RESOURCE_REPLACE || death->resource_kind == P101_TOOL_EVENT_RESOURCE_TRANSFER) && strcmp(death->resource_id, birth_id) == 0)));
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static int pointer_is_null(const char *text)
{
    return text[0] == '\0' || strcmp(text, "-") == 0 || strcmp(text, "0") == 0 || strcmp(text, "0x0") == 0 || strcmp(text, "(nil)") == 0 || strcmp(text, "NULL") == 0;
}

static int build_call_edges(struct p101_error *err, struct p101_tool_model *model, size_t *matched_exit)
{
    int p101_single_result_;
    for(size_t index = 0U; index < model->node_count; index++)
    {
        const struct p101_tool_model_node *node;

        node = &model->nodes[index].value;
        if(node->record_kind != P101_TOOL_EVENT_RECORD_CALL)
        {
            continue;
        }
        if(node->call_kind == P101_TOOL_EVENT_CALL_ENTER)
        {
            size_t parent;

            parent = find_active_enter(model, matched_exit, index, 0);
            if(parent != SIZE_MAX && add_edge(err, model, P101_TOOL_MODEL_EDGE_CALL_PARENT, parent, index) != 0)
            {
                p101_single_result_ = -1;
                goto p101_single_exit_;    // GCOVR_EXCL_LINE -- reserve_edges failure is injected at its owning boundary.
            }
        }
        else
        {
            size_t enter;

            enter = find_active_enter(model, matched_exit, index, 1);
            if(enter != SIZE_MAX)
            {
                matched_exit[enter] = index;
                if(add_edge(err, model, P101_TOOL_MODEL_EDGE_CALL_RETURN, enter, index) != 0)
                {
                    p101_single_result_ = -1;
                    goto p101_single_exit_;    // GCOVR_EXCL_LINE -- reserve_edges failure is injected at its owning boundary.
                }
            }
        }
    }
    p101_single_result_ = 0;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static int build_resource_edges(struct p101_error *err, struct p101_tool_model *model, const size_t *matched_exit)
{
    int p101_single_result_;
    for(size_t index = 0U; index < model->node_count; index++)
    {
        const struct p101_tool_model_node *node;
        size_t                             call;
        size_t                             death;

        node = &model->nodes[index].value;
        if(node->domain != P101_TOOL_MODEL_NODE_RESOURCE)
        {
            continue;
        }
        call = find_enclosing_call(model, matched_exit, index);
        if(call != SIZE_MAX && add_edge(err, model, P101_TOOL_MODEL_EDGE_CALL_CAUSED_EVENT, call, index) != 0)
        {
            p101_single_result_ = -1;
            goto p101_single_exit_;    // GCOVR_EXCL_LINE -- reserve_edges failure is injected at its owning boundary.
        }
        death = find_lifetime_end(model, index);
        if(death != SIZE_MAX && add_edge(err, model, P101_TOOL_MODEL_EDGE_RESOURCE_LIFETIME, index, death) != 0)
        {
            p101_single_result_ = -1;
            goto p101_single_exit_;    // GCOVR_EXCL_LINE -- reserve_edges failure is injected at its owning boundary.
        }
        if(node->record_kind == P101_TOOL_EVENT_RECORD_FORK || node->record_kind == P101_TOOL_EVENT_RECORD_SPAWN)
        {
            for(size_t child = 0U; child < model->node_count; child++)
            {
                if(model->nodes[child].value.pid == node->child_pid && add_edge(err, model, P101_TOOL_MODEL_EDGE_PROCESS_CHILD_EVENT, index, child) != 0)
                {
                    p101_single_result_ = -1;
                    goto p101_single_exit_;    // GCOVR_EXCL_LINE -- reserve_edges failure is injected at its owning boundary.
                }
            }
        }
    }
    p101_single_result_ = 0;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}
