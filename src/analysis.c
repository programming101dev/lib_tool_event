#include <errno.h>
#include <inttypes.h>
#include <p101_error/error.h>
#include <p101_tool_event/analysis.h>
#include <p101_tool_event/lesson_catalog.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

enum
{
    INITIAL_FINDING_CAPACITY = 16,
    SYNC_KEY_ID_SIZE         = 32,
    EVIDENCE_TEXT_SIZE       = 192,
    NODE_ID_SIZE             = 384,
    TRACE_LINE_SIZE          = 2048,
    TRACE_MAX_INDENTATION    = 120,
    TRACE_INITIAL_CAPACITY   = 4096,
    PATH_SIZE                = 4096,
    OUTPUT_DIRECTORY_MODE    = 0775,
    JSON_CONTROL_LIMIT       = 0x20
};

struct owned_finding
{
    struct p101_tool_analysis_finding value;
    char                              node_id[NODE_ID_SIZE];
    char                              evidence_from[EVIDENCE_TEXT_SIZE];
    char                              evidence_to[EVIDENCE_TEXT_SIZE];
    char                              evidence_detail[EVIDENCE_TEXT_SIZE];
};

struct graph_arc
{
    size_t to;
    size_t next;
};

struct ordered_node
{
    const struct p101_tool_model_node *node;
    size_t                             original_index;
};

struct sync_item
{
    bool                               active;
    bool                               join;
    const struct p101_tool_model_node *node;
    char                               thread[EVIDENCE_TEXT_SIZE];
    char                               resource[EVIDENCE_TEXT_SIZE];
    char                               target[EVIDENCE_TEXT_SIZE];
};

struct sync_edge
{
    char from[EVIDENCE_TEXT_SIZE];
    char to[EVIDENCE_TEXT_SIZE];
};

struct sync_key
{
    char id[SYNC_KEY_ID_SIZE];
    char from[EVIDENCE_TEXT_SIZE];
    char to[EVIDENCE_TEXT_SIZE];
    char message[EVIDENCE_TEXT_SIZE];
    char file[EVIDENCE_TEXT_SIZE];
    char function[EVIDENCE_TEXT_SIZE];
    int  line;
};

struct trace_context
{
    long   pid;
    size_t context;
    size_t top;
    size_t max_depth;
    size_t depth;
    size_t unmatched;
    size_t mismatched;
};

struct trace_stack_entry
{
    size_t node_index;
    size_t previous;
};

struct p101_tool_analysis
{
    const struct p101_tool_model *model;
    struct ordered_node          *ordered;
    size_t                        ordered_count;
    struct owned_finding         *findings;
    size_t                        finding_count;
    size_t                        finding_capacity;
    size_t                        policy_counts[4];
    size_t                        resource_records;
    size_t                        synchronization_records;
    size_t                        lock_order_edges;
    size_t                        call_records;
    size_t                        sanitizer_records;
    size_t                        sanitizer_counts[4];
    struct trace_context         *trace_contexts;
    size_t                        trace_context_count;
    char                         *trace_tree;
    size_t                        trace_tree_length;
    size_t                        trace_tree_capacity;
    bool                          trouble;
};

static int build_causal_order(struct p101_error *err, struct p101_tool_analysis *analysis);
static int analyze_resources(struct p101_error *err, struct p101_tool_analysis *analysis);
static int analyze_synchronization(struct p101_error *err, struct p101_tool_analysis *analysis);
static int analyze_trace(struct p101_error *err, struct p101_tool_analysis *analysis);
static int analyze_sanitizer(struct p101_error *err, struct p101_tool_analysis *analysis, const char *path);
static int add_finding(struct p101_error *err, struct p101_tool_analysis *analysis, const char *identifier, p101_tool_analysis_policy policy, const char *message, const struct p101_tool_model_node *node, const char *from, const char *to, const char *detail);
static int reserve_findings(struct p101_error *err, struct p101_tool_analysis *analysis);
static int append_trace(struct p101_error *err, struct p101_tool_analysis *analysis, const char *text);
static int append_trace_line(struct p101_error *err, struct p101_tool_analysis *analysis, const struct p101_tool_model_node *node, size_t depth, bool entering);
static const char           *node_kind(const struct p101_tool_model_node *node);
static void                  format_node_id(char destination[NODE_ID_SIZE], const struct p101_tool_model_node *node);
static int                   ordered_node_compare(const void *left, const void *right);
static int                   heap_push(size_t *heap, size_t capacity, size_t *size, size_t value);
static size_t                heap_pop(size_t *heap, size_t *size);
static int                   add_arc(struct graph_arc *arcs, size_t arc_capacity, size_t *arc_count, size_t *heads, size_t *indegree, size_t node_count, size_t from, size_t to);
static bool                  same_context(const struct p101_tool_model_node *left, const struct p101_tool_model_node *right);
static const char           *lifecycle_identifier(const struct p101_tool_event_lifecycle_finding *finding);
static const char           *lifecycle_message(const char *identifier);
static bool                  synchronization_class(const char *resource_class);
static bool                  held_class(const char *resource_class);
static void                  format_sync_thread(char destination[EVIDENCE_TEXT_SIZE], const struct p101_tool_model_node *node);
static void                  format_sync_resource(char destination[EVIDENCE_TEXT_SIZE], const struct p101_tool_model_node *node, const char *identity);
static bool                  sync_reaches(const struct sync_edge *edges, size_t edge_count, const char *start, const char *target, bool joins_only);
static int                   add_sync_finding(struct p101_error *err, struct p101_tool_analysis *analysis, const char *identifier, const struct p101_tool_model_node *node, const char *from, const char *to);
static struct trace_context *trace_context(struct p101_error *err, struct p101_tool_analysis *analysis, long pid, size_t context);
static int                   write_text_reports(struct p101_error *err, const struct p101_tool_analysis *analysis, const char *directory);
static int                   write_json_reports(struct p101_error *err, const struct p101_tool_analysis *analysis, const char *directory);
static int                   write_graph(struct p101_error *err, const struct p101_tool_analysis *analysis, const char *directory);
static int                   open_output(struct p101_error *err, const char *directory, const char *name, FILE **stream);
static int                   close_output(struct p101_error *err, FILE **stream);
static int                   write_json_string(FILE *stream, const char *text);
static int                   write_string(FILE *stream, const char *text);
static int                   write_json_document(FILE *stream, const struct p101_tool_analysis *analysis, const char *schema, int policy);
static int                   write_finding_json(FILE *stream, const struct p101_tool_analysis_finding *finding);
static const char           *policy_name(p101_tool_analysis_policy policy);
static int                   collect_prefix_sync_keys(struct p101_error *err, struct ordered_node *order, size_t count, struct sync_key **keys, size_t *key_count);
static bool                  sync_key_present(const struct sync_key *keys, size_t count, const struct p101_tool_analysis_finding *finding);
static int                   append_sync_key(struct p101_error *err, struct sync_key **keys, size_t *count, const struct p101_tool_analysis_finding *finding);
static bool                  interleaving_node(const struct p101_tool_model_node *node);
static bool                  same_sync_thread(const struct p101_tool_model_node *left, const struct p101_tool_model_node *right);
static bool                  directly_ordered(const struct p101_tool_analysis *analysis, size_t left, size_t right);
static bool                  schedule_seen(const size_t *orders, size_t order_count, size_t node_count, const size_t *candidate);
static int                   write_sync_key_json(FILE *stream, const struct sync_key *key);

struct p101_tool_analysis *p101_tool_analysis_create(struct p101_error *err, const struct p101_tool_model *model)
{
    struct p101_tool_analysis *p101_single_result_;
    struct p101_tool_analysis *analysis;
    void                      *allocation;

    analysis = NULL;
    if(model == NULL)
    {
        P101_ERROR_RAISE_ERRNO(err, EINVAL);
        goto p101_single_exit_;
    }
    allocation = calloc(1U, sizeof(*analysis));
    analysis   = (struct p101_tool_analysis *)allocation;
    if(analysis == NULL)
    {
        P101_ERROR_RAISE_ERRNO(err, ENOMEM);
        goto p101_single_exit_;
    }
    analysis->model = model;

p101_single_exit_:
    p101_single_result_ = analysis;
    return p101_single_result_;
}

void p101_tool_analysis_destroy(struct p101_tool_analysis **analysis)
{
    if(analysis != NULL && *analysis != NULL)
    {
        free((*analysis)->ordered);
        free((*analysis)->findings);
        free((*analysis)->trace_contexts);
        free((*analysis)->trace_tree);
        free(*analysis);
        *analysis = NULL;
    }
}

int p101_tool_analysis_run(struct p101_error *err, struct p101_tool_analysis *analysis, const char *sanitizer_path)
{
    int p101_single_result_;
    int operation_status;

    if(analysis == NULL || analysis->ordered != NULL)
    {
        P101_ERROR_RAISE_ERRNO(err, EINVAL);
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    operation_status = build_causal_order(err, analysis);
    if(operation_status == 0)
    {
        operation_status = analyze_resources(err, analysis);
    }
    if(operation_status == 0)
    {
        operation_status = analyze_synchronization(err, analysis);
    }
    if(operation_status == 0)
    {
        operation_status = analyze_trace(err, analysis);
    }
    if(operation_status == 0)
    {
        operation_status = analyze_sanitizer(err, analysis, sanitizer_path);
    }
    p101_single_result_ = operation_status;

p101_single_exit_:
    return p101_single_result_;
}

size_t p101_tool_analysis_finding_count(const struct p101_tool_analysis *analysis)
{
    size_t p101_single_result_;

    p101_single_result_ = analysis == NULL ? 0U : analysis->finding_count;
    return p101_single_result_;
}

const struct p101_tool_analysis_finding *p101_tool_analysis_finding_at(const struct p101_tool_analysis *analysis, size_t index)
{
    const struct p101_tool_analysis_finding *p101_single_result_;

    p101_single_result_ = NULL;
    if(analysis != NULL && index < analysis->finding_count)
    {
        p101_single_result_ = &analysis->findings[index].value;
    }
    return p101_single_result_;
}

size_t p101_tool_analysis_policy_finding_count(const struct p101_tool_analysis *analysis, p101_tool_analysis_policy policy)
{
    size_t p101_single_result_;

    p101_single_result_ = 0U;
    if(analysis != NULL && policy >= P101_TOOL_ANALYSIS_RESOURCE && policy <= P101_TOOL_ANALYSIS_SANITIZER)
    {
        p101_single_result_ = analysis->policy_counts[(size_t)policy];
    }
    return p101_single_result_;
}

int p101_tool_analysis_status(const struct p101_tool_analysis *analysis)
{
    int p101_single_result_;

    p101_single_result_ = 2;
    if(analysis != NULL && !analysis->trouble)
    {
        p101_single_result_ = analysis->finding_count == 0U ? 0 : 1;
    }
    return p101_single_result_;
}

int p101_tool_analysis_policy_status(const struct p101_tool_analysis *analysis, p101_tool_analysis_policy policy)
{
    int p101_single_result_;

    p101_single_result_ = 2;
    if(analysis != NULL && !analysis->trouble && policy >= P101_TOOL_ANALYSIS_RESOURCE && policy <= P101_TOOL_ANALYSIS_SANITIZER)
    {
        p101_single_result_ = analysis->policy_counts[(size_t)policy] == 0U ? 0 : 1;
    }
    return p101_single_result_;
}

static int build_causal_order(struct p101_error *err, struct p101_tool_analysis *analysis)
{
    int                  p101_single_result_;
    size_t               node_count;
    size_t               model_edge_count;
    struct ordered_node *by_context;
    size_t              *heads;
    size_t              *indegree;
    size_t              *heap;
    struct graph_arc    *arcs;
    size_t               arc_capacity;
    size_t               arc_count;
    size_t               heap_size;
    size_t               emitted;
    int                  operation_status;
    size_t               allocation_count;
    size_t               allocation_bytes;
    void                *allocation;

    node_count       = p101_tool_model_node_count(analysis->model);
    model_edge_count = p101_tool_model_edge_count(analysis->model);
    by_context       = NULL;
    heads            = NULL;
    indegree         = NULL;
    heap             = NULL;
    arcs             = NULL;
    operation_status = -1;
    if(model_edge_count > SIZE_MAX - node_count)
    {
        P101_ERROR_RAISE_ERRNO(err, EOVERFLOW);
        goto done;
    }
    arc_capacity      = model_edge_count + node_count;
    allocation_count  = node_count == 0U ? 1U : node_count;
    allocation        = calloc(allocation_count, sizeof(*analysis->ordered));
    analysis->ordered = (struct ordered_node *)allocation;
    allocation        = calloc(allocation_count, sizeof(*by_context));
    by_context        = (struct ordered_node *)allocation;
    allocation        = calloc(allocation_count, sizeof(*heads));
    heads             = (size_t *)allocation;
    allocation        = calloc(allocation_count, sizeof(*indegree));
    indegree          = (size_t *)allocation;
    allocation_bytes  = allocation_count * sizeof(*heap);
    allocation        = malloc(allocation_bytes);
    heap              = (size_t *)allocation;
    allocation_count  = arc_capacity == 0U ? 1U : arc_capacity;
    allocation        = calloc(allocation_count, sizeof(*arcs));
    arcs              = (struct graph_arc *)allocation;
    if(analysis->ordered == NULL || by_context == NULL || heads == NULL || indegree == NULL || heap == NULL || arcs == NULL)
    {
        P101_ERROR_RAISE_ERRNO(err, ENOMEM);
        goto done;
    }
    for(size_t index = 0U; index < node_count; index++)
    {
        const struct p101_tool_model_node *node;

        node                             = p101_tool_model_node_at(analysis->model, index);
        by_context[index].node           = node;
        by_context[index].original_index = index;
        heads[index]                     = SIZE_MAX;
    }
    arc_count = 0U;
    for(size_t index = 0U; index < model_edge_count; index++)
    {
        const struct p101_tool_model_edge *edge;

        edge             = p101_tool_model_edge_at(analysis->model, index);
        operation_status = add_arc(arcs, arc_capacity, &arc_count, heads, indegree, node_count, edge->from, edge->to);
        if(operation_status != 0)
        {
            P101_ERROR_RAISE_ERRNO(err, EINVAL);
            goto done;
        }
    }
    qsort(by_context, node_count, sizeof(*by_context), ordered_node_compare);
    for(size_t index = 1U; index < node_count; index++)
    {
        bool context_matches;

        context_matches = same_context(by_context[index - 1U].node, by_context[index].node);
        if(context_matches)
        {
            operation_status = add_arc(arcs, arc_capacity, &arc_count, heads, indegree, node_count, by_context[index - 1U].original_index, by_context[index].original_index);
            if(operation_status != 0)
            {
                P101_ERROR_RAISE_ERRNO(err, EINVAL);
                goto done;
            }
        }
    }
    heap_size = 0U;
    for(size_t index = 0U; index < node_count; index++)
    {
        if(indegree[index] == 0U)
        {
            operation_status = heap_push(heap, node_count, &heap_size, index);
            if(operation_status != 0)
            {
                P101_ERROR_RAISE_ERRNO(err, EOVERFLOW);
                goto done;
            }
        }
    }
    emitted = 0U;
    while(heap_size > 0U)
    {
        size_t current;
        size_t arc;

        current = heap_pop(heap, &heap_size);
        if(current >= node_count || emitted >= node_count)
        {
            P101_ERROR_RAISE_ERRNO(err, EINVAL);
            goto done;
        }
        analysis->ordered[emitted].node           = p101_tool_model_node_at(analysis->model, current);
        analysis->ordered[emitted].original_index = current;
        emitted++;
        arc = heads[current];
        while(arc != SIZE_MAX)
        {
            size_t destination;

            if(arc >= arc_count)
            {
                P101_ERROR_RAISE_ERRNO(err, EINVAL);
                goto done;
            }
            destination = arcs[arc].to;
            if(destination >= node_count || indegree[destination] == 0U)
            {
                P101_ERROR_RAISE_ERRNO(err, EINVAL);
                goto done;
            }
            indegree[destination]--;
            if(indegree[destination] == 0U)
            {
                operation_status = heap_push(heap, node_count, &heap_size, destination);
                if(operation_status != 0)
                {
                    P101_ERROR_RAISE_ERRNO(err, EOVERFLOW);
                    goto done;
                }
            }
            arc = arcs[arc].next;
        }
    }
    if(emitted != node_count)
    {
        P101_ERROR_RAISE_ERRNO(err, EINVAL);
        analysis->trouble = true;
        goto done;
    }
    analysis->ordered_count = emitted;
    operation_status        = 0;

done:
    free(by_context);
    free(heads);
    free(indegree);
    free(heap);
    free(arcs);
    p101_single_result_ = operation_status;
    return p101_single_result_;
}

static int ordered_node_compare(const void *left, const void *right)
{
    int                        p101_single_result_;
    const struct ordered_node *left_value;
    const struct ordered_node *right_value;

    left_value  = (const struct ordered_node *)left;
    right_value = (const struct ordered_node *)right;
    if(left_value->node->pid != right_value->node->pid)
    {
        p101_single_result_ = left_value->node->pid < right_value->node->pid ? -1 : 1;
    }
    else if(left_value->node->context_id != right_value->node->context_id)
    {
        p101_single_result_ = left_value->node->context_id < right_value->node->context_id ? -1 : 1;
    }
    else if(left_value->node->sequence != right_value->node->sequence)
    {
        p101_single_result_ = left_value->node->sequence < right_value->node->sequence ? -1 : 1;
    }
    else
    {
        if(left_value->original_index == right_value->original_index)
        {
            p101_single_result_ = 0;
        }
        else if(left_value->original_index < right_value->original_index)
        {
            p101_single_result_ = -1;
        }
        else
        {
            p101_single_result_ = 1;
        }
    }
    return p101_single_result_;
}

static bool same_context(const struct p101_tool_model_node *left, const struct p101_tool_model_node *right)
{
    bool p101_single_result_;

    p101_single_result_ = (_Bool)((left->pid == right->pid && left->context_id == right->context_id) != 0);
    return p101_single_result_;
}

static int add_arc(struct graph_arc *arcs, size_t arc_capacity, size_t *arc_count, size_t *heads, size_t *indegree, size_t node_count, size_t from, size_t to)
{
    int    p101_single_result_;
    bool   duplicate;
    size_t arc;

    if(from >= node_count || to >= node_count || *arc_count > arc_capacity)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    duplicate = (_Bool)((from == to) != 0);
    arc       = heads[from];
    while(!duplicate && arc != SIZE_MAX)
    {
        duplicate = (_Bool)((arcs[arc].to == to) != 0);
        arc       = arcs[arc].next;
    }
    if(!duplicate)
    {
        if(*arc_count == arc_capacity)
        {
            p101_single_result_ = -1;
            goto p101_single_exit_;
        }
        arcs[*arc_count].to   = to;
        arcs[*arc_count].next = heads[from];
        heads[from]           = *arc_count;
        (*arc_count)++;
        indegree[to]++;
    }
    p101_single_result_ = 0;

p101_single_exit_:
    return p101_single_result_;
}

static int heap_push(size_t *heap, size_t capacity, size_t *size, size_t value)
{
    int    p101_single_result_;
    size_t index;

    if(*size >= capacity)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    index = *size;
    (*size)++;
    while(index > 0U)
    {
        size_t parent;

        parent = (index - 1U) / 2U;
        if(heap[parent] <= value)
        {
            break;
        }
        heap[index] = heap[parent];
        index       = parent;
    }
    heap[index]         = value;
    p101_single_result_ = 0;

p101_single_exit_:
    return p101_single_result_;
}

static size_t heap_pop(size_t *heap, size_t *size)
{
    size_t p101_single_result_;
    size_t root;
    size_t value;
    size_t index;

    root = heap[0];
    (*size)--;
    value = heap[*size];
    index = 0U;
    while((index * 2U) + 1U < *size)
    {
        size_t child;

        child = (index * 2U) + 1U;
        if(child + 1U < *size && heap[child + 1U] < heap[child])
        {
            child++;
        }
        if(heap[child] >= value)
        {
            break;
        }
        heap[index] = heap[child];
        index       = child;
    }
    if(*size > 0U)
    {
        heap[index] = value;
    }
    p101_single_result_ = root;
    return p101_single_result_;
}

static int reserve_findings(struct p101_error *err, struct p101_tool_analysis *analysis)
{
    int                   p101_single_result_;
    size_t                new_capacity;
    struct owned_finding *storage;
    void                 *allocation;

    if(analysis->finding_count < analysis->finding_capacity)
    {
        p101_single_result_ = 0;
        goto p101_single_exit_;
    }
    new_capacity = analysis->finding_capacity == 0U ? INITIAL_FINDING_CAPACITY : analysis->finding_capacity * 2U;
    if(new_capacity < analysis->finding_capacity || new_capacity > SIZE_MAX / sizeof(*analysis->findings))
    {
        P101_ERROR_RAISE_ERRNO(err, EOVERFLOW);
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    allocation = realloc(analysis->findings, new_capacity * sizeof(*analysis->findings));
    storage    = (struct owned_finding *)allocation;
    if(storage == NULL)
    {
        P101_ERROR_RAISE_ERRNO(err, ENOMEM);
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    analysis->findings         = storage;
    analysis->finding_capacity = new_capacity;
    p101_single_result_        = 0;

p101_single_exit_:
    return p101_single_result_;
}

static int add_finding(struct p101_error *err, struct p101_tool_analysis *analysis, const char *identifier, p101_tool_analysis_policy policy, const char *message, const struct p101_tool_model_node *node, const char *from, const char *to, const char *detail)
{
    int                   p101_single_result_;
    int                   operation_status;
    struct owned_finding *finding;

    operation_status = reserve_findings(err, analysis);
    if(operation_status != 0)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    finding = &analysis->findings[analysis->finding_count];
    memset(finding, 0, sizeof(*finding));
    format_node_id(finding->node_id, node);
    if(from != NULL)
    {
        operation_status = snprintf(finding->evidence_from, sizeof(finding->evidence_from), "%s", from);
        if(operation_status < 0 || (size_t)operation_status >= sizeof(finding->evidence_from))
        {
            P101_ERROR_RAISE_ERRNO(err, EOVERFLOW);
            p101_single_result_ = -1;
            goto p101_single_exit_;
        }
    }
    if(to != NULL)
    {
        operation_status = snprintf(finding->evidence_to, sizeof(finding->evidence_to), "%s", to);
        if(operation_status < 0 || (size_t)operation_status >= sizeof(finding->evidence_to))
        {
            P101_ERROR_RAISE_ERRNO(err, EOVERFLOW);
            p101_single_result_ = -1;
            goto p101_single_exit_;
        }
    }
    if(detail != NULL)
    {
        operation_status = snprintf(finding->evidence_detail, sizeof(finding->evidence_detail), "%s", detail);
        if(operation_status < 0 || (size_t)operation_status >= sizeof(finding->evidence_detail))
        {
            P101_ERROR_RAISE_ERRNO(err, EOVERFLOW);
            p101_single_result_ = -1;
            goto p101_single_exit_;
        }
    }
    finding->value.diagnostic_id   = identifier;
    finding->value.policy          = policy;
    finding->value.message         = message;
    finding->value.node_id         = finding->node_id;
    finding->value.file_name       = node == NULL || node->file_name == NULL ? "?" : node->file_name;
    finding->value.function_name   = node == NULL || node->function_name == NULL ? "?" : node->function_name;
    finding->value.line_number     = node == NULL ? 0 : node->line_number;
    finding->value.evidence_from   = finding->evidence_from;
    finding->value.evidence_to     = finding->evidence_to;
    finding->value.evidence_detail = finding->evidence_detail;
    analysis->finding_count++;
    analysis->policy_counts[(size_t)policy]++;
    p101_single_result_ = 0;

p101_single_exit_:
    return p101_single_result_;
}

static const struct p101_tool_model_node *find_node(const struct p101_tool_analysis *analysis, long pid, size_t context, size_t sequence)
{
    const struct p101_tool_model_node *p101_single_result_;

    p101_single_result_ = NULL;
    for(size_t index = 0U; index < analysis->ordered_count; index++)
    {
        const struct p101_tool_model_node *node;

        node = analysis->ordered[index].node;
        if(node->pid == pid && node->context_id == context && node->sequence == sequence)
        {
            p101_single_result_ = node;
            break;
        }
    }
    return p101_single_result_;
}

static int analyze_resources(struct p101_error *err, struct p101_tool_analysis *analysis)
{
    int    p101_single_result_;
    size_t finding_count;
    int    operation_status;

    analysis->resource_records = 0U;
    for(size_t index = 0U; index < analysis->ordered_count; index++)
    {
        if(analysis->ordered[index].node->domain == P101_TOOL_MODEL_NODE_RESOURCE)
        {
            analysis->resource_records++;
        }
    }
    finding_count = p101_tool_model_lifecycle_finding_count(analysis->model);
    for(size_t index = 0U; index < finding_count; index++)
    {
        const struct p101_tool_event_lifecycle_finding *lifecycle_finding;
        const struct p101_tool_model_node              *node;
        const char                                     *identifier;
        const char                                     *message;

        lifecycle_finding = p101_tool_model_lifecycle_finding_at(analysis->model, index);
        if(lifecycle_finding == NULL)
        {
            P101_ERROR_RAISE_ERRNO(err, EINVAL);
            p101_single_result_ = -1;
            goto p101_single_exit_;
        }
        node             = find_node(analysis, lifecycle_finding->pid, lifecycle_finding->context_id, lifecycle_finding->sequence);
        identifier       = lifecycle_identifier(lifecycle_finding);
        message          = lifecycle_message(identifier);
        operation_status = add_finding(err, analysis, identifier, P101_TOOL_ANALYSIS_RESOURCE, message, node, lifecycle_finding->resource_class, lifecycle_finding->resource_id, NULL);
        if(operation_status != 0)
        {
            p101_single_result_ = -1;
            goto p101_single_exit_;
        }
    }
    p101_single_result_ = 0;

p101_single_exit_:
    return p101_single_result_;
}

static const char *lifecycle_identifier(const struct p101_tool_event_lifecycle_finding *finding)
{
    const char *p101_single_result_;
    bool        descriptor;
    bool        allocation;
    int         comparison;

    comparison = strcmp(finding->resource_class, "fd");
    descriptor = comparison == 0;
    comparison = strcmp(finding->resource_class, "allocation");
    allocation = comparison == 0;
#ifdef __clang__
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wcovered-switch-default"
#endif
    switch(finding->kind)
    {
        case P101_TOOL_EVENT_LIFECYCLE_FINDING_LEAK:
            if(descriptor)
            {
                p101_single_result_ = "P101-FD-001";
            }
            else if(allocation)
            {
                p101_single_result_ = "P101-ALLOC-001";
            }
            else
            {
                p101_single_result_ = "P101-RESOURCE-001";
            }
            break;
        case P101_TOOL_EVENT_LIFECYCLE_FINDING_DOUBLE_RELEASE:
            if(descriptor)
            {
                p101_single_result_ = "P101-FD-002";
            }
            else if(allocation)
            {
                p101_single_result_ = "P101-ALLOC-002";
            }
            else
            {
                p101_single_result_ = "P101-RESOURCE-002";
            }
            break;
        case P101_TOOL_EVENT_LIFECYCLE_FINDING_STRAY_RELEASE:
            if(descriptor)
            {
                p101_single_result_ = "P101-FD-003";
            }
            else if(allocation)
            {
                p101_single_result_ = "P101-ALLOC-003";
            }
            else
            {
                p101_single_result_ = "P101-RESOURCE-003";
            }
            break;
        case P101_TOOL_EVENT_LIFECYCLE_FINDING_BAD_REPLACE:
            if(allocation)
            {
                p101_single_result_ = "P101-ALLOC-004";
            }
            else
            {
                p101_single_result_ = "P101-RESOURCE-004";
            }
            break;
        case P101_TOOL_EVENT_LIFECYCLE_FINDING_DUPLICATE_ACQUIRE:
            p101_single_result_ = "P101-RESOURCE-005";
            break;
        case P101_TOOL_EVENT_LIFECYCLE_FINDING_EXEC_INHERIT:
            p101_single_result_ = "P101-FD-004";
            break;
        default:
            p101_single_result_ = "P101-RESOURCE-000";
            break;
    }
#ifdef __clang__
    #pragma clang diagnostic pop
#endif
    return p101_single_result_;
}

static const char *lifecycle_message(const char *identifier)
{
    const char *p101_single_result_;
    int         comparison;

    comparison = strcmp(identifier, "P101-FD-001");
    if(comparison == 0)
    {
        p101_single_result_ = "descriptor is still open at the end of the run";
    }
    else
    {
        static const char *const identifiers[] = {
            "P101-FD-002",
            "P101-FD-003",
            "P101-FD-004",
            "P101-ALLOC-001",
            "P101-ALLOC-002",
            "P101-ALLOC-003",
            "P101-ALLOC-004",
            "P101-RESOURCE-001",
            "P101-RESOURCE-002",
            "P101-RESOURCE-003",
            "P101-RESOURCE-004",
        };
        static const char *const messages[] = {
            "descriptor was closed more than once",
            "descriptor was closed without an observed acquisition",
            "descriptor would be inherited across exec without CLOEXEC",
            "allocation is still live at the end of the run",
            "allocation was freed more than once",
            "pointer was freed without an observed allocation",
            "realloc referenced a pointer that was not live",
            "resource is still live at the end of the run",
            "resource was released more than once",
            "resource was released without an observed acquisition",
            "resource replacement referenced a resource that was not live",
        };

        p101_single_result_ = "resource was acquired while the same identity was already live";
        for(size_t index = 0U; index < sizeof(identifiers) / sizeof(identifiers[0]); index++)
        {
            comparison = strcmp(identifier, identifiers[index]);
            if(comparison == 0)
            {
                p101_single_result_ = messages[index];
                break;
            }
        }
    }
    return p101_single_result_;
}

static const char *node_kind(const struct p101_tool_model_node *node)
{
    const char *p101_single_result_;

    if(node == NULL)
    {
        p101_single_result_ = "lifecycle";
    }
    else if(node->record_kind == P101_TOOL_EVENT_RECORD_CALL)
    {
        p101_single_result_ = node->call_kind == P101_TOOL_EVENT_CALL_ENTER ? "call-enter" : "call-exit";
    }
    else if(node->record_kind == P101_TOOL_EVENT_RECORD_RESOURCE)
    {
        p101_single_result_ = "resource";
    }
    else if(node->record_kind == P101_TOOL_EVENT_RECORD_FORK)
    {
        p101_single_result_ = "fork";
    }
    else if(node->record_kind == P101_TOOL_EVENT_RECORD_SPAWN)
    {
        p101_single_result_ = "spawn";
    }
    else if(node->record_kind == P101_TOOL_EVENT_RECORD_EXEC)
    {
        p101_single_result_ = "exec";
    }
    else if(node->record_kind == P101_TOOL_EVENT_RECORD_EXEC_FAIL)
    {
        p101_single_result_ = "exec-fail";
    }
    else if(node->record_kind == P101_TOOL_EVENT_RECORD_FD)
    {
        p101_single_result_ = "fd";
    }
    else
    {
        p101_single_result_ = "allocation";
    }
    return p101_single_result_;
}

static void format_node_id(char destination[NODE_ID_SIZE], const struct p101_tool_model_node *node)
{
    const char *domain;
    const char *kind;
    const char *run_id;
    int         operation_status;

    if(node == NULL)
    {
        operation_status = snprintf(destination, NODE_ID_SIZE, "lifecycle:unknown");
        (void)operation_status;
        goto p101_single_exit_;
    }
    domain           = node->domain == P101_TOOL_MODEL_NODE_CALL ? "call" : "resource";
    kind             = node_kind(node);
    run_id           = node->run_id == NULL ? "?" : node->run_id;
    operation_status = snprintf(destination, NODE_ID_SIZE, "%s:%s:%ld:%zu:%zu:%s", domain, run_id, node->pid, node->context_id, node->sequence, kind);
    (void)operation_status;

p101_single_exit_:
    return;
}

static bool held_class(const char *resource_class)
{
    bool p101_single_result_;
    int  mutex_comparison;
    int  rwlock_comparison;

    mutex_comparison    = strcmp(resource_class, "pthread-mutex-held");
    rwlock_comparison   = strcmp(resource_class, "pthread-rwlock-held");
    p101_single_result_ = (_Bool)((mutex_comparison == 0 || rwlock_comparison == 0) != 0);
    return p101_single_result_;
}

static bool synchronization_class(const char *resource_class)
{
    bool p101_single_result_;
    bool is_held;
    int  mutex_wait;
    int  read_wait;
    int  write_wait;
    int  condition_wait;
    int  join_wait;

    is_held             = held_class(resource_class);
    mutex_wait          = strcmp(resource_class, "pthread-mutex-wait");
    read_wait           = strcmp(resource_class, "pthread-rwlock-read-wait");
    write_wait          = strcmp(resource_class, "pthread-rwlock-write-wait");
    condition_wait      = strcmp(resource_class, "pthread-condition-wait");
    join_wait           = strcmp(resource_class, "pthread-join-wait");
    p101_single_result_ = (_Bool)((is_held || mutex_wait == 0 || read_wait == 0 || write_wait == 0 || condition_wait == 0 || join_wait == 0) != 0);
    return p101_single_result_;
}

static void format_sync_thread(char destination[EVIDENCE_TEXT_SIZE], const struct p101_tool_model_node *node)
{
    const char *metadata;
    int         operation_status;

    metadata         = node->metadata == NULL || node->metadata[0] == '\0' ? "thread=?" : node->metadata;
    operation_status = snprintf(destination, EVIDENCE_TEXT_SIZE, "%ld:%zu:%s", node->pid, node->context_id, metadata);
    (void)operation_status;
}

static void format_sync_resource(char destination[EVIDENCE_TEXT_SIZE], const struct p101_tool_model_node *node, const char *identity)
{
    int         operation_status;
    size_t      identity_length;
    size_t      prefix_length;
    size_t      destination_length;
    const char *separator;

    separator          = strchr(identity, '@');
    identity_length    = strlen(identity);
    prefix_length      = separator == NULL ? identity_length : (size_t)(separator - identity);
    operation_status   = snprintf(destination, EVIDENCE_TEXT_SIZE, "%ld:", node->pid);
    destination_length = operation_status < 0 ? 0U : (size_t)operation_status;
    if(operation_status < 0)
    {
        destination[0] = '\0';
    }
    else if(destination_length >= EVIDENCE_TEXT_SIZE)
    {
        destination[EVIDENCE_TEXT_SIZE - 1U] = '\0';
    }
    else
    {
        size_t available_length;
        size_t copy_length;

        available_length = EVIDENCE_TEXT_SIZE - destination_length - 1U;
        copy_length      = prefix_length < available_length ? prefix_length : available_length;
        memcpy(destination + destination_length, identity, copy_length);
        destination[destination_length + copy_length] = '\0';
    }
}

static bool sync_reaches(const struct sync_edge *edges, size_t edge_count, const char *start, const char *target, bool joins_only)
{
    bool p101_single_result_;
    char (*pending)[EVIDENCE_TEXT_SIZE];
    char (*visited)[EVIDENCE_TEXT_SIZE];
    size_t pending_count;
    size_t visited_count;
    int    operation_status;
    size_t allocation_count;
    void  *allocation;
    int    comparison;

    (void)joins_only;
    allocation_count    = edge_count + 1U;
    allocation          = calloc(allocation_count, sizeof(*pending));
    pending             = (char (*)[EVIDENCE_TEXT_SIZE])allocation;
    allocation          = calloc(allocation_count, sizeof(*visited));
    visited             = (char (*)[EVIDENCE_TEXT_SIZE])allocation;
    pending_count       = 0U;
    visited_count       = 0U;
    comparison          = strcmp(start, target);
    p101_single_result_ = comparison == 0;
    if(pending == NULL || visited == NULL || p101_single_result_)
    {
        goto done;
    }
    operation_status = snprintf(pending[pending_count], EVIDENCE_TEXT_SIZE, "%s", start);
    (void)operation_status;
    pending_count++;
    while(pending_count > 0U && !p101_single_result_)
    {
        char current[EVIDENCE_TEXT_SIZE];
        bool already_visited;

        pending_count--;
        operation_status = snprintf(current, sizeof(current), "%s", pending[pending_count]);
        (void)operation_status;
        already_visited = false;
        for(size_t index = 0U; index < visited_count; index++)
        {
            int visited_comparison;

            visited_comparison = strcmp(visited[index], current);
            if(visited_comparison == 0)
            {
                already_visited = true;
                break;
            }
        }
        if(already_visited)
        {
            continue;
        }
        operation_status = snprintf(visited[visited_count], EVIDENCE_TEXT_SIZE, "%s", current);
        (void)operation_status;
        visited_count++;
        for(size_t index = 0U; index < edge_count; index++)
        {
            int from_comparison;
            int target_comparison;

            from_comparison = strcmp(edges[index].from, current);
            if(from_comparison != 0)
            {
                continue;
            }
            target_comparison = strcmp(edges[index].to, target);
            if(target_comparison == 0)
            {
                p101_single_result_ = true;
                break;
            }
            if(pending_count < edge_count + 1U)
            {
                operation_status = snprintf(pending[pending_count], EVIDENCE_TEXT_SIZE, "%s", edges[index].to);
                (void)operation_status;
                pending_count++;
            }
        }
    }

done:
    free(pending);
    free(visited);
    return p101_single_result_;
}

static int add_sync_finding(struct p101_error *err, struct p101_tool_analysis *analysis, const char *identifier, const struct p101_tool_model_node *node, const char *from, const char *to)
{
    int         p101_single_result_;
    const char *message;
    bool        duplicate;
    int         identifier_comparison;

    duplicate = false;
    for(size_t index = 0U; index < analysis->finding_count; index++)
    {
        const struct p101_tool_analysis_finding *finding;
        int                                      id_comparison;
        int                                      from_comparison;
        int                                      to_comparison;

        finding         = &analysis->findings[index].value;
        id_comparison   = strcmp(finding->diagnostic_id, identifier);
        from_comparison = strcmp(finding->evidence_from, from);
        to_comparison   = strcmp(finding->evidence_to, to);
        if(id_comparison == 0 && from_comparison == 0 && to_comparison == 0)
        {
            duplicate = true;
            break;
        }
    }
    if(duplicate)
    {
        p101_single_result_ = 0;
        goto p101_single_exit_;
    }
    identifier_comparison = strcmp(identifier, "P101-SYNC-001");
    if(identifier_comparison == 0)
    {
        message = "lock-order graph contains a cycle";
    }
    else
    {
        identifier_comparison = strcmp(identifier, "P101-SYNC-002");
        if(identifier_comparison == 0)
        {
            message = "live wait-for graph contains a deadlock cycle";
        }
        else
        {
            message = "thread join graph contains a cycle";
        }
    }
    p101_single_result_ = add_finding(err, analysis, identifier, P101_TOOL_ANALYSIS_SYNCHRONIZATION, message, node, from, to, NULL);

p101_single_exit_:
    return p101_single_result_;
}

static int analyze_synchronization(struct p101_error *err, struct p101_tool_analysis *analysis)
{
    int               p101_single_result_;
    struct sync_item *held;
    struct sync_item *waits;
    struct sync_edge *lock_edges;
    struct sync_edge *wait_edges;
    struct sync_edge *join_edges;
    size_t            capacity;
    size_t            held_count;
    size_t            wait_count;
    size_t            lock_edge_count;
    size_t            wait_edge_count;
    size_t            join_edge_count;
    int               operation_status;
    void             *allocation;

    capacity         = analysis->ordered_count == 0U ? 1U : analysis->ordered_count;
    allocation       = calloc(capacity, sizeof(*held));
    held             = (struct sync_item *)allocation;
    allocation       = calloc(capacity, sizeof(*waits));
    waits            = (struct sync_item *)allocation;
    allocation       = calloc(capacity, sizeof(*lock_edges));
    lock_edges       = (struct sync_edge *)allocation;
    allocation       = calloc(capacity * 2U, sizeof(*wait_edges));
    wait_edges       = (struct sync_edge *)allocation;
    allocation       = calloc(capacity, sizeof(*join_edges));
    join_edges       = (struct sync_edge *)allocation;
    held_count       = 0U;
    wait_count       = 0U;
    lock_edge_count  = 0U;
    wait_edge_count  = 0U;
    join_edge_count  = 0U;
    operation_status = 0;
    if(held == NULL || waits == NULL || lock_edges == NULL || wait_edges == NULL || join_edges == NULL)
    {
        P101_ERROR_RAISE_ERRNO(err, ENOMEM);
        operation_status = -1;
        goto done;
    }
    for(size_t index = 0U; index < analysis->ordered_count; index++)
    {
        const struct p101_tool_model_node *node;
        bool                               is_sync;
        bool                               is_held;
        bool                               is_join;
        int                                class_comparison;
        char                               current_thread[EVIDENCE_TEXT_SIZE];
        char                               current_resource[EVIDENCE_TEXT_SIZE];

        node = analysis->ordered[index].node;
        if(node->domain != P101_TOOL_MODEL_NODE_RESOURCE || node->record_kind != P101_TOOL_EVENT_RECORD_RESOURCE || node->resource_class == NULL)
        {
            continue;
        }
        is_sync = synchronization_class(node->resource_class);
        if(!is_sync)
        {
            continue;
        }
        analysis->synchronization_records++;
        is_held          = held_class(node->resource_class);
        class_comparison = strcmp(node->resource_class, "pthread-join-wait");
        is_join          = class_comparison == 0;
        format_sync_thread(current_thread, node);
        format_sync_resource(current_resource, node, node->resource_id == NULL ? "?" : node->resource_id);
        if(is_held && node->resource_kind == P101_TOOL_EVENT_RESOURCE_ACQUIRE)
        {
            for(size_t held_index = 0U; held_index < held_count; held_index++)
            {
                int thread_comparison;
                int resource_comparison;

                thread_comparison   = strcmp(held[held_index].thread, current_thread);
                resource_comparison = strcmp(held[held_index].resource, current_resource);
                if(held[held_index].active && thread_comparison == 0 && resource_comparison != 0)
                {
                    bool cycle;

                    cycle = sync_reaches(lock_edges, lock_edge_count, current_resource, held[held_index].resource, false);
                    if(cycle)
                    {
                        operation_status = add_sync_finding(err, analysis, "P101-SYNC-001", node, held[held_index].resource, current_resource);
                        if(operation_status != 0)
                        {
                            goto done;
                        }
                    }
                    snprintf(lock_edges[lock_edge_count].from, EVIDENCE_TEXT_SIZE, "%s", held[held_index].resource);
                    snprintf(lock_edges[lock_edge_count].to, EVIDENCE_TEXT_SIZE, "%s", current_resource);
                    lock_edge_count++;
                }
            }
            held[held_count].active = true;
            held[held_count].node   = node;
            snprintf(held[held_count].thread, EVIDENCE_TEXT_SIZE, "%s", current_thread);
            snprintf(held[held_count].resource, EVIDENCE_TEXT_SIZE, "%s", current_resource);
            held_count++;
        }
        else if(is_held && node->resource_kind == P101_TOOL_EVENT_RESOURCE_RELEASE)
        {
            for(size_t held_index = held_count; held_index > 0U; held_index--)
            {
                size_t item;
                int    thread_comparison;
                int    resource_comparison;

                item                = held_index - 1U;
                thread_comparison   = strcmp(held[item].thread, current_thread);
                resource_comparison = strcmp(held[item].resource, current_resource);
                if(held[item].active && thread_comparison == 0 && resource_comparison == 0)
                {
                    held[item].active = false;
                    break;
                }
            }
        }
        else if(!is_held && node->resource_kind == P101_TOOL_EVENT_RESOURCE_ACQUIRE)
        {
            waits[wait_count].active = true;
            waits[wait_count].join   = is_join;
            waits[wait_count].node   = node;
            if(is_join)
            {
                format_sync_resource(waits[wait_count].thread, node, node->resource_id == NULL ? "?" : node->resource_id);
                snprintf(waits[wait_count].resource, EVIDENCE_TEXT_SIZE, "%s", waits[wait_count].thread);
                format_sync_resource(waits[wait_count].target, node, node->related_id == NULL ? "?" : node->related_id);
            }
            else
            {
                snprintf(waits[wait_count].thread, EVIDENCE_TEXT_SIZE, "%s", current_thread);
                snprintf(waits[wait_count].resource, EVIDENCE_TEXT_SIZE, "%s", current_resource);
            }
            wait_count++;
        }
        else if(!is_held && node->resource_kind == P101_TOOL_EVENT_RESOURCE_RELEASE)
        {
            for(size_t wait_index = wait_count; wait_index > 0U; wait_index--)
            {
                size_t      item;
                int         thread_comparison;
                int         resource_comparison;
                const char *expected_thread;

                item = wait_index - 1U;

                if(is_join)
                {
                    expected_thread = current_resource;
                }
                else
                {
                    expected_thread = current_thread;
                }
                thread_comparison   = strcmp(waits[item].thread, expected_thread);
                resource_comparison = strcmp(waits[item].resource, current_resource);
                if(waits[item].active && thread_comparison == 0 && resource_comparison == 0)
                {
                    waits[item].active = false;
                    break;
                }
            }
        }
    }
    for(size_t wait_index = 0U; wait_index < wait_count; wait_index++)
    {
        if(!waits[wait_index].active)
        {
            continue;
        }
        if(waits[wait_index].join)
        {
            snprintf(join_edges[join_edge_count].from, EVIDENCE_TEXT_SIZE, "%s", waits[wait_index].thread);
            snprintf(join_edges[join_edge_count].to, EVIDENCE_TEXT_SIZE, "%s", waits[wait_index].target);
            join_edge_count++;
            snprintf(wait_edges[wait_edge_count].from, EVIDENCE_TEXT_SIZE, "%s", waits[wait_index].thread);
            snprintf(wait_edges[wait_edge_count].to, EVIDENCE_TEXT_SIZE, "%s", waits[wait_index].target);
            wait_edge_count++;
        }
        else
        {
            for(size_t held_index = 0U; held_index < held_count; held_index++)
            {
                int comparison;

                comparison = strcmp(held[held_index].resource, waits[wait_index].resource);
                if(held[held_index].active && comparison == 0)
                {
                    snprintf(wait_edges[wait_edge_count].from, EVIDENCE_TEXT_SIZE, "%s", waits[wait_index].thread);
                    snprintf(wait_edges[wait_edge_count].to, EVIDENCE_TEXT_SIZE, "%s", held[held_index].thread);
                    wait_edge_count++;
                }
            }
        }
    }
    for(size_t wait_index = 0U; wait_index < wait_count; wait_index++)
    {
        bool cycle;

        if(!waits[wait_index].active)
        {
            continue;
        }
        if(waits[wait_index].join)
        {
            cycle = sync_reaches(join_edges, join_edge_count, waits[wait_index].target, waits[wait_index].thread, true);
            if(cycle)
            {
                operation_status = add_sync_finding(err, analysis, "P101-SYNC-003", waits[wait_index].node, waits[wait_index].thread, waits[wait_index].target);
            }
        }
        else
        {
            for(size_t edge_index = 0U; edge_index < wait_edge_count; edge_index++)
            {
                int comparison;

                comparison = strcmp(wait_edges[edge_index].from, waits[wait_index].thread);
                if(comparison != 0)
                {
                    continue;
                }
                cycle = sync_reaches(wait_edges, wait_edge_count, wait_edges[edge_index].to, waits[wait_index].thread, false);
                if(cycle)
                {
                    operation_status = add_sync_finding(err, analysis, "P101-SYNC-002", waits[wait_index].node, waits[wait_index].thread, wait_edges[edge_index].to);
                    break;
                }
            }
        }
        if(operation_status != 0)
        {
            goto done;
        }
    }
    analysis->lock_order_edges = lock_edge_count;

done:
    free(held);
    free(waits);
    free(lock_edges);
    free(wait_edges);
    free(join_edges);
    p101_single_result_ = operation_status;
    return p101_single_result_;
}

static struct trace_context *trace_context(struct p101_error *err, struct p101_tool_analysis *analysis, long pid, size_t context)
{
    struct trace_context *p101_single_result_;

    p101_single_result_ = NULL;
    for(size_t index = 0U; index < analysis->trace_context_count; index++)
    {
        if(analysis->trace_contexts[index].pid == pid && analysis->trace_contexts[index].context == context)
        {
            p101_single_result_ = &analysis->trace_contexts[index];
            goto p101_single_exit_;
        }
    }
    if(analysis->trace_context_count >= analysis->ordered_count)
    {
        P101_ERROR_RAISE_ERRNO(err, EOVERFLOW);
        goto p101_single_exit_;
    }
    p101_single_result_          = &analysis->trace_contexts[analysis->trace_context_count];
    p101_single_result_->pid     = pid;
    p101_single_result_->context = context;
    p101_single_result_->top     = SIZE_MAX;
    analysis->trace_context_count++;

p101_single_exit_:
    return p101_single_result_;
}

static int analyze_trace(struct p101_error *err, struct p101_tool_analysis *analysis)
{
    int                       p101_single_result_;
    struct trace_stack_entry *stack_entries;
    size_t                    stack_entry_count;
    int                       operation_status;
    size_t                    allocation_count;
    void                     *allocation;

    allocation_count         = analysis->ordered_count == 0U ? 1U : analysis->ordered_count;
    allocation               = calloc(allocation_count, sizeof(*analysis->trace_contexts));
    analysis->trace_contexts = (struct trace_context *)allocation;
    allocation               = calloc(allocation_count, sizeof(*stack_entries));
    stack_entries            = (struct trace_stack_entry *)allocation;
    stack_entry_count        = 0U;
    operation_status         = 0;
    if(analysis->trace_contexts == NULL || stack_entries == NULL)
    {
        P101_ERROR_RAISE_ERRNO(err, ENOMEM);
        operation_status = -1;
        goto done;
    }
    for(size_t index = 0U; index < analysis->ordered_count; index++)
    {
        const struct p101_tool_model_node *node;
        struct trace_context              *context;

        node = analysis->ordered[index].node;
        if(node->domain == P101_TOOL_MODEL_NODE_RESOURCE && node->record_kind == P101_TOOL_EVENT_RECORD_FORK)
        {
            const struct trace_context *parent;
            struct trace_context       *child;

            parent = trace_context(err, analysis, node->pid, node->context_id);
            child  = trace_context(err, analysis, node->child_pid, node->context_id);
            if(parent == NULL || child == NULL)
            {
                operation_status = -1;
                goto done;
            }
            child->top       = parent->top;
            child->depth     = parent->depth;
            child->max_depth = parent->depth;
            if(child->top != SIZE_MAX)
            {
                const struct p101_tool_model_node *active;
                int                                name_comparison;

                active          = analysis->ordered[stack_entries[child->top].node_index].node;
                name_comparison = strcmp(active->call_name == NULL ? "" : active->call_name, node->function_name == NULL ? "" : node->function_name);
                if(name_comparison == 0)
                {
                    child->top = stack_entries[child->top].previous;
                    if(child->depth > 0U)
                    {
                        child->depth--;
                    }
                }
            }
            continue;
        }
        if(node->domain != P101_TOOL_MODEL_NODE_CALL)
        {
            continue;
        }
        analysis->call_records++;
        context = trace_context(err, analysis, node->pid, node->context_id);
        if(context == NULL)
        {
            operation_status = -1;
            goto done;
        }
        if(node->call_kind == P101_TOOL_EVENT_CALL_ENTER)
        {
            operation_status = append_trace_line(err, analysis, node, context->depth, true);
            if(operation_status != 0)
            {
                goto done;
            }
            stack_entries[stack_entry_count].node_index = index;
            stack_entries[stack_entry_count].previous   = context->top;
            context->top                                = stack_entry_count;
            stack_entry_count++;
            context->depth++;
            if(context->depth > context->max_depth)
            {
                context->max_depth = context->depth;
            }
        }
        else
        {
            const struct p101_tool_model_node *active;
            bool                               identity_mismatch;
            int                                comparison;

            operation_status = append_trace_line(err, analysis, node, context->depth == 0U ? 0U : context->depth - 1U, false);
            if(operation_status != 0)
            {
                goto done;
            }
            if(context->top == SIZE_MAX)
            {
                context->unmatched++;
                operation_status = add_finding(err, analysis, "P101-TRACE-001", P101_TOOL_ANALYSIS_TRACE, "call exit has no matching active call", node, NULL, NULL, node->call_name);
                if(operation_status != 0)
                {
                    goto done;
                }
                continue;
            }
            active            = analysis->ordered[stack_entries[context->top].node_index].node;
            comparison        = strcmp(active->call_name == NULL ? "" : active->call_name, node->call_name == NULL ? "" : node->call_name);
            identity_mismatch = comparison != 0;
            if(!identity_mismatch)
            {
                comparison        = strcmp(active->file_name == NULL ? "" : active->file_name, node->file_name == NULL ? "" : node->file_name);
                identity_mismatch = comparison != 0;
            }
            if(!identity_mismatch)
            {
                comparison        = strcmp(active->function_name == NULL ? "" : active->function_name, node->function_name == NULL ? "" : node->function_name);
                identity_mismatch = comparison != 0;
            }
            if(identity_mismatch)
            {
                context->mismatched++;
                operation_status = add_finding(err, analysis, "P101-TRACE-002", P101_TOOL_ANALYSIS_TRACE, "call exit does not match the active call", node, NULL, NULL, node->call_name);
                if(operation_status != 0)
                {
                    goto done;
                }
                continue;
            }
            context->top = stack_entries[context->top].previous;
            if(context->depth > 0U)
            {
                context->depth--;
            }
        }
    }
    for(size_t context_index = 0U; context_index < analysis->trace_context_count; context_index++)
    {
        size_t top;

        top = analysis->trace_contexts[context_index].top;
        while(top != SIZE_MAX)
        {
            const struct p101_tool_model_node *node;

            node             = analysis->ordered[stack_entries[top].node_index].node;
            operation_status = add_finding(err, analysis, "P101-TRACE-003", P101_TOOL_ANALYSIS_TRACE, "call remained open at the end of the event stream", node, NULL, NULL, node->call_name);
            if(operation_status != 0)
            {
                goto done;
            }
            top = stack_entries[top].previous;
        }
    }

done:
    free(stack_entries);
    p101_single_result_ = operation_status;
    return p101_single_result_;
}

static int append_trace_line(struct p101_error *err, struct p101_tool_analysis *analysis, const struct p101_tool_model_node *node, size_t depth, bool entering)
{
    int         p101_single_result_;
    char        line[TRACE_LINE_SIZE];
    size_t      indentation;
    int         operation_status;
    const char *call_name;
    const char *file_name;
    const char *arguments;
    const char *result;
    int         comparison;

    if(depth > TRACE_MAX_INDENTATION / 2U)
    {
        indentation = TRACE_MAX_INDENTATION;
    }
    else
    {
        indentation = depth * 2U;
    }
    call_name = node->call_name == NULL ? "?" : node->call_name;
    file_name = node->file_name == NULL ? "?" : node->file_name;
    arguments = "";
    if(node->arguments != NULL)
    {
        comparison = strcmp(node->arguments, "-");
        if(comparison != 0)
        {
            arguments = node->arguments;
        }
    }
    result = "";
    if(node->result != NULL)
    {
        comparison = strcmp(node->result, "-");
        if(comparison != 0)
        {
            result = node->result;
        }
    }
    if(entering)
    {
        operation_status = snprintf(line, sizeof(line), "#%zu pid %ld context %zu %*s%s(%s)  [%s:%d]\n", node->sequence, node->pid, node->context_id, (int)indentation, "", call_name, arguments, file_name, node->line_number);
    }
    else
    {
        operation_status = snprintf(line, sizeof(line), "#%zu pid %ld context %zu %*s-> %s%s%s  [%s:%d]\n", node->sequence, node->pid, node->context_id, (int)indentation, "", call_name, result[0] == '\0' ? "" : " = ", result, file_name, node->line_number);
    }
    if(operation_status < 0 || (size_t)operation_status >= sizeof(line))
    {
        P101_ERROR_RAISE_ERRNO(err, EOVERFLOW);
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    p101_single_result_ = append_trace(err, analysis, line);

p101_single_exit_:
    return p101_single_result_;
}

static int append_trace(struct p101_error *err, struct p101_tool_analysis *analysis, const char *text)
{
    int    p101_single_result_;
    size_t text_length;
    size_t required;
    size_t new_capacity;
    char  *storage;
    void  *allocation;

    text_length = strlen(text);
    if(text_length > SIZE_MAX - analysis->trace_tree_length - 1U)
    {
        P101_ERROR_RAISE_ERRNO(err, EOVERFLOW);
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    required = analysis->trace_tree_length + text_length + 1U;
    if(required > analysis->trace_tree_capacity)
    {
        new_capacity = analysis->trace_tree_capacity == 0U ? TRACE_INITIAL_CAPACITY : analysis->trace_tree_capacity;
        while(new_capacity < required && new_capacity <= SIZE_MAX / 2U)
        {
            new_capacity *= 2U;
        }
        if(new_capacity < required)
        {
            P101_ERROR_RAISE_ERRNO(err, EOVERFLOW);
            p101_single_result_ = -1;
            goto p101_single_exit_;
        }
        allocation = realloc(analysis->trace_tree, new_capacity);
        storage    = (char *)allocation;
        if(storage == NULL)
        {
            P101_ERROR_RAISE_ERRNO(err, ENOMEM);
            p101_single_result_ = -1;
            goto p101_single_exit_;
        }
        analysis->trace_tree          = storage;
        analysis->trace_tree_capacity = new_capacity;
    }
    memcpy(analysis->trace_tree + analysis->trace_tree_length, text, text_length + 1U);
    analysis->trace_tree_length += text_length;
    p101_single_result_ = 0;

p101_single_exit_:
    return p101_single_result_;
}

static int analyze_sanitizer(struct p101_error *err, struct p101_tool_analysis *analysis, const char *path)
{
    int     p101_single_result_;
    FILE   *stream;
    char   *line;
    size_t  line_capacity;
    ssize_t line_length;
    size_t  line_number;
    int     operation_status;
    int     read_status;

    if(path == NULL)
    {
        p101_single_result_ = 0;
        goto p101_single_exit_;
    }
    stream = fopen(path, "re");
    if(stream == NULL)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
        analysis->trouble   = true;
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    line             = NULL;
    line_capacity    = 0U;
    line_number      = 0U;
    operation_status = 0;
    line_length      = getline(&line, &line_capacity, stream);
    read_status      = line_length >= 0 ? 0 : -1;
    while(read_status == 0)
    {
        const char                 *identifier;
        const char                 *message;
        const char                 *detail;
        size_t                      sanitizer_index;
        struct p101_tool_model_node synthetic;

        if(line == NULL)
        {
            P101_ERROR_RAISE_ERRNO(err, EIO);
            operation_status = -1;
            break;
        }
        (void)line_length;
        line_number++;
        analysis->sanitizer_records++;
        identifier      = NULL;
        message         = NULL;
        detail          = NULL;
        sanitizer_index = 0U;
        detail          = strstr(line, "AddressSanitizer:");
        if(detail != NULL)
        {
            identifier      = "P101-SAN-001";
            message         = "AddressSanitizer reported an invalid memory access";
            sanitizer_index = 0U;
        }
        else
        {
            detail = strstr(line, "LeakSanitizer:");
            if(detail != NULL)
            {
                identifier      = "P101-SAN-002";
                message         = "LeakSanitizer reported leaked memory";
                sanitizer_index = 1U;
            }
            else
            {
                detail = strstr(line, "runtime error:");
                if(detail != NULL)
                {
                    identifier      = "P101-SAN-003";
                    message         = "UndefinedBehaviorSanitizer reported undefined behavior";
                    sanitizer_index = 2U;
                }
                else
                {
                    detail = strstr(line, "ThreadSanitizer:");
                    if(detail != NULL)
                    {
                        identifier      = "P101-SAN-004";
                        message         = "ThreadSanitizer reported a data race or synchronization defect";
                        sanitizer_index = 3U;
                    }
                }
            }
        }
        if(identifier != NULL)
        {
            memset(&synthetic, 0, sizeof(synthetic));
            synthetic.domain        = P101_TOOL_MODEL_NODE_RESOURCE;
            synthetic.run_id        = "stderr";
            synthetic.sequence      = line_number;
            synthetic.file_name     = "stderr.txt";
            synthetic.function_name = "?";
            synthetic.line_number   = (int)line_number;
            operation_status        = add_finding(err, analysis, identifier, P101_TOOL_ANALYSIS_SANITIZER, message, &synthetic, NULL, NULL, detail);
            if(operation_status != 0)
            {
                break;
            }
            analysis->sanitizer_counts[sanitizer_index]++;
        }
        line_length = getline(&line, &line_capacity, stream);
        read_status = line_length >= 0 ? 0 : -1;
    }
    read_status = ferror(stream);
    if(read_status != 0 && operation_status == 0)
    {
        P101_ERROR_RAISE_ERRNO(err, errno == 0 ? EIO : errno);
        operation_status = -1;
    }
    free(line);
    read_status = fclose(stream);
    if(read_status != 0 && operation_status == 0)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
        operation_status = -1;
    }
    p101_single_result_ = operation_status;

p101_single_exit_:
    return p101_single_result_;
}

int p101_tool_analysis_write_interleaving(struct p101_error *err, const struct p101_tool_analysis *analysis, FILE *stream, size_t schedule_limit, size_t *counterexample_count)
{
    int              p101_single_result_;
    struct sync_key *baseline;
    size_t           baseline_count;
    size_t          *orders;
    size_t          *parents;
    size_t          *swap_left;
    size_t          *swap_right;
    size_t          *candidate;
    size_t          *chain;
    size_t           node_count;
    size_t           order_count;
    size_t           queue_index;
    size_t           counterexamples;
    int              operation_status;
    size_t           allocation_count;
    size_t           allocation_bytes;
    size_t           candidate_nodes_bytes;
    void            *allocation;

    baseline        = NULL;
    baseline_count  = 0U;
    orders          = NULL;
    parents         = NULL;
    swap_left       = NULL;
    swap_right      = NULL;
    candidate       = NULL;
    chain           = NULL;
    counterexamples = 0U;
    if(analysis == NULL || stream == NULL || schedule_limit == 0U || analysis->ordered == NULL)
    {
        P101_ERROR_RAISE_ERRNO(err, EINVAL);
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    node_count = analysis->ordered_count;
    if(schedule_limit > SIZE_MAX / sizeof(size_t))
    {
        P101_ERROR_RAISE_ERRNO(err, EOVERFLOW);
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    if(node_count != 0U && schedule_limit > SIZE_MAX / node_count)
    {
        P101_ERROR_RAISE_ERRNO(err, EOVERFLOW);
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    allocation_count = schedule_limit * (node_count == 0U ? 1U : node_count);
    if(allocation_count > SIZE_MAX / sizeof(size_t) || node_count > SIZE_MAX / sizeof(struct ordered_node))
    {
        P101_ERROR_RAISE_ERRNO(err, EOVERFLOW);
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    candidate_nodes_bytes = node_count * sizeof(struct ordered_node);
    operation_status      = collect_prefix_sync_keys(err, analysis->ordered, node_count, &baseline, &baseline_count);
    if(operation_status != 0)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    allocation       = calloc(allocation_count, sizeof(*orders));
    orders           = (size_t *)allocation;
    allocation_bytes = schedule_limit * sizeof(*parents);
    allocation       = malloc(allocation_bytes);
    parents          = (size_t *)allocation;
    allocation       = calloc(schedule_limit, sizeof(*swap_left));
    swap_left        = (size_t *)allocation;
    allocation       = calloc(schedule_limit, sizeof(*swap_right));
    swap_right       = (size_t *)allocation;
    allocation_count = node_count == 0U ? 1U : node_count;
    allocation_bytes = allocation_count * sizeof(*candidate);
    allocation       = malloc(allocation_bytes);
    candidate        = (size_t *)allocation;
    allocation_bytes = schedule_limit * sizeof(*chain);
    allocation       = malloc(allocation_bytes);
    chain            = (size_t *)allocation;
    if(orders == NULL || parents == NULL || swap_left == NULL || swap_right == NULL || candidate == NULL || chain == NULL)
    {
        P101_ERROR_RAISE_ERRNO(err, ENOMEM);
        goto done;
    }
    for(size_t index = 0U; index < node_count; index++)
    {
        orders[index] = index;
    }
    parents[0]       = SIZE_MAX;
    order_count      = 1U;
    queue_index      = 0U;
    operation_status = write_string(stream, "{\n  \"schema\": \"p101-interleaving-walk-v1\",\n  \"counterexamples\": [");
    while(queue_index < order_count && order_count < schedule_limit && counterexamples == 0U && operation_status == 0)
    {
        const size_t *current;

        current = &orders[queue_index * (node_count == 0U ? 1U : node_count)];
        for(size_t index = 0U; index + 1U < node_count && order_count < schedule_limit && counterexamples == 0U && operation_status == 0; index++)
        {
            const struct ordered_node *left;
            const struct ordered_node *right;
            struct ordered_node       *candidate_nodes;
            struct sync_key           *candidate_keys;
            size_t                     candidate_key_count;
            bool                       eligible;
            bool                       seen;

            left     = &analysis->ordered[current[index]];
            right    = &analysis->ordered[current[index + 1U]];
            eligible = interleaving_node(left->node);
            if(eligible)
            {
                eligible = interleaving_node(right->node);
            }
            if(eligible)
            {
                bool same_thread;

                same_thread = same_sync_thread(left->node, right->node);
                eligible    = (_Bool)(!same_thread);
            }
            if(eligible)
            {
                bool ordered;

                ordered  = directly_ordered(analysis, left->original_index, right->original_index);
                eligible = (_Bool)(!ordered);
            }
            if(!eligible)
            {
                continue;
            }
            memcpy(candidate, current, node_count * sizeof(*candidate));
            candidate[index]      = current[index + 1U];
            candidate[index + 1U] = current[index];
            seen                  = schedule_seen(orders, order_count, node_count, candidate);
            if(seen)
            {
                continue;
            }
            memcpy(&orders[order_count * node_count], candidate, node_count * sizeof(*candidate));
            parents[order_count]    = queue_index;
            swap_left[order_count]  = current[index];
            swap_right[order_count] = current[index + 1U];
            allocation              = malloc(candidate_nodes_bytes);
            candidate_nodes         = (struct ordered_node *)allocation;
            candidate_keys          = NULL;
            candidate_key_count     = 0U;
            if(candidate_nodes == NULL)
            {
                P101_ERROR_RAISE_ERRNO(err, ENOMEM);
                operation_status = -1;
                break;
            }
            for(size_t node_index = 0U; node_index < node_count; node_index++)
            {
                candidate_nodes[node_index] = analysis->ordered[candidate[node_index]];
            }
            operation_status = collect_prefix_sync_keys(err, candidate_nodes, node_count, &candidate_keys, &candidate_key_count);
            if(operation_status == 0)
            {
                size_t new_count;

                new_count = 0U;
                for(size_t key_index = 0U; key_index < candidate_key_count; key_index++)
                {
                    struct p101_tool_analysis_finding finding;
                    bool                              present;

                    memset(&finding, 0, sizeof(finding));
                    finding.diagnostic_id = candidate_keys[key_index].id;
                    finding.evidence_from = candidate_keys[key_index].from;
                    finding.evidence_to   = candidate_keys[key_index].to;
                    present               = sync_key_present(baseline, baseline_count, &finding);
                    if(!present)
                    {
                        new_count++;
                    }
                }
                if(new_count > 0U)
                {
                    size_t chain_count;
                    size_t cursor;

                    operation_status = write_string(stream, counterexamples == 0U ? "\n    {\"swaps\":[" : ",\n    {\"swaps\":[");
                    chain_count      = 0U;
                    cursor           = order_count;
                    while(cursor != SIZE_MAX)
                    {
                        chain[chain_count] = cursor;
                        chain_count++;
                        cursor = parents[cursor];
                    }
                    for(size_t chain_index = chain_count; chain_index > 1U && operation_status == 0; chain_index--)
                    {
                        size_t                             item;
                        const struct p101_tool_model_node *before;
                        const struct p101_tool_model_node *after;
                        char                               before_id[NODE_ID_SIZE];
                        char                               after_id[NODE_ID_SIZE];

                        item   = chain[chain_index - 2U];
                        before = analysis->ordered[swap_left[item]].node;
                        after  = analysis->ordered[swap_right[item]].node;
                        format_node_id(before_id, before);
                        format_node_id(after_id, after);
                        operation_status = write_string(stream, chain_index == chain_count ? "{\"before\":" : ",{\"before\":");
                        if(operation_status == 0)
                        {
                            operation_status = write_json_string(stream, before_id);
                        }
                        if(operation_status == 0)
                        {
                            operation_status = write_string(stream, ",\"after\":");
                        }
                        if(operation_status == 0)
                        {
                            operation_status = write_json_string(stream, after_id);
                        }
                        if(operation_status == 0)
                        {
                            operation_status = write_string(stream, "}");
                        }
                    }
                    if(operation_status == 0)
                    {
                        operation_status = write_string(stream, "],\"findings\":[");
                    }
                    new_count = 0U;
                    for(size_t key_index = 0U; key_index < candidate_key_count && operation_status == 0; key_index++)
                    {
                        struct p101_tool_analysis_finding finding;
                        bool                              present;

                        memset(&finding, 0, sizeof(finding));
                        finding.diagnostic_id = candidate_keys[key_index].id;
                        finding.evidence_from = candidate_keys[key_index].from;
                        finding.evidence_to   = candidate_keys[key_index].to;
                        present               = sync_key_present(baseline, baseline_count, &finding);
                        if(present)
                        {
                            continue;
                        }
                        operation_status = write_string(stream, new_count == 0U ? "" : ",");
                        if(operation_status == 0)
                        {
                            operation_status = write_sync_key_json(stream, &candidate_keys[key_index]);
                        }
                        new_count++;
                    }
                    if(operation_status == 0)
                    {
                        operation_status = write_string(stream, "]}");
                    }
                    counterexamples++;
                }
            }
            free(candidate_nodes);
            free(candidate_keys);
            order_count++;
        }
        queue_index++;
    }
    if(operation_status == 0)
    {
        operation_status = fprintf(stream,
                                   "\n  ],\n  \"summary\": {\"schedules_explored\": %zu, \"counterexample_schedules\": %zu, \"baseline_findings\": %zu, \"bound\": %zu},\n"
                                   "  \"blind_spots\": [\"explores reorderings of observed synchronization events only\", \"does not execute the program or invent unobserved branches\", \"preserves recorded causal edges and each thread's local order\"]\n}\n",
                                   order_count,
                                   counterexamples,
                                   analysis->policy_counts[P101_TOOL_ANALYSIS_SYNCHRONIZATION],
                                   schedule_limit);
        operation_status = operation_status < 0 ? -1 : 0;
    }

done:
    free(baseline);
    free(orders);
    free(parents);
    free(swap_left);
    free(swap_right);
    free(candidate);
    free(chain);
    if(counterexample_count != NULL)
    {
        *counterexample_count = counterexamples;
    }
    p101_single_result_ = operation_status;

p101_single_exit_:
    return p101_single_result_;
}

static int collect_prefix_sync_keys(struct p101_error *err, struct ordered_node *order, size_t count, struct sync_key **keys, size_t *key_count)
{
    int p101_single_result_;
    int operation_status;

    operation_status = 0;
    for(size_t prefix = 1U; prefix <= count && operation_status == 0; prefix++)
    {
        struct p101_tool_analysis prefix_analysis;

        memset(&prefix_analysis, 0, sizeof(prefix_analysis));
        prefix_analysis.ordered       = order;
        prefix_analysis.ordered_count = prefix;
        operation_status              = analyze_synchronization(err, &prefix_analysis);
        for(size_t index = 0U; index < prefix_analysis.finding_count && operation_status == 0; index++)
        {
            const struct p101_tool_analysis_finding *finding;
            bool                                     present;

            finding = &prefix_analysis.findings[index].value;
            present = sync_key_present(*keys, *key_count, finding);
            if(!present)
            {
                operation_status = append_sync_key(err, keys, key_count, finding);
            }
        }
        free(prefix_analysis.findings);
    }
    p101_single_result_ = operation_status;
    return p101_single_result_;
}

static bool sync_key_present(const struct sync_key *keys, size_t count, const struct p101_tool_analysis_finding *finding)
{
    bool p101_single_result_;

    p101_single_result_ = false;
    for(size_t index = 0U; index < count; index++)
    {
        int id_comparison;
        int from_comparison;
        int to_comparison;

        id_comparison   = strcmp(keys[index].id, finding->diagnostic_id);
        from_comparison = strcmp(keys[index].from, finding->evidence_from);
        to_comparison   = strcmp(keys[index].to, finding->evidence_to);
        if(id_comparison == 0 && from_comparison == 0 && to_comparison == 0)
        {
            p101_single_result_ = true;
            break;
        }
    }
    return p101_single_result_;
}

static int append_sync_key(struct p101_error *err, struct sync_key **keys, size_t *count, const struct p101_tool_analysis_finding *finding)
{
    int              p101_single_result_;
    struct sync_key *storage;
    struct sync_key *key;
    int              operation_status;
    void            *allocation;

    if(*count == SIZE_MAX / sizeof(**keys))
    {
        P101_ERROR_RAISE_ERRNO(err, EOVERFLOW);
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    allocation = realloc(*keys, (*count + 1U) * sizeof(**keys));
    storage    = (struct sync_key *)allocation;
    if(storage == NULL)
    {
        P101_ERROR_RAISE_ERRNO(err, ENOMEM);
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    *keys = storage;
    key   = &storage[*count];
    memset(key, 0, sizeof(*key));
    operation_status = snprintf(key->id, sizeof(key->id), "%s", finding->diagnostic_id);
    if(operation_status < 0 || (size_t)operation_status >= sizeof(key->id))
    {
        operation_status = -1;
    }
    if(operation_status >= 0)
    {
        operation_status = snprintf(key->from, sizeof(key->from), "%s", finding->evidence_from);
        operation_status = operation_status < 0 || (size_t)operation_status >= sizeof(key->from) ? -1 : 0;
    }
    if(operation_status == 0)
    {
        operation_status = snprintf(key->to, sizeof(key->to), "%s", finding->evidence_to);
        operation_status = operation_status < 0 || (size_t)operation_status >= sizeof(key->to) ? -1 : 0;
    }
    if(operation_status == 0)
    {
        operation_status = snprintf(key->message, sizeof(key->message), "%s", finding->message);
        operation_status = operation_status < 0 || (size_t)operation_status >= sizeof(key->message) ? -1 : 0;
    }
    if(operation_status == 0)
    {
        operation_status = snprintf(key->file, sizeof(key->file), "%s", finding->file_name);
        operation_status = operation_status < 0 || (size_t)operation_status >= sizeof(key->file) ? -1 : 0;
    }
    if(operation_status == 0)
    {
        operation_status = snprintf(key->function, sizeof(key->function), "%s", finding->function_name);
        operation_status = operation_status < 0 || (size_t)operation_status >= sizeof(key->function) ? -1 : 0;
    }
    if(operation_status != 0)
    {
        P101_ERROR_RAISE_ERRNO(err, EOVERFLOW);
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    key->line = finding->line_number;
    (*count)++;
    p101_single_result_ = 0;

p101_single_exit_:
    return p101_single_result_;
}

static bool interleaving_node(const struct p101_tool_model_node *node)
{
    bool p101_single_result_;

    p101_single_result_ = (_Bool)((node != NULL && node->domain == P101_TOOL_MODEL_NODE_RESOURCE && node->record_kind == P101_TOOL_EVENT_RECORD_RESOURCE && node->resource_class != NULL) != 0);
    if(p101_single_result_)
    {
        p101_single_result_ = synchronization_class(node->resource_class);
    }
    return p101_single_result_;
}

static bool same_sync_thread(const struct p101_tool_model_node *left, const struct p101_tool_model_node *right)
{
    bool p101_single_result_;

    p101_single_result_ = (_Bool)((left->pid == right->pid && left->context_id == right->context_id) != 0);
    if(left->metadata != NULL && right->metadata != NULL && left->metadata[0] != '\0' && right->metadata[0] != '\0')
    {
        int comparison;

        comparison          = strcmp(left->metadata, right->metadata);
        p101_single_result_ = (_Bool)((left->pid == right->pid && comparison == 0) != 0);
    }
    return p101_single_result_;
}

static bool directly_ordered(const struct p101_tool_analysis *analysis, size_t left, size_t right)
{
    bool   p101_single_result_;
    size_t edge_count;

    p101_single_result_ = false;
    edge_count          = p101_tool_model_edge_count(analysis->model);
    for(size_t index = 0U; index < edge_count; index++)
    {
        const struct p101_tool_model_edge *edge;

        edge = p101_tool_model_edge_at(analysis->model, index);
        if(edge->from == left && edge->to == right)
        {
            p101_single_result_ = true;
            break;
        }
    }
    return p101_single_result_;
}

static bool schedule_seen(const size_t *orders, size_t order_count, size_t node_count, const size_t *candidate)
{
    bool p101_single_result_;

    p101_single_result_ = false;
    for(size_t index = 0U; index < order_count; index++)
    {
        int comparison;

        comparison = memcmp(&orders[index * node_count], candidate, node_count * sizeof(*candidate));
        if(comparison == 0)
        {
            p101_single_result_ = true;
            break;
        }
    }
    return p101_single_result_;
}

static int write_sync_key_json(FILE *stream, const struct sync_key *key)
{
    int p101_single_result_;
    int operation_status;

    operation_status = write_string(stream, "{\"id\":");
    if(operation_status == 0)
    {
        operation_status = write_json_string(stream, key->id);
    }
    if(operation_status == 0)
    {
        operation_status = write_string(stream, ",\"message\":");
    }
    if(operation_status == 0)
    {
        operation_status = write_json_string(stream, key->message);
    }
    if(operation_status == 0)
    {
        operation_status = write_string(stream, ",\"location\":{\"file\":");
    }
    if(operation_status == 0)
    {
        operation_status = write_json_string(stream, key->file);
    }
    if(operation_status == 0)
    {
        operation_status = fprintf(stream, ",\"line\":%d,\"function\":", key->line);
        operation_status = operation_status < 0 ? -1 : 0;
    }
    if(operation_status == 0)
    {
        operation_status = write_json_string(stream, key->function);
    }
    if(operation_status == 0)
    {
        operation_status = write_string(stream, "},\"evidence\":{\"from\":");
    }
    if(operation_status == 0)
    {
        operation_status = write_json_string(stream, key->from);
    }
    if(operation_status == 0)
    {
        operation_status = write_string(stream, ",\"to\":");
    }
    if(operation_status == 0)
    {
        operation_status = write_json_string(stream, key->to);
    }
    if(operation_status == 0)
    {
        operation_status = write_string(stream, "}}");
    }
    p101_single_result_ = operation_status;
    return p101_single_result_;
}

int p101_tool_analysis_write_bundle(struct p101_error *err, const struct p101_tool_analysis *analysis, const char *output_directory)
{
    int p101_single_result_;
    int operation_status;

    if(analysis == NULL || output_directory == NULL || analysis->ordered == NULL)
    {
        P101_ERROR_RAISE_ERRNO(err, EINVAL);
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    operation_status = mkdir(output_directory, OUTPUT_DIRECTORY_MODE);
    if(operation_status != 0 && errno != EEXIST)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    operation_status = write_text_reports(err, analysis, output_directory);
    if(operation_status == 0)
    {
        operation_status = write_json_reports(err, analysis, output_directory);
    }
    if(operation_status == 0)
    {
        operation_status = write_graph(err, analysis, output_directory);
    }
    p101_single_result_ = operation_status;

p101_single_exit_:
    return p101_single_result_;
}

static int write_policy_text(struct p101_error *err, const struct p101_tool_analysis *analysis, const char *directory, const char *name, p101_tool_analysis_policy policy, const char *heading)
{
    int                p101_single_result_;
    FILE              *stream;
    int                operation_status;
    size_t             count;
    bool               error_present;
    struct p101_error *close_error;

    stream           = NULL;
    operation_status = open_output(err, directory, name, &stream);
    if(operation_status != 0)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    count            = analysis->policy_counts[(size_t)policy];
    operation_status = fprintf(stream, "%s\nfindings=%zu\n", heading, count);
    operation_status = operation_status < 0 ? -1 : 0;
    for(size_t index = 0U; index < analysis->finding_count && operation_status >= 0; index++)
    {
        const struct p101_tool_analysis_finding *finding;

        finding = &analysis->findings[index].value;
        if(finding->policy != policy)
        {
            continue;
        }
        operation_status = fprintf(stream, "%s: %s [%s:%d in %s()]\n", finding->diagnostic_id, finding->message, finding->file_name, finding->line_number, finding->function_name);
        operation_status = operation_status < 0 ? -1 : 0;
    }
    if(operation_status < 0)
    {
        P101_ERROR_RAISE_ERRNO(err, EIO);
        p101_single_result_ = -1;
        goto close_stream;
    }
    p101_single_result_ = 0;

close_stream:
    error_present = p101_error_has_error(err);
    if(error_present)
    {
        close_error = P101_ERROR_OPTIONAL;
    }
    else
    {
        close_error = err;
    }
    operation_status = close_output(close_error, &stream);
    if(operation_status != 0)
    {
        p101_single_result_ = -1;
    }

p101_single_exit_:
    return p101_single_result_;
}

static int write_text_reports(struct p101_error *err, const struct p101_tool_analysis *analysis, const char *directory)
{
    int   p101_single_result_;
    int   operation_status;
    FILE *stream;

    operation_status = write_policy_text(err, analysis, directory, "resource-report.txt", P101_TOOL_ANALYSIS_RESOURCE, "p101 resource policy");
    if(operation_status == 0)
    {
        operation_status = write_policy_text(err, analysis, directory, "concurrency-report.txt", P101_TOOL_ANALYSIS_SYNCHRONIZATION, "p101 synchronization policy");
    }
    if(operation_status == 0)
    {
        operation_status = write_policy_text(err, analysis, directory, "sanitizer-report.txt", P101_TOOL_ANALYSIS_SANITIZER, "p101 sanitizer policy");
    }
    stream = NULL;
    if(operation_status == 0)
    {
        operation_status = open_output(err, directory, "trace-tree.txt", &stream);
    }
    if(operation_status == 0)
    {
        const char *tree;

        tree             = analysis->trace_tree == NULL ? "" : analysis->trace_tree;
        operation_status = write_string(stream, tree);
        if(operation_status != 0)
        {
            P101_ERROR_RAISE_ERRNO(err, EIO);
            operation_status = -1;
        }
    }
    if(stream != NULL)
    {
        int close_status;

        close_status = close_output(err, &stream);
        if(close_status != 0)
        {
            operation_status = -1;
        }
    }
    if(operation_status == 0)
    {
        operation_status = open_output(err, directory, "trace-summary.txt", &stream);
    }
    if(operation_status == 0)
    {
        operation_status = fprintf(stream,
                                   "event_schema=p101-tool-event-format-v5 event_id_policy=wire-sequence-with-derived-input-order\nrecords=%zu execution_contexts=%zu findings=%zu\n",
                                   analysis->call_records,
                                   analysis->trace_context_count,
                                   analysis->policy_counts[P101_TOOL_ANALYSIS_TRACE]);
        if(operation_status < 0)
        {
            P101_ERROR_RAISE_ERRNO(err, EIO);
            operation_status = -1;
        }
        else
        {
            operation_status = 0;
        }
    }
    if(stream != NULL)
    {
        int close_status;

        close_status = close_output(err, &stream);
        if(close_status != 0)
        {
            operation_status = -1;
        }
    }
    if(operation_status == 0)
    {
        operation_status = open_output(err, directory, "correlated-report.txt", &stream);
    }
    if(operation_status == 0)
    {
        operation_status = fprintf(stream, "# p101 correlated runtime report\n\nFindings: %zu\n\n", analysis->finding_count);
        operation_status = operation_status < 0 ? -1 : 0;
        for(size_t index = 0U; index < analysis->finding_count && operation_status >= 0; index++)
        {
            const struct p101_tool_analysis_finding *finding;

            finding          = &analysis->findings[index].value;
            operation_status = fprintf(stream, "- %s: %s (`%s:%d`)\n", finding->diagnostic_id, finding->message, finding->file_name, finding->line_number);
            operation_status = operation_status < 0 ? -1 : 0;
        }
        if(operation_status >= 0)
        {
            operation_status = write_string(stream, "\nThis report is bounded by emitted p101 wrapper events.\n");
        }
        if(operation_status < 0)
        {
            P101_ERROR_RAISE_ERRNO(err, EIO);
            operation_status = -1;
        }
    }
    if(stream != NULL)
    {
        int close_status;

        close_status = close_output(err, &stream);
        if(close_status != 0)
        {
            operation_status = -1;
        }
    }
    p101_single_result_ = operation_status;
    return p101_single_result_;
}

static int write_json_reports(struct p101_error *err, const struct p101_tool_analysis *analysis, const char *directory)
{
    int         p101_single_result_;
    int         operation_status;
    FILE       *stream;
    const char *names[]    = {"resource-report.json", "concurrency-report.json", "sanitizer-report.json", "correlated-report.json"};
    const char *schemas[]  = {"p101-resource-policy-findings-v1", "p101-synchronization-policy-findings-v1", "p101-sanitizer-findings-v1", "p101-analysis-findings-v1"};
    const int   policies[] = {P101_TOOL_ANALYSIS_RESOURCE, P101_TOOL_ANALYSIS_SYNCHRONIZATION, P101_TOOL_ANALYSIS_SANITIZER, -1};

    operation_status = 0;
    stream           = NULL;

    for(size_t index = 0U; index < 4U && operation_status == 0; index++)
    {
        operation_status = open_output(err, directory, names[index], &stream);
        if(operation_status == 0)
        {
            operation_status = write_json_document(stream, analysis, schemas[index], policies[index]);
        }
        if(stream != NULL)
        {
            int close_status;

            close_status = close_output(err, &stream);
            if(close_status != 0)
            {
                operation_status = -1;
            }
        }
    }
    p101_single_result_ = operation_status;
    return p101_single_result_;
}

static int write_json_document(FILE *stream, const struct p101_tool_analysis *analysis, const char *schema, int policy)
{
    int    p101_single_result_;
    int    operation_status;
    size_t count;
    size_t emitted;

    count            = policy < 0 ? analysis->finding_count : analysis->policy_counts[(size_t)policy];
    operation_status = write_string(stream, "{\n  \"schema\": ");
    if(operation_status == 0)
    {
        operation_status = write_json_string(stream, schema);
    }
    if(operation_status == 0)
    {
        operation_status = write_string(stream, ",\n  \"findings\": [");
    }
    emitted = 0U;
    for(size_t index = 0U; index < analysis->finding_count && operation_status == 0; index++)
    {
        const struct p101_tool_analysis_finding *finding;

        finding = &analysis->findings[index].value;
        if(policy >= 0 && finding->policy != (p101_tool_analysis_policy)policy)
        {
            continue;
        }
        operation_status = write_string(stream, emitted == 0U ? "\n    " : ",\n    ");
        if(operation_status == 0)
        {
            operation_status = write_finding_json(stream, finding);
        }
        emitted++;
    }
    if(operation_status == 0)
    {
        operation_status = fprintf(stream, "\n  ],\n  \"summary\": {\"findings\": %zu}\n}\n", count);
        if(operation_status < 0)
        {
            operation_status = -1;
        }
        else
        {
            operation_status = 0;
        }
    }
    p101_single_result_ = operation_status;
    return p101_single_result_;
}

static int write_finding_json(FILE *stream, const struct p101_tool_analysis_finding *finding)
{
    int                                     p101_single_result_;
    int                                     operation_status;
    const struct p101_tool_rule_definition *lesson;

    operation_status = write_string(stream, "{\"id\":");
    if(operation_status == 0)
    {
        operation_status = write_json_string(stream, finding->diagnostic_id);
    }
    if(operation_status == 0)
    {
        operation_status = write_string(stream, ",\"severity\":\"error\",\"policy\":");
    }
    if(operation_status == 0)
    {
        const char *name;

        name             = policy_name(finding->policy);
        operation_status = write_json_string(stream, name);
    }
    if(operation_status == 0)
    {
        operation_status = write_string(stream, ",\"location\":{\"file\":");
    }
    if(operation_status == 0)
    {
        operation_status = write_json_string(stream, finding->file_name);
    }
    if(operation_status == 0)
    {
        operation_status = fprintf(stream, ",\"line\":%d,\"function\":", finding->line_number);
        if(operation_status >= 0)
        {
            operation_status = write_json_string(stream, finding->function_name);
        }
    }
    if(operation_status == 0)
    {
        operation_status = write_string(stream, "},\"message\":");
    }
    if(operation_status == 0)
    {
        operation_status = write_json_string(stream, finding->message);
    }
    lesson = p101_tool_rule_definition_lookup_id(finding->diagnostic_id);
    if(operation_status == 0 && lesson != NULL)
    {
        operation_status = write_string(stream, ",\"lesson\":{\"primary\":{\"lesson_id\":");
    }
    if(operation_status == 0 && lesson != NULL)
    {
        operation_status = write_json_string(stream, lesson->lesson_id);
    }
    if(operation_status == 0 && lesson != NULL)
    {
        operation_status = write_string(stream, ",\"path\":");
    }
    if(operation_status == 0 && lesson != NULL)
    {
        operation_status = write_json_string(stream, lesson->lesson_path);
    }
    if(operation_status == 0 && lesson != NULL)
    {
        operation_status = write_string(stream, ",\"url\":");
    }
    if(operation_status == 0 && lesson != NULL)
    {
        operation_status = write_json_string(stream, lesson->lesson_url);
    }
    if(operation_status == 0 && lesson != NULL)
    {
        operation_status = write_string(stream, "},\"related\":[]}");
    }
    if(operation_status == 0)
    {
        operation_status = write_string(stream, ",\"evidence\":{\"node\":");
    }
    if(operation_status == 0)
    {
        operation_status = write_json_string(stream, finding->node_id);
    }
    if(operation_status == 0 && finding->evidence_from[0] != '\0')
    {
        operation_status = write_string(stream, ",\"from\":");
        if(operation_status == 0)
        {
            operation_status = write_json_string(stream, finding->evidence_from);
        }
    }
    if(operation_status == 0 && finding->evidence_to[0] != '\0')
    {
        operation_status = write_string(stream, ",\"to\":");
        if(operation_status == 0)
        {
            operation_status = write_json_string(stream, finding->evidence_to);
        }
    }
    if(operation_status == 0 && finding->evidence_detail[0] != '\0')
    {
        operation_status = write_string(stream, ",\"detail\":");
        if(operation_status == 0)
        {
            operation_status = write_json_string(stream, finding->evidence_detail);
        }
    }
    if(operation_status == 0)
    {
        operation_status = write_string(stream, "}}");
    }
    p101_single_result_ = operation_status;
    return p101_single_result_;
}

static int write_graph(struct p101_error *err, const struct p101_tool_analysis *analysis, const char *directory)
{
    int                p101_single_result_;
    FILE              *stream;
    int                operation_status;
    size_t             edge_count;
    size_t             emitted;
    bool               error_present;
    struct p101_error *close_error;

    stream           = NULL;
    operation_status = open_output(err, directory, "resource-lifetimes.md", &stream);
    if(operation_status != 0)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    operation_status = write_string(stream, "# Resource lifetime graph\n\n```mermaid\nflowchart LR\n");
    edge_count       = p101_tool_model_edge_count(analysis->model);
    emitted          = 0U;
    for(size_t index = 0U; index < edge_count && operation_status != EOF; index++)
    {
        const struct p101_tool_model_edge *edge;

        edge = p101_tool_model_edge_at(analysis->model, index);
        if(edge->kind != P101_TOOL_MODEL_EDGE_RESOURCE_LIFETIME)
        {
            continue;
        }
        operation_status = fprintf(stream, "  n%zua[\"resource acquired\"] --> n%zub[\"resource released\"]\n", emitted, emitted);
        operation_status = operation_status < 0 ? -1 : 0;
        emitted++;
    }
    if(emitted == 0U && operation_status != EOF)
    {
        operation_status = write_string(stream, "  empty[\"No completed resource lifetimes observed\"]\n");
    }
    if(operation_status != EOF)
    {
        operation_status = write_string(stream, "```\n");
    }
    if(operation_status == EOF)
    {
        P101_ERROR_RAISE_ERRNO(err, EIO);
        p101_single_result_ = -1;
    }
    else
    {
        p101_single_result_ = 0;
    }
    error_present = p101_error_has_error(err);
    if(error_present)
    {
        close_error = P101_ERROR_OPTIONAL;
    }
    else
    {
        close_error = err;
    }
    operation_status = close_output(close_error, &stream);
    if(operation_status != 0)
    {
        p101_single_result_ = -1;
    }

p101_single_exit_:
    return p101_single_result_;
}

static int open_output(struct p101_error *err, const char *directory, const char *name, FILE **stream)
{
    int  p101_single_result_;
    char path[PATH_SIZE];
    int  operation_status;

    operation_status = snprintf(path, sizeof(path), "%s/%s", directory, name);
    if(operation_status < 0 || (size_t)operation_status >= sizeof(path))
    {
        P101_ERROR_RAISE_ERRNO(err, EOVERFLOW);
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    *stream = fopen(path, "we");
    if(*stream == NULL)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    p101_single_result_ = 0;

p101_single_exit_:
    return p101_single_result_;
}

static int close_output(struct p101_error *err, FILE **stream)
{
    int p101_single_result_;
    int flush_status;
    int close_status;
    int error_number;

    errno        = 0;
    flush_status = fflush(*stream);
    error_number = flush_status == 0 ? 0 : errno;
    errno        = 0;
    close_status = fclose(*stream);
    if(close_status != 0 && error_number == 0)
    {
        error_number = errno;
    }
    *stream = NULL;
    if(flush_status != 0 || close_status != 0)
    {
        P101_ERROR_RAISE_ERRNO(err, error_number == 0 ? EIO : error_number);
        p101_single_result_ = -1;
    }
    else
    {
        p101_single_result_ = 0;
    }
    return p101_single_result_;
}

static int write_json_string(FILE *stream, const char *text)
{
    int p101_single_result_;
    int operation_status;

    operation_status = fputc('"', stream);
    for(size_t index = 0U; text[index] != '\0' && operation_status != EOF; index++)
    {
        unsigned char character;

        character = (unsigned char)text[index];
        if(character == '"' || character == '\\')
        {
            operation_status = fputc('\\', stream);
        }
        if(operation_status != EOF)
        {
            if(character == '\n')
            {
                operation_status = fputs("\\n", stream);
            }
            else if(character == '\r')
            {
                operation_status = fputs("\\r", stream);
            }
            else if(character == '\t')
            {
                operation_status = fputs("\\t", stream);
            }
            else if(character < JSON_CONTROL_LIMIT)
            {
                operation_status = fprintf(stream, "\\u%04x", character);
            }
            else
            {
                operation_status = fputc(character, stream);
            }
        }
    }
    if(operation_status != EOF)
    {
        operation_status = fputc('"', stream);
    }
    p101_single_result_ = operation_status == EOF ? -1 : 0;
    return p101_single_result_;
}

static int write_string(FILE *stream, const char *text)
{
    int p101_single_result_;
    int operation_status;

    operation_status    = fputs(text, stream);
    p101_single_result_ = operation_status == EOF ? -1 : 0;
    return p101_single_result_;
}

static const char *policy_name(p101_tool_analysis_policy policy)
{
    const char *p101_single_result_;

#ifdef __clang__
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wcovered-switch-default"
#endif
    switch(policy)
    {
        case P101_TOOL_ANALYSIS_RESOURCE:
            p101_single_result_ = "resource";
            break;
        case P101_TOOL_ANALYSIS_SYNCHRONIZATION:
            p101_single_result_ = "synchronization";
            break;
        case P101_TOOL_ANALYSIS_TRACE:
            p101_single_result_ = "trace";
            break;
        case P101_TOOL_ANALYSIS_SANITIZER:
            p101_single_result_ = "sanitizer";
            break;
        default:
            p101_single_result_ = "unknown";
            break;
    }
#ifdef __clang__
    #pragma clang diagnostic pop
#endif
    return p101_single_result_;
}
