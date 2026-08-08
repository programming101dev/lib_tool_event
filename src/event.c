#include <errno.h>
#include <limits.h>
#include <p101_error/attributes.h>
#include <p101_record/record.h>
#include <p101_tool_event/event.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum
{
    NUMBER_BASE              = 10,
    MAX_FIELDS               = 20,
    EVENT_FD_MAX             = 1048576,
    METADATA_FIELDS          = 7,
    RUN_ID_INDEX             = 1,
    PID_INDEX                = 2,
    CONTEXT_INDEX            = 3,
    SEQUENCE_INDEX           = 4,
    MONOTONIC_INDEX          = 5,
    WALL_INDEX               = 6,
    FD_PAYLOAD_FIELDS        = 5,
    ALLOC_PAYLOAD_FIELDS     = 7,
    FORK_PAYLOAD_FIELDS      = 4,
    SPAWN_PAYLOAD_FIELDS     = 5,
    EXEC_PAYLOAD_FIELDS      = 6,
    EXEC_FAIL_PAYLOAD_FIELDS = 4,
    CALL_PAYLOAD_FIELDS      = 7,
    RESOURCE_PAYLOAD_FIELDS  = 9,
    COMPLETE_PAYLOAD_FIELDS  = 3,
    ALLOC_FUNCTION_INDEX     = 5,
    ALLOC_FILE_INDEX         = 6,
    EXEC_TARGET_INDEX        = 5,
    CALL_RESULT_INDEX        = 5,
    CALL_FILE_INDEX          = 6,
    RESOURCE_METADATA_INDEX  = 5,
    RESOURCE_LINE_INDEX      = 6,
    RESOURCE_FUNCTION_INDEX  = 7,
    RESOURCE_FILE_INDEX      = 8,
    HEALTH_INITIAL_CAPACITY  = 8
};

static int                          parse_long_field(const char *text, long min, long max, long *out);
static int                          parse_optional_size_field(const char *text, size_t *out, int *available);
static p101_tool_event_parse_status parse_metadata(char *fields[], size_t field_count, struct p101_tool_event_record *record, size_t *payload);
static bool                         payload_arity_matches(size_t count, size_t payload, size_t fields_needed);
static p101_tool_event_parse_status parse_payload(const char *magic, char *fields[], size_t count, size_t payload, struct p101_tool_event_record *record);
static void                         unescape_record(struct p101_tool_event_record *record);

struct line_builder
{
    char   data[P101_TOOL_EVENT_LINE_MAX_BYTES + 1U];
    size_t length;
    int    failed;
};

static void                                    append_char(struct line_builder *builder, char value);
static void                                    append_text(struct line_builder *builder, const char *text);
static void                                    append_format(struct line_builder *builder, const char *format, ...) P101_ATTR_PRINTF(2, 3);
static void                                    append_field(struct line_builder *builder, const char *text);
static void                                    write_metadata(struct line_builder *builder, const struct p101_tool_event_output *record);
static void                                    write_payload(struct line_builder *builder, const struct p101_tool_event_output *record);
static int                                     output_is_valid(const struct p101_tool_event_output *record);
static bool                                    lookup_record_magic(const char *text, size_t *index);
static bool                                    lookup_fd_kind(const char *text, size_t *index);
static bool                                    lookup_alloc_kind(const char *text, size_t *index);
static bool                                    lookup_call_kind(const char *text, size_t *index);
static bool                                    lookup_resource_kind(const char *text, size_t *index);
static const char                             *record_magic(p101_tool_event_record_kind kind);
static const char                             *fd_kind_name(p101_tool_event_fd_kind kind);
static const char                             *alloc_kind_name(p101_tool_event_alloc_kind kind);
static const char                             *call_kind_name(p101_tool_event_call_kind kind);
static const char                             *resource_kind_name(p101_tool_event_resource_kind kind);
static struct p101_tool_event_producer_health *find_or_add_producer(struct p101_tool_event_stream_health *health, const char *run_id, long pid, size_t context_id);

#ifdef P101_TOOL_EVENT_TESTING
static int force_health_allocation_failure;
static int force_health_allocation_failure_errno = ENOMEM;
static int force_zero_errno_on_read_error;
static int force_zero_errno_on_write_error;
static int force_format_overflow;

void p101_tool_event_test_force_health_allocation_failure(void)
{
    force_health_allocation_failure = 1;
}

void p101_tool_event_test_set_health_allocation_failure_errno(int errnum)
{
    force_health_allocation_failure_errno = errnum;
}

void p101_tool_event_test_force_zero_errno_on_read_error(void)
{
    force_zero_errno_on_read_error = 1;
}

void p101_tool_event_test_force_zero_errno_on_write_error(void)
{
    force_zero_errno_on_write_error = 1;
}

void p101_tool_event_test_force_format_overflow(void)
{
    force_format_overflow = 1;
}
#endif

p101_tool_event_line_status p101_tool_event_read_line(struct p101_error *err, FILE *stream, char *line, size_t line_size)
{
    p101_tool_event_line_status p101_single_result_;
    bool                        saw_byte;
    bool                        malformed;
    size_t                      length;

    if(line != NULL && line_size > 0U)
    {
        line[0] = '\0';
    }

    if(stream == NULL || line == NULL || line_size == 0U)
    {
        P101_ERROR_RAISE_CHECK(err);
        p101_single_result_ = P101_TOOL_EVENT_LINE_ERROR;
        goto p101_single_exit_;
    }

    saw_byte  = false;
    malformed = false;
    length    = 0U;

    while(true)
    {
        int ch;
        int stream_failed;

        ch = fgetc(stream);
        if(ch == EOF)
        {
            stream_failed = ferror(stream);
            if(stream_failed != 0)
            {
                line[length] = '\0';
#ifdef P101_TOOL_EVENT_TESTING
                if(force_zero_errno_on_read_error != 0)
                {
                    force_zero_errno_on_read_error = 0;
                    errno                          = 0;
                }
#endif
                P101_ERROR_RAISE_ERRNO(err, errno == 0 ? EIO : errno);
                p101_single_result_ = P101_TOOL_EVENT_LINE_ERROR;
                goto p101_single_exit_;
            }
            break;
        }

        saw_byte = true;
        if(ch == '\0')
        {
            malformed = true;
        }

        if(length + 1U < line_size)
        {
            line[length++] = (char)ch;
        }
        else
        {
            malformed = true;
        }

        if(ch == '\n')
        {
            break;
        }
    }

    if(!saw_byte)
    {
        p101_single_result_ = P101_TOOL_EVENT_LINE_EOF;
        goto p101_single_exit_;
    }

    line[length] = '\0';
    if(malformed)
    {
        p101_single_result_ = P101_TOOL_EVENT_LINE_MALFORMED;
        goto p101_single_exit_;
    }
    p101_single_result_ = P101_TOOL_EVENT_LINE_OK;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

p101_tool_event_parse_status p101_tool_event_parse_line(char *line, struct p101_tool_event_record *record)
{
    p101_tool_event_parse_status p101_single_result_;
    char                        *cursor;
    char                        *fields[MAX_FIELDS];
    const char                  *magic;
    size_t                       count;
    size_t                       length;
    size_t                       payload;
    p101_tool_event_parse_status status;
    int                          is_ours;

    if(line == NULL || record == NULL)
    {
        p101_single_result_ = P101_TOOL_EVENT_PARSE_MALFORMED;
        goto p101_single_exit_;
    }

    is_ours = p101_tool_event_line_is_ours(line);
    if(is_ours == 0)
    {
        p101_single_result_ = P101_TOOL_EVENT_PARSE_OTHER;
        goto p101_single_exit_;
    }

    memset(record, 0, sizeof(*record));
    record->fd          = -1;
    record->child_pid   = -1;
    record->line_number = -1;

    length = strlen(line);
    while(line[length - 1U] == '\n' || line[length - 1U] == '\r')
    {
        line[--length] = '\0';
    }

    cursor = line;
    magic  = p101_record_split(&cursor);
    count  = 0U;
    while(cursor != NULL && count < MAX_FIELDS)
    {
        fields[count++] = p101_record_split(&cursor);
    }
    if(cursor != NULL)
    {
        p101_single_result_ = P101_TOOL_EVENT_PARSE_MALFORMED;
        goto p101_single_exit_;
    }

    status = parse_metadata(fields, count, record, &payload);
    if(status != P101_TOOL_EVENT_PARSE_OK)
    {
        p101_single_result_ = status;
        goto p101_single_exit_;
    }

    status = parse_payload(magic, fields, count, payload, record);
    if(status == P101_TOOL_EVENT_PARSE_OK)
    {
        unescape_record(record);
    }
    p101_single_result_ = status;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

int p101_tool_event_write(FILE *stream, const struct p101_tool_event_output *record)
{
    int                 p101_single_result_;
    struct line_builder builder;
    const char         *magic;
    int                 actual_error;
    int                 saved_error;
    int                 result;
    int                 valid;
    int                 flush_status;
    int                 descriptor;
    ssize_t             bytes_written;

    valid = 0;
    if(stream != NULL && record != NULL)
    {
        valid = output_is_valid(record);
    }
    if(valid == 0)
    {
        errno               = EINVAL;
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }

    /*
     * Build the complete protocol unit in a bounded private buffer, then
     * publish it with one operating-system write. This avoids allocation in
     * the observer path and prevents field-by-field interleaving.
     */
    memset(&builder, 0, sizeof(builder));
    magic = record_magic(record->record_kind);
    append_text(&builder, magic);
    append_char(&builder, '\t');
    write_metadata(&builder, record);
    write_payload(&builder, record);
    append_char(&builder, '\n');
    if(builder.failed != 0)
    {
        errno               = EMSGSIZE;
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }

    saved_error  = errno;
    actual_error = 0;
    result       = 0;
    errno        = 0;
    flockfile(stream);
    flush_status  = fflush(stream);
    bytes_written = (ssize_t)builder.length;
    if(flush_status != EOF)
    {
        descriptor    = fileno(stream);
        bytes_written = write(descriptor, builder.data, builder.length);
    }
    if(flush_status == EOF || bytes_written != (ssize_t)builder.length)
    {
        result = -1;
#ifdef P101_TOOL_EVENT_TESTING
        if(force_zero_errno_on_write_error != 0)
        {
            force_zero_errno_on_write_error = 0;
            errno                           = 0;
        }
#endif
        actual_error = errno == 0 ? EIO : errno;
    }
    funlockfile(stream);
    errno               = result == 0 ? saved_error : actual_error;
    p101_single_result_ = result;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

int p101_tool_event_line_is_ours(const char *line)
{
    int                      p101_single_result_;
    static const char *const prefixes[] = {"P101FD\t", "P101ALLOC\t", "P101FORK\t", "P101SPAWN\t", "P101EXEC\t", "P101EXECFAIL\t", "P101CALL\t", "P101RESOURCE\t", "P101COMPLETE\t"};

    if(line == NULL)
    {
        p101_single_result_ = 0;
        goto p101_single_exit_;
    }

    for(size_t i = 0U; i < sizeof(prefixes) / sizeof(prefixes[0]); i++)
    {
        size_t prefix_length;
        int    comparison;

        prefix_length = strlen(prefixes[i]);
        comparison    = strncmp(line, prefixes[i], prefix_length);
        if(comparison == 0)
        {
            p101_single_result_ = 1;
            goto p101_single_exit_;
        }
    }
    p101_single_result_ = 0;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

int p101_tool_event_stream_health_observe(struct p101_tool_event_stream_health *health, const struct p101_tool_event_record *record)
{
    int                                     p101_single_result_;
    struct p101_tool_event_producer_health *producer;
    size_t                                  run_id_length;
    int                                     run_id_comparison;

    if(health == NULL || record == NULL)
    {
        errno               = EINVAL;
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }

    run_id_length = 0U;
    if(record->run_id != NULL)
    {
        run_id_length = strlen(record->run_id);
    }
    if(record->run_id == NULL || record->run_id[0] == '\0' || run_id_length > P101_TOOL_EVENT_RUN_ID_MAX_BYTES)
    {
        health->invalid_run_ids++;
        errno               = EINVAL;
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    if(health->distinct_run_ids == 0U)
    {
        for(size_t index = 0U; index <= run_id_length; index++)
        {
            health->run_id[index] = record->run_id[index];
        }
        health->distinct_run_ids = 1U;
    }
    else
    {
        run_id_comparison = strcmp(health->run_id, record->run_id);
        if(run_id_comparison != 0)
        {
            health->mixed_run_ids    = 1;
            health->distinct_run_ids = 2U;
        }
    }

    producer = find_or_add_producer(health, record->run_id, record->pid, record->context_id);
    if(producer == NULL)
    {
        health->allocation_failed = 1;
        p101_single_result_       = -1;
        goto p101_single_exit_;
    }

    health->records_observed++;
    producer->records_observed++;
    if(record->record_kind == P101_TOOL_EVENT_RECORD_EXEC)
    {
        producer->pending_exec = 1;
    }
    else if(record->record_kind == P101_TOOL_EVENT_RECORD_EXEC_FAIL || record->record_kind == P101_TOOL_EVENT_RECORD_COMPLETE)
    {
        producer->pending_exec = 0;
    }
    if(producer->completion_records > 0U)
    {
        producer->records_after_completion++;
        health->records_after_completion++;
    }
    if(record->sequence != 0U && record->sequence == producer->last_sequence)
    {
        producer->duplicate_sequences++;
        health->duplicate_sequences++;
    }
    else if(record->sequence != 0U && producer->last_sequence != 0U && record->sequence < producer->last_sequence)
    {
        producer->nonmonotonic_sequences++;
        health->nonmonotonic_sequences++;
    }
    if(record->sequence > producer->last_sequence)
    {
        producer->last_sequence = record->sequence;
    }
    if(record->record_kind != P101_TOOL_EVENT_RECORD_COMPLETE)
    {
        p101_single_result_ = 0;
        goto p101_single_exit_;
    }

    health->completion_records++;
    producer->completion_records++;
    if(record->events_attempted != producer->records_observed - producer->completion_records)
    {
        producer->attempted_count_mismatches++;
        health->attempted_count_mismatches++;
    }
    if(record->write_failed != 0)
    {
        health->producer_write_failures++;
        health->last_write_errno = record->write_errno;
        producer->write_failed   = 1;
        producer->write_errno    = record->write_errno;
    }
    p101_single_result_ = 0;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

int p101_tool_event_stream_health_is_complete(const struct p101_tool_event_stream_health *health)
{
    int    p101_single_result_;
    size_t incomplete_producers;

    p101_single_result_ = 0;
    if(health == NULL)
    {
        goto p101_single_exit_;
    }

    incomplete_producers = p101_tool_event_stream_health_incomplete_producers(health);
    if(health->records_observed == 0U)
    {
        goto p101_single_exit_;
    }
    if(health->producer_count == 0U)
    {
        goto p101_single_exit_;
    }
    if(health->producer_write_failures != 0U)
    {
        goto p101_single_exit_;
    }
    if(health->duplicate_sequences != 0U)
    {
        goto p101_single_exit_;
    }
    if(health->nonmonotonic_sequences != 0U)
    {
        goto p101_single_exit_;
    }
    if(health->attempted_count_mismatches != 0U)
    {
        goto p101_single_exit_;
    }
    if(health->records_after_completion != 0U)
    {
        goto p101_single_exit_;
    }
    if(health->distinct_run_ids != 1U)
    {
        goto p101_single_exit_;
    }
    if(health->invalid_run_ids != 0U)
    {
        goto p101_single_exit_;
    }
    if(health->mixed_run_ids != 0)
    {
        goto p101_single_exit_;
    }
    if(health->allocation_failed != 0)
    {
        goto p101_single_exit_;
    }
    if(incomplete_producers != 0U)
    {
        goto p101_single_exit_;
    }
    p101_single_result_ = 1;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

size_t p101_tool_event_stream_health_incomplete_producers(const struct p101_tool_event_stream_health *health)
{
    size_t p101_single_result_;
    size_t incomplete;

    if(health == NULL)
    {
        p101_single_result_ = 0U;
        goto p101_single_exit_;
    }

    incomplete = 0U;
    for(size_t index = 0U; index < health->producer_count; index++)
    {
        const struct p101_tool_event_producer_health *producer;

        producer = &health->producers[index];
        if(producer->completion_records != 1U || producer->write_failed != 0 || producer->attempted_count_mismatches != 0U)
        {
            incomplete++;
        }
    }
    p101_single_result_ = incomplete;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

void p101_tool_event_stream_health_destroy(struct p101_tool_event_stream_health *health)
{
    if(health == NULL)
    {
        goto p101_single_exit_;
    }

    free(health->producers);
    memset(health, 0, sizeof(*health));

p101_single_exit_:
    return;
}

static struct p101_tool_event_producer_health *find_or_add_producer(struct p101_tool_event_stream_health *health, const char *run_id, long pid, size_t context_id)
{
    struct p101_tool_event_producer_health *p101_single_result_;
    size_t                                  run_id_length;
    for(size_t index = 0U; index < health->producer_count; index++)
    {
        int run_id_comparison;

        run_id_comparison = strcmp(health->producers[index].run_id, run_id);
        if(run_id_comparison == 0 && health->producers[index].pid == pid && health->producers[index].context_id == context_id)
        {
            p101_single_result_ = &health->producers[index];
            goto p101_single_exit_;
        }
    }

    if(health->producer_count == health->producer_capacity)
    {
        struct p101_tool_event_producer_health *grown;
        size_t                                  capacity;
        void                                   *storage;

        capacity = health->producer_capacity == 0U ? HEALTH_INITIAL_CAPACITY : health->producer_capacity * 2U;
#ifdef P101_TOOL_EVENT_TESTING
        if(force_health_allocation_failure != 0)
        {
            force_health_allocation_failure       = 0;
            errno                                 = force_health_allocation_failure_errno;
            force_health_allocation_failure_errno = ENOMEM;
            grown                                 = NULL;
        }
        else
#endif
        {
            storage = realloc(health->producers, capacity * sizeof(*health->producers));
            grown   = (struct p101_tool_event_producer_health *)storage;
        }
        if(grown == NULL)
        {
            p101_single_result_ = NULL;
            goto p101_single_exit_;
        }
        health->producers         = grown;
        health->producer_capacity = capacity;
    }

    memset(&health->producers[health->producer_count], 0, sizeof(*health->producers));
    run_id_length = strlen(run_id);
    for(size_t index = 0U; index <= run_id_length; index++)
    {
        health->producers[health->producer_count].run_id[index] = run_id[index];
    }
    health->producers[health->producer_count].pid        = pid;
    health->producers[health->producer_count].context_id = context_id;
    health->producer_count++;
    p101_single_result_ = &health->producers[health->producer_count - 1U];
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

const char *p101_tool_event_parse_status_name(p101_tool_event_parse_status status)
{
    const char *p101_single_result_;
#ifdef __clang__
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wcovered-switch-default"
#endif
    switch(status)
    {
        case P101_TOOL_EVENT_PARSE_OTHER:
            p101_single_result_ = "not a p101 event record";
            goto p101_single_exit_;
        case P101_TOOL_EVENT_PARSE_OK:
            p101_single_result_ = "ok";
            goto p101_single_exit_;
        case P101_TOOL_EVENT_PARSE_MALFORMED:
            p101_single_result_ = "malformed record";
            goto p101_single_exit_;
        case P101_TOOL_EVENT_PARSE_BAD_VERSION:
            p101_single_result_ = "unsupported record version";
            goto p101_single_exit_;
        default:
            p101_single_result_ = "unknown event parse status";
            goto p101_single_exit_;
    }
#ifdef __clang__
    #pragma clang diagnostic pop
#endif

p101_single_exit_:
    return p101_single_result_;
}

static int parse_long_field(const char *text, long min, long max, long *out)
{
    int   p101_single_result_;
    char *end;
    long  value;

    if(*text == '\0')
    {
        p101_single_result_ = 0;
        goto p101_single_exit_;
    }

    errno = 0;
    value = strtol(text, &end, NUMBER_BASE);
    if(end == text || *end != '\0')
    {
        p101_single_result_ = 0;
        goto p101_single_exit_;
    }
    if(errno != 0)
    {
        p101_single_result_ = 0;
        goto p101_single_exit_;
    }
    if(value < min || value > max)
    {
        p101_single_result_ = 0;
        goto p101_single_exit_;
    }
    *out                = value;
    p101_single_result_ = 1;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static int parse_optional_size_field(const char *text, size_t *out, int *available)
{
    int p101_single_result_;
    int comparison;
    int parsed;

    *out       = 0U;
    *available = 0;
    comparison = strcmp(text, "-");
    if(comparison == 0)
    {
        p101_single_result_ = 1;
        goto p101_single_exit_;
    }
    parsed = p101_record_parse_size(text, out);
    if(parsed == 0)
    {
        p101_single_result_ = 0;
        goto p101_single_exit_;
    }
    *available          = 1;
    p101_single_result_ = 1;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static p101_tool_event_parse_status parse_metadata(char *fields[], size_t field_count, struct p101_tool_event_record *record, size_t *payload)
{
    p101_tool_event_parse_status p101_single_result_;
    long                         version;
    int                          parsed;
    size_t                       run_id_length;

    version = 0;
    parsed  = 0;
    if(field_count >= METADATA_FIELDS)
    {
        parsed = parse_long_field(fields[0], 0, LONG_MAX, &version);
    }
    if(parsed == 0)
    {
        p101_single_result_ = P101_TOOL_EVENT_PARSE_MALFORMED;
        goto p101_single_exit_;
    }

    if(version != P101_TOOL_EVENT_LOG_VERSION)
    {
        p101_single_result_ = P101_TOOL_EVENT_PARSE_BAD_VERSION;
        goto p101_single_exit_;
    }
    record->version = (int)version;
    record->run_id  = fields[RUN_ID_INDEX];
    run_id_length   = strlen(record->run_id);
    if(record->run_id[0] == '\0' || run_id_length > P101_TOOL_EVENT_RUN_ID_MAX_BYTES)
    {
        p101_single_result_ = P101_TOOL_EVENT_PARSE_MALFORMED;
        goto p101_single_exit_;
    }
    parsed = parse_long_field(fields[PID_INDEX], 0, LONG_MAX, &record->pid);
    if(parsed == 0)
    {
        p101_single_result_ = P101_TOOL_EVENT_PARSE_MALFORMED;
        goto p101_single_exit_;
    }

    parsed = p101_record_parse_size(fields[CONTEXT_INDEX], &record->context_id);
    if(parsed == 0)
    {
        p101_single_result_ = P101_TOOL_EVENT_PARSE_MALFORMED;
        goto p101_single_exit_;
    }
    *payload = METADATA_FIELDS;
    parsed   = p101_record_parse_size(fields[SEQUENCE_INDEX], &record->sequence);
    if(parsed != 0)
    {
        parsed = parse_optional_size_field(fields[MONOTONIC_INDEX], &record->monotonic_ns, &record->monotonic_ns_available);
    }
    if(parsed != 0)
    {
        parsed = parse_optional_size_field(fields[WALL_INDEX], &record->wall_unix_ns, &record->wall_unix_ns_available);
    }
    if(parsed == 0)
    {
        p101_single_result_ = P101_TOOL_EVENT_PARSE_MALFORMED;
        goto p101_single_exit_;
    }
    p101_single_result_ = P101_TOOL_EVENT_PARSE_OK;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static void append_char(struct line_builder *builder, char value)
{
    if(builder->failed != 0)
    {
        goto p101_single_exit_;
    }
    if(builder->length >= P101_TOOL_EVENT_LINE_MAX_BYTES)
    {
        builder->failed = 1;
        goto p101_single_exit_;
    }
    builder->data[builder->length++] = value;
    builder->data[builder->length]   = '\0';

p101_single_exit_:
    return;
}

static void append_text(struct line_builder *builder, const char *text)
{
    while(*text != '\0')
    {
        append_char(builder, *text++);
    }
}

static void append_format(struct line_builder *builder, const char *format, ...)
{
    va_list arguments;
    int     written;
    size_t  available;

    if(builder->failed != 0)
    {
        goto p101_single_exit_;
    }
    available = sizeof(builder->data) - builder->length;
    va_start(arguments, format);
    written = vsnprintf(builder->data + builder->length, available, format, arguments);
    va_end(arguments);
#ifdef P101_TOOL_EVENT_TESTING
    if(force_format_overflow != 0)
    {
        force_format_overflow = 0;
        written               = (int)available;
    }
#endif
    if((size_t)written >= available)
    {
        builder->failed = 1;
        goto p101_single_exit_;
    }
    builder->length += (size_t)written;

p101_single_exit_:
    return;
}

static void write_metadata(struct line_builder *builder, const struct p101_tool_event_output *record)
{
    int version;

    version = record->version == 0 ? P101_TOOL_EVENT_LOG_VERSION : record->version;
    append_format(builder, "%d\t", version);
    append_field(builder, record->run_id);
    append_format(builder, "\t%ld\t%zu\t%zu\t", record->pid, record->context_id, record->sequence);
    if(record->monotonic_ns_available != 0)
    {
        append_format(builder, "%zu\t", record->monotonic_ns);
    }
    else
    {
        append_text(builder, "-\t");
    }
    if(record->wall_unix_ns_available != 0)
    {
        append_format(builder, "%zu\t", record->wall_unix_ns);
    }
    else
    {
        append_text(builder, "-\t");
    }
}

static void write_payload(struct line_builder *builder, const struct p101_tool_event_output *record)
{
#ifdef __clang__
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wcovered-switch-default"
#endif
    switch(record->record_kind)
    {
        case P101_TOOL_EVENT_RECORD_FD:
        {
            const char *kind_name;

            kind_name = fd_kind_name(record->fd_kind);
            append_format(builder, "%s\t%d\t%d\t", kind_name, record->fd, record->line_number);
            append_field(builder, record->function_name);
            append_char(builder, '\t');
            append_field(builder, record->file_name);
            break;
        }
        case P101_TOOL_EVENT_RECORD_ALLOC:
        {
            const char *kind_name;

            kind_name = alloc_kind_name(record->alloc_kind);
            append_format(builder, "%s\t", kind_name);
            append_field(builder, record->ptr);
            append_char(builder, '\t');
            append_field(builder, record->new_ptr);
            append_format(builder, "\t%zu\t%d\t", record->size, record->line_number);
            append_field(builder, record->function_name);
            append_char(builder, '\t');
            append_field(builder, record->file_name);
            break;
        }
        case P101_TOOL_EVENT_RECORD_FORK:
            append_format(builder, "%ld\t%d\t", record->child_pid, record->line_number);
            append_field(builder, record->function_name);
            append_char(builder, '\t');
            append_field(builder, record->file_name);
            break;
        case P101_TOOL_EVENT_RECORD_SPAWN:
            append_format(builder, "%ld\t%d\t", record->child_pid, record->line_number);
            append_field(builder, record->function_name);
            append_char(builder, '\t');
            append_field(builder, record->file_name);
            append_char(builder, '\t');
            append_field(builder, record->target);
            break;
        case P101_TOOL_EVENT_RECORD_EXEC:
            append_format(builder, "%d\t%d\t%d\t", record->fd, record->cloexec, record->line_number);
            append_field(builder, record->function_name);
            append_char(builder, '\t');
            append_field(builder, record->file_name);
            append_char(builder, '\t');
            append_field(builder, record->target);
            break;
        case P101_TOOL_EVENT_RECORD_EXEC_FAIL:
            append_format(builder, "%d\t", record->line_number);
            append_field(builder, record->function_name);
            append_char(builder, '\t');
            append_field(builder, record->file_name);
            append_char(builder, '\t');
            append_field(builder, record->target);
            break;
        case P101_TOOL_EVENT_RECORD_CALL:
        {
            const char *kind_name;

            kind_name = call_kind_name(record->call_kind);
            append_format(builder, "%s\t%d\t", kind_name, record->line_number);
            append_field(builder, record->function_name);
            append_char(builder, '\t');
            append_field(builder, record->call_name);
            append_char(builder, '\t');
            append_field(builder, record->arguments);
            append_char(builder, '\t');
            append_field(builder, record->result);
            append_char(builder, '\t');
            append_field(builder, record->file_name);
            break;
        }
        case P101_TOOL_EVENT_RECORD_RESOURCE:
        {
            const char *kind_name;

            kind_name = resource_kind_name(record->resource_kind);
            append_format(builder, "%s\t", kind_name);
            append_field(builder, record->resource_class);
            append_char(builder, '\t');
            append_field(builder, record->resource_id);
            append_char(builder, '\t');
            append_field(builder, record->related_id);
            append_format(builder, "\t%zu\t", record->size);
            append_field(builder, record->metadata);
            append_format(builder, "\t%d\t", record->line_number);
            append_field(builder, record->function_name);
            append_char(builder, '\t');
            append_field(builder, record->file_name);
            break;
        }
        case P101_TOOL_EVENT_RECORD_COMPLETE:
            append_format(builder, "%zu\t%d\t%d", record->events_attempted, record->write_failed, record->write_errno);
            break;
        default:
            break;
    }
#ifdef __clang__
    #pragma clang diagnostic pop
#endif
}

static void append_field(struct line_builder *builder, const char *text)
{
    if(text == NULL)
    {
        append_text(builder, "-");
    }
    else if(text[0] == '-' && text[1] == '\0')
    {
        append_text(builder, "\\-");
    }
    else
    {
        while(*text != '\0')
        {
            unsigned char ch;
            const char   *escaped;

            ch      = (unsigned char)*text++;
            escaped = p101_record_escape_byte(ch);
            if(escaped != NULL)
            {
                append_text(builder, escaped);
            }
            else
            {
                append_char(builder, (char)ch);
            }
        }
    }
}

static int output_is_valid(const struct p101_tool_event_output *record)
{
    int    p101_single_result_;
    int    version;
    size_t run_id_length;

    version       = record->version == 0 ? P101_TOOL_EVENT_LOG_VERSION : record->version;
    run_id_length = 0U;
    if(record->run_id != NULL)
    {
        run_id_length = strlen(record->run_id);
    }
    if(version != P101_TOOL_EVENT_LOG_VERSION || record->run_id == NULL || record->run_id[0] == '\0' || run_id_length > P101_TOOL_EVENT_RUN_ID_MAX_BYTES || record->pid < 0 || (record->monotonic_ns_available != 0 && record->monotonic_ns_available != 1) ||
       (record->wall_unix_ns_available != 0 && record->wall_unix_ns_available != 1))
    {
        p101_single_result_ = 0;
        goto p101_single_exit_;
    }
#ifdef __clang__
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wcovered-switch-default"
#endif
    switch(record->record_kind)
    {
        case P101_TOOL_EVENT_RECORD_FD:
            p101_single_result_ = record->fd >= 0 && record->fd <= EVENT_FD_MAX && record->line_number >= 0 && (record->fd_kind == P101_TOOL_EVENT_FD_OPEN || record->fd_kind == P101_TOOL_EVENT_FD_CLOSE);
            goto p101_single_exit_;
        case P101_TOOL_EVENT_RECORD_ALLOC:
            p101_single_result_ = record->line_number >= 0 && (record->alloc_kind == P101_TOOL_EVENT_ALLOC_ALLOC || record->alloc_kind == P101_TOOL_EVENT_ALLOC_FREE || record->alloc_kind == P101_TOOL_EVENT_ALLOC_REALLOC);
            goto p101_single_exit_;
        case P101_TOOL_EVENT_RECORD_CALL:
            p101_single_result_ = record->line_number >= 0 && (record->call_kind == P101_TOOL_EVENT_CALL_ENTER || record->call_kind == P101_TOOL_EVENT_CALL_EXIT);
            goto p101_single_exit_;
        case P101_TOOL_EVENT_RECORD_RESOURCE:
            p101_single_result_ = (record->line_number >= 0 && (record->resource_kind == P101_TOOL_EVENT_RESOURCE_ACQUIRE || record->resource_kind == P101_TOOL_EVENT_RESOURCE_RELEASE || record->resource_kind == P101_TOOL_EVENT_RESOURCE_REPLACE ||
                                                                record->resource_kind == P101_TOOL_EVENT_RESOURCE_TRANSFER));
            goto p101_single_exit_;
        case P101_TOOL_EVENT_RECORD_FORK:
        case P101_TOOL_EVENT_RECORD_SPAWN:
            p101_single_result_ = record->child_pid >= 0 && record->line_number >= 0;
            goto p101_single_exit_;
        case P101_TOOL_EVENT_RECORD_EXEC:
            p101_single_result_ = record->fd >= 0 && record->fd <= EVENT_FD_MAX && (record->cloexec == 0 || record->cloexec == 1) && record->line_number >= 0;
            goto p101_single_exit_;
        case P101_TOOL_EVENT_RECORD_EXEC_FAIL:
            p101_single_result_ = record->line_number >= 0;
            goto p101_single_exit_;
        case P101_TOOL_EVENT_RECORD_COMPLETE:
            p101_single_result_ = (record->write_failed == 0 || record->write_failed == 1) && ((record->write_failed == 0 && record->write_errno == 0) || (record->write_failed == 1 && record->write_errno > 0));
            goto p101_single_exit_;
        default:
            break;
    }
#ifdef __clang__
    #pragma clang diagnostic pop
#endif
    p101_single_result_ = 0;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

/*
 * Single source of truth for the wire tokens: each *_name accessor below owns
 * the only table for its enum, and the matching lookup_* walks that enum's
 * range through the accessor, so the parser recognizes exactly what the
 * writers can emit and a token cannot be renamed on one side only.
 *
 * The tables are function-local on purpose. Hoisting them to file scope lets
 * the static analyzer constant-fold a read into a concrete string literal,
 * which alpha.core.PointerArithm then reports against append_text's pointer
 * walk; kept local, the loaded value stays symbolic and the checker is quiet.
 */
static bool lookup_record_magic(const char *text, size_t *index)
{
    bool found;

    found = false;
    for(size_t position = 0U; position <= (size_t)P101_TOOL_EVENT_RECORD_COMPLETE; position++)
    {
        int comparison;

        comparison = strcmp(record_magic((p101_tool_event_record_kind)position), text);
        if(comparison == 0)
        {
            *index = position;
            found  = true;
            break;
        }
    }

    return found;
}

static bool lookup_fd_kind(const char *text, size_t *index)
{
    bool found;

    found = false;
    for(size_t position = 0U; position <= (size_t)P101_TOOL_EVENT_FD_CLOSE; position++)
    {
        int comparison;

        comparison = strcmp(fd_kind_name((p101_tool_event_fd_kind)position), text);
        if(comparison == 0)
        {
            *index = position;
            found  = true;
            break;
        }
    }

    return found;
}

static bool lookup_alloc_kind(const char *text, size_t *index)
{
    bool found;

    found = false;
    for(size_t position = 0U; position <= (size_t)P101_TOOL_EVENT_ALLOC_REALLOC; position++)
    {
        int comparison;

        comparison = strcmp(alloc_kind_name((p101_tool_event_alloc_kind)position), text);
        if(comparison == 0)
        {
            *index = position;
            found  = true;
            break;
        }
    }

    return found;
}

static bool lookup_call_kind(const char *text, size_t *index)
{
    bool found;

    found = false;
    for(size_t position = 0U; position <= (size_t)P101_TOOL_EVENT_CALL_EXIT; position++)
    {
        int comparison;

        comparison = strcmp(call_kind_name((p101_tool_event_call_kind)position), text);
        if(comparison == 0)
        {
            *index = position;
            found  = true;
            break;
        }
    }

    return found;
}

static bool lookup_resource_kind(const char *text, size_t *index)
{
    bool found;

    found = false;
    for(size_t position = 0U; position <= (size_t)P101_TOOL_EVENT_RESOURCE_TRANSFER; position++)
    {
        int comparison;

        comparison = strcmp(resource_kind_name((p101_tool_event_resource_kind)position), text);
        if(comparison == 0)
        {
            *index = position;
            found  = true;
            break;
        }
    }

    return found;
}

static const char *record_magic(p101_tool_event_record_kind kind)
{
    static const char *const names[] = {
        [P101_TOOL_EVENT_RECORD_FD]        = "P101FD",
        [P101_TOOL_EVENT_RECORD_ALLOC]     = "P101ALLOC",
        [P101_TOOL_EVENT_RECORD_FORK]      = "P101FORK",
        [P101_TOOL_EVENT_RECORD_SPAWN]     = "P101SPAWN",
        [P101_TOOL_EVENT_RECORD_EXEC]      = "P101EXEC",
        [P101_TOOL_EVENT_RECORD_EXEC_FAIL] = "P101EXECFAIL",
        [P101_TOOL_EVENT_RECORD_CALL]      = "P101CALL",
        [P101_TOOL_EVENT_RECORD_RESOURCE]  = "P101RESOURCE",
        [P101_TOOL_EVENT_RECORD_COMPLETE]  = "P101COMPLETE",
    };

    return names[kind];
}

static const char *fd_kind_name(p101_tool_event_fd_kind kind)
{
    static const char *const names[] = {
        [P101_TOOL_EVENT_FD_OPEN]  = "OPEN",
        [P101_TOOL_EVENT_FD_CLOSE] = "CLOSE",
    };

    return names[kind];
}

static const char *alloc_kind_name(p101_tool_event_alloc_kind kind)
{
    static const char *const names[] = {
        [P101_TOOL_EVENT_ALLOC_ALLOC]   = "ALLOC",
        [P101_TOOL_EVENT_ALLOC_FREE]    = "FREE",
        [P101_TOOL_EVENT_ALLOC_REALLOC] = "REALLOC",
    };

    return names[kind];
}

static const char *call_kind_name(p101_tool_event_call_kind kind)
{
    static const char *const names[] = {
        [P101_TOOL_EVENT_CALL_ENTER] = "ENTER",
        [P101_TOOL_EVENT_CALL_EXIT]  = "EXIT",
    };

    return names[kind];
}

static const char *resource_kind_name(p101_tool_event_resource_kind kind)
{
    static const char *const names[] = {
        [P101_TOOL_EVENT_RESOURCE_ACQUIRE]  = "ACQUIRE",
        [P101_TOOL_EVENT_RESOURCE_RELEASE]  = "RELEASE",
        [P101_TOOL_EVENT_RESOURCE_REPLACE]  = "REPLACE",
        [P101_TOOL_EVENT_RESOURCE_TRANSFER] = "TRANSFER",
    };

    return names[kind];
}

/*
 * Whether count fields leave exactly fields_needed of them after the metadata
 * that ends at payload.
 *
 * Deliberately not "count == payload + fields_needed": size_t arithmetic wraps,
 * so a payload of SIZE_MAX - 3 satisfies that for a count of 1, and every
 * fields[payload + n] read in parse_payload then runs off the front of the
 * array. Subtracting states the same arity rule and cannot wrap, and the
 * count <= MAX_FIELDS term spells out what fields[] actually holds instead of
 * trusting the caller to have filled it from the same bound.
 */
static bool payload_arity_matches(size_t count, size_t payload, size_t fields_needed)
{
    bool matches;

    matches = false;
    if(count <= (size_t)MAX_FIELDS && count >= fields_needed && payload == count - fields_needed)
    {
        matches = true;
    }

    return matches;
}

static p101_tool_event_parse_status parse_payload(const char *magic, char *fields[], size_t count, size_t payload, struct p101_tool_event_record *record)
{
    p101_tool_event_parse_status p101_single_result_;
    long                         value;
    size_t                       magic_index;
    bool                         found;
    int                          parsed;

    value = 0;
    found = lookup_record_magic(magic, &magic_index);
    if(!found)
    {
        magic_index = SIZE_MAX;
    }

    if(magic_index == (size_t)P101_TOOL_EVENT_RECORD_FD)
    {
        size_t action_index;
        bool   action_found;

        if(!payload_arity_matches(count, payload, FD_PAYLOAD_FIELDS))
        {
            p101_single_result_ = P101_TOOL_EVENT_PARSE_MALFORMED;
            goto p101_single_exit_;
        }
        action_found = lookup_fd_kind(fields[payload], &action_index);
        if(!action_found)
        {
            p101_single_result_ = P101_TOOL_EVENT_PARSE_MALFORMED;
            goto p101_single_exit_;
        }
        record->fd_kind = (p101_tool_event_fd_kind)action_index;
        parsed          = parse_long_field(fields[payload + 1U], 0, EVENT_FD_MAX, &value);
        if(parsed == 0)
        {
            p101_single_result_ = P101_TOOL_EVENT_PARSE_MALFORMED;
            goto p101_single_exit_;
        }
        record->fd = (int)value;
        parsed     = parse_long_field(fields[payload + 2U], 0, INT_MAX, &value);
        if(parsed == 0)
        {
            p101_single_result_ = P101_TOOL_EVENT_PARSE_MALFORMED;
            goto p101_single_exit_;
        }
        record->line_number   = (int)value;
        record->function_name = fields[payload + 3U];
        record->file_name     = fields[payload + 4U];
        record->record_kind   = P101_TOOL_EVENT_RECORD_FD;
        p101_single_result_   = P101_TOOL_EVENT_PARSE_OK;
        goto p101_single_exit_;
    }

    if(magic_index == (size_t)P101_TOOL_EVENT_RECORD_ALLOC)
    {
        size_t action_index;
        bool   action_found;
        int    null_comparison;

        if(!payload_arity_matches(count, payload, ALLOC_PAYLOAD_FIELDS))
        {
            p101_single_result_ = P101_TOOL_EVENT_PARSE_MALFORMED;
            goto p101_single_exit_;
        }
        action_found = lookup_alloc_kind(fields[payload], &action_index);
        if(!action_found)
        {
            p101_single_result_ = P101_TOOL_EVENT_PARSE_MALFORMED;
            goto p101_single_exit_;
        }
        record->alloc_kind = (p101_tool_event_alloc_kind)action_index;
        record->ptr        = fields[payload + 1U];
        null_comparison    = strcmp(fields[payload + 2U], "-");
        record->new_ptr    = null_comparison == 0 ? NULL : fields[payload + 2U];
        parsed             = p101_record_parse_size(fields[payload + 3U], &record->size);
        if(parsed != 0)
        {
            parsed = parse_long_field(fields[payload + 4U], 0, INT_MAX, &value);
        }
        if(parsed == 0)
        {
            p101_single_result_ = P101_TOOL_EVENT_PARSE_MALFORMED;
            goto p101_single_exit_;
        }
        record->line_number   = (int)value;
        record->function_name = fields[payload + ALLOC_FUNCTION_INDEX];
        record->file_name     = fields[payload + ALLOC_FILE_INDEX];
        record->record_kind   = P101_TOOL_EVENT_RECORD_ALLOC;
        p101_single_result_   = P101_TOOL_EVENT_PARSE_OK;
        goto p101_single_exit_;
    }

    if(magic_index == (size_t)P101_TOOL_EVENT_RECORD_FORK)
    {
        parsed = parse_long_field(fields[payload], 0, LONG_MAX, &record->child_pid);
        if(parsed != 0)
        {
            parsed = parse_long_field(fields[payload + 1U], 0, INT_MAX, &value);
        }
        if(!payload_arity_matches(count, payload, FORK_PAYLOAD_FIELDS) || parsed == 0)
        {
            p101_single_result_ = P101_TOOL_EVENT_PARSE_MALFORMED;
            goto p101_single_exit_;
        }
        record->line_number   = (int)value;
        record->function_name = fields[payload + 2U];
        record->file_name     = fields[payload + 3U];
        record->target        = NULL;
        record->record_kind   = P101_TOOL_EVENT_RECORD_FORK;
        p101_single_result_   = P101_TOOL_EVENT_PARSE_OK;
        goto p101_single_exit_;
    }

    if(magic_index == (size_t)P101_TOOL_EVENT_RECORD_SPAWN)
    {
        parsed = parse_long_field(fields[payload], 0, LONG_MAX, &record->child_pid);
        if(parsed != 0)
        {
            parsed = parse_long_field(fields[payload + 1U], 0, INT_MAX, &value);
        }
        if(!payload_arity_matches(count, payload, SPAWN_PAYLOAD_FIELDS) || parsed == 0)
        {
            p101_single_result_ = P101_TOOL_EVENT_PARSE_MALFORMED;
            goto p101_single_exit_;
        }
        record->line_number   = (int)value;
        record->function_name = fields[payload + 2U];
        record->file_name     = fields[payload + 3U];
        record->target        = fields[payload + 4U];
        record->record_kind   = P101_TOOL_EVENT_RECORD_SPAWN;
        p101_single_result_   = P101_TOOL_EVENT_PARSE_OK;
        goto p101_single_exit_;
    }

    if(magic_index == (size_t)P101_TOOL_EVENT_RECORD_EXEC)
    {
        parsed = parse_long_field(fields[payload], 0, EVENT_FD_MAX, &value);
        if(!payload_arity_matches(count, payload, EXEC_PAYLOAD_FIELDS) || parsed == 0)
        {
            p101_single_result_ = P101_TOOL_EVENT_PARSE_MALFORMED;
            goto p101_single_exit_;
        }
        record->fd = (int)value;
        parsed     = parse_long_field(fields[payload + 1U], 0, 1, &value);
        if(parsed == 0)
        {
            p101_single_result_ = P101_TOOL_EVENT_PARSE_MALFORMED;
            goto p101_single_exit_;
        }
        record->cloexec = (int)value;
        parsed          = parse_long_field(fields[payload + 2U], 0, INT_MAX, &value);
        if(parsed == 0)
        {
            p101_single_result_ = P101_TOOL_EVENT_PARSE_MALFORMED;
            goto p101_single_exit_;
        }
        record->line_number   = (int)value;
        record->function_name = fields[payload + 3U];
        record->file_name     = fields[payload + 4U];
        record->target        = fields[payload + EXEC_TARGET_INDEX];
        record->record_kind   = P101_TOOL_EVENT_RECORD_EXEC;
        p101_single_result_   = P101_TOOL_EVENT_PARSE_OK;
        goto p101_single_exit_;
    }

    if(magic_index == (size_t)P101_TOOL_EVENT_RECORD_EXEC_FAIL)
    {
        parsed = parse_long_field(fields[payload], 0, INT_MAX, &value);
        if(!payload_arity_matches(count, payload, EXEC_FAIL_PAYLOAD_FIELDS) || parsed == 0)
        {
            p101_single_result_ = P101_TOOL_EVENT_PARSE_MALFORMED;
            goto p101_single_exit_;
        }
        record->line_number   = (int)value;
        record->function_name = fields[payload + 1U];
        record->file_name     = fields[payload + 2U];
        record->target        = fields[payload + 3U];
        record->record_kind   = P101_TOOL_EVENT_RECORD_EXEC_FAIL;
        p101_single_result_   = P101_TOOL_EVENT_PARSE_OK;
        goto p101_single_exit_;
    }

    if(magic_index == (size_t)P101_TOOL_EVENT_RECORD_CALL)
    {
        size_t action_index;
        bool   action_found;

        if(!payload_arity_matches(count, payload, CALL_PAYLOAD_FIELDS))
        {
            p101_single_result_ = P101_TOOL_EVENT_PARSE_MALFORMED;
            goto p101_single_exit_;
        }
        action_found = lookup_call_kind(fields[payload], &action_index);
        if(!action_found)
        {
            p101_single_result_ = P101_TOOL_EVENT_PARSE_MALFORMED;
            goto p101_single_exit_;
        }
        record->call_kind = (p101_tool_event_call_kind)action_index;
        parsed            = parse_long_field(fields[payload + 1U], 0, INT_MAX, &value);
        if(parsed == 0)
        {
            p101_single_result_ = P101_TOOL_EVENT_PARSE_MALFORMED;
            goto p101_single_exit_;
        }
        record->line_number   = (int)value;
        record->function_name = fields[payload + 2U];
        record->call_name     = fields[payload + 3U];
        record->arguments     = fields[payload + 4U];
        record->result        = fields[payload + CALL_RESULT_INDEX];
        record->file_name     = fields[payload + CALL_FILE_INDEX];
        record->record_kind   = P101_TOOL_EVENT_RECORD_CALL;
        p101_single_result_   = P101_TOOL_EVENT_PARSE_OK;
        goto p101_single_exit_;
    }

    if(magic_index == (size_t)P101_TOOL_EVENT_RECORD_RESOURCE)
    {
        size_t action_index;
        bool   action_found;
        int    null_comparison;

        if(!payload_arity_matches(count, payload, RESOURCE_PAYLOAD_FIELDS))
        {
            p101_single_result_ = P101_TOOL_EVENT_PARSE_MALFORMED;
            goto p101_single_exit_;
        }
        action_found = lookup_resource_kind(fields[payload], &action_index);
        if(!action_found)
        {
            p101_single_result_ = P101_TOOL_EVENT_PARSE_MALFORMED;
            goto p101_single_exit_;
        }
        record->resource_kind  = (p101_tool_event_resource_kind)action_index;
        record->resource_class = fields[payload + 1U];
        record->resource_id    = fields[payload + 2U];
        null_comparison        = strcmp(fields[payload + 3U], "-");
        record->related_id     = null_comparison == 0 ? NULL : fields[payload + 3U];
        parsed                 = p101_record_parse_size(fields[payload + 4U], &record->size);
        if(parsed != 0)
        {
            parsed = parse_long_field(fields[payload + RESOURCE_LINE_INDEX], 0, INT_MAX, &value);
        }
        if(parsed == 0)
        {
            p101_single_result_ = P101_TOOL_EVENT_PARSE_MALFORMED;
            goto p101_single_exit_;
        }
        record->metadata      = fields[payload + RESOURCE_METADATA_INDEX];
        record->line_number   = (int)value;
        record->function_name = fields[payload + RESOURCE_FUNCTION_INDEX];
        record->file_name     = fields[payload + RESOURCE_FILE_INDEX];
        record->record_kind   = P101_TOOL_EVENT_RECORD_RESOURCE;
        p101_single_result_   = P101_TOOL_EVENT_PARSE_OK;
        goto p101_single_exit_;
    }

    if(magic_index == (size_t)P101_TOOL_EVENT_RECORD_COMPLETE)
    {
        parsed = p101_record_parse_size(fields[payload], &record->events_attempted);
        if(parsed != 0)
        {
            parsed = parse_long_field(fields[payload + 1U], 0, 1, &value);
        }
        if(!payload_arity_matches(count, payload, COMPLETE_PAYLOAD_FIELDS) || parsed == 0)
        {
            p101_single_result_ = P101_TOOL_EVENT_PARSE_MALFORMED;
            goto p101_single_exit_;
        }
        record->write_failed = (int)value;
        parsed               = parse_long_field(fields[payload + 2U], 0, INT_MAX, &value);
        if(parsed == 0)
        {
            p101_single_result_ = P101_TOOL_EVENT_PARSE_MALFORMED;
            goto p101_single_exit_;
        }
        record->write_errno = (int)value;
        if((record->write_failed == 0 && record->write_errno != 0) || (record->write_failed != 0 && record->write_errno == 0))
        {
            p101_single_result_ = P101_TOOL_EVENT_PARSE_MALFORMED;
            goto p101_single_exit_;
        }
        record->record_kind = P101_TOOL_EVENT_RECORD_COMPLETE;
        p101_single_result_ = P101_TOOL_EVENT_PARSE_OK;
        goto p101_single_exit_;
    }

    p101_single_result_ = P101_TOOL_EVENT_PARSE_OTHER;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static void unescape_record(struct p101_tool_event_record *record)
{
    p101_record_unescape_field(record->run_id);
    p101_record_unescape_field(record->ptr);
    p101_record_unescape_field(record->new_ptr);
    p101_record_unescape_field(record->target);
    p101_record_unescape_field(record->resource_class);
    p101_record_unescape_field(record->resource_id);
    p101_record_unescape_field(record->related_id);
    p101_record_unescape_field(record->metadata);
    p101_record_unescape_field(record->function_name);
    p101_record_unescape_field(record->call_name);
    p101_record_unescape_field(record->arguments);
    p101_record_unescape_field(record->result);
    p101_record_unescape_field(record->file_name);
}

#ifdef P101_TOOL_EVENT_TESTING
p101_tool_event_parse_status p101_tool_event_test_parse_unknown_payload(void)
{
    struct p101_tool_event_record record;
    char                         *fields[1] = {NULL};

    memset(&record, 0, sizeof(record));
    return parse_payload("P101UNKNOWN", fields, 0U, 0U, &record);
}

void p101_tool_event_test_write_unknown_payload(void)
{
    struct line_builder           builder;
    struct p101_tool_event_output record;

    memset(&builder, 0, sizeof(builder));
    memset(&record, 0, sizeof(record));
    record.record_kind = (p101_tool_event_record_kind)99;
    write_payload(&builder, &record);
}
#endif
