#include <errno.h>
#include <limits.h>
#include <p101_tool_event/event.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

enum
{
    NUMBER_BASE              = 10,
    MAX_FIELDS               = 20,
    EVENT_FD_MAX             = 1048576,
    METADATA_V2_FIELDS       = 5,
    METADATA_V3_FIELDS       = 6,
    FD_PAYLOAD_FIELDS        = 5,
    ALLOC_PAYLOAD_FIELDS     = 7,
    FORK_PAYLOAD_FIELDS      = 4,
    SPAWN_PAYLOAD_FIELDS     = 5,
    EXEC_PAYLOAD_FIELDS      = 6,
    EXEC_FAIL_PAYLOAD_FIELDS = 4,
    CALL_PAYLOAD_FIELDS      = 7,
    RESOURCE_PAYLOAD_FIELDS  = 9,
    ALLOC_FUNCTION_INDEX     = 5,
    ALLOC_FILE_INDEX         = 6,
    EXEC_TARGET_INDEX        = 5,
    CALL_RESULT_INDEX        = 5,
    CALL_FILE_INDEX          = 6,
    RESOURCE_METADATA_INDEX  = 5,
    RESOURCE_LINE_INDEX      = 6,
    RESOURCE_FUNCTION_INDEX  = 7,
    RESOURCE_FILE_INDEX      = 8,
    ASCII_DELETE             = 0x7F
};

static int                          parse_long_field(const char *text, long min, long max, long *out);
static int                          parse_optional_size_field(const char *text, size_t *out, int *available);
static p101_tool_event_parse_status parse_metadata(char *fields[], size_t field_count, struct p101_tool_event_record *record, size_t *payload);
static p101_tool_event_parse_status parse_payload(const char *magic, char *fields[], size_t count, size_t payload, struct p101_tool_event_record *record);
static void                         unescape_record(struct p101_tool_event_record *record);
static int                          write_metadata(FILE *stream, const struct p101_tool_event_output *record);
static int                          write_payload(FILE *stream, const struct p101_tool_event_output *record);
static int                          write_field(FILE *stream, const char *text);
static int                          output_is_valid(const struct p101_tool_event_output *record);
static const char                  *record_magic(p101_tool_event_record_kind kind);
static const char                  *alloc_kind_name(p101_tool_event_alloc_kind kind);
static const char                  *resource_kind_name(p101_tool_event_resource_kind kind);

p101_tool_event_line_status p101_tool_event_read_line(struct p101_error *err, FILE *stream, char *line, size_t line_size)
{
    bool   saw_byte;
    bool   malformed;
    size_t length;

    if(line != NULL && line_size > 0U)
    {
        line[0] = '\0';
    }

    if(stream == NULL || line == NULL || line_size == 0U)
    {
        P101_ERROR_RAISE_CHECK(err);
        return P101_TOOL_EVENT_LINE_ERROR;
    }

    saw_byte  = false;
    malformed = false;
    length    = 0U;

    while(true)
    {
        int ch;

        ch = fgetc(stream);
        if(ch == EOF)
        {
            if(ferror(stream) != 0)
            {
                line[length] = '\0';
                P101_ERROR_RAISE_ERRNO(err, errno == 0 ? EIO : errno);
                return P101_TOOL_EVENT_LINE_ERROR;
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
        return P101_TOOL_EVENT_LINE_EOF;
    }

    line[length] = '\0';
    if(malformed)
    {
        return P101_TOOL_EVENT_LINE_MALFORMED;
    }
    return P101_TOOL_EVENT_LINE_OK;
}

p101_tool_event_parse_status p101_tool_event_parse_line(char *line, struct p101_tool_event_record *record)
{
    char                        *cursor;
    char                        *fields[MAX_FIELDS];
    const char                  *magic;
    size_t                       count;
    size_t                       length;
    size_t                       payload;
    p101_tool_event_parse_status status;

    if(line == NULL || record == NULL)
    {
        return P101_TOOL_EVENT_PARSE_MALFORMED;
    }

    if(!p101_tool_event_line_is_ours(line))
    {
        return P101_TOOL_EVENT_PARSE_OTHER;
    }

    memset(record, 0, sizeof(*record));
    record->fd          = -1;
    record->child_pid   = -1;
    record->line_number = -1;

    length = strlen(line);
    while(length > 0U && (line[length - 1U] == '\n' || line[length - 1U] == '\r'))
    {
        line[--length] = '\0';
    }

    cursor = line;
    magic  = p101_tool_event_split(&cursor);
    count  = 0U;
    while(cursor != NULL && count < MAX_FIELDS)
    {
        fields[count++] = p101_tool_event_split(&cursor);
    }
    if(cursor != NULL || count == 0U)
    {
        return P101_TOOL_EVENT_PARSE_MALFORMED;
    }

    status = parse_metadata(fields, count, record, &payload);
    if(status != P101_TOOL_EVENT_PARSE_OK)
    {
        return status;
    }

    status = parse_payload(magic, fields, count, payload, record);
    if(status == P101_TOOL_EVENT_PARSE_OK)
    {
        unescape_record(record);
    }
    return status;
}

int p101_tool_event_write(FILE *stream, const struct p101_tool_event_output *record)
{
    char       *line;
    FILE       *line_stream;
    const char *magic;
    size_t      line_size;
    int         actual_error;
    int         saved_error;
    int         result;

    if(stream == NULL || record == NULL || !output_is_valid(record))
    {
        errno = EINVAL;
        return -1;
    }

    /*
     * Build the protocol unit away from the destination, then publish it with
     * one stdio write. The destination lock protects shared FILE objects; the
     * single write also avoids field-by-field interleaving when independent
     * streams append to the same pipe or regular file.
     */
    saved_error  = errno;
    errno        = 0;
    actual_error = 0;
    line         = NULL;
    line_size    = 0U;
    line_stream  = open_memstream(&line, &line_size);
    if(line_stream == NULL)
    {
        if(errno == 0)
        {
            errno = EIO;
        }
        return -1;
    }

    magic  = record_magic(record->record_kind);
    result = 0;
    if(magic == NULL || fputs(magic, line_stream) == EOF || fputc('\t', line_stream) == EOF || write_metadata(line_stream, record) != 0 || write_payload(line_stream, record) != 0 || fputc('\n', line_stream) == EOF)
    {
        result       = -1;
        actual_error = errno;
    }
    if(fclose(line_stream) == EOF)
    {
        result = -1;
        if(actual_error == 0)
        {
            actual_error = errno;
        }
    }
    line_stream = NULL;
    if(result == 0)
    {
        errno = 0;
        flockfile(stream);
        if(fwrite(line, 1U, line_size, stream) != line_size || fflush(stream) == EOF)
        {
            result       = -1;
            actual_error = errno;
        }
        funlockfile(stream);
    }
    if(result == 0)
    {
        actual_error = saved_error;
    }
    else if(actual_error == 0)
    {
        actual_error = EIO;
    }
    free(line);
    errno = actual_error;
    return result;
}

int p101_tool_event_line_is_ours(const char *line)
{
    static const char *const prefixes[] = {"P101FD\t", "P101ALLOC\t", "P101FORK\t", "P101SPAWN\t", "P101EXEC\t", "P101EXECFAIL\t", "P101CALL\t", "P101RESOURCE\t"};

    if(line == NULL)
    {
        return 0;
    }

    for(size_t i = 0U; i < sizeof(prefixes) / sizeof(prefixes[0]); i++)
    {
        if(strncmp(line, prefixes[i], strlen(prefixes[i])) == 0)
        {
            return 1;
        }
    }
    return 0;
}

const char *p101_tool_event_parse_status_name(p101_tool_event_parse_status status)
{
#ifdef __clang__
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wcovered-switch-default"
#endif
    switch(status)
    {
        case P101_TOOL_EVENT_PARSE_OTHER:
            return "not a p101 event record";
        case P101_TOOL_EVENT_PARSE_OK:
            return "ok";
        case P101_TOOL_EVENT_PARSE_MALFORMED:
            return "malformed record";
        case P101_TOOL_EVENT_PARSE_BAD_VERSION:
            return "unsupported record version";
        default:
            return "unknown event parse status";
    }
#ifdef __clang__
    #pragma clang diagnostic pop
#endif
}

char *p101_tool_event_split(char **cursor)
{
    char *start;
    char *tab;

    if(cursor == NULL || *cursor == NULL)
    {
        return NULL;
    }

    start = *cursor;
    tab   = start;
    while(*tab != '\0' && *tab != '\t')
    {
        tab++;
    }

    if(*tab == '\0')
    {
        *cursor = NULL;
    }
    else
    {
        *tab    = '\0';
        *cursor = tab + 1;
    }
    return start;
}

void p101_tool_event_unescape_field(char *field)
{
    char *read_cursor;
    char *write_cursor;

    if(field == NULL)
    {
        return;
    }

    read_cursor  = field;
    write_cursor = field;
    while(*read_cursor != '\0')
    {
        if(read_cursor[0] == '\\' && read_cursor[1] != '\0')
        {
            read_cursor++;
            if(*read_cursor == 't')
            {
                *write_cursor = '\t';
            }
            else if(*read_cursor == 'n')
            {
                *write_cursor = '\n';
            }
            else if(*read_cursor == 'r')
            {
                *write_cursor = '\r';
            }
            else
            {
                *write_cursor = *read_cursor;
            }
            read_cursor++;
            write_cursor++;
        }
        else
        {
            *write_cursor++ = *read_cursor++;
        }
    }
    *write_cursor = '\0';
}

int p101_tool_event_parse_size_field(const char *text, size_t *out)
{
    const char *cursor;
    size_t      value;

    if(text == NULL || out == NULL || *text == '\0')
    {
        return 0;
    }

    cursor = text;
    value  = 0U;
    while(*cursor != '\0')
    {
        size_t digit;

        if(*cursor < '0' || *cursor > '9')
        {
            return 0;
        }
        digit = (size_t)(*cursor - '0');
        if(value > (SIZE_MAX - digit) / (size_t)NUMBER_BASE)
        {
            return 0;
        }
        value = (value * (size_t)NUMBER_BASE) + digit;
        cursor++;
    }
    *out = value;
    return 1;
}

static int parse_long_field(const char *text, long min, long max, long *out)
{
    char *end;
    long  value;

    if(text == NULL || out == NULL || *text == '\0')
    {
        return 0;
    }

    errno = 0;
    value = strtol(text, &end, NUMBER_BASE);
    if(errno != 0 || end == text || *end != '\0' || value < min || value > max)
    {
        return 0;
    }
    *out = value;
    return 1;
}

static int parse_optional_size_field(const char *text, size_t *out, int *available)
{
    *out       = 0U;
    *available = 0;
    if(text == NULL)
    {
        return 0;
    }
    if(strcmp(text, "-") == 0)
    {
        return 1;
    }
    if(!p101_tool_event_parse_size_field(text, out))
    {
        return 0;
    }
    *available = 1;
    return 1;
}

static p101_tool_event_parse_status parse_metadata(char *fields[], size_t field_count, struct p101_tool_event_record *record, size_t *payload)
{
    long   version;
    size_t sequence_index;
    size_t monotonic_index;
    size_t wall_index;

    if(field_count < METADATA_V2_FIELDS || !parse_long_field(fields[0], 0, LONG_MAX, &version))
    {
        return P101_TOOL_EVENT_PARSE_MALFORMED;
    }

    if(version != P101_TOOL_EVENT_LOG_VERSION_2 && version != P101_TOOL_EVENT_LOG_VERSION_3)
    {
        return P101_TOOL_EVENT_PARSE_BAD_VERSION;
    }
    record->version = (int)version;
    if(!parse_long_field(fields[1], 0, LONG_MAX, &record->pid))
    {
        return P101_TOOL_EVENT_PARSE_MALFORMED;
    }

    if(version == P101_TOOL_EVENT_LOG_VERSION_3)
    {
        if(field_count < METADATA_V3_FIELDS)
        {
            return P101_TOOL_EVENT_PARSE_MALFORMED;
        }
        sequence_index  = 3U;
        monotonic_index = 4U;
        wall_index      = METADATA_V2_FIELDS;
        *payload        = METADATA_V3_FIELDS;
        if(!p101_tool_event_parse_size_field(fields[2U], &record->context_id))
        {
            return P101_TOOL_EVENT_PARSE_MALFORMED;
        }
    }
    else
    {
        record->context_id = 0U;
        sequence_index     = 2U;
        monotonic_index    = 3U;
        wall_index         = 4U;
        *payload           = METADATA_V2_FIELDS;
    }

    if(!p101_tool_event_parse_size_field(fields[sequence_index], &record->sequence) || !parse_optional_size_field(fields[monotonic_index], &record->monotonic_ns, &record->monotonic_ns_available) ||
       !parse_optional_size_field(fields[wall_index], &record->wall_unix_ns, &record->wall_unix_ns_available))
    {
        return P101_TOOL_EVENT_PARSE_MALFORMED;
    }
    return P101_TOOL_EVENT_PARSE_OK;
}

static int write_metadata(FILE *stream, const struct p101_tool_event_output *record)
{
    int version;

    version = record->version == 0 ? P101_TOOL_EVENT_LOG_VERSION : record->version;
    if(version == P101_TOOL_EVENT_LOG_VERSION_3)
    {
        if(fprintf(stream, "%d\t%ld\t%zu\t%zu\t", version, record->pid, record->context_id, record->sequence) < 0)
        {
            return -1;
        }
    }
    else if(version == P101_TOOL_EVENT_LOG_VERSION_2)
    {
        if(fprintf(stream, "%d\t%ld\t%zu\t", version, record->pid, record->sequence) < 0)
        {
            return -1;
        }
    }
    else
    {
        return -1;
    }

    if(record->monotonic_ns_available != 0)
    {
        if(fprintf(stream, "%zu\t", record->monotonic_ns) < 0)
        {
            return -1;
        }
    }
    else if(fputs("-\t", stream) == EOF)
    {
        return -1;
    }

    if(record->wall_unix_ns_available != 0)
    {
        return fprintf(stream, "%zu\t", record->wall_unix_ns) < 0 ? -1 : 0;
    }
    return fputs("-\t", stream) == EOF ? -1 : 0;
}

static int write_payload(FILE *stream, const struct p101_tool_event_output *record)
{
#ifdef __clang__
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wcovered-switch-default"
#endif
    switch(record->record_kind)
    {
        case P101_TOOL_EVENT_RECORD_FD:
            if(fprintf(stream, "%s\t%d\t%d\t", record->fd_kind == P101_TOOL_EVENT_FD_OPEN ? "OPEN" : "CLOSE", record->fd, record->line_number) < 0 || write_field(stream, record->function_name) != 0 || fputc('\t', stream) == EOF)
            {
                return -1;
            }
            return write_field(stream, record->file_name);
        case P101_TOOL_EVENT_RECORD_ALLOC:
            if(fprintf(stream, "%s\t", alloc_kind_name(record->alloc_kind)) < 0 || write_field(stream, record->ptr) != 0 || fputc('\t', stream) == EOF || write_field(stream, record->new_ptr) != 0 ||
               fprintf(stream, "\t%zu\t%d\t", record->size, record->line_number) < 0 || write_field(stream, record->function_name) != 0 || fputc('\t', stream) == EOF)
            {
                return -1;
            }
            return write_field(stream, record->file_name);
        case P101_TOOL_EVENT_RECORD_FORK:
            if(fprintf(stream, "%ld\t%d\t", record->child_pid, record->line_number) < 0 || write_field(stream, record->function_name) != 0 || fputc('\t', stream) == EOF)
            {
                return -1;
            }
            return write_field(stream, record->file_name);
        case P101_TOOL_EVENT_RECORD_SPAWN:
            if(fprintf(stream, "%ld\t%d\t", record->child_pid, record->line_number) < 0 || write_field(stream, record->function_name) != 0 || fputc('\t', stream) == EOF || write_field(stream, record->file_name) != 0 || fputc('\t', stream) == EOF)
            {
                return -1;
            }
            return write_field(stream, record->target);
        case P101_TOOL_EVENT_RECORD_EXEC:
            if(fprintf(stream, "%d\t%d\t%d\t", record->fd, record->cloexec, record->line_number) < 0 || write_field(stream, record->function_name) != 0 || fputc('\t', stream) == EOF || write_field(stream, record->file_name) != 0 || fputc('\t', stream) == EOF)
            {
                return -1;
            }
            return write_field(stream, record->target);
        case P101_TOOL_EVENT_RECORD_EXEC_FAIL:
            if(fprintf(stream, "%d\t", record->line_number) < 0 || write_field(stream, record->function_name) != 0 || fputc('\t', stream) == EOF || write_field(stream, record->file_name) != 0 || fputc('\t', stream) == EOF)
            {
                return -1;
            }
            return write_field(stream, record->target);
        case P101_TOOL_EVENT_RECORD_CALL:
            if(fprintf(stream, "%s\t%d\t", record->call_kind == P101_TOOL_EVENT_CALL_ENTER ? "ENTER" : "EXIT", record->line_number) < 0 || write_field(stream, record->function_name) != 0 || fputc('\t', stream) == EOF ||
               write_field(stream, record->call_name) != 0 || fputc('\t', stream) == EOF || write_field(stream, record->arguments) != 0 || fputc('\t', stream) == EOF || write_field(stream, record->result) != 0 || fputc('\t', stream) == EOF)
            {
                return -1;
            }
            return write_field(stream, record->file_name);
        case P101_TOOL_EVENT_RECORD_RESOURCE:
            if(fprintf(stream, "%s\t", resource_kind_name(record->resource_kind)) < 0 || write_field(stream, record->resource_class) != 0 || fputc('\t', stream) == EOF || write_field(stream, record->resource_id) != 0 || fputc('\t', stream) == EOF ||
               write_field(stream, record->related_id) != 0 || fprintf(stream, "\t%zu\t", record->size) < 0 || write_field(stream, record->metadata) != 0 || fprintf(stream, "\t%d\t", record->line_number) < 0 ||
               write_field(stream, record->function_name) != 0 || fputc('\t', stream) == EOF)
            {
                return -1;
            }
            return write_field(stream, record->file_name);
        default:
            break;
    }
#ifdef __clang__
    #pragma clang diagnostic pop
#endif
    return -1;
}

static int write_field(FILE *stream, const char *text)
{
    if(text == NULL)
    {
        return fputc('-', stream) == EOF ? -1 : 0;
    }
    if(text[0] == '-' && text[1] == '\0')
    {
        return fputs("\\-", stream) == EOF ? -1 : 0;
    }

    while(*text != '\0')
    {
        unsigned char ch;
        const char   *escaped;

        ch      = (unsigned char)*text++;
        escaped = NULL;
        if(ch == '\t')
        {
            escaped = "\\t";
        }
        else if(ch == '\n')
        {
            escaped = "\\n";
        }
        else if(ch == '\r')
        {
            escaped = "\\r";
        }
        else if(ch == '\\')
        {
            escaped = "\\\\";
        }

        if(escaped != NULL)
        {
            if(fputs(escaped, stream) == EOF)
            {
                return -1;
            }
        }
        else if(fputc((ch < ' ' || ch == ASCII_DELETE) ? '?' : (int)ch, stream) == EOF)
        {
            return -1;
        }
    }
    return 0;
}

static int output_is_valid(const struct p101_tool_event_output *record)
{
#ifdef __clang__
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wcovered-switch-default"
#endif
    switch(record->record_kind)
    {
        case P101_TOOL_EVENT_RECORD_FD:
            return record->fd_kind == P101_TOOL_EVENT_FD_OPEN || record->fd_kind == P101_TOOL_EVENT_FD_CLOSE;
        case P101_TOOL_EVENT_RECORD_ALLOC:
            return record->alloc_kind == P101_TOOL_EVENT_ALLOC_ALLOC || record->alloc_kind == P101_TOOL_EVENT_ALLOC_FREE || record->alloc_kind == P101_TOOL_EVENT_ALLOC_REALLOC;
        case P101_TOOL_EVENT_RECORD_CALL:
            return record->call_kind == P101_TOOL_EVENT_CALL_ENTER || record->call_kind == P101_TOOL_EVENT_CALL_EXIT;
        case P101_TOOL_EVENT_RECORD_RESOURCE:
            return record->resource_kind == P101_TOOL_EVENT_RESOURCE_ACQUIRE || record->resource_kind == P101_TOOL_EVENT_RESOURCE_RELEASE || record->resource_kind == P101_TOOL_EVENT_RESOURCE_REPLACE ||
                   record->resource_kind == P101_TOOL_EVENT_RESOURCE_TRANSFER;
        case P101_TOOL_EVENT_RECORD_FORK:
        case P101_TOOL_EVENT_RECORD_SPAWN:
        case P101_TOOL_EVENT_RECORD_EXEC:
        case P101_TOOL_EVENT_RECORD_EXEC_FAIL:
            return 1;
        default:
            break;
    }
#ifdef __clang__
    #pragma clang diagnostic pop
#endif
    return 0;
}

static const char *record_magic(p101_tool_event_record_kind kind)
{
#ifdef __clang__
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wcovered-switch-default"
#endif
    switch(kind)
    {
        case P101_TOOL_EVENT_RECORD_FD:
            return "P101FD";
        case P101_TOOL_EVENT_RECORD_ALLOC:
            return "P101ALLOC";
        case P101_TOOL_EVENT_RECORD_FORK:
            return "P101FORK";
        case P101_TOOL_EVENT_RECORD_SPAWN:
            return "P101SPAWN";
        case P101_TOOL_EVENT_RECORD_EXEC:
            return "P101EXEC";
        case P101_TOOL_EVENT_RECORD_EXEC_FAIL:
            return "P101EXECFAIL";
        case P101_TOOL_EVENT_RECORD_CALL:
            return "P101CALL";
        case P101_TOOL_EVENT_RECORD_RESOURCE:
            return "P101RESOURCE";
        default:
            break;
    }
#ifdef __clang__
    #pragma clang diagnostic pop
#endif
    return NULL;
}

static const char *alloc_kind_name(p101_tool_event_alloc_kind kind)
{
#ifdef __clang__
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wcovered-switch-default"
#endif
    switch(kind)
    {
        case P101_TOOL_EVENT_ALLOC_ALLOC:
            return "ALLOC";
        case P101_TOOL_EVENT_ALLOC_FREE:
            return "FREE";
        case P101_TOOL_EVENT_ALLOC_REALLOC:
            return "REALLOC";
        default:
            break;
    }
#ifdef __clang__
    #pragma clang diagnostic pop
#endif
    return "UNKNOWN";
}

static const char *resource_kind_name(p101_tool_event_resource_kind kind)
{
#ifdef __clang__
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wcovered-switch-default"
#endif
    switch(kind)
    {
        case P101_TOOL_EVENT_RESOURCE_ACQUIRE:
            return "ACQUIRE";
        case P101_TOOL_EVENT_RESOURCE_RELEASE:
            return "RELEASE";
        case P101_TOOL_EVENT_RESOURCE_REPLACE:
            return "REPLACE";
        case P101_TOOL_EVENT_RESOURCE_TRANSFER:
            return "TRANSFER";
        default:
            break;
    }
#ifdef __clang__
    #pragma clang diagnostic pop
#endif
    return "UNKNOWN";
}

static p101_tool_event_parse_status parse_payload(const char *magic, char *fields[], size_t count, size_t payload, struct p101_tool_event_record *record)
{
    long value;

    if(strcmp(magic, "P101FD") == 0)
    {
        if(count != payload + FD_PAYLOAD_FIELDS)
        {
            return P101_TOOL_EVENT_PARSE_MALFORMED;
        }
        if(strcmp(fields[payload], "OPEN") == 0)
        {
            record->fd_kind = P101_TOOL_EVENT_FD_OPEN;
        }
        else if(strcmp(fields[payload], "CLOSE") == 0)
        {
            record->fd_kind = P101_TOOL_EVENT_FD_CLOSE;
        }
        else
        {
            return P101_TOOL_EVENT_PARSE_MALFORMED;
        }
        if(!parse_long_field(fields[payload + 1U], 0, EVENT_FD_MAX, &value))
        {
            return P101_TOOL_EVENT_PARSE_MALFORMED;
        }
        record->fd = (int)value;
        if(!parse_long_field(fields[payload + 2U], 0, INT_MAX, &value))
        {
            return P101_TOOL_EVENT_PARSE_MALFORMED;
        }
        record->line_number   = (int)value;
        record->function_name = fields[payload + 3U];
        record->file_name     = fields[payload + 4U];
        record->record_kind   = P101_TOOL_EVENT_RECORD_FD;
        return P101_TOOL_EVENT_PARSE_OK;
    }

    if(strcmp(magic, "P101ALLOC") == 0)
    {
        if(count != payload + ALLOC_PAYLOAD_FIELDS)
        {
            return P101_TOOL_EVENT_PARSE_MALFORMED;
        }
        if(strcmp(fields[payload], "ALLOC") == 0)
        {
            record->alloc_kind = P101_TOOL_EVENT_ALLOC_ALLOC;
        }
        else if(strcmp(fields[payload], "FREE") == 0)
        {
            record->alloc_kind = P101_TOOL_EVENT_ALLOC_FREE;
        }
        else if(strcmp(fields[payload], "REALLOC") == 0)
        {
            record->alloc_kind = P101_TOOL_EVENT_ALLOC_REALLOC;
        }
        else
        {
            return P101_TOOL_EVENT_PARSE_MALFORMED;
        }
        record->ptr     = fields[payload + 1U];
        record->new_ptr = strcmp(fields[payload + 2U], "-") == 0 ? NULL : fields[payload + 2U];
        if(!p101_tool_event_parse_size_field(fields[payload + 3U], &record->size) || !parse_long_field(fields[payload + 4U], 0, INT_MAX, &value))
        {
            return P101_TOOL_EVENT_PARSE_MALFORMED;
        }
        record->line_number   = (int)value;
        record->function_name = fields[payload + ALLOC_FUNCTION_INDEX];
        record->file_name     = fields[payload + ALLOC_FILE_INDEX];
        record->record_kind   = P101_TOOL_EVENT_RECORD_ALLOC;
        return P101_TOOL_EVENT_PARSE_OK;
    }

    if(strcmp(magic, "P101FORK") == 0 || strcmp(magic, "P101SPAWN") == 0)
    {
        size_t expected;

        expected = strcmp(magic, "P101FORK") == 0 ? FORK_PAYLOAD_FIELDS : SPAWN_PAYLOAD_FIELDS;
        if(count != payload + expected || !parse_long_field(fields[payload], 0, LONG_MAX, &record->child_pid) || !parse_long_field(fields[payload + 1U], 0, INT_MAX, &value))
        {
            return P101_TOOL_EVENT_PARSE_MALFORMED;
        }
        record->line_number   = (int)value;
        record->function_name = fields[payload + 2U];
        record->file_name     = fields[payload + 3U];
        record->target        = expected == SPAWN_PAYLOAD_FIELDS ? fields[payload + 4U] : NULL;
        record->record_kind   = expected == FORK_PAYLOAD_FIELDS ? P101_TOOL_EVENT_RECORD_FORK : P101_TOOL_EVENT_RECORD_SPAWN;
        return P101_TOOL_EVENT_PARSE_OK;
    }

    if(strcmp(magic, "P101EXEC") == 0)
    {
        if(count != payload + EXEC_PAYLOAD_FIELDS || !parse_long_field(fields[payload], 0, EVENT_FD_MAX, &value))
        {
            return P101_TOOL_EVENT_PARSE_MALFORMED;
        }
        record->fd = (int)value;
        if(!parse_long_field(fields[payload + 1U], 0, 1, &value))
        {
            return P101_TOOL_EVENT_PARSE_MALFORMED;
        }
        record->cloexec = (int)value;
        if(!parse_long_field(fields[payload + 2U], 0, INT_MAX, &value))
        {
            return P101_TOOL_EVENT_PARSE_MALFORMED;
        }
        record->line_number   = (int)value;
        record->function_name = fields[payload + 3U];
        record->file_name     = fields[payload + 4U];
        record->target        = fields[payload + EXEC_TARGET_INDEX];
        record->record_kind   = P101_TOOL_EVENT_RECORD_EXEC;
        return P101_TOOL_EVENT_PARSE_OK;
    }

    if(strcmp(magic, "P101EXECFAIL") == 0)
    {
        if(count != payload + EXEC_FAIL_PAYLOAD_FIELDS || !parse_long_field(fields[payload], 0, INT_MAX, &value))
        {
            return P101_TOOL_EVENT_PARSE_MALFORMED;
        }
        record->line_number   = (int)value;
        record->function_name = fields[payload + 1U];
        record->file_name     = fields[payload + 2U];
        record->target        = fields[payload + 3U];
        record->record_kind   = P101_TOOL_EVENT_RECORD_EXEC_FAIL;
        return P101_TOOL_EVENT_PARSE_OK;
    }

    if(strcmp(magic, "P101CALL") == 0)
    {
        if(count != payload + CALL_PAYLOAD_FIELDS)
        {
            return P101_TOOL_EVENT_PARSE_MALFORMED;
        }
        if(strcmp(fields[payload], "ENTER") == 0)
        {
            record->call_kind = P101_TOOL_EVENT_CALL_ENTER;
        }
        else if(strcmp(fields[payload], "EXIT") == 0)
        {
            record->call_kind = P101_TOOL_EVENT_CALL_EXIT;
        }
        else
        {
            return P101_TOOL_EVENT_PARSE_MALFORMED;
        }
        if(!parse_long_field(fields[payload + 1U], 0, INT_MAX, &value))
        {
            return P101_TOOL_EVENT_PARSE_MALFORMED;
        }
        record->line_number   = (int)value;
        record->function_name = fields[payload + 2U];
        record->call_name     = fields[payload + 3U];
        record->arguments     = fields[payload + 4U];
        record->result        = fields[payload + CALL_RESULT_INDEX];
        record->file_name     = fields[payload + CALL_FILE_INDEX];
        record->record_kind   = P101_TOOL_EVENT_RECORD_CALL;
        return P101_TOOL_EVENT_PARSE_OK;
    }

    if(strcmp(magic, "P101RESOURCE") == 0)
    {
        if(count != payload + RESOURCE_PAYLOAD_FIELDS)
        {
            return P101_TOOL_EVENT_PARSE_MALFORMED;
        }
        if(strcmp(fields[payload], "ACQUIRE") == 0)
        {
            record->resource_kind = P101_TOOL_EVENT_RESOURCE_ACQUIRE;
        }
        else if(strcmp(fields[payload], "RELEASE") == 0)
        {
            record->resource_kind = P101_TOOL_EVENT_RESOURCE_RELEASE;
        }
        else if(strcmp(fields[payload], "REPLACE") == 0)
        {
            record->resource_kind = P101_TOOL_EVENT_RESOURCE_REPLACE;
        }
        else if(strcmp(fields[payload], "TRANSFER") == 0)
        {
            record->resource_kind = P101_TOOL_EVENT_RESOURCE_TRANSFER;
        }
        else
        {
            return P101_TOOL_EVENT_PARSE_MALFORMED;
        }
        record->resource_class = fields[payload + 1U];
        record->resource_id    = fields[payload + 2U];
        record->related_id     = strcmp(fields[payload + 3U], "-") == 0 ? NULL : fields[payload + 3U];
        if(!p101_tool_event_parse_size_field(fields[payload + 4U], &record->size) || !parse_long_field(fields[payload + RESOURCE_LINE_INDEX], 0, INT_MAX, &value))
        {
            return P101_TOOL_EVENT_PARSE_MALFORMED;
        }
        record->metadata      = fields[payload + RESOURCE_METADATA_INDEX];
        record->line_number   = (int)value;
        record->function_name = fields[payload + RESOURCE_FUNCTION_INDEX];
        record->file_name     = fields[payload + RESOURCE_FILE_INDEX];
        record->record_kind   = P101_TOOL_EVENT_RECORD_RESOURCE;
        return P101_TOOL_EVENT_PARSE_OK;
    }

    return P101_TOOL_EVENT_PARSE_OTHER;
}

static void unescape_record(struct p101_tool_event_record *record)
{
    p101_tool_event_unescape_field(record->ptr);
    p101_tool_event_unescape_field(record->new_ptr);
    p101_tool_event_unescape_field(record->target);
    p101_tool_event_unescape_field(record->resource_class);
    p101_tool_event_unescape_field(record->resource_id);
    p101_tool_event_unescape_field(record->related_id);
    p101_tool_event_unescape_field(record->metadata);
    p101_tool_event_unescape_field(record->function_name);
    p101_tool_event_unescape_field(record->call_name);
    p101_tool_event_unescape_field(record->arguments);
    p101_tool_event_unescape_field(record->result);
    p101_tool_event_unescape_field(record->file_name);
}
