#include <errno.h>
#include <limits.h>
#include <p101_error/error.h>
#include <p101_record/record.h>
#include <p101_tool_event/event.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int failures;

extern p101_tool_event_parse_status p101_tool_event_test_parse_unknown_payload(void);
extern void                         p101_tool_event_test_force_zero_errno_on_read_error(void);
extern void                         p101_tool_event_test_force_zero_errno_on_write_error(void);
extern void                         p101_tool_event_test_force_format_overflow(void);
extern void                         p101_tool_event_test_write_unknown_payload(void);

#define EXPECT(condition)                                                                                                                                                                                                                                          \
    do                                                                                                                                                                                                                                                             \
    {                                                                                                                                                                                                                                                              \
        if(!(condition))                                                                                                                                                                                                                                           \
        {                                                                                                                                                                                                                                                          \
            failures++;                                                                                                                                                                                                                                            \
        }                                                                                                                                                                                                                                                          \
    } while(0)

static p101_tool_event_parse_status parse_text(const char *text, struct p101_tool_event_record *record)
{
    char line[P101_TOOL_EVENT_LINE_MAX_BYTES + 64];

    (void)snprintf(line, sizeof(line), "%s", text);
    return p101_tool_event_parse_line(line, record);
}

static void expect_json_contents_write_failure(const char *text)
{
    FILE *stream;

    stream = tmpfile();
    EXPECT(stream != NULL);
    if(stream != NULL)
    {
        EXPECT(setvbuf(stream, NULL, _IONBF, 0U) == 0);
        EXPECT(close(fileno(stream)) == 0);
        EXPECT(p101_record_write_json_string_contents(stream, text) == -1);
        (void)fclose(stream);
    }
}

static void test_line_reader(void)
{
    char               line[8];
    struct p101_error *err;
    FILE              *stream;

    err = p101_error_create(false);
    EXPECT(p101_tool_event_read_line(err, NULL, line, sizeof(line)) == P101_TOOL_EVENT_LINE_ERROR);
    p101_error_reset(err);
    stream = tmpfile();
    EXPECT(stream != NULL);
    EXPECT(p101_tool_event_read_line(err, stream, NULL, sizeof(line)) == P101_TOOL_EVENT_LINE_ERROR);
    p101_error_reset(err);
    EXPECT(p101_tool_event_read_line(err, stream, line, 0U) == P101_TOOL_EVENT_LINE_ERROR);
    p101_error_reset(err);
    EXPECT(p101_tool_event_read_line(err, stream, line, sizeof(line)) == P101_TOOL_EVENT_LINE_EOF);
    EXPECT(fputs("ok\nx", stream) >= 0);
    rewind(stream);
    EXPECT(p101_tool_event_read_line(err, stream, line, sizeof(line)) == P101_TOOL_EVENT_LINE_OK);
    EXPECT(strcmp(line, "ok\n") == 0);
    EXPECT(p101_tool_event_read_line(err, stream, line, sizeof(line)) == P101_TOOL_EVENT_LINE_OK);
    EXPECT(strcmp(line, "x") == 0);
    EXPECT(p101_tool_event_read_line(err, stream, line, sizeof(line)) == P101_TOOL_EVENT_LINE_EOF);
    fclose(stream);

    stream = tmpfile();
    EXPECT(stream != NULL);
    EXPECT(fwrite("a\0b\n", 1U, 4U, stream) == 4U);
    rewind(stream);
    EXPECT(p101_tool_event_read_line(err, stream, line, sizeof(line)) == P101_TOOL_EVENT_LINE_MALFORMED);
    fclose(stream);

    stream = tmpfile();
    EXPECT(stream != NULL);
    EXPECT(fputs("123456789\n", stream) >= 0);
    rewind(stream);
    EXPECT(p101_tool_event_read_line(err, stream, line, sizeof(line)) == P101_TOOL_EVENT_LINE_MALFORMED);
    fclose(stream);

    stream = tmpfile();
    EXPECT(stream != NULL);
    EXPECT(close(fileno(stream)) == 0);
    errno = 0;
    EXPECT(p101_tool_event_read_line(err, stream, line, sizeof(line)) == P101_TOOL_EVENT_LINE_ERROR);
    EXPECT(p101_error_has_error(err));
    fclose(stream);

    p101_error_reset(err);
    stream = tmpfile();
    EXPECT(stream != NULL);
    EXPECT(close(fileno(stream)) == 0);
    p101_tool_event_test_force_zero_errno_on_read_error();
    EXPECT(p101_tool_event_read_line(err, stream, line, sizeof(line)) == P101_TOOL_EVENT_LINE_ERROR);
    EXPECT(p101_error_is_errno(err, EIO));
    fclose(stream);
    p101_error_destroy(err);
}

P101_ATTR_SEMANTIC_ROLE("p101:boundary-case:boundary:tool-event-record:stale_version")

static void test_small_helpers(void)
{
    static const char *const prefixes[] = {
        "P101FD\t",
        "P101ALLOC\t",
        "P101FORK\t",
        "P101SPAWN\t",
        "P101EXEC\t",
        "P101EXECFAIL\t",
        "P101CALL\t",
        "P101RESOURCE\t",
        "P101COMPLETE\t",
    };
    char   split_text[] = "one\ttwo";
    char  *cursor;
    char   escaped[] = "a\\tb\\nc\\rd\\\\e\\q\\";
    char   json[128];
    FILE  *stream;
    size_t value;

    EXPECT(!p101_tool_event_line_is_ours(NULL));
    EXPECT(!p101_tool_event_line_is_ours("P101NOPE\t"));
    for(size_t index = 0U; index < sizeof(prefixes) / sizeof(prefixes[0]); index++)
    {
        EXPECT(p101_tool_event_line_is_ours(prefixes[index]));
    }

    EXPECT(p101_record_split(NULL) == NULL);
    cursor = NULL;
    EXPECT(p101_record_split(&cursor) == NULL);
    cursor = split_text;
    EXPECT(strcmp(p101_record_split(&cursor), "one") == 0);
    EXPECT(strcmp(p101_record_split(&cursor), "two") == 0);
    EXPECT(cursor == NULL);

    p101_record_unescape_field(NULL);
    p101_record_unescape_field(escaped);
    EXPECT(strcmp(escaped, "a\tb\nc\rd\\eq\\") == 0);

    EXPECT(!p101_record_parse_size(NULL, &value));
    EXPECT(!p101_record_parse_size("", &value));
    EXPECT(!p101_record_parse_size("1", NULL));
    EXPECT(!p101_record_parse_size("-1", &value));
    EXPECT(!p101_record_parse_size("1x", &value));
    EXPECT(!p101_record_parse_size("999999999999999999999999999999999999", &value));
    EXPECT(p101_record_parse_size("0", &value) && value == 0U);
    EXPECT(p101_record_parse_size("42", &value) && value == 42U);
    EXPECT(p101_record_write_json_string(NULL, "x") == -1 && errno == EINVAL);
    EXPECT(p101_record_write_json_string(NULL, NULL) == -1 && errno == EINVAL);
    EXPECT(p101_record_write_json_string_contents(NULL, "x") == -1 && errno == EINVAL);
    EXPECT(p101_record_write_json_string_contents(NULL, NULL) == -1 && errno == EINVAL);
    stream = tmpfile();
    EXPECT(stream != NULL);
    if(stream != NULL)
    {
        EXPECT(p101_record_write_json_string(stream, "\"\\\b\f\n\r\t\1z") == 0);
        rewind(stream);
        EXPECT(fgets(json, sizeof(json), stream) != NULL);
        EXPECT(strcmp(json, "\"\\\"\\\\\\b\\f\\n\\r\\t\\u0001z\"") == 0);
        EXPECT(fclose(stream) == 0);
    }
    stream = tmpfile();
    EXPECT(stream != NULL);
    if(stream != NULL)
    {
        EXPECT(p101_record_write_json_string(stream, NULL) == -1 && errno == EINVAL);
        EXPECT(p101_record_write_json_string_contents(stream, NULL) == -1 && errno == EINVAL);
        EXPECT(fclose(stream) == 0);
    }
    stream = tmpfile();
    EXPECT(stream != NULL);
    if(stream != NULL)
    {
        EXPECT(setvbuf(stream, NULL, _IONBF, 0U) == 0);
        EXPECT(close(fileno(stream)) == 0);
        EXPECT(p101_record_write_json_string(stream, "x") == -1);
        (void)fclose(stream);
    }
    expect_json_contents_write_failure("\"");
    expect_json_contents_write_failure("\\");
    expect_json_contents_write_failure("\b");
    expect_json_contents_write_failure("\f");
    expect_json_contents_write_failure("\n");
    expect_json_contents_write_failure("\r");
    expect_json_contents_write_failure("\t");
    expect_json_contents_write_failure("\1");
    expect_json_contents_write_failure("z");

    EXPECT(strcmp(p101_tool_event_parse_status_name(P101_TOOL_EVENT_PARSE_OTHER), "not a p101 event record") == 0);
    EXPECT(strcmp(p101_tool_event_parse_status_name(P101_TOOL_EVENT_PARSE_OK), "ok") == 0);
    EXPECT(strcmp(p101_tool_event_parse_status_name(P101_TOOL_EVENT_PARSE_MALFORMED), "malformed record") == 0);
    EXPECT(strcmp(p101_tool_event_parse_status_name(P101_TOOL_EVENT_PARSE_BAD_VERSION), "unsupported record version") == 0);
    EXPECT(strcmp(p101_tool_event_parse_status_name((p101_tool_event_parse_status)99), "unknown event parse status") == 0);
}

P101_ATTR_SEMANTIC_ROLE("p101:boundary-case:boundary:tool-event-record:clean")

static void test_valid_parser_records(void)
{
    static const char *const records[] = {
        "P101FD\t5\ttest\t1\t2\t3\t-\t-\tOPEN\t0\t0\tf\tc\n",
        "P101FD\t5\ttest\t1\t2\t3\t5\t5\tCLOSE\t1048576\t2147483647\tf\tc\r\n",
        "P101ALLOC\t5\ttest\t1\t2\t3\t-\t-\tALLOC\t0x1\t-\t5\t1\tf\tc\n",
        "P101ALLOC\t5\ttest\t1\t2\t3\t-\t-\tFREE\t0x1\t-\t0\t1\tf\tc\n",
        "P101ALLOC\t5\ttest\t1\t2\t3\t-\t-\tREALLOC\t0x1\t0x2\t9\t1\tf\tc\n",
        "P101FORK\t5\ttest\t1\t2\t3\t-\t-\t2\t1\tf\tc\n",
        "P101SPAWN\t5\ttest\t1\t2\t3\t-\t-\t2\t1\tf\tc\ttarget\n",
        "P101EXEC\t5\ttest\t1\t2\t3\t-\t-\t5\t0\t1\tf\tc\ttarget\n",
        "P101EXECFAIL\t5\ttest\t1\t2\t3\t-\t-\t1\tf\tc\ttarget\n",
        "P101CALL\t5\ttest\t1\t2\t3\t-\t-\tENTER\t1\tf\tcall\ta\\tb\t-\tc\n",
        "P101CALL\t5\ttest\t1\t2\t3\t-\t-\tEXIT\t1\tf\tcall\t-\tresult\tc\n",
        "P101RESOURCE\t5\ttest\t1\t2\t3\t-\t-\tACQUIRE\tclass\tid\t-\t1\tmeta\t1\tf\tc\n",
        "P101RESOURCE\t5\ttest\t1\t2\t3\t-\t-\tRELEASE\tclass\tid\t-\t0\t-\t1\tf\tc\n",
        "P101RESOURCE\t5\ttest\t1\t2\t3\t-\t-\tREPLACE\tclass\tid\tnew\t2\t-\t1\tf\tc\n",
        "P101RESOURCE\t5\ttest\t1\t2\t3\t-\t-\tTRANSFER\tclass\tid\tnew\t2\t-\t1\tf\tc\n",
        "P101COMPLETE\t5\ttest\t1\t2\t3\t-\t-\t2\t0\t0\n",
        "P101COMPLETE\t5\ttest\t1\t2\t3\t-\t-\t2\t1\t5\n",
    };
    struct p101_tool_event_record record;

    for(size_t index = 0U; index < sizeof(records) / sizeof(records[0]); index++)
    {
        EXPECT(parse_text(records[index], &record) == P101_TOOL_EVENT_PARSE_OK);
    }
}

P101_ATTR_SEMANTIC_ROLE("p101:boundary-case:boundary:tool-event-record:typed_refusal")

static void test_malformed_parser_records(void)
{
    static const char *const malformed[] = {
        "P101FD",
        "P101FD\t",
        "P101FD\t5\t1\t2\t3\t-\n",
        "P101FD\t4\trun\t1\t2\t3\t-\t-\tOPEN\t0\t0\tf\tc\n",
        "P101FD\t5\t\t1\t2\t3\t-\t-\tOPEN\t0\t0\tf\tc\n",
        "P101FD\tx\trun\t1\t2\t3\t-\t-\tOPEN\t1\t1\tf\tc\n",
        "P101FD\t-1\trun\t1\t2\t3\t-\t-\tOPEN\t1\t1\tf\tc\n",
        "P101FD\t5\trun\t\t2\t3\t-\t-\tOPEN\t1\t1\tf\tc\n",
        "P101FD\t5\trun\tx\t2\t3\t-\t-\tOPEN\t1\t1\tf\tc\n",
        "P101FD\t5\trun\t-1\t2\t3\t-\t-\tOPEN\t1\t1\tf\tc\n",
        "P101FD\t5\trun\t999999999999999999999999999999999\t2\t3\t-\t-\tOPEN\t1\t1\tf\tc\n",
        "P101FD\t5\trun\t1\tx\t3\t-\t-\tOPEN\t1\t1\tf\tc\n",
        "P101FD\t5\trun\t1\t-1\t3\t-\t-\tOPEN\t1\t1\tf\tc\n",
        "P101FD\t5\trun\t1\t2\tx\t-\t-\tOPEN\t1\t1\tf\tc\n",
        "P101FD\t5\trun\t1\t2\t-1\t-\t-\tOPEN\t1\t1\tf\tc\n",
        "P101FD\t5\trun\t1\t2\t3\tx\t-\tOPEN\t1\t1\tf\tc\n",
        "P101FD\t5\trun\t1\t2\t3\t-\tx\tOPEN\t1\t1\tf\tc\n",
        "P101FD\t5\trun\t1\t2\t3\t-\t-\tBAD\t1\t1\tf\tc\n",
        "P101FD\t5\trun\t1\t2\t3\t-\t-\tOPEN\t-1\t1\tf\tc\n",
        "P101FD\t5\trun\t1\t2\t3\t-\t-\tOPEN\t1048577\t1\tf\tc\n",
        "P101FD\t5\trun\t1\t2\t3\t-\t-\tOPEN\t1\t-1\tf\tc\n",
        "P101FD\t5\trun\t1\t2\t3\t-\t-\tOPEN\t1\t2147483648\tf\tc\n",
        "P101FD\t5\trun\t1\t2\t3\t-\t-\tOPEN\t1\t1x\tf\tc\n",
        "P101FD\t5\trun\t1\t2\t3\t-\t-\tOPEN\t1\t1\tf\n",
        "P101ALLOC\t5\trun\t1\t2\t3\t-\t-\tBAD\tp\t-\t1\t1\tf\tc\n",
        "P101ALLOC\t5\trun\t1\t2\t3\t-\t-\tALLOC\tp\t-\t1\t1\tf\n",
        "P101ALLOC\t5\trun\t1\t2\t3\t-\t-\tALLOC\tp\t-\tx\t1\tf\tc\n",
        "P101ALLOC\t5\trun\t1\t2\t3\t-\t-\tALLOC\tp\t-\t1\tx\tf\tc\n",
        "P101FORK\t5\trun\t1\t2\t3\t-\t-\t-1\t1\tf\tc\n",
        "P101FORK\t5\trun\t1\t2\t3\t-\t-\t1\tx\tf\tc\n",
        "P101FORK\t5\trun\t1\t2\t3\t-\t-\t1\n",
        "P101SPAWN\t5\trun\t1\t2\t3\t-\t-\t1\t1\tf\tc\n",
        "P101SPAWN\t5\trun\t1\t2\t3\t-\t-\t1\n",
        "P101EXEC\t5\trun\t1\t2\t3\t-\t-\t-1\t0\t1\tf\tc\tt\n",
        "P101EXEC\t5\trun\t1\t2\t3\t-\t-\t1\t2\t1\tf\tc\tt\n",
        "P101EXEC\t5\trun\t1\t2\t3\t-\t-\t1\t0\tx\tf\tc\tt\n",
        "P101EXEC\t5\trun\t1\t2\t3\t-\t-\t1\t0\t1\tf\tc\n",
        "P101EXEC\t5\trun\t1\t2\t3\t-\t-\n",
        "P101EXECFAIL\t5\trun\t1\t2\t3\t-\t-\tx\tf\tc\tt\n",
        "P101EXECFAIL\t5\trun\t1\t2\t3\t-\t-\t1\tf\tc\n",
        "P101EXECFAIL\t5\trun\t1\t2\t3\t-\t-\n",
        "P101CALL\t5\trun\t1\t2\t3\t-\t-\tBAD\t1\tf\tc\ta\tr\tc\n",
        "P101CALL\t5\trun\t1\t2\t3\t-\t-\tENTER\t1\tf\tc\ta\tr\n",
        "P101CALL\t5\trun\t1\t2\t3\t-\t-\tENTER\tx\tf\tc\ta\tr\tc\n",
        "P101RESOURCE\t5\trun\t1\t2\t3\t-\t-\tBAD\tc\ti\t-\t1\tm\t1\tf\tc\n",
        "P101RESOURCE\t5\trun\t1\t2\t3\t-\t-\tACQUIRE\tc\ti\t-\tx\tm\t1\tf\tc\n",
        "P101RESOURCE\t5\trun\t1\t2\t3\t-\t-\tACQUIRE\tc\ti\t-\t1\tm\tx\tf\tc\n",
        "P101RESOURCE\t5\trun\t1\t2\t3\t-\t-\tACQUIRE\tc\ti\t-\t1\tm\t1\tf\n",
        "P101COMPLETE\t5\trun\t1\t2\t3\t-\t-\tx\t0\t0\n",
        "P101COMPLETE\t5\trun\t1\t2\t3\t-\t-\t1\t2\t0\n",
        "P101COMPLETE\t5\trun\t1\t2\t3\t-\t-\t1\t0\tx\n",
        "P101COMPLETE\t5\trun\t1\t2\t3\t-\t-\t1\t0\t1\n",
        "P101COMPLETE\t5\trun\t1\t2\t3\t-\t-\t1\t1\t0\n",
        "P101COMPLETE\t5\trun\t1\t2\t3\t-\t-\t1\t0\n",
        "P101COMPLETE\t5\trun\t1\t2\t3\t-\t-\n",
    };
    struct p101_tool_event_record record;
    char                          too_many[512] = "P101FD\t5\trun\t1\t2\t3\t-\t-";
    char                          overlong_run_id[P101_TOOL_EVENT_RUN_ID_MAX_BYTES + 2U];
    char                          overlong_record[P101_TOOL_EVENT_LINE_MAX_BYTES];

    EXPECT(p101_tool_event_parse_line(NULL, &record) == P101_TOOL_EVENT_PARSE_MALFORMED);
    EXPECT(p101_tool_event_parse_line(too_many, NULL) == P101_TOOL_EVENT_PARSE_MALFORMED);
    EXPECT(parse_text("not ours\n", &record) == P101_TOOL_EVENT_PARSE_OTHER);
    EXPECT(parse_text("P101WHAT\t5\t1\t2\t3\t-\t-\n", &record) == P101_TOOL_EVENT_PARSE_OTHER);
    memset(overlong_run_id, 'r', sizeof(overlong_run_id) - 1U);
    overlong_run_id[sizeof(overlong_run_id) - 1U] = '\0';
    (void)snprintf(overlong_record, sizeof(overlong_record), "P101FD\t5\t%s\t1\t2\t3\t-\t-\tOPEN\t1\t1\tf\tc\n", overlong_run_id);
    EXPECT(parse_text(overlong_record, &record) == P101_TOOL_EVENT_PARSE_MALFORMED);
    for(size_t index = 0U; index < sizeof(malformed) / sizeof(malformed[0]); index++)
    {
        EXPECT(parse_text(malformed[index], &record) != P101_TOOL_EVENT_PARSE_OK);
    }
    for(size_t index = 0U; index < 20U; index++)
    {
        (void)strcat(too_many, "\tx");
    }
    EXPECT(p101_tool_event_parse_line(too_many, &record) == P101_TOOL_EVENT_PARSE_MALFORMED);
}

static void set_common_output(struct p101_tool_event_output *output, p101_tool_event_record_kind kind)
{
    memset(output, 0, sizeof(*output));
    output->record_kind            = kind;
    output->run_id                 = "test-run";
    output->pid                    = 7;
    output->context_id             = 8U;
    output->sequence               = 9U;
    output->monotonic_ns           = 10U;
    output->wall_unix_ns           = 11U;
    output->monotonic_ns_available = 1;
    output->wall_unix_ns_available = 1;
    output->fd                     = 3;
    output->cloexec                = 1;
    output->child_pid              = 12;
    output->line_number            = 13;
    output->ptr                    = "old";
    output->new_ptr                = "new";
    output->target                 = "target";
    output->resource_class         = "class";
    output->resource_id            = "id";
    output->related_id             = "related";
    output->metadata               = "a\tb\nc\rd\\e";
    output->size                   = 14U;
    output->function_name          = "function";
    output->call_name              = "call";
    output->arguments              = "arguments";
    output->result                 = "result";
    output->file_name              = "file";
}

static void test_all_writer_records(void)
{
    static const p101_tool_event_record_kind kinds[] = {
        P101_TOOL_EVENT_RECORD_FD,
        P101_TOOL_EVENT_RECORD_ALLOC,
        P101_TOOL_EVENT_RECORD_FORK,
        P101_TOOL_EVENT_RECORD_SPAWN,
        P101_TOOL_EVENT_RECORD_EXEC,
        P101_TOOL_EVENT_RECORD_EXEC_FAIL,
        P101_TOOL_EVENT_RECORD_CALL,
        P101_TOOL_EVENT_RECORD_RESOURCE,
        P101_TOOL_EVENT_RECORD_COMPLETE,
    };

    for(size_t index = 0U; index < sizeof(kinds) / sizeof(kinds[0]); index++)
    {
        struct p101_tool_event_output output;
        struct p101_tool_event_record record;
        char                          line[P101_TOOL_EVENT_LINE_MAX_BYTES];
        FILE                         *stream;

        set_common_output(&output, kinds[index]);
        output.fd_kind       = (index & 1U) == 0U ? P101_TOOL_EVENT_FD_OPEN : P101_TOOL_EVENT_FD_CLOSE;
        output.alloc_kind    = (p101_tool_event_alloc_kind)(index % 3U);
        output.call_kind     = (index & 1U) == 0U ? P101_TOOL_EVENT_CALL_ENTER : P101_TOOL_EVENT_CALL_EXIT;
        output.resource_kind = (p101_tool_event_resource_kind)(index % 4U);
        if(kinds[index] == P101_TOOL_EVENT_RECORD_COMPLETE)
        {
            output.events_attempted = 8U;
            output.write_failed     = 0;
            output.write_errno      = 0;
        }
        stream = tmpfile();
        EXPECT(stream != NULL);
        EXPECT(p101_tool_event_write(stream, &output) == 0);
        rewind(stream);
        EXPECT(fgets(line, sizeof(line), stream) != NULL);
        EXPECT(p101_tool_event_parse_line(line, &record) == P101_TOOL_EVENT_PARSE_OK);
        EXPECT(record.record_kind == kinds[index]);
        fclose(stream);
    }

    {
        struct p101_tool_event_output output;
        FILE                         *stream = tmpfile();

        set_common_output(&output, P101_TOOL_EVENT_RECORD_FD);
        output.version                = 0;
        output.monotonic_ns_available = 0;
        output.wall_unix_ns_available = 0;
        output.fd_kind                = P101_TOOL_EVENT_FD_CLOSE;
        output.function_name          = NULL;
        output.file_name              = "-";
        EXPECT(p101_tool_event_write(stream, &output) == 0);
        fclose(stream);
    }
}

static void expect_invalid_output(struct p101_tool_event_output *output)
{
    FILE *stream = tmpfile();

    EXPECT(stream != NULL);
    errno = 0;
    EXPECT(p101_tool_event_write(stream, output) == -1);
    EXPECT(errno == EINVAL);
    fclose(stream);
}

static void test_invalid_writer_records(void)
{
    struct p101_tool_event_output output;
    FILE                         *stream;
    char                          overlong_run_id[P101_TOOL_EVENT_RUN_ID_MAX_BYTES + 2U];

    set_common_output(&output, P101_TOOL_EVENT_RECORD_FD);
    EXPECT(p101_tool_event_write(NULL, &output) == -1);
    stream = tmpfile();
    EXPECT(p101_tool_event_write(stream, NULL) == -1);
    fclose(stream);

    output.version = 3;
    expect_invalid_output(&output);
    set_common_output(&output, P101_TOOL_EVENT_RECORD_FD);
    output.run_id = NULL;
    expect_invalid_output(&output);
    set_common_output(&output, P101_TOOL_EVENT_RECORD_FD);
    output.run_id = "";
    expect_invalid_output(&output);
    set_common_output(&output, P101_TOOL_EVENT_RECORD_FD);
    memset(overlong_run_id, 'r', sizeof(overlong_run_id) - 1U);
    overlong_run_id[sizeof(overlong_run_id) - 1U] = '\0';
    output.run_id                                 = overlong_run_id;
    expect_invalid_output(&output);
    set_common_output(&output, P101_TOOL_EVENT_RECORD_FD);
    output.pid = -1;
    expect_invalid_output(&output);
    set_common_output(&output, P101_TOOL_EVENT_RECORD_FD);
    output.monotonic_ns_available = 2;
    expect_invalid_output(&output);
    set_common_output(&output, P101_TOOL_EVENT_RECORD_FD);
    output.wall_unix_ns_available = -1;
    expect_invalid_output(&output);

    set_common_output(&output, P101_TOOL_EVENT_RECORD_FD);
    output.fd = -1;
    expect_invalid_output(&output);
    output.fd = 1048577;
    expect_invalid_output(&output);
    output.fd          = 1;
    output.line_number = -1;
    expect_invalid_output(&output);
    output.line_number = 1;
    output.fd_kind     = (p101_tool_event_fd_kind)9;
    expect_invalid_output(&output);

    set_common_output(&output, P101_TOOL_EVENT_RECORD_ALLOC);
    output.alloc_kind = (p101_tool_event_alloc_kind)9;
    expect_invalid_output(&output);
    output.alloc_kind  = P101_TOOL_EVENT_ALLOC_ALLOC;
    output.line_number = -1;
    expect_invalid_output(&output);

    set_common_output(&output, P101_TOOL_EVENT_RECORD_CALL);
    output.call_kind = (p101_tool_event_call_kind)9;
    expect_invalid_output(&output);

    set_common_output(&output, P101_TOOL_EVENT_RECORD_RESOURCE);
    output.resource_kind = (p101_tool_event_resource_kind)9;
    expect_invalid_output(&output);

    set_common_output(&output, P101_TOOL_EVENT_RECORD_FORK);
    output.child_pid = -1;
    expect_invalid_output(&output);
    set_common_output(&output, P101_TOOL_EVENT_RECORD_SPAWN);
    output.line_number = -1;
    expect_invalid_output(&output);

    set_common_output(&output, P101_TOOL_EVENT_RECORD_EXEC);
    output.cloexec = 2;
    expect_invalid_output(&output);
    set_common_output(&output, P101_TOOL_EVENT_RECORD_EXEC_FAIL);
    output.line_number = -1;
    expect_invalid_output(&output);

    set_common_output(&output, P101_TOOL_EVENT_RECORD_COMPLETE);
    output.write_failed = 2;
    expect_invalid_output(&output);
    output.write_failed = 0;
    output.write_errno  = EIO;
    expect_invalid_output(&output);
    output.write_failed = 1;
    output.write_errno  = 0;
    expect_invalid_output(&output);

    set_common_output(&output, (p101_tool_event_record_kind)99);
    expect_invalid_output(&output);
}

P101_ATTR_SEMANTIC_ROLE("p101:boundary-case:boundary:tool-event-record:binding_swap")
P101_ATTR_SEMANTIC_ROLE("p101:boundary-case:boundary:tool-event-record:resource_limit")

static void test_writer_failures_and_field_boundaries(void)
{
    struct p101_tool_event_output output;
    char                          oversized[P101_TOOL_EVENT_LINE_MAX_BYTES + 32U];
    char                          delete_character[] = {(char)0x7f, '\0'};
    FILE                         *stream;

    memset(oversized, 'x', sizeof(oversized) - 1U);
    oversized[sizeof(oversized) - 1U] = '\0';
    set_common_output(&output, P101_TOOL_EVENT_RECORD_RESOURCE);
    output.resource_kind  = P101_TOOL_EVENT_RESOURCE_ACQUIRE;
    output.resource_class = oversized;
    stream                = tmpfile();
    EXPECT(stream != NULL);
    errno = 0;
    EXPECT(p101_tool_event_write(stream, &output) == -1);
    EXPECT(errno == EMSGSIZE);
    fclose(stream);

    set_common_output(&output, P101_TOOL_EVENT_RECORD_CALL);
    output.call_kind     = P101_TOOL_EVENT_CALL_ENTER;
    output.function_name = "\001";
    output.call_name     = delete_character;
    output.file_name     = "-long";
    stream               = tmpfile();
    EXPECT(stream != NULL);
    EXPECT(p101_tool_event_write(stream, &output) == 0);
    fclose(stream);

    stream = tmpfile();
    EXPECT(stream != NULL);
    EXPECT(close(fileno(stream)) == 0);
    errno = 0;
    EXPECT(p101_tool_event_write(stream, &output) == -1);
    EXPECT(errno != 0);
    fclose(stream);

    stream = tmpfile();
    EXPECT(stream != NULL);
    EXPECT(setvbuf(stream, NULL, _IOFBF, BUFSIZ) == 0);
    EXPECT(fputs("pending", stream) >= 0);
    EXPECT(close(fileno(stream)) == 0);
    errno = 0;
    EXPECT(p101_tool_event_write(stream, &output) == -1);
    EXPECT(errno != 0);
    fclose(stream);

    stream = tmpfile();
    EXPECT(stream != NULL);
    EXPECT(close(fileno(stream)) == 0);
    p101_tool_event_test_force_zero_errno_on_write_error();
    EXPECT(p101_tool_event_write(stream, &output) == -1);
    EXPECT(errno == EIO);
    fclose(stream);

    p101_tool_event_test_write_unknown_payload();
    EXPECT(p101_tool_event_test_parse_unknown_payload() == P101_TOOL_EVENT_PARSE_OTHER);

    set_common_output(&output, P101_TOOL_EVENT_RECORD_FD);
    output.fd_kind = P101_TOOL_EVENT_FD_OPEN;
    stream         = tmpfile();
    EXPECT(stream != NULL);
    p101_tool_event_test_force_format_overflow();
    EXPECT(p101_tool_event_write(stream, &output) == -1);
    EXPECT(errno == EMSGSIZE);
    fclose(stream);
}

static void test_writer_validation_paths(void)
{
    struct p101_tool_event_output output;
    FILE                         *stream;

#define EXPECT_WRITES()                                                                                                                                                                                                                                            \
    do                                                                                                                                                                                                                                                             \
    {                                                                                                                                                                                                                                                              \
        stream = tmpfile();                                                                                                                                                                                                                                        \
        EXPECT(stream != NULL);                                                                                                                                                                                                                                    \
        EXPECT(p101_tool_event_write(stream, &output) == 0);                                                                                                                                                                                                       \
        fclose(stream);                                                                                                                                                                                                                                            \
    } while(0)

    set_common_output(&output, P101_TOOL_EVENT_RECORD_ALLOC);
    output.alloc_kind = P101_TOOL_EVENT_ALLOC_ALLOC;
    EXPECT_WRITES();
    output.alloc_kind = P101_TOOL_EVENT_ALLOC_REALLOC;
    EXPECT_WRITES();

    set_common_output(&output, P101_TOOL_EVENT_RECORD_CALL);
    output.call_kind = P101_TOOL_EVENT_CALL_EXIT;
    EXPECT_WRITES();
    output.line_number = -1;
    expect_invalid_output(&output);

    set_common_output(&output, P101_TOOL_EVENT_RECORD_RESOURCE);
    output.resource_kind = P101_TOOL_EVENT_RESOURCE_RELEASE;
    EXPECT_WRITES();
    output.resource_kind = P101_TOOL_EVENT_RESOURCE_REPLACE;
    EXPECT_WRITES();
    output.line_number = -1;
    expect_invalid_output(&output);

    set_common_output(&output, P101_TOOL_EVENT_RECORD_EXEC);
    output.cloexec = 0;
    EXPECT_WRITES();
    output.fd = -1;
    expect_invalid_output(&output);
    output.fd = 1048577;
    expect_invalid_output(&output);
    output.fd          = 1;
    output.line_number = -1;
    expect_invalid_output(&output);
#undef EXPECT_WRITES
}

int main(void)
{
    test_line_reader();
    test_small_helpers();
    test_valid_parser_records();
    test_malformed_parser_records();
    test_all_writer_records();
    test_invalid_writer_records();
    test_writer_failures_and_field_boundaries();
    test_writer_validation_paths();
    return failures == 0 ? 0 : 1;
}
