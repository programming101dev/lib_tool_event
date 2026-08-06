#include <errno.h>
#include <p101_error/error.h>
#include <p101_tool_event/event.h>
#include <p101_tool_event/model.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

enum
{
    EXIT_TROUBLE = 2
};

struct arguments
{
    const char *resource_path;
    const char *call_path;
    const char *output_path;
};

static void usage(FILE *stream, const char *program);
static int  parse_arguments(int argc, char *argv[], struct arguments *args);
static int  ingest_path(struct p101_error *err, struct p101_tool_model *model, const char *path, bool calls, struct p101_tool_event_stream_health *health);
static int  ingest_stream(struct p101_error *err, struct p101_tool_model *model, FILE *stream, bool calls, struct p101_tool_event_stream_health *health);
static int  record_belongs_in_stream(const struct p101_tool_event_record *record, bool calls);
static int  write_model(struct p101_error *err, const struct p101_tool_model *model, const char *path);
static int  admitted_streams_are_complete(const struct p101_tool_event_stream_health *resource_health, const struct p101_tool_event_stream_health *call_health);
static int  stream_integrity_is_valid(const struct p101_tool_event_stream_health *health);
static int  producer_completed_or_execed(const struct p101_tool_event_producer_health *producer, const struct p101_tool_event_stream_health *resource_health);

#ifdef P101_TOOL_EVENT_TESTING
extern void p101_tool_event_test_model_fail_allocation_after(size_t successful_allocations);
extern void p101_tool_event_test_force_health_allocation_failure(void);
extern void p101_tool_event_test_set_health_allocation_failure_errno(int errnum);
#endif

int main(int argc, char *argv[])
{
    int                                  p101_single_result_;
    struct arguments                     args;
    struct p101_error                   *err;
    struct p101_tool_event_stream_health call_health;
    struct p101_tool_event_stream_health resource_health;
    struct p101_tool_model              *model;
    int                                  parse_status;
    int                                  result;
    int                                  operation_status;
    int                                  io_status;
    int                                  streams_complete;
    bool                                 error_present;

    memset(&args, 0, sizeof(args));
    memset(&call_health, 0, sizeof(call_health));
    memset(&resource_health, 0, sizeof(resource_health));
    model        = NULL;
    result       = EXIT_TROUBLE;
    parse_status = parse_arguments(argc, argv, &args);
    if(parse_status > 0)
    {
        p101_single_result_ = EXIT_SUCCESS;
        goto p101_single_exit_;
    }
    if(parse_status < 0)
    {
        p101_single_result_ = EXIT_TROUBLE;
        goto p101_single_exit_;
    }

    err = p101_error_create(false);
    if(err == NULL)    // GCOVR_EXCL_BR_LINE: lib_error has no injectable allocator; null remains a defensive process-start check.
    {
        io_status = fputs("p101-event-model: could not create error object\n", stderr);    // GCOVR_EXCL_LINE
        (void)io_status;
        p101_single_result_ = EXIT_TROUBLE;
        goto p101_single_exit_;    // GCOVR_EXCL_LINE
    }
#ifdef P101_TOOL_EVENT_TESTING
    if(getenv("P101_TOOL_EVENT_TEST_FAIL_MODEL_CREATE") != NULL)
    {
        p101_tool_event_test_model_fail_allocation_after(0U);
    }
#endif
    model = p101_tool_model_create(err);
    if(model == NULL)
    {
        goto done;
    }
    operation_status = ingest_path(err, model, args.resource_path, false, &resource_health);
    if(operation_status == 0)
    {
        operation_status = ingest_path(err, model, args.call_path, true, &call_health);
    }
    if(operation_status != 0)
    {
        goto done;
    }
    streams_complete = admitted_streams_are_complete(&resource_health, &call_health);
    if(streams_complete == 0)
    {
        io_status = fputs("p101-event-model: an admitted event stream is incomplete\n", stderr);
        (void)io_status;
        goto done;
    }
#ifdef P101_TOOL_EVENT_TESTING
    if(getenv("P101_TOOL_EVENT_TEST_FAIL_FINISH") != NULL)
    {
        p101_tool_event_test_model_fail_allocation_after(0U);
    }
#endif
    operation_status = p101_tool_model_finish(err, model);
    if(operation_status == 0)
    {
        operation_status = write_model(err, model, args.output_path);
    }
    if(operation_status != 0)
    {
        goto done;
    }
    result = EXIT_SUCCESS;

done:
    error_present = p101_error_has_error(err);
    if(error_present)
    {
        const char *message;

        message   = p101_error_get_message(err);
        io_status = fprintf(stderr, "p101-event-model: %s\n", message);
        (void)io_status;
    }
    p101_tool_event_stream_health_destroy(&resource_health);
    p101_tool_event_stream_health_destroy(&call_health);
    p101_tool_model_destroy(&model);
    p101_error_destroy(err);
    p101_single_result_ = result;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static void usage(FILE *stream, const char *program)
{
    int io_status;

    io_status = fprintf(stream, "Usage: %s -r <resources.log> -c <calls.log> [-o <run-model.json>]\n", program);
    (void)io_status;
}

static int parse_arguments(int argc, char *argv[], struct arguments *args)
{
    int p101_single_result_;
    int index;
    int comparison;

    comparison = -1;
    if(argc == 2)
    {
        comparison = strcmp(argv[1], "-h");
        if(comparison != 0)
        {
            comparison = strcmp(argv[1], "--help");
        }
    }
    if(argc == 2 && comparison == 0)
    {
        usage(stdout, argv[0]);
        p101_single_result_ = 1;
        goto p101_single_exit_;
    }
    for(index = 1; index < argc; index++)
    {
        const char **destination;

        destination = NULL;
        comparison  = strcmp(argv[index], "-r");
        if(comparison == 0)
        {
            destination = &args->resource_path;
        }
        else
        {
            comparison = strcmp(argv[index], "-c");
            if(comparison == 0)
            {
                destination = &args->call_path;
            }
            else
            {
                comparison = strcmp(argv[index], "-o");
                if(comparison == 0)
                {
                    destination = &args->output_path;
                }
                else
                {
                    usage(stderr, argv[0]);
                    p101_single_result_ = -1;
                    goto p101_single_exit_;
                }
            }
        }
        index++;
        if(index >= argc || argv[index][0] == '\0' || *destination != NULL)
        {
            usage(stderr, argv[0]);
            p101_single_result_ = -1;
            goto p101_single_exit_;
        }
        *destination = argv[index];
    }
    if(args->resource_path == NULL || args->call_path == NULL)
    {
        usage(stderr, argv[0]);
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    p101_single_result_ = 0;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static int ingest_path(struct p101_error *err, struct p101_tool_model *model, const char *path, bool calls, struct p101_tool_event_stream_health *health)
{
    int   p101_single_result_;
    FILE *stream;
    int   result;
    int   close_status;

    stream = fopen(path, "r");    // NOLINT(android-cloexec-fopen) -- portable C17 CLI; the stream is never inherited.
    if(stream == NULL)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
#ifdef P101_TOOL_EVENT_TESTING
    if(getenv("P101_TOOL_EVENT_TEST_READ_ERROR") != NULL)
    {
        (void)close(fileno(stream));
    }
#endif
    result = ingest_stream(err, model, stream, calls, health);
    // GCOVR_EXCL_START: fclose failure for a successfully read regular file is
    // not portably injectable; read and parse failures are covered separately.
    close_status = fclose(stream);
    if(close_status != 0 && result == 0)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
        result = -1;
    }
    // GCOVR_EXCL_STOP
    p101_single_result_ = result;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static int ingest_stream(struct p101_error *err, struct p101_tool_model *model, FILE *stream, bool calls, struct p101_tool_event_stream_health *health)
{
    int  p101_single_result_;
    char line[P101_TOOL_EVENT_LINE_MAX_BYTES];

    for(;;)
    {
        struct p101_tool_event_record record;
        p101_tool_event_line_status   line_status;
        p101_tool_event_parse_status  parse_status;
        int                           operation_status;
        int                           belongs;

        line_status = p101_tool_event_read_line(err, stream, line, sizeof(line));
        if(line_status == P101_TOOL_EVENT_LINE_EOF)
        {
            p101_single_result_ = 0;
            goto p101_single_exit_;
        }
        if(line_status != P101_TOOL_EVENT_LINE_OK)
        {
            if(line_status == P101_TOOL_EVENT_LINE_MALFORMED)
            {
                P101_ERROR_RAISE_ERRNO(err, EINVAL);
            }
            p101_single_result_ = -1;
            goto p101_single_exit_;
        }
        parse_status = p101_tool_event_parse_line(line, &record);
        if(parse_status == P101_TOOL_EVENT_PARSE_OTHER)
        {
            continue;
        }
        if(parse_status != P101_TOOL_EVENT_PARSE_OK)
        {
            P101_ERROR_RAISE_ERRNO(err, EINVAL);
            p101_single_result_ = -1;
            goto p101_single_exit_;
        }
#ifdef P101_TOOL_EVENT_TESTING
        if(getenv("P101_TOOL_EVENT_TEST_FAIL_HEALTH") != NULL)
        {
            if(getenv("P101_TOOL_EVENT_TEST_ZERO_HEALTH_ERRNO") != NULL)
            {
                p101_tool_event_test_set_health_allocation_failure_errno(0);
            }
            p101_tool_event_test_force_health_allocation_failure();
        }
#endif
        operation_status = p101_tool_event_stream_health_observe(health, &record);
        if(operation_status != 0)
        {
            P101_ERROR_RAISE_ERRNO(err, errno == 0 ? ENOMEM : errno);
            p101_single_result_ = -1;
            goto p101_single_exit_;
        }
#ifdef P101_TOOL_EVENT_TESTING
        if(getenv("P101_TOOL_EVENT_TEST_FAIL_INGEST") != NULL)
        {
            p101_tool_event_test_model_fail_allocation_after(0U);
        }
#endif
        belongs = 0;
        if(record.record_kind != P101_TOOL_EVENT_RECORD_COMPLETE)
        {
            belongs = record_belongs_in_stream(&record, calls);
        }
        operation_status = 0;
        if(belongs != 0)
        {
            operation_status = p101_tool_model_ingest(err, model, &record);
        }
        if(operation_status != 0)
        {
            p101_single_result_ = -1;
            goto p101_single_exit_;
        }
    }

p101_single_exit_:
    return p101_single_result_;
}

static int record_belongs_in_stream(const struct p101_tool_event_record *record, bool calls)
{
    int p101_single_result_;
    if(calls)
    {
        p101_single_result_ = record->record_kind == P101_TOOL_EVENT_RECORD_CALL;
        goto p101_single_exit_;
    }
    p101_single_result_ = record->record_kind != P101_TOOL_EVENT_RECORD_CALL;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static int admitted_streams_are_complete(const struct p101_tool_event_stream_health *resource_health, const struct p101_tool_event_stream_health *call_health)
{
    int                                         p101_single_result_;
    const struct p101_tool_event_stream_health *streams[] = {resource_health, call_health};

    for(size_t stream = 0U; stream < sizeof(streams) / sizeof(streams[0]); stream++)
    {
        const struct p101_tool_event_stream_health *health;
        int                                         valid;

        health = streams[stream];
        valid  = stream_integrity_is_valid(health);
        if(valid == 0)
        {
            p101_single_result_ = 0;
            goto p101_single_exit_;
        }
        for(size_t producer = 0U; producer < health->producer_count; producer++)
        {
            int completed;

            completed = producer_completed_or_execed(&health->producers[producer], resource_health);
            if(completed == 0)
            {
                p101_single_result_ = 0;
                goto p101_single_exit_;
            }
        }
    }
    p101_single_result_ = 1;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static int stream_integrity_is_valid(const struct p101_tool_event_stream_health *health)
{
    return health != NULL && health->records_observed > 0U && health->producer_count > 0U && health->producer_write_failures == 0U && health->duplicate_sequences == 0U && health->nonmonotonic_sequences == 0U && health->attempted_count_mismatches == 0U &&
           health->records_after_completion == 0U && health->distinct_run_ids == 1U && health->invalid_run_ids == 0U && health->mixed_run_ids == 0 && health->allocation_failed == 0;
}

static int producer_completed_or_execed(const struct p101_tool_event_producer_health *producer, const struct p101_tool_event_stream_health *resource_health)
{
    int p101_single_result_;
    if(producer->completion_records == 1U && producer->write_failed == 0 && producer->attempted_count_mismatches == 0U)
    {
        p101_single_result_ = 1;
        goto p101_single_exit_;
    }
    if(producer->completion_records != 0U || resource_health == NULL)
    {
        p101_single_result_ = 0;
        goto p101_single_exit_;    // GCOVR_EXCL_LINE -- validated streams cannot reach a second completion; the caller always supplies resource health.
    }
    for(size_t index = 0U; index < resource_health->producer_count; index++)
    {
        const struct p101_tool_event_producer_health *resource_producer;
        int                                           run_id_comparison;

        resource_producer = &resource_health->producers[index];
        run_id_comparison = strcmp(resource_producer->run_id, producer->run_id);
        if(resource_producer->pid == producer->pid && resource_producer->context_id == producer->context_id && run_id_comparison == 0 && resource_producer->pending_exec != 0)
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

static int write_model(struct p101_error *err, const struct p101_tool_model *model, const char *path)
{
    int   p101_single_result_;
    FILE *stream;
    int   result;
    int   close_status;

    stream = stdout;
    if(path != NULL)
    {
        stream = fopen(path, "w");    // NOLINT(android-cloexec-fopen) -- portable C17 CLI; the stream is never inherited.
    }
    if(stream == NULL)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    result = p101_tool_model_write_json(err, stream, model);
    // GCOVR_EXCL_START: fclose failure for a successfully written regular file
    // is not portably injectable; open and write failures are covered.
    close_status = 0;
    if(path != NULL)
    {
        close_status = fclose(stream);
    }
    if(close_status != 0 && result == 0)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
        result = -1;
    }
    // GCOVR_EXCL_STOP
    p101_single_result_ = result;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}
