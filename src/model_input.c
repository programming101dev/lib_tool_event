#include <errno.h>
#include <p101_error/error.h>
#include <p101_tool_event/event.h>
#include <p101_tool_event/model.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>

static int  ingest_path(struct p101_error *err, struct p101_tool_model *model, const char *path, bool calls, struct p101_tool_event_stream_health *health);
static int  ingest_stream(struct p101_error *err, struct p101_tool_model *model, FILE *stream, bool calls, struct p101_tool_event_stream_health *health);
static bool streams_complete(const struct p101_tool_event_stream_health *resource_health, const struct p101_tool_event_stream_health *call_health);
static bool stream_valid(const struct p101_tool_event_stream_health *health);
static bool producer_complete(const struct p101_tool_event_producer_health *producer, const struct p101_tool_event_stream_health *resource_health);

int p101_tool_model_ingest_paths(struct p101_error *err, struct p101_tool_model *model, const char *resource_path, const char *call_path)
{
    int                                  p101_single_result_;
    struct p101_tool_event_stream_health resource_health;
    struct p101_tool_event_stream_health call_health;
    int                                  operation_status;
    bool                                 complete;

    memset(&resource_health, 0, sizeof(resource_health));
    memset(&call_health, 0, sizeof(call_health));
    if(model == NULL || resource_path == NULL || call_path == NULL)
    {
        P101_ERROR_RAISE_ERRNO(err, EINVAL);
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    operation_status = ingest_path(err, model, resource_path, false, &resource_health);
    if(operation_status == 0)
    {
        operation_status = ingest_path(err, model, call_path, true, &call_health);
    }
    complete = false;
    if(operation_status == 0)
    {
        complete = streams_complete(&resource_health, &call_health);
    }
    if(operation_status == 0 && !complete)
    {
        P101_ERROR_RAISE_ERRNO(err, EINVAL);
        operation_status = -1;
    }
    if(operation_status == 0)
    {
        operation_status = p101_tool_model_finish(err, model);
    }
    p101_tool_event_stream_health_destroy(&resource_health);
    p101_tool_event_stream_health_destroy(&call_health);
    p101_single_result_ = operation_status;

p101_single_exit_:
    return p101_single_result_;
}

static int ingest_path(struct p101_error *err, struct p101_tool_model *model, const char *path, bool calls, struct p101_tool_event_stream_health *health)
{
    int   p101_single_result_;
    FILE *stream;
    int   operation_status;
    int   close_status;

    stream = fopen(path, "re");
    if(stream == NULL)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    operation_status = ingest_stream(err, model, stream, calls, health);
    close_status     = fclose(stream);
    if(close_status != 0 && operation_status == 0)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
        operation_status = -1;
    }
    p101_single_result_ = operation_status;

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
        bool                          belongs;

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
        operation_status = p101_tool_event_stream_health_observe(health, &record);
        if(operation_status != 0)
        {
            P101_ERROR_RAISE_ERRNO(err, errno == 0 ? ENOMEM : errno);
            p101_single_result_ = -1;
            goto p101_single_exit_;
        }
        belongs = record.record_kind != P101_TOOL_EVENT_RECORD_COMPLETE;
        if(belongs && calls)
        {
            belongs = record.record_kind == P101_TOOL_EVENT_RECORD_CALL;
        }
        else if(belongs)
        {
            belongs = record.record_kind != P101_TOOL_EVENT_RECORD_CALL;
        }
        if(belongs)
        {
            operation_status = p101_tool_model_ingest(err, model, &record);
            if(operation_status != 0)
            {
                p101_single_result_ = -1;
                goto p101_single_exit_;
            }
        }
    }

p101_single_exit_:
    return p101_single_result_;
}

static bool streams_complete(const struct p101_tool_event_stream_health *resource_health, const struct p101_tool_event_stream_health *call_health)
{
    bool                                        p101_single_result_;
    const struct p101_tool_event_stream_health *streams[] = {resource_health, call_health};

    p101_single_result_ = true;
    for(size_t stream_index = 0U; stream_index < 2U && p101_single_result_; stream_index++)
    {
        const struct p101_tool_event_stream_health *health;

        health              = streams[stream_index];
        p101_single_result_ = stream_valid(health);
        for(size_t producer_index = 0U; producer_index < health->producer_count && p101_single_result_; producer_index++)
        {
            p101_single_result_ = producer_complete(&health->producers[producer_index], resource_health);
        }
    }
    return p101_single_result_;
}

static bool stream_valid(const struct p101_tool_event_stream_health *health)
{
    bool p101_single_result_;

    p101_single_result_ = (_Bool)((health != NULL && health->records_observed > 0U && health->producer_count > 0U && health->producer_write_failures == 0U && health->duplicate_sequences == 0U && health->nonmonotonic_sequences == 0U &&
                                   health->attempted_count_mismatches == 0U && health->records_after_completion == 0U && health->distinct_run_ids == 1U && health->invalid_run_ids == 0U && health->mixed_run_ids == 0 && health->allocation_failed == 0) != 0);
    return p101_single_result_;
}

static bool producer_complete(const struct p101_tool_event_producer_health *producer, const struct p101_tool_event_stream_health *resource_health)
{
    bool p101_single_result_;

    p101_single_result_ = (_Bool)((producer->completion_records == 1U && producer->write_failed == 0 && producer->attempted_count_mismatches == 0U) != 0);
    if(p101_single_result_ || producer->completion_records != 0U)
    {
        goto p101_single_exit_;
    }
    for(size_t index = 0U; index < resource_health->producer_count; index++)
    {
        const struct p101_tool_event_producer_health *candidate;
        int                                           run_comparison;

        candidate      = &resource_health->producers[index];
        run_comparison = strcmp(candidate->run_id, producer->run_id);
        if(candidate->pid == producer->pid && candidate->context_id == producer->context_id && run_comparison == 0 && candidate->pending_exec != 0)
        {
            p101_single_result_ = true;
            break;
        }
    }

p101_single_exit_:
    return p101_single_result_;
}
