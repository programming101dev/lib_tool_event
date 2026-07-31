#include <errno.h>
#include <p101_tool_event/event.h>
#include <string.h>

static int failures;

extern void p101_tool_event_test_force_health_allocation_failure(void);
extern void p101_tool_event_test_set_health_allocation_failure_errno(int errnum);

#define EXPECT(condition)                                                                                                                                                                                                                                          \
    do                                                                                                                                                                                                                                                             \
    {                                                                                                                                                                                                                                                              \
        if(!(condition))                                                                                                                                                                                                                                           \
        {                                                                                                                                                                                                                                                          \
            failures++;                                                                                                                                                                                                                                            \
        }                                                                                                                                                                                                                                                          \
    } while(0)

static void test_invalid_and_allocation_failure(void)
{
    struct p101_tool_event_stream_health health = {0};
    struct p101_tool_event_record        record = {0};

    EXPECT(p101_tool_event_stream_health_observe(NULL, &record) == -1);
    EXPECT(errno == EINVAL);
    EXPECT(p101_tool_event_stream_health_observe(&health, NULL) == -1);
    EXPECT(errno == EINVAL);
    p101_tool_event_test_force_health_allocation_failure();
    EXPECT(p101_tool_event_stream_health_observe(&health, &record) == -1);
    EXPECT(health.allocation_failed == 1);
    errno = EDOM;
    p101_tool_event_test_set_health_allocation_failure_errno(0);
    p101_tool_event_test_force_health_allocation_failure();
    EXPECT(p101_tool_event_stream_health_observe(&health, &record) == -1);
    EXPECT(errno == 0);
    p101_tool_event_stream_health_destroy(&health);
    p101_tool_event_stream_health_destroy(NULL);
    EXPECT(p101_tool_event_stream_health_incomplete_producers(NULL) == 0U);
}

static void test_growth_and_lookup(void)
{
    struct p101_tool_event_stream_health health = {0};
    struct p101_tool_event_record        record = {0};

    record.record_kind = P101_TOOL_EVENT_RECORD_FD;
    for(long pid = 1; pid <= 10; pid++)
    {
        record.pid        = pid;
        record.context_id = (size_t)pid;
        record.sequence   = 0U;
        EXPECT(p101_tool_event_stream_health_observe(&health, &record) == 0);
    }
    EXPECT(health.producer_count == 10U);
    record.pid        = 1;
    record.context_id = 1U;
    record.sequence   = 1U;
    EXPECT(p101_tool_event_stream_health_observe(&health, &record) == 0);
    record.context_id = 99U;
    EXPECT(p101_tool_event_stream_health_observe(&health, &record) == 0);
    EXPECT(health.producer_count == 11U);
    p101_tool_event_stream_health_destroy(&health);
}

static void test_completeness_conditions(void)
{
    struct p101_tool_event_producer_health producer = {0};
    struct p101_tool_event_stream_health   health   = {0};

    producer.completion_records = 1U;
    health.records_observed     = 1U;
    health.producer_count       = 1U;
    health.producers            = &producer;
    EXPECT(p101_tool_event_stream_health_is_complete(&health));

    EXPECT(!p101_tool_event_stream_health_is_complete(NULL));
    health.records_observed = 0U;
    EXPECT(!p101_tool_event_stream_health_is_complete(&health));
    health.records_observed = 1U;
    health.producer_count   = 0U;
    EXPECT(!p101_tool_event_stream_health_is_complete(&health));
    health.producer_count          = 1U;
    health.producer_write_failures = 1U;
    EXPECT(!p101_tool_event_stream_health_is_complete(&health));
    health.producer_write_failures = 0U;
    health.duplicate_sequences     = 1U;
    EXPECT(!p101_tool_event_stream_health_is_complete(&health));
    health.duplicate_sequences    = 0U;
    health.nonmonotonic_sequences = 1U;
    EXPECT(!p101_tool_event_stream_health_is_complete(&health));
    health.nonmonotonic_sequences     = 0U;
    health.attempted_count_mismatches = 1U;
    EXPECT(!p101_tool_event_stream_health_is_complete(&health));
    health.attempted_count_mismatches = 0U;
    health.records_after_completion   = 1U;
    EXPECT(!p101_tool_event_stream_health_is_complete(&health));
    health.records_after_completion = 0U;
    health.allocation_failed        = 1;
    EXPECT(!p101_tool_event_stream_health_is_complete(&health));
    health.allocation_failed = 0;

    producer.completion_records = 0U;
    EXPECT(p101_tool_event_stream_health_incomplete_producers(&health) == 1U);
    producer.completion_records = 1U;
    producer.write_failed       = 1;
    EXPECT(p101_tool_event_stream_health_incomplete_producers(&health) == 1U);
    producer.write_failed               = 0;
    producer.attempted_count_mismatches = 1U;
    EXPECT(p101_tool_event_stream_health_incomplete_producers(&health) == 1U);
    producer.attempted_count_mismatches = 0U;
    EXPECT(p101_tool_event_stream_health_incomplete_producers(&health) == 0U);
}

int main(void)
{
    test_invalid_and_allocation_failure();
    test_growth_and_lookup();
    test_completeness_conditions();
    return failures == 0 ? 0 : 1;
}
