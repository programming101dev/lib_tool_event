#include <p101_error/error.h>
#include <p101_tool_event/analysis.h>
#include <p101_tool_event/event.h>
#include <p101_tool_event/model.h>
#include <stdio.h>
#include <string.h>

static int failures;

#define EXPECT(condition)                                                                                                                                                                                                                                          \
    do                                                                                                                                                                                                                                                             \
    {                                                                                                                                                                                                                                                              \
        if(!(condition))                                                                                                                                                                                                                                           \
        {                                                                                                                                                                                                                                                          \
            (void)fprintf(stderr, "EXPECT failed at %s:%d: %s\n", __FILE__, __LINE__, #condition);                                                                                                                                                                 \
            failures++;                                                                                                                                                                                                                                            \
        }                                                                                                                                                                                                                                                          \
    } while(0)

static void ingest_line(struct p101_error *err, struct p101_tool_model *model, char *line)
{
    struct p101_tool_event_record record;
    p101_tool_event_parse_status  parse_status;
    int                           ingest_status;

    parse_status = p101_tool_event_parse_line(line, &record);
    EXPECT(parse_status == P101_TOOL_EVENT_PARSE_OK);
    if(parse_status == P101_TOOL_EVENT_PARSE_OK)
    {
        ingest_status = p101_tool_model_ingest(err, model, &record);
        EXPECT(ingest_status == 0);
    }
}

static bool analysis_has_finding(const struct p101_tool_analysis *analysis, const char *identifier)
{
    bool   found;
    size_t finding_count;

    found         = false;
    finding_count = p101_tool_analysis_finding_count(analysis);
    for(size_t index = 0U; index < finding_count; index++)
    {
        const struct p101_tool_analysis_finding *finding;
        int                                      comparison;

        finding    = p101_tool_analysis_finding_at(analysis, index);
        comparison = strcmp(finding->diagnostic_id, identifier);
        if(comparison == 0)
        {
            found = true;
            break;
        }
    }
    return found;
}

static void run_release_order_case(bool reverse_release, bool expected_finding)
{
    char                       acquire_a[]        = "P101RESOURCE\t5\tanalysis-test\t42\t7\t1\t100\t200\tACQUIRE\tpthread-mutex-held\tA\t-\t0\tthread=7\t12\tworker\tworker.c\n";
    char                       acquire_b[]        = "P101RESOURCE\t5\tanalysis-test\t42\t7\t2\t110\t210\tACQUIRE\tpthread-mutex-held\tB\t-\t0\tthread=7\t13\tworker\tworker.c\n";
    char                       release_a_first[]  = "P101RESOURCE\t5\tanalysis-test\t42\t7\t3\t120\t220\tRELEASE\tpthread-mutex-held\tA\t-\t0\tthread=7\t14\tworker\tworker.c\n";
    char                       release_b_second[] = "P101RESOURCE\t5\tanalysis-test\t42\t7\t4\t130\t230\tRELEASE\tpthread-mutex-held\tB\t-\t0\tthread=7\t15\tworker\tworker.c\n";
    char                       release_b_first[]  = "P101RESOURCE\t5\tanalysis-test\t42\t7\t3\t120\t220\tRELEASE\tpthread-mutex-held\tB\t-\t0\tthread=7\t14\tworker\tworker.c\n";
    char                       release_a_second[] = "P101RESOURCE\t5\tanalysis-test\t42\t7\t4\t130\t230\tRELEASE\tpthread-mutex-held\tA\t-\t0\tthread=7\t15\tworker\tworker.c\n";
    struct p101_error         *err;
    struct p101_tool_model    *model;
    struct p101_tool_analysis *analysis;
    int                        operation_status;
    bool                       found;

    err   = p101_error_create(false);
    model = p101_tool_model_create(err);
    EXPECT(err != NULL);
    EXPECT(model != NULL);
    ingest_line(err, model, acquire_a);
    ingest_line(err, model, acquire_b);
    if(reverse_release)
    {
        ingest_line(err, model, release_b_first);
        ingest_line(err, model, release_a_second);
    }
    else
    {
        ingest_line(err, model, release_a_first);
        ingest_line(err, model, release_b_second);
    }
    operation_status = p101_tool_model_finish(err, model);
    EXPECT(operation_status == 0);
    analysis = p101_tool_analysis_create(err, model);
    EXPECT(analysis != NULL);
    operation_status = p101_tool_analysis_run(err, analysis, NULL);
    EXPECT(operation_status == 0);
    found = analysis_has_finding(analysis, "P101-SYNC-004");
    EXPECT(found == expected_finding);
    p101_tool_analysis_destroy(&analysis);
    p101_tool_model_destroy(&model);
    p101_error_destroy(err);
}

static void run_wait_while_held_case(bool join_wait, bool release_before_wait, bool expected_finding)
{
    char                       acquire_lock[]    = "P101RESOURCE\t5\tanalysis-test\t42\t7\t1\t100\t200\tACQUIRE\tpthread-mutex-held\tA\t-\t0\tthread=7\t12\tworker\tworker.c\n";
    char                       release_lock[]    = "P101RESOURCE\t5\tanalysis-test\t42\t7\t2\t110\t210\tRELEASE\tpthread-mutex-held\tA\t-\t0\tthread=7\t13\tworker\tworker.c\n";
    char                       begin_join[]      = "P101RESOURCE\t5\tanalysis-test\t42\t7\t3\t120\t220\tACQUIRE\tpthread-join-wait\t7\t8\t0\tthread=7\t14\tworker\tworker.c\n";
    char                       end_join[]        = "P101RESOURCE\t5\tanalysis-test\t42\t7\t4\t130\t230\tRELEASE\tpthread-join-wait\t7\t8\t0\tthread=7\t15\tworker\tworker.c\n";
    char                       begin_condition[] = "P101RESOURCE\t5\tanalysis-test\t42\t7\t3\t120\t220\tACQUIRE\tpthread-condition-wait\tC\t-\t0\tthread=7\t14\tworker\tworker.c\n";
    char                       end_condition[]   = "P101RESOURCE\t5\tanalysis-test\t42\t7\t4\t130\t230\tRELEASE\tpthread-condition-wait\tC\t-\t0\tthread=7\t15\tworker\tworker.c\n";
    struct p101_error         *err;
    struct p101_tool_model    *model;
    struct p101_tool_analysis *analysis;
    int                        operation_status;
    bool                       found;

    err   = p101_error_create(false);
    model = p101_tool_model_create(err);
    EXPECT(err != NULL);
    EXPECT(model != NULL);
    ingest_line(err, model, acquire_lock);
    if(release_before_wait)
    {
        ingest_line(err, model, release_lock);
    }
    ingest_line(err, model, join_wait ? begin_join : begin_condition);
    ingest_line(err, model, join_wait ? end_join : end_condition);
    operation_status = p101_tool_model_finish(err, model);
    EXPECT(operation_status == 0);
    analysis = p101_tool_analysis_create(err, model);
    EXPECT(analysis != NULL);
    operation_status = p101_tool_analysis_run(err, analysis, NULL);
    EXPECT(operation_status == 0);
    found = analysis_has_finding(analysis, "P101-SYNC-005");
    EXPECT(found == expected_finding);
    p101_tool_analysis_destroy(&analysis);
    p101_tool_model_destroy(&model);
    p101_error_destroy(err);
}

static void run_resource_use_case(bool acquire_first, bool expected_finding)
{
    char                       acquire[] = "P101RESOURCE\t5\tanalysis-test\t42\t7\t1\t100\t200\tACQUIRE\tstream\tS\t-\t0\t-\t12\tworker\tworker.c\n";
    char                       use[]     = "P101RESOURCE\t5\tanalysis-test\t42\t7\t2\t110\t210\tUSE\tstream\tS\t-\t0\t-\t13\tworker\tworker.c\n";
    char                       release[] = "P101RESOURCE\t5\tanalysis-test\t42\t7\t3\t120\t220\tRELEASE\tstream\tS\t-\t0\t-\t14\tworker\tworker.c\n";
    struct p101_error         *err;
    struct p101_tool_model    *model;
    struct p101_tool_analysis *analysis;
    int                        operation_status;
    bool                       found;

    err   = p101_error_create(false);
    model = p101_tool_model_create(err);
    EXPECT(err != NULL);
    EXPECT(model != NULL);
    if(acquire_first)
    {
        ingest_line(err, model, acquire);
    }
    ingest_line(err, model, use);
    if(acquire_first)
    {
        ingest_line(err, model, release);
    }
    operation_status = p101_tool_model_finish(err, model);
    EXPECT(operation_status == 0);
    analysis = p101_tool_analysis_create(err, model);
    EXPECT(analysis != NULL);
    operation_status = p101_tool_analysis_run(err, analysis, NULL);
    EXPECT(operation_status == 0);
    found = analysis_has_finding(analysis, "P101-RESOURCE-007");
    EXPECT(found == expected_finding);
    p101_tool_analysis_destroy(&analysis);
    p101_tool_model_destroy(&model);
    p101_error_destroy(err);
}

static void run_process_completion_case(bool release_process, bool expected_finding)
{
    char                       acquire[] = "P101RESOURCE\t5\tanalysis-test\t42\t7\t1\t100\t200\tACQUIRE\tchild-process\t808\t-\t0\t-\t12\tworker\tworker.c\n";
    char                       release[] = "P101RESOURCE\t5\tanalysis-test\t42\t7\t2\t110\t210\tRELEASE\tchild-process\t808\t-\t0\t-\t13\tworker\tworker.c\n";
    struct p101_error         *err;
    struct p101_tool_model    *model;
    struct p101_tool_analysis *analysis;
    int                        operation_status;
    bool                       found;

    err   = p101_error_create(false);
    model = p101_tool_model_create(err);
    EXPECT(err != NULL);
    EXPECT(model != NULL);
    ingest_line(err, model, acquire);
    if(release_process)
    {
        ingest_line(err, model, release);
    }
    operation_status = p101_tool_model_finish(err, model);
    EXPECT(operation_status == 0);
    analysis = p101_tool_analysis_create(err, model);
    EXPECT(analysis != NULL);
    operation_status = p101_tool_analysis_run(err, analysis, NULL);
    EXPECT(operation_status == 0);
    found = analysis_has_finding(analysis, "P101-PROC-001");
    EXPECT(found == expected_finding);
    p101_tool_analysis_destroy(&analysis);
    p101_tool_model_destroy(&model);
    p101_error_destroy(err);
}

static void run_extended_semantic_cases(void)
{
    char                       mutex_acquire[]      = "P101RESOURCE\t5\tanalysis-test\t42\t7\t1\t100\t200\tACQUIRE\tpthread-mutex\tM\t-\t0\tthread=7\t12\tworker\tworker.c\n";
    char                       held_acquire[]       = "P101RESOURCE\t5\tanalysis-test\t42\t7\t2\t110\t210\tACQUIRE\tpthread-mutex-held\tM@thread=7\t-\t0\tthread=7\t13\tworker\tworker.c\n";
    char                       mutex_destroy[]      = "P101RESOURCE\t5\tanalysis-test\t42\t7\t3\t120\t220\tRELEASE\tpthread-mutex\tM\t-\t0\tthread=7\t14\tworker\tworker.c\n";
    char                       held_release[]       = "P101RESOURCE\t5\tanalysis-test\t42\t7\t4\t130\t230\tRELEASE\tpthread-mutex-held\tM@thread=7\t-\t0\tthread=7\t15\tworker\tworker.c\n";
    char                       joinable_acquire[]   = "P101RESOURCE\t5\tanalysis-test\t42\t7\t5\t140\t240\tACQUIRE\tpthread-joinable-thread\tT\t-\t0\t-\t16\tworker\tworker.c\n";
    char                       terminal_attempt[]   = "P101RESOURCE\t5\tanalysis-test\t42\t7\t6\t150\t250\tUSE\tpthread-terminal-attempt\tT\t-\t0\t-\t17\tworker\tworker.c\n";
    char                       joinable_release[]   = "P101RESOURCE\t5\tanalysis-test\t42\t7\t7\t160\t260\tRELEASE\tpthread-joinable-thread\tT\t-\t0\t-\t18\tworker\tworker.c\n";
    char                       terminal_again[]     = "P101RESOURCE\t5\tanalysis-test\t42\t7\t8\t170\t270\tUSE\tpthread-terminal-attempt\tT\t-\t0\t-\t19\tworker\tworker.c\n";
    char                       condition_a[]        = "P101RESOURCE\t5\tanalysis-test\t42\t7\t9\t180\t280\tACQUIRE\tpthread-condition-wait\tC@thread=7\tA\t0\tthread=7\t20\tworker\tworker.c\n";
    char                       condition_b[]        = "P101RESOURCE\t5\tanalysis-test\t42\t8\t10\t190\t290\tACQUIRE\tpthread-condition-wait\tC@thread=8\tB\t0\tthread=8\t21\tworker\tworker.c\n";
    char                       blocking_lock[]      = "P101RESOURCE\t5\tanalysis-test\t42\t7\t11\t200\t300\tACQUIRE\tpthread-mutex-held\tL@thread=7\t-\t0\tthread=7\t22\tworker\tworker.c\n";
    char                       blocking_operation[] = "P101RESOURCE\t5\tanalysis-test\t42\t7\t12\t210\t310\tUSE\tblocking-operation\tread\t-\t0\t-\t23\tworker\tworker.c\n";
    char                       zero_allocation[]    = "P101ALLOC\t5\tanalysis-test\t42\t7\t13\t220\t320\tALLOC\t0x1\t-\t0\t24\tworker\tworker.c\n";
    char                       allocation_release[] = "P101ALLOC\t5\tanalysis-test\t42\t7\t14\t230\t330\tFREE\t0x1\t-\t0\t25\tworker\tworker.c\n";
    struct p101_error         *err;
    struct p101_tool_model    *model;
    struct p101_tool_analysis *analysis;
    int                        operation_status;

    err   = p101_error_create(false);
    model = p101_tool_model_create(err);
    EXPECT(err != NULL);
    EXPECT(model != NULL);
    ingest_line(err, model, mutex_acquire);
    ingest_line(err, model, held_acquire);
    ingest_line(err, model, mutex_destroy);
    ingest_line(err, model, held_release);
    ingest_line(err, model, joinable_acquire);
    ingest_line(err, model, terminal_attempt);
    ingest_line(err, model, joinable_release);
    ingest_line(err, model, terminal_again);
    ingest_line(err, model, condition_a);
    ingest_line(err, model, condition_b);
    ingest_line(err, model, blocking_lock);
    ingest_line(err, model, blocking_operation);
    ingest_line(err, model, zero_allocation);
    ingest_line(err, model, allocation_release);
    operation_status = p101_tool_model_finish(err, model);
    EXPECT(operation_status == 0);
    analysis = p101_tool_analysis_create(err, model);
    EXPECT(analysis != NULL);
    operation_status = p101_tool_analysis_run(err, analysis, NULL);
    EXPECT(operation_status == 0);
    EXPECT(analysis_has_finding(analysis, "P101-SYNC-007"));
    EXPECT(analysis_has_finding(analysis, "P101-SYNC-008"));
    EXPECT(analysis_has_finding(analysis, "P101-SYNC-009"));
    EXPECT(analysis_has_finding(analysis, "P101-SYNC-010"));
    EXPECT(analysis_has_finding(analysis, "P101-MEM-001"));
    p101_tool_analysis_destroy(&analysis);
    p101_tool_model_destroy(&model);
    p101_error_destroy(err);
}

static void run_clean_extended_semantic_cases(void)
{
    char                       mutex_acquire[]      = "P101RESOURCE\t5\tanalysis-clean\t42\t7\t1\t100\t200\tACQUIRE\tpthread-mutex\tM\t-\t0\tthread=7\t12\tworker\tworker.c\n";
    char                       held_acquire[]       = "P101RESOURCE\t5\tanalysis-clean\t42\t7\t2\t110\t210\tACQUIRE\tpthread-mutex-held\tM@thread=7\t-\t0\tthread=7\t13\tworker\tworker.c\n";
    char                       held_release[]       = "P101RESOURCE\t5\tanalysis-clean\t42\t7\t3\t120\t220\tRELEASE\tpthread-mutex-held\tM@thread=7\t-\t0\tthread=7\t14\tworker\tworker.c\n";
    char                       mutex_destroy[]      = "P101RESOURCE\t5\tanalysis-clean\t42\t7\t4\t130\t230\tRELEASE\tpthread-mutex\tM\t-\t0\tthread=7\t15\tworker\tworker.c\n";
    char                       joinable_acquire[]   = "P101RESOURCE\t5\tanalysis-clean\t42\t7\t5\t140\t240\tACQUIRE\tpthread-joinable-thread\tT\t-\t0\t-\t16\tworker\tworker.c\n";
    char                       terminal_attempt[]   = "P101RESOURCE\t5\tanalysis-clean\t42\t7\t6\t150\t250\tUSE\tpthread-terminal-attempt\tT\t-\t0\t-\t17\tworker\tworker.c\n";
    char                       joinable_release[]   = "P101RESOURCE\t5\tanalysis-clean\t42\t7\t7\t160\t260\tRELEASE\tpthread-joinable-thread\tT\t-\t0\t-\t18\tworker\tworker.c\n";
    char                       condition_a_begin[]  = "P101RESOURCE\t5\tanalysis-clean\t42\t7\t8\t170\t270\tACQUIRE\tpthread-condition-wait\tC@thread=7\tA\t0\tthread=7\t19\tworker\tworker.c\n";
    char                       condition_a_end[]    = "P101RESOURCE\t5\tanalysis-clean\t42\t7\t9\t180\t280\tRELEASE\tpthread-condition-wait\tC@thread=7\tA\t0\tthread=7\t20\tworker\tworker.c\n";
    char                       condition_b_begin[]  = "P101RESOURCE\t5\tanalysis-clean\t42\t8\t10\t190\t290\tACQUIRE\tpthread-condition-wait\tC@thread=8\tB\t0\tthread=8\t21\tworker\tworker.c\n";
    char                       condition_b_end[]    = "P101RESOURCE\t5\tanalysis-clean\t42\t8\t11\t200\t300\tRELEASE\tpthread-condition-wait\tC@thread=8\tB\t0\tthread=8\t22\tworker\tworker.c\n";
    char                       blocking_operation[] = "P101RESOURCE\t5\tanalysis-clean\t42\t7\t12\t210\t310\tUSE\tblocking-operation\tread\t-\t0\t-\t23\tworker\tworker.c\n";
    char                       allocation[]         = "P101ALLOC\t5\tanalysis-clean\t42\t7\t13\t220\t320\tALLOC\t0x1\t-\t1\t24\tworker\tworker.c\n";
    char                       allocation_release[] = "P101ALLOC\t5\tanalysis-clean\t42\t7\t14\t230\t330\tFREE\t0x1\t-\t0\t25\tworker\tworker.c\n";
    struct p101_error         *err;
    struct p101_tool_model    *model;
    struct p101_tool_analysis *analysis;
    int                        operation_status;

    err   = p101_error_create(false);
    model = p101_tool_model_create(err);
    EXPECT(err != NULL);
    EXPECT(model != NULL);
    ingest_line(err, model, mutex_acquire);
    ingest_line(err, model, held_acquire);
    ingest_line(err, model, held_release);
    ingest_line(err, model, mutex_destroy);
    ingest_line(err, model, joinable_acquire);
    ingest_line(err, model, terminal_attempt);
    ingest_line(err, model, joinable_release);
    ingest_line(err, model, condition_a_begin);
    ingest_line(err, model, condition_a_end);
    ingest_line(err, model, condition_b_begin);
    ingest_line(err, model, condition_b_end);
    ingest_line(err, model, blocking_operation);
    ingest_line(err, model, allocation);
    ingest_line(err, model, allocation_release);
    operation_status = p101_tool_model_finish(err, model);
    EXPECT(operation_status == 0);
    analysis = p101_tool_analysis_create(err, model);
    EXPECT(analysis != NULL);
    operation_status = p101_tool_analysis_run(err, analysis, NULL);
    EXPECT(operation_status == 0);
    EXPECT(!analysis_has_finding(analysis, "P101-SYNC-007"));
    EXPECT(!analysis_has_finding(analysis, "P101-SYNC-008"));
    EXPECT(!analysis_has_finding(analysis, "P101-SYNC-009"));
    EXPECT(!analysis_has_finding(analysis, "P101-SYNC-010"));
    EXPECT(!analysis_has_finding(analysis, "P101-MEM-001"));
    p101_tool_analysis_destroy(&analysis);
    p101_tool_model_destroy(&model);
    p101_error_destroy(err);
}

int main(void)
{
    run_release_order_case(true, false);
    run_release_order_case(false, true);
    run_wait_while_held_case(true, true, false);
    run_wait_while_held_case(true, false, true);
    run_wait_while_held_case(false, false, false);
    run_resource_use_case(true, false);
    run_resource_use_case(false, true);
    run_process_completion_case(true, false);
    run_process_completion_case(false, true);
    run_extended_semantic_cases();
    run_clean_extended_semantic_cases();
    return failures == 0 ? 0 : 1;
}
