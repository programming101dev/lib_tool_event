#ifndef P101_TOOL_EVENT_ANALYSIS_H
#define P101_TOOL_EVENT_ANALYSIS_H

#include <p101_tool_event/model.h>
#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C"
{
#endif

    typedef enum
    {
        P101_TOOL_ANALYSIS_RESOURCE = 0,
        P101_TOOL_ANALYSIS_SYNCHRONIZATION,
        P101_TOOL_ANALYSIS_TRACE,
        P101_TOOL_ANALYSIS_SANITIZER
    } p101_tool_analysis_policy;

    struct p101_tool_analysis_finding
    {
        const char               *diagnostic_id;
        p101_tool_analysis_policy policy;
        const char               *message;
        const char               *node_id;
        const char               *file_name;
        const char               *function_name;
        int                       line_number;
        const char               *evidence_from;
        const char               *evidence_to;
        const char               *evidence_detail;
    };

    struct p101_tool_analysis;

    struct p101_tool_analysis               *p101_tool_analysis_create(struct p101_error *err, const struct p101_tool_model *model);
    void                                     p101_tool_analysis_destroy(struct p101_tool_analysis **analysis);
    int                                      p101_tool_analysis_run(struct p101_error *err, struct p101_tool_analysis *analysis, const char *sanitizer_path);
    size_t                                   p101_tool_analysis_finding_count(const struct p101_tool_analysis *analysis);
    const struct p101_tool_analysis_finding *p101_tool_analysis_finding_at(const struct p101_tool_analysis *analysis, size_t index);
    size_t                                   p101_tool_analysis_policy_finding_count(const struct p101_tool_analysis *analysis, p101_tool_analysis_policy policy);
    int                                      p101_tool_analysis_status(const struct p101_tool_analysis *analysis);
    int                                      p101_tool_analysis_policy_status(const struct p101_tool_analysis *analysis, p101_tool_analysis_policy policy);
    int                                      p101_tool_analysis_write_bundle(struct p101_error *err, const struct p101_tool_analysis *analysis, const char *output_directory);
    int                                      p101_tool_analysis_write_interleaving(struct p101_error *err, const struct p101_tool_analysis *analysis, FILE *stream, size_t schedule_limit, size_t *counterexample_count);

#ifdef __cplusplus
}
#endif

#endif
