#include <p101_tool_event/report.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define CHECK(condition)                                                                                                                                                                                                                                           \
    do                                                                                                                                                                                                                                                             \
    {                                                                                                                                                                                                                                                              \
        if(!(condition))                                                                                                                                                                                                                                           \
        {                                                                                                                                                                                                                                                          \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #condition);                                                                                                                                                                                   \
            return EXIT_FAILURE;                                                                                                                                                                                                                                   \
        }                                                                                                                                                                                                                                                          \
    } while(0)

static int read_stream(FILE *stream, char *output, size_t output_size)
{
    int    error_state;
    int    result;
    size_t bytes;

    rewind(stream);
    bytes       = fread(output, 1U, output_size - 1U, stream);
    error_state = ferror(stream);
    if(error_state != 0)
    {
        result = -1;
    }
    else
    {
        output[bytes] = '\0';
        result        = 0;
    }
    return result;
}

int main(void)
{
    struct p101_tool_diagnostic           diagnostic;
    const struct p101_tool_report_counter counters[] = {
        {"files_scanned", 3U},
        {"checks",        7U}
    };
    const struct p101_tool_report_counter duplicate_counters[] = {
        {"checks", 1U},
        {"checks", 2U}
    };
    const struct p101_tool_report_options options = {"audit-test", "Clang facts", "Unscanned code is outside this report.", P101_TOOL_DIAGNOSTIC_OUTPUT_HUMAN | P101_TOOL_DIAGNOSTIC_OUTPUT_JSON, true};
    struct p101_tool_report               report;
    unsigned int                          outputs;
    char                                  output[4096];
    FILE                                 *human_stream;
    FILE                                 *json_stream;
    int                                   status;
    const char                           *match;

    status = p101_tool_diagnostic_initialize(&diagnostic, P101_TOOL_FINDING_WRAP_001, P101_TOOL_DIAGNOSTIC_WARNING, "src/main.c", 9U, 2U, "main", "a useful message");
    CHECK(status == 0);
    outputs = 0U;
    status  = p101_tool_report_parse_output_option("-d:human,json", &outputs);
    CHECK(status == 0);
    CHECK(outputs == (P101_TOOL_DIAGNOSTIC_OUTPUT_HUMAN | P101_TOOL_DIAGNOSTIC_OUTPUT_JSON));
    status = p101_tool_report_parse_output_option("-j", &outputs);
    CHECK(status == -1);

    human_stream = tmpfile();
    json_stream  = tmpfile();
    CHECK(human_stream != NULL);
    CHECK(json_stream != NULL);
    status = p101_tool_report_begin(&report, json_stream, human_stream, &options);
    CHECK(status == 0);
    status = p101_tool_report_emit(&report, &diagnostic);
    CHECK(status == 0);
    status = p101_tool_report_end(&report, P101_TOOL_OUTCOME_FINDINGS, 1, duplicate_counters, sizeof(duplicate_counters) / sizeof(duplicate_counters[0]));
    CHECK(status == -1);
    status = p101_tool_report_end(&report, P101_TOOL_OUTCOME_FINDINGS, 256, counters, sizeof(counters) / sizeof(counters[0]));
    CHECK(status == -1);
    status = p101_tool_report_end(&report, P101_TOOL_OUTCOME_FINDINGS, 1, counters, sizeof(counters) / sizeof(counters[0]));
    CHECK(status == 0);

    status = read_stream(human_stream, output, sizeof(output));
    CHECK(status == 0);
    match = strstr(output, "report: tool=\"audit-test\" admitted_inputs=\"Clang facts\"");
    CHECK(match != NULL);
    match = strstr(output, "report: does_not_prove=\"Unscanned code is outside this report.\"");
    CHECK(match != NULL);
    match = strstr(output, "src/main.c:9:2: warning: a useful message [P101-WRAP-001]");
    CHECK(match != NULL);
    match = strstr(output, "audit-test: outcome=findings exit_status=1 findings=1 files_scanned=3 checks=7");
    CHECK(match != NULL);

    status = read_stream(json_stream, output, sizeof(output));
    CHECK(status == 0);
    match = strstr(output, "\"schema\":\"p101-tool-report-v1\"");
    CHECK(match != NULL);
    match = strstr(output, "\"tool\":\"audit-test\"");
    CHECK(match != NULL);
    match = strstr(output, "\"admitted_inputs\":\"Clang facts\"");
    CHECK(match != NULL);
    match = strstr(output, "\"does_not_prove\":\"Unscanned code is outside this report.\"");
    CHECK(match != NULL);
    match = strstr(output, "\"message\":\"a useful message\"");
    CHECK(match != NULL);
    match = strstr(output, "\"summary\":{\"findings\":1,\"files_scanned\":3,\"checks\":7}");
    CHECK(match != NULL);
    match = strstr(output, "\"outcome\":\"findings\",\"exit_status\":1");
    CHECK(match != NULL);

    status = fclose(human_stream);
    CHECK(status == 0);
    status = fclose(json_stream);
    CHECK(status == 0);
    return EXIT_SUCCESS;
}
