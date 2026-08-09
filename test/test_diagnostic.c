#include <p101_tool_event/diagnostic.h>
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

#define CHECK_ZERO(expression)                                                                                                                                                                                                                                     \
    do                                                                                                                                                                                                                                                             \
    {                                                                                                                                                                                                                                                              \
        int check_result_;                                                                                                                                                                                                                                         \
        check_result_ = (expression);                                                                                                                                                                                                                              \
        CHECK(check_result_ == 0);                                                                                                                                                                                                                                 \
    } while(0)

#define CHECK_MINUS_ONE(expression)                                                                                                                                                                                                                                \
    do                                                                                                                                                                                                                                                             \
    {                                                                                                                                                                                                                                                              \
        int check_result_;                                                                                                                                                                                                                                         \
        check_result_ = (expression);                                                                                                                                                                                                                              \
        CHECK(check_result_ == -1);                                                                                                                                                                                                                                \
    } while(0)

#define CHECK_CONTAINS(haystack, needle)                                                                                                                                                                                                                           \
    do                                                                                                                                                                                                                                                             \
    {                                                                                                                                                                                                                                                              \
        const char *check_match_;                                                                                                                                                                                                                                  \
        check_match_ = strstr((haystack), (needle));                                                                                                                                                                                                               \
        CHECK(check_match_ != NULL);                                                                                                                                                                                                                               \
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
    const struct p101_tool_rule_definition *rule;
    struct p101_tool_diagnostic             diagnostic;
    char                                    output[2048];
    unsigned int                            outputs;
    FILE                                   *stream;
    FILE                                   *json_stream;

    rule = p101_tool_rule_definition_lookup(P101_TOOL_FINDING_WRAP_001);
    CHECK(rule != NULL);
    CHECK(strcmp(rule->id, "P101-WRAP-001") == 0);
    CHECK(strcmp(rule->lesson_id, "P101-LESSON-WRAPPER-BOUNDARIES") == 0);
    CHECK(strcmp(rule->lesson_path, "lessons/wrapper-boundaries.md") == 0);
    CHECK(strcmp(rule->lesson_url, "https://github.com/programming101dev/playgrounds/blob/main/lessons/wrapper-boundaries.md") == 0);
    CHECK(p101_tool_rule_definition_lookup(P101_TOOL_FINDING_COUNT) == NULL);
    CHECK_ZERO(p101_tool_diagnostic_initialize(&diagnostic, P101_TOOL_FINDING_WRAP_001, P101_TOOL_DIAGNOSTIC_ERROR, "src/main.c", 12U, 7U, "run", "raw call\nneeds a wrapper"));
    CHECK_MINUS_ONE(p101_tool_diagnostic_initialize(&diagnostic, P101_TOOL_FINDING_WRAP_001, (p101_tool_diagnostic_severity)99, "src/main.c", 12U, 7U, "run", "message"));

    stream = tmpfile();
    CHECK(stream != NULL);
    CHECK_ZERO(p101_tool_diagnostic_write(stream, P101_TOOL_DIAGNOSTIC_TEXT, &diagnostic));
    CHECK_ZERO(read_stream(stream, output, sizeof(output)));
    CHECK_CONTAINS(output, "src/main.c:12:7: error: raw call\\nneeds a wrapper [P101-WRAP-001] (function run)\n");
    CHECK_CONTAINS(output, "src/main.c:12:7: note: learn more: P101-LESSON-WRAPPER-BOUNDARIES");
    CHECK_CONTAINS(output, "playgrounds/blob/main/lessons/wrapper-boundaries.md");
    CHECK_ZERO(fclose(stream));

    stream = tmpfile();
    CHECK(stream != NULL);
    CHECK_ZERO(p101_tool_diagnostic_write(stream, P101_TOOL_DIAGNOSTIC_JSON, &diagnostic));
    CHECK_ZERO(read_stream(stream, output, sizeof(output)));
    CHECK_CONTAINS(output, "\"schema\":\"p101-tool-diagnostic-v1\"");
    CHECK_CONTAINS(output, "\"id\":\"P101-WRAP-001\"");
    CHECK_CONTAINS(output, "\"message\":\"raw call\\nneeds a wrapper\"");
    CHECK_CONTAINS(output, "\"lesson\":{\"id\":\"P101-LESSON-WRAPPER-BOUNDARIES\"");
    CHECK_ZERO(fclose(stream));

    outputs = 0U;
    CHECK_ZERO(p101_tool_diagnostic_parse_outputs("human", &outputs));
    CHECK(outputs == P101_TOOL_DIAGNOSTIC_OUTPUT_HUMAN);
    CHECK_ZERO(p101_tool_diagnostic_parse_outputs("json", &outputs));
    CHECK(outputs == P101_TOOL_DIAGNOSTIC_OUTPUT_JSON);
    CHECK_ZERO(p101_tool_diagnostic_parse_outputs("human,json", &outputs));
    CHECK(outputs == (P101_TOOL_DIAGNOSTIC_OUTPUT_HUMAN | P101_TOOL_DIAGNOSTIC_OUTPUT_JSON));
    CHECK_MINUS_ONE(p101_tool_diagnostic_parse_outputs("xml", &outputs));

    stream      = tmpfile();
    json_stream = tmpfile();
    CHECK(stream != NULL);
    CHECK(json_stream != NULL);
    CHECK_ZERO(p101_tool_diagnostic_write_outputs(stream, json_stream, &diagnostic));
    CHECK_ZERO(read_stream(stream, output, sizeof(output)));
    CHECK_CONTAINS(output, "error: raw call\\nneeds a wrapper");
    CHECK_ZERO(read_stream(json_stream, output, sizeof(output)));
    CHECK_CONTAINS(output, "\"message\":\"raw call\\nneeds a wrapper\"");
    CHECK_ZERO(fclose(stream));
    CHECK_ZERO(fclose(json_stream));

    CHECK_MINUS_ONE(p101_tool_diagnostic_write(NULL, P101_TOOL_DIAGNOSTIC_TEXT, &diagnostic));
    CHECK_MINUS_ONE(p101_tool_diagnostic_write_outputs(NULL, NULL, &diagnostic));
    return EXIT_SUCCESS;
}
