#include <p101_tool_event/summary.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int failures;

#define EXPECT(condition)                                                                                                                                                                                                                                          \
    do                                                                                                                                                                                                                                                             \
    {                                                                                                                                                                                                                                                              \
        if(!(condition))                                                                                                                                                                                                                                           \
        {                                                                                                                                                                                                                                                          \
            (void)fprintf(stderr, "failure at line %d: %s\n", __LINE__, #condition);                                                                                                                                                                               \
            failures++;                                                                                                                                                                                                                                            \
        }                                                                                                                                                                                                                                                          \
    } while(0)

static const char valid_summary[] = "{\"schema\":\"p101-resource-tracker-findings-v3\",\"records\":1,\"fd_leaks\":2,\"allocation_leaks\":3,\"bad_releases\":4,\"exec_inheritances\":5,\"generic_resource_leaks\":6,\"generic_bad_releases\":7,"
                                    "\"malformed\":8,\"bad_version\":9,\"refused\":10,\"log_health\":{\"complete\":true}}";

static void replace_once(char *output, size_t output_size, const char *source, const char *needle, const char *replacement)
{
    const char *match;
    size_t      prefix;

    match = strstr(source, needle);
    EXPECT(match != NULL);
    prefix = (size_t)(match - source);
    (void)snprintf(output, output_size, "%.*s%s%s", (int)prefix, source, replacement, match + strlen(needle));
}

static void test_valid_summary_and_count(void)
{
    struct p101_tool_event_resource_summary summary;
    char                                    text[2048];

    EXPECT(p101_tool_event_parse_resource_summary_json(valid_summary, &summary));
    EXPECT(summary.records == 1U);
    EXPECT(summary.fd_leaks == 2U);
    EXPECT(summary.allocation_leaks == 3U);
    EXPECT(summary.bad_releases == 4U);
    EXPECT(summary.exec_inheritances == 5U);
    EXPECT(summary.generic_resource_leaks == 6U);
    EXPECT(summary.generic_bad_releases == 7U);
    EXPECT(summary.malformed == 8U);
    EXPECT(summary.bad_version == 9U);
    EXPECT(summary.refused == 10U);
    EXPECT(summary.log_complete);
    EXPECT(p101_tool_event_resource_summary_finding_count(&summary) == 54U);
    summary.log_complete = false;
    EXPECT(p101_tool_event_resource_summary_finding_count(&summary) == 55U);
    summary.parsed = false;
    EXPECT(p101_tool_event_resource_summary_finding_count(&summary) == 0U);
    EXPECT(p101_tool_event_resource_summary_finding_count(NULL) == 0U);

    replace_once(text, sizeof(text), valid_summary, "\"complete\":true", "\"complete\":false,\"other\":[1,true,false,null,\"x\",{\"a\":-1.5e+2}]");
    EXPECT(p101_tool_event_parse_resource_summary_json(text, &summary));
    EXPECT(!summary.log_complete);

    (void)snprintf(text, sizeof(text), " \n\t%s\r ", valid_summary);
    EXPECT(p101_tool_event_parse_resource_summary_json(text, &summary));
}

static void test_json_size(void)
{
    char   long_key[128];
    size_t value;

    EXPECT(p101_tool_event_parse_json_size("{\"a\":1}", "a", &value) && value == 1U);
    EXPECT(p101_tool_event_parse_json_size("{\"x\":{\"a\":9},\"a\":2}", "\"a\"", &value) && value == 2U);
    EXPECT(p101_tool_event_parse_json_size("{\"x\":[],\"a\":3}", "a", &value) && value == 3U);
    EXPECT(!p101_tool_event_parse_json_size(NULL, "a", &value));
    EXPECT(!p101_tool_event_parse_json_size("{}", NULL, &value));
    EXPECT(!p101_tool_event_parse_json_size("{}", "a", NULL));
    EXPECT(!p101_tool_event_parse_json_size("{}", "", &value));
    memset(long_key, 'a', sizeof(long_key) - 1U);
    long_key[sizeof(long_key) - 1U] = '\0';
    EXPECT(!p101_tool_event_parse_json_size("{}", long_key, &value));
    EXPECT(!p101_tool_event_parse_json_size("[]", "a", &value));
    EXPECT(!p101_tool_event_parse_json_size("{\"a\":1,\"a\":2}", "a", &value));
    EXPECT(!p101_tool_event_parse_json_size("{\"a\":\"x\"}", "a", &value));
    EXPECT(!p101_tool_event_parse_json_size("{\"a\":1}trailing", "a", &value));
    EXPECT(!p101_tool_event_parse_json_size("{\"b\":?}", "a", &value));
    EXPECT(!p101_tool_event_parse_json_size("{bad:1}", "a", &value));
    EXPECT(!p101_tool_event_parse_json_size("{\"b\" 1}", "a", &value));
    EXPECT(!p101_tool_event_parse_json_size("{\"b\":1 \"a\":2}", "a", &value));
    EXPECT(!p101_tool_event_parse_json_size("{\"a\":184467440737095516160}", "a", &value));
    EXPECT(!p101_tool_event_parse_json_size("{\"b\":1}", "a", &value));
    EXPECT(!p101_tool_event_parse_json_size("{\"unterminated", "a", &value));
    EXPECT(!p101_tool_event_parse_json_size("{}", "\"\"", &value));
    EXPECT(!p101_tool_event_parse_json_size("{}", "\"a", &value));
    EXPECT(!p101_tool_event_parse_json_size("{}", "aa", &value));
}

static void test_recognized_field_failures(void)
{
    static const char *const fields[] = {
        "\"records\":1",
        "\"fd_leaks\":2",
        "\"allocation_leaks\":3",
        "\"bad_releases\":4",
        "\"exec_inheritances\":5",
        "\"generic_resource_leaks\":6",
        "\"generic_bad_releases\":7",
        "\"malformed\":8",
        "\"bad_version\":9",
        "\"refused\":10",
    };
    char text[4096];

    for(size_t index = 0U; index < sizeof(fields) / sizeof(fields[0]); index++)
    {
        char  invalid[160];
        char  duplicate[320];
        char  key[128];
        char *colon;

        (void)snprintf(invalid, sizeof(invalid), "%s", fields[index]);
        colon  = strchr(invalid, ':');
        *colon = '\0';
        (void)snprintf(key, sizeof(key), "%s", invalid);
        (void)snprintf(invalid, sizeof(invalid), "%s:\"bad\"", key);
        replace_once(text, sizeof(text), valid_summary, fields[index], invalid);
        {
            struct p101_tool_event_resource_summary summary;

            EXPECT(!p101_tool_event_parse_resource_summary_json(text, &summary));
        }

        (void)snprintf(duplicate, sizeof(duplicate), "%s,%s", fields[index], fields[index]);
        replace_once(text, sizeof(text), valid_summary, fields[index], duplicate);
        {
            struct p101_tool_event_resource_summary summary;

            EXPECT(!p101_tool_event_parse_resource_summary_json(text, &summary));
        }
    }
}

static void test_summary_structure_failures(void)
{
    static const char *const invalid[] = {
        "",
        "[]",
        "{",
        "{\"schema\"}",
        "{\"schema\":}",
        "{\"schema\":\"p101-resource-tracker-findings-v3\" trailing}",
        "{\"schema\":\"wrong\",\"records\":1,\"fd_leaks\":2,\"allocation_leaks\":3,\"bad_releases\":4,\"exec_inheritances\":5,\"generic_resource_leaks\":6,\"generic_bad_releases\":7,\"malformed\":8,\"bad_version\":9,\"refused\":10,\"log_health\":{\"complete\":true}}",
        "{\"schema\":\"p101-resource-tracker-findings-v3\",\"schema\":\"p101-resource-tracker-findings-v3\"}",
        "{\"schema\":7}",
        "{\"unknown\":?}",
        "{\"log_health\":false}",
        "{\"log_health\":{}}",
        "{\"log_health\":{\"complete\":maybe}}",
        "{\"log_health\":{\"complete\":true,\"complete\":false}}",
        "{\"log_health\":{\"x\":?}}",
        "{\"log_health\":{\"x\":1 \"complete\":true}}",
        "{\"log_health\":{\"bad key\" 1}}",
        "{\"log_health\":{bad:1}}",
        "{\"log_health\":{\"complete\":true},\"log_health\":{\"complete\":true}}",
    };
    struct p101_tool_event_resource_summary summary;

    EXPECT(!p101_tool_event_parse_resource_summary_json(NULL, &summary));
    EXPECT(!p101_tool_event_parse_resource_summary_json("{}", NULL));
    for(size_t index = 0U; index < sizeof(invalid) / sizeof(invalid[0]); index++)
    {
        EXPECT(!p101_tool_event_parse_resource_summary_json(invalid[index], &summary));
    }
}

static void test_unknown_json_values(void)
{
    static const char *const valid_values[] = {
        "\"text\"",
        "\"quote:\\\" slash:\\/ backslash:\\\\ tab:\\t unicode:\\u00Af\"",
        "{}",
        "{\"nested\":[0,1]}",
        "[]",
        "[0,-1,2.5,3e4,4E-2,true,false,null]",
        "0",
        "-1",
        "12.5",
        "1e+2",
        "true",
        "false",
        "null",
    };
    static const char *const invalid_values[] = {
        "\"unterminated",
        "\"bad\\x\"",
        "\"bad\\u0xx0\"",
        "\"\001\"",
        "01",
        "0/",
        "0:",
        "-?",
        "-",
        "1.",
        "1.a",
        "1e",
        "1e?",
        "[1 2]",
        "[?]",
        "{\"a\" 1}",
        "{\"a\":?}",
        "{\"a\":1 \"b\":2}",
        "{\"a\":1,bad:2}",
        "{\"a\":1,\"b\" 2}",
        "\"unterminated",
        "\"bad\\uG000\"",
        "\"bad\\u0G00\"",
        "\"bad\\u00G0\"",
        "\"bad\\u000G\"",
        "\"bad\\u/000\"",
        "\"bad\\u:000\"",
        "\"bad\\u`000\"",
        "\"bad\\ug000\"",
        "\"bad\\u@000\"",
    };
    struct p101_tool_event_resource_summary summary;
    char                                    text[4096];

    for(size_t index = 0U; index < sizeof(valid_values) / sizeof(valid_values[0]); index++)
    {
        (void)snprintf(text, sizeof(text), "{\"unknown\":%s,%s", valid_values[index], valid_summary + 1);
        EXPECT(p101_tool_event_parse_resource_summary_json(text, &summary));
    }

    (void)snprintf(text, sizeof(text), "%sx", valid_summary);
    EXPECT(!p101_tool_event_parse_resource_summary_json(text, &summary));
    for(size_t index = 0U; index < sizeof(invalid_values) / sizeof(invalid_values[0]); index++)
    {
        (void)snprintf(text, sizeof(text), "{\"unknown\":%s,%s", invalid_values[index], valid_summary + 1);
        EXPECT(!p101_tool_event_parse_resource_summary_json(text, &summary));
    }

    replace_once(text, sizeof(text), valid_summary, "\"records\":1", "\"records\"::");
    EXPECT(!p101_tool_event_parse_resource_summary_json(text, &summary));

    (void)snprintf(text, sizeof(text), "{\"%096d\":1,%s", 0, valid_summary + 1);
    EXPECT(!p101_tool_event_parse_resource_summary_json(text, &summary));
}

static void test_depth_limit(void)
{
    struct p101_tool_event_resource_summary summary;
    char                                    text[4096];
    size_t                                  used;

    used = (size_t)snprintf(text, sizeof(text), "{\"unknown\":");
    for(size_t index = 0U; index < 66U; index++)
    {
        text[used++] = '[';
    }
    text[used++] = '0';
    for(size_t index = 0U; index < 66U; index++)
    {
        text[used++] = ']';
    }
    (void)snprintf(text + used, sizeof(text) - used, ",%s", valid_summary + 1);
    EXPECT(!p101_tool_event_parse_resource_summary_json(text, &summary));
}

int main(void)
{
    test_valid_summary_and_count();
    test_json_size();
    test_recognized_field_failures();
    test_summary_structure_failures();
    test_unknown_json_values();
    test_depth_limit();
    return failures == 0 ? 0 : 1;
}
