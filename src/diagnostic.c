#include <errno.h>
#include <p101_record/record.h>
#include <p101_tool_event/diagnostic.h>
#include <string.h>

static int write_text_field(FILE *stream, const char *text);
static int write_literal(FILE *stream, const char *text);
static int write_json_string(FILE *stream, const char *text);
static int write_json(FILE *stream, const struct p101_tool_diagnostic *diagnostic);
static int write_text(FILE *stream, const struct p101_tool_diagnostic *diagnostic);
static int validate_rule_definition(const struct p101_tool_rule_definition *rule);

const char *p101_tool_diagnostic_severity_name(p101_tool_diagnostic_severity severity)
{
    const char *name;

#ifdef __clang__
    #pragma clang diagnostic push
    #pragma clang diagnostic ignored "-Wcovered-switch-default"
#endif
    switch(severity)
    {
        case P101_TOOL_DIAGNOSTIC_NOTE:
            name = "note";
            break;
        case P101_TOOL_DIAGNOSTIC_WARNING:
            name = "warning";
            break;
        case P101_TOOL_DIAGNOSTIC_ERROR:
            name = "error";
            break;
        default:
            name = "unknown";
            break;
    }
#ifdef __clang__
    #pragma clang diagnostic pop
#endif
    return name;
}

static int validate_rule_definition(const struct p101_tool_rule_definition *rule)
{
    int result;

    if(rule == NULL || rule->id == NULL || rule->id[0] == '\0' || rule->lesson_id == NULL || rule->lesson_id[0] == '\0' || rule->lesson_path == NULL || rule->lesson_path[0] == '\0' || rule->lesson_url == NULL || rule->lesson_url[0] == '\0')
    {
        errno  = EINVAL;
        result = -1;
    }
    else
    {
        result = 0;
    }
    return result;
}

int p101_tool_diagnostic_initialize(struct p101_tool_diagnostic *diagnostic, p101_tool_finding finding, p101_tool_diagnostic_severity severity, const char *path, size_t line, size_t column, const char *function_name, const char *message)
{
    const struct p101_tool_rule_definition *rule;
    const char                             *severity_name;
    int                                     comparison;
    int                                     result;

    if(diagnostic == NULL || message == NULL)
    {
        errno  = EINVAL;
        result = -1;
        goto p101_single_exit_;
    }
    rule   = p101_tool_rule_definition_lookup(finding);
    result = validate_rule_definition(rule);
    if(result != 0)
    {
        goto p101_single_exit_;
    }
    severity_name = p101_tool_diagnostic_severity_name(severity);
    comparison    = strcmp(severity_name, "unknown");
    if(comparison == 0)
    {
        errno  = EINVAL;
        result = -1;
        goto p101_single_exit_;
    }

    diagnostic->id            = rule->id;
    diagnostic->severity      = severity;
    diagnostic->path          = path;
    diagnostic->line          = line;
    diagnostic->column        = column;
    diagnostic->function_name = function_name;
    diagnostic->message       = message;
    diagnostic->lesson_id     = rule->lesson_id;
    diagnostic->lesson_path   = rule->lesson_path;
    diagnostic->lesson_url    = rule->lesson_url;
    result                    = 0;

p101_single_exit_:
    return result;
}

int p101_tool_diagnostic_parse_outputs(const char *specification, unsigned int *outputs)
{
    int human_comparison;
    int json_comparison;
    int human_json_comparison;
    int json_human_comparison;
    int result;

    if(specification == NULL || outputs == NULL)
    {
        errno  = EINVAL;
        result = -1;
        goto p101_single_exit_;
    }

    human_comparison      = strcmp(specification, "human");
    json_comparison       = strcmp(specification, "json");
    human_json_comparison = strcmp(specification, "human,json");
    json_human_comparison = strcmp(specification, "json,human");
    if(human_comparison == 0)
    {
        *outputs = P101_TOOL_DIAGNOSTIC_OUTPUT_HUMAN;
        result   = 0;
    }
    else if(json_comparison == 0)
    {
        *outputs = P101_TOOL_DIAGNOSTIC_OUTPUT_JSON;
        result   = 0;
    }
    else if(human_json_comparison == 0 || json_human_comparison == 0)
    {
        *outputs = P101_TOOL_DIAGNOSTIC_OUTPUT_HUMAN | P101_TOOL_DIAGNOSTIC_OUTPUT_JSON;
        result   = 0;
    }
    else
    {
        errno  = EINVAL;
        result = -1;
    }

p101_single_exit_:
    return result;
}

int p101_tool_diagnostic_write(FILE *stream, p101_tool_diagnostic_format format, const struct p101_tool_diagnostic *diagnostic)
{
    int result;

    if(stream == NULL || diagnostic == NULL || diagnostic->id == NULL || diagnostic->message == NULL)
    {
        errno  = EINVAL;
        result = -1;
        goto p101_single_exit_;
    }

    if(format == P101_TOOL_DIAGNOSTIC_TEXT)
    {
        result = write_text(stream, diagnostic);
    }
    else if(format == P101_TOOL_DIAGNOSTIC_JSON)
    {
        result = write_json(stream, diagnostic);
    }
    else
    {
        errno  = EINVAL;
        result = -1;
    }

p101_single_exit_:
    return result;
}

int p101_tool_diagnostic_write_outputs(FILE *human_stream, FILE *json_stream, const struct p101_tool_diagnostic *diagnostic)
{
    int result;

    if(human_stream == NULL && json_stream == NULL)
    {
        errno  = EINVAL;
        result = -1;
        goto p101_single_exit_;
    }

    result = 0;
    if(human_stream != NULL)
    {
        result = p101_tool_diagnostic_write(human_stream, P101_TOOL_DIAGNOSTIC_TEXT, diagnostic);
        if(result != 0)
        {
            goto p101_single_exit_;
        }
    }
    if(json_stream != NULL)
    {
        result = p101_tool_diagnostic_write(json_stream, P101_TOOL_DIAGNOSTIC_JSON, diagnostic);
    }

p101_single_exit_:
    return result;
}

static int write_text_field(FILE *stream, const char *text)
{
    const unsigned char *cursor;
    int                  result;

    result = 0;
    if(text == NULL)
    {
        goto p101_single_exit_;
    }

    cursor = (const unsigned char *)text;
    while(*cursor != '\0')
    {
        const char *escaped;

        escaped = p101_record_escape_byte(*cursor);
        if(escaped == NULL)
        {
            int write_status;

            write_status = fputc((int)*cursor, stream);
            if(write_status == EOF)
            {
                result = -1;
                goto p101_single_exit_;
            }
        }
        else
        {
            int write_status;

            write_status = fputs(escaped, stream);
            if(write_status == EOF)
            {
                result = -1;
                goto p101_single_exit_;
            }
        }
        cursor++;
    }

p101_single_exit_:
    return result;
}

static int write_literal(FILE *stream, const char *text)
{
    int result;

    result = fputs(text, stream);
    if(result == EOF)
    {
        result = -1;
    }
    else
    {
        result = 0;
    }
    return result;
}

static int write_json_string(FILE *stream, const char *text)
{
    int result;

    result = p101_record_write_json_string(stream, text);
    return result;
}

static int write_text(FILE *stream, const struct p101_tool_diagnostic *diagnostic)
{
    const char *path;
    const char *severity;
    bool        lesson_present;
    int         result;

    path     = diagnostic->path == NULL || diagnostic->path[0] == '\0' ? "<unknown>" : diagnostic->path;
    severity = p101_tool_diagnostic_severity_name(diagnostic->severity);
    result   = write_text_field(stream, path);
    if(result != 0)
    {
        goto p101_single_exit_;
    }
    result = fprintf(stream, ":%zu:%zu: %s: ", diagnostic->line, diagnostic->column, severity);
    if(result < 0)
    {
        result = -1;
        goto p101_single_exit_;
    }
    result = write_text_field(stream, diagnostic->message);
    if(result != 0)
    {
        goto p101_single_exit_;
    }
    result = fprintf(stream, " [%s]", diagnostic->id);
    if(result < 0)
    {
        result = -1;
        goto p101_single_exit_;
    }
    if(diagnostic->function_name != NULL && diagnostic->function_name[0] != '\0')
    {
        result = write_literal(stream, " (function ");
        if(result != 0)
        {
            result = -1;
            goto p101_single_exit_;
        }
        result = write_text_field(stream, diagnostic->function_name);
        if(result != 0)
        {
            goto p101_single_exit_;
        }
        result = fputc(')', stream);
        if(result == EOF)
        {
            result = -1;
            goto p101_single_exit_;
        }
    }
    result = fputc('\n', stream);
    if(result == EOF)
    {
        result = -1;
        goto p101_single_exit_;
    }

    lesson_present = false;
    if(diagnostic->lesson_id != NULL && diagnostic->lesson_id[0] != '\0' && diagnostic->lesson_path != NULL && diagnostic->lesson_path[0] != '\0' && diagnostic->lesson_url != NULL && diagnostic->lesson_url[0] != '\0')
    {
        lesson_present = true;
    }
    if(lesson_present)
    {
        result = write_text_field(stream, path);
        if(result != 0)
        {
            goto p101_single_exit_;
        }
        result = fprintf(stream, ":%zu:%zu: note: learn more: %s (%s) [%s]\n", diagnostic->line, diagnostic->column, diagnostic->lesson_id, diagnostic->lesson_url, diagnostic->id);
        if(result < 0)
        {
            result = -1;
            goto p101_single_exit_;
        }
    }
    result = 0;

p101_single_exit_:
    return result;
}

static int write_json(FILE *stream, const struct p101_tool_diagnostic *diagnostic)
{
    const char *severity;
    const char *path;
    const char *function_name;
    bool        lesson_present;
    int         result;

    severity      = p101_tool_diagnostic_severity_name(diagnostic->severity);
    path          = diagnostic->path == NULL ? "" : diagnostic->path;
    function_name = diagnostic->function_name == NULL ? "" : diagnostic->function_name;
    result        = write_literal(stream, "{\"schema\":\"" P101_TOOL_DIAGNOSTIC_SCHEMA_NAME "\",\"id\":");
    if(result != 0)
    {
        goto p101_single_exit_;
    }
    result = write_json_string(stream, diagnostic->id);
    if(result != 0)
    {
        goto p101_single_exit_;
    }
    result = write_literal(stream, ",\"severity\":");
    if(result != 0)
    {
        goto p101_single_exit_;
    }
    result = write_json_string(stream, severity);
    if(result != 0)
    {
        goto p101_single_exit_;
    }
    result = write_literal(stream, ",\"location\":{\"path\":");
    if(result != 0)
    {
        goto p101_single_exit_;
    }
    result = write_json_string(stream, path);
    if(result != 0)
    {
        goto p101_single_exit_;
    }
    result = fprintf(stream, ",\"line\":%zu,\"column\":%zu,\"function\":", diagnostic->line, diagnostic->column);
    if(result < 0)
    {
        result = -1;
        goto p101_single_exit_;
    }
    result = write_json_string(stream, function_name);
    if(result != 0)
    {
        goto p101_single_exit_;
    }
    result = write_literal(stream, "},\"message\":");
    if(result != 0)
    {
        goto p101_single_exit_;
    }
    result = write_json_string(stream, diagnostic->message);
    if(result != 0)
    {
        goto p101_single_exit_;
    }

    lesson_present = false;
    if(diagnostic->lesson_id != NULL && diagnostic->lesson_id[0] != '\0' && diagnostic->lesson_path != NULL && diagnostic->lesson_path[0] != '\0' && diagnostic->lesson_url != NULL && diagnostic->lesson_url[0] != '\0')
    {
        lesson_present = true;
    }
    if(lesson_present)
    {
        result = write_literal(stream, ",\"lesson\":{\"id\":");
        if(result != 0)
        {
            goto p101_single_exit_;
        }
        result = write_json_string(stream, diagnostic->lesson_id);
        if(result != 0)
        {
            goto p101_single_exit_;
        }
        result = write_literal(stream, ",\"path\":");
        if(result != 0)
        {
            goto p101_single_exit_;
        }
        result = write_json_string(stream, diagnostic->lesson_path);
        if(result != 0)
        {
            goto p101_single_exit_;
        }
        result = write_literal(stream, ",\"url\":");
        if(result != 0)
        {
            goto p101_single_exit_;
        }
        result = write_json_string(stream, diagnostic->lesson_url);
        if(result != 0)
        {
            goto p101_single_exit_;
        }
        result = fputc('}', stream);
        if(result == EOF)
        {
            result = -1;
            goto p101_single_exit_;
        }
    }
    result = fputc('}', stream);
    if(result == EOF)
    {
        result = -1;
        goto p101_single_exit_;
    }
    result = 0;

p101_single_exit_:
    return result;
}
