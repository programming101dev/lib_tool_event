#ifndef P101_TOOL_EVENT_DIAGNOSTIC_H
#define P101_TOOL_EVENT_DIAGNOSTIC_H

#include <p101_tool_event/lesson_catalog.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define P101_TOOL_DIAGNOSTIC_SCHEMA_NAME "p101-tool-diagnostic-v1"

    typedef enum
    {
        P101_TOOL_DIAGNOSTIC_NOTE = 0,
        P101_TOOL_DIAGNOSTIC_WARNING,
        P101_TOOL_DIAGNOSTIC_ERROR
    } p101_tool_diagnostic_severity;

    typedef enum
    {
        P101_TOOL_DIAGNOSTIC_TEXT = 0,
        P101_TOOL_DIAGNOSTIC_JSON
    } p101_tool_diagnostic_format;

    enum
    {
        P101_TOOL_DIAGNOSTIC_OUTPUT_HUMAN = 1U,
        P101_TOOL_DIAGNOSTIC_OUTPUT_JSON  = 2U
    };

    /*
     * A normalized source finding. The producer owns the policy behind the
     * finding and supplies the stable identifier and lesson route. This
     * library owns only serialization.
     *
     * Text records use the compiler-compatible grammar:
     *   path:line:column: severity: message [id]
     * Optional lesson guidance is a second `note:` record at the same source
     * location. JSON output is one object without a trailing newline so a
     * caller can place it in an array or use it as JSON Lines.
     */
    struct p101_tool_diagnostic
    {
        const char                   *id;
        p101_tool_diagnostic_severity severity;
        const char                   *path;
        size_t                        line;
        size_t                        column;
        const char                   *function_name;
        const char                   *message;
        const char                   *lesson_id;
        const char                   *lesson_path;
        const char                   *lesson_url;
    };

    const char *p101_tool_diagnostic_severity_name(p101_tool_diagnostic_severity severity);
    int         p101_tool_diagnostic_initialize(struct p101_tool_diagnostic *diagnostic, p101_tool_finding finding, p101_tool_diagnostic_severity severity, const char *path, size_t line, size_t column, const char *function_name, const char *message);
    int         p101_tool_diagnostic_parse_outputs(const char *specification, unsigned int *outputs);
    int         p101_tool_diagnostic_write(FILE *stream, p101_tool_diagnostic_format format, const struct p101_tool_diagnostic *diagnostic);
    int         p101_tool_diagnostic_write_outputs(FILE *human_stream, FILE *json_stream, const struct p101_tool_diagnostic *diagnostic);

#ifdef __cplusplus
}
#endif

#endif
