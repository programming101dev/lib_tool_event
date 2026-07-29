#ifndef P101_TOOL_EVENT_EVENT_H
#define P101_TOOL_EVENT_EVENT_H

#include <p101_error/error.h>
#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C"
{
#endif

    enum
    {
        P101_TOOL_EVENT_LINE_MAX_BYTES = 4096,
        P101_TOOL_EVENT_LOG_VERSION_2  = 2,
        P101_TOOL_EVENT_LOG_VERSION_3  = 3,
        P101_TOOL_EVENT_LOG_VERSION    = P101_TOOL_EVENT_LOG_VERSION_3
    };

    typedef enum
    {
        P101_TOOL_EVENT_LINE_EOF = 0,
        P101_TOOL_EVENT_LINE_OK,
        P101_TOOL_EVENT_LINE_MALFORMED,
        P101_TOOL_EVENT_LINE_ERROR
    } p101_tool_event_line_status;

    typedef enum
    {
        P101_TOOL_EVENT_PARSE_OTHER = 0,
        P101_TOOL_EVENT_PARSE_OK,
        P101_TOOL_EVENT_PARSE_MALFORMED,
        P101_TOOL_EVENT_PARSE_BAD_VERSION
    } p101_tool_event_parse_status;

    typedef enum
    {
        P101_TOOL_EVENT_RECORD_FD = 0,
        P101_TOOL_EVENT_RECORD_ALLOC,
        P101_TOOL_EVENT_RECORD_FORK,
        P101_TOOL_EVENT_RECORD_SPAWN,
        P101_TOOL_EVENT_RECORD_EXEC,
        P101_TOOL_EVENT_RECORD_EXEC_FAIL,
        P101_TOOL_EVENT_RECORD_CALL,
        P101_TOOL_EVENT_RECORD_RESOURCE
    } p101_tool_event_record_kind;

    typedef enum
    {
        P101_TOOL_EVENT_FD_OPEN = 0,
        P101_TOOL_EVENT_FD_CLOSE
    } p101_tool_event_fd_kind;

    typedef enum
    {
        P101_TOOL_EVENT_ALLOC_ALLOC = 0,
        P101_TOOL_EVENT_ALLOC_FREE,
        P101_TOOL_EVENT_ALLOC_REALLOC
    } p101_tool_event_alloc_kind;

    typedef enum
    {
        P101_TOOL_EVENT_CALL_ENTER = 0,
        P101_TOOL_EVENT_CALL_EXIT
    } p101_tool_event_call_kind;

    typedef enum
    {
        P101_TOOL_EVENT_RESOURCE_ACQUIRE = 0,
        P101_TOOL_EVENT_RESOURCE_RELEASE,
        P101_TOOL_EVENT_RESOURCE_REPLACE,
        P101_TOOL_EVENT_RESOURCE_TRANSFER
    } p101_tool_event_resource_kind;

    struct p101_tool_event_record
    {
        int                           version;
        p101_tool_event_record_kind   record_kind;
        long                          pid;
        long                          child_pid;
        size_t                        context_id;
        size_t                        sequence;
        size_t                        monotonic_ns;
        size_t                        wall_unix_ns;
        int                           monotonic_ns_available;
        int                           wall_unix_ns_available;
        int                           fd;
        int                           cloexec;
        p101_tool_event_fd_kind       fd_kind;
        p101_tool_event_alloc_kind    alloc_kind;
        p101_tool_event_call_kind     call_kind;
        p101_tool_event_resource_kind resource_kind;
        char                         *ptr;
        char                         *new_ptr;
        char                         *target;
        char                         *resource_class;
        char                         *resource_id;
        char                         *related_id;
        char                         *metadata;
        size_t                        size;
        int                           line_number;
        char                         *function_name;
        char                         *call_name;
        char                         *arguments;
        char                         *result;
        char                         *file_name;
    };

    struct p101_tool_event_output
    {
        int                           version;
        p101_tool_event_record_kind   record_kind;
        long                          pid;
        long                          child_pid;
        size_t                        context_id;
        size_t                        sequence;
        size_t                        monotonic_ns;
        size_t                        wall_unix_ns;
        int                           monotonic_ns_available;
        int                           wall_unix_ns_available;
        int                           fd;
        int                           cloexec;
        p101_tool_event_fd_kind       fd_kind;
        p101_tool_event_alloc_kind    alloc_kind;
        p101_tool_event_call_kind     call_kind;
        p101_tool_event_resource_kind resource_kind;
        const char                   *ptr;
        const char                   *new_ptr;
        const char                   *target;
        const char                   *resource_class;
        const char                   *resource_id;
        const char                   *related_id;
        const char                   *metadata;
        size_t                        size;
        int                           line_number;
        const char                   *function_name;
        const char                   *call_name;
        const char                   *arguments;
        const char                   *result;
        const char                   *file_name;
    };

    p101_tool_event_line_status  p101_tool_event_read_line(struct p101_error *err, FILE *stream, char *line, size_t line_size);
    p101_tool_event_parse_status p101_tool_event_parse_line(char *line, struct p101_tool_event_record *record);
    int                          p101_tool_event_write(FILE *stream, const struct p101_tool_event_output *record);
    int                          p101_tool_event_line_is_ours(const char *line);
    const char                  *p101_tool_event_parse_status_name(p101_tool_event_parse_status status);
    char                        *p101_tool_event_split(char **cursor);
    void                         p101_tool_event_unescape_field(char *field);
    int                          p101_tool_event_parse_size_field(const char *text, size_t *out);

#ifdef __cplusplus
}
#endif

#endif
