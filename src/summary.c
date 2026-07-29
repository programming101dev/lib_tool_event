#include <p101_tool_event/summary.h>
#include <stdint.h>
#include <string.h>

enum
{
    NUMBER_BASE = 10
};

bool p101_tool_event_parse_json_size(const char *text, const char *key, size_t *value)
{
    const char *cursor;
    size_t      parsed;

    if(text == NULL || key == NULL || value == NULL)
    {
        return false;
    }

    cursor = strstr(text, key);
    if(cursor == NULL)
    {
        return false;
    }
    cursor = strchr(cursor, ':');
    if(cursor == NULL)
    {
        return false;
    }

    cursor++;
    while(*cursor == ' ' || *cursor == '\t')
    {
        cursor++;
    }
    if(*cursor < '0' || *cursor > '9')
    {
        return false;
    }

    parsed = 0U;
    while(*cursor >= '0' && *cursor <= '9')
    {
        size_t digit;

        digit = (size_t)(*cursor - '0');
        if(parsed > (SIZE_MAX - digit) / (size_t)NUMBER_BASE)
        {
            return false;
        }
        parsed = (parsed * (size_t)NUMBER_BASE) + digit;
        cursor++;
    }
    *value = parsed;
    return true;
}

bool p101_tool_event_parse_resource_summary_json(const char *text, struct p101_tool_event_resource_summary *summary)
{
    bool required;

    if(text == NULL || summary == NULL)
    {
        return false;
    }

    memset(summary, 0, sizeof(*summary));
    required = (p101_tool_event_parse_json_size(text, "\"records\"", &summary->records) && p101_tool_event_parse_json_size(text, "\"fd_leaks\"", &summary->fd_leaks) && p101_tool_event_parse_json_size(text, "\"allocation_leaks\"", &summary->allocation_leaks) &&
                p101_tool_event_parse_json_size(text, "\"bad_releases\"", &summary->bad_releases)) != 0;

    (void)p101_tool_event_parse_json_size(text, "\"exec_inheritances\"", &summary->exec_inheritances);
    (void)p101_tool_event_parse_json_size(text, "\"generic_resource_leaks\"", &summary->generic_resource_leaks);
    (void)p101_tool_event_parse_json_size(text, "\"generic_bad_releases\"", &summary->generic_bad_releases);
    (void)p101_tool_event_parse_json_size(text, "\"malformed\"", &summary->malformed);
    (void)p101_tool_event_parse_json_size(text, "\"bad_version\"", &summary->bad_version);
    (void)p101_tool_event_parse_json_size(text, "\"refused\"", &summary->refused);
    summary->parsed = required;
    return required;
}

size_t p101_tool_event_resource_summary_finding_count(const struct p101_tool_event_resource_summary *summary)
{
    if(summary == NULL || !summary->parsed)
    {
        return 0U;
    }
    return summary->fd_leaks + summary->allocation_leaks + summary->bad_releases + summary->exec_inheritances + summary->generic_resource_leaks + summary->generic_bad_releases + summary->malformed + summary->bad_version + summary->refused;
}
