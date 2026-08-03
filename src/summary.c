#include <p101_tool_event/summary.h>
#include <stdint.h>
#include <string.h>

enum
{
    NUMBER_BASE        = 10,
    JSON_MAX_DEPTH     = 64,
    JSON_KEY_CAPACITY  = 96,
    JSON_CONTROL_LIMIT = 32,
    JSON_TRUE_LENGTH   = 4,
    JSON_FALSE_LENGTH  = 5,
    DECIMAL_MAX_DIGIT  = 9
};

struct json_cursor
{
    const char *current;
};

static void skip_space(struct json_cursor *cursor);
static bool parse_string(struct json_cursor *cursor, char *output, size_t output_size);
static bool parse_size(struct json_cursor *cursor, size_t *value);
static bool parse_boolean(struct json_cursor *cursor, bool *value);
static bool skip_number(struct json_cursor *cursor);
static bool skip_value(struct json_cursor *cursor, size_t depth);
static bool skip_object(struct json_cursor *cursor, size_t depth);
static bool skip_array(struct json_cursor *cursor, size_t depth);
static bool key_text(const char *key, char output[JSON_KEY_CAPACITY]);
static bool find_top_level_size(const char *text, const char *wanted, size_t *value);
static bool parse_log_health(struct json_cursor *cursor, bool *complete);
static bool parse_policy_summary(struct json_cursor *cursor, struct p101_tool_event_policy_summary *summary);
static bool is_decimal_digit(char value);
static bool is_hex_digit(char value);

static bool is_decimal_digit(char value)
{
    return (unsigned int)(unsigned char)(value - '0') <= DECIMAL_MAX_DIGIT;
}

static bool is_hex_digit(char value)
{
    return (is_decimal_digit(value) || (strchr("abcdefABCDEF", (int)value) != NULL && value != '\0')) != 0;
}

bool p101_tool_event_parse_json_size(const char *text, const char *key, size_t *value)
{
    char wanted[JSON_KEY_CAPACITY];

    if(text == NULL || key == NULL || value == NULL || !key_text(key, wanted))
    {
        return false;
    }
    return find_top_level_size(text, wanted, value);
}

bool p101_tool_event_parse_policy_summary_json(const char *text, const char *schema, struct p101_tool_event_policy_summary *summary)
{
    struct json_cursor cursor;
    unsigned int       seen;
    bool               first;
    bool               schema_ok;

    enum
    {
        SEEN_SCHEMA   = 1U << 0U,
        SEEN_SUMMARY  = 1U << 1U,
        SEEN_REQUIRED = SEEN_SCHEMA | SEEN_SUMMARY
    };

    if(text == NULL || schema == NULL || schema[0] == '\0' || summary == NULL)
    {
        return false;
    }

    memset(summary, 0, sizeof(*summary));
    cursor.current = text;
    seen           = 0U;
    first          = true;
    schema_ok      = false;
    skip_space(&cursor);
    if(*cursor.current++ != '{')
    {
        return false;
    }

    while(true)
    {
        char key[JSON_KEY_CAPACITY];

        skip_space(&cursor);
        if(*cursor.current == '}')
        {
            cursor.current++;
            break;
        }
        if(!first)
        {
            if(*cursor.current++ != ',')
            {
                return false;
            }
            skip_space(&cursor);
        }
        first = false;
        if(!parse_string(&cursor, key, sizeof(key)))
        {
            return false;
        }
        skip_space(&cursor);
        if(*cursor.current++ != ':')
        {
            return false;
        }
        skip_space(&cursor);

        if(strcmp(key, "schema") == 0)
        {
            char actual_schema[JSON_KEY_CAPACITY];

            if((seen & SEEN_SCHEMA) != 0U || !parse_string(&cursor, actual_schema, sizeof(actual_schema)))
            {
                return false;
            }
            seen |= SEEN_SCHEMA;
            schema_ok = strcmp(actual_schema, schema) == 0;
        }
        else if(strcmp(key, "summary") == 0)
        {
            if((seen & SEEN_SUMMARY) != 0U || !parse_policy_summary(&cursor, summary))
            {
                return false;
            }
            seen |= SEEN_SUMMARY;
        }
        else if(!skip_value(&cursor, 0U))
        {
            return false;
        }
    }

    skip_space(&cursor);
    summary->parsed = (*cursor.current == '\0' && seen == SEEN_REQUIRED && schema_ok) != 0;
    return summary->parsed;
}

bool p101_tool_event_parse_resource_summary_json(const char *text, struct p101_tool_event_resource_summary *summary)
{
    struct json_cursor cursor;
    unsigned int       seen;
    bool               first;
    bool               schema_ok;

    enum
    {
        SEEN_SCHEMA        = 1U << 0U,
        SEEN_RECORDS       = 1U << 1U,
        SEEN_FD_LEAKS      = 1U << 2U,
        SEEN_ALLOC_LEAKS   = 1U << 3U,
        SEEN_BAD_RELEASES  = 1U << 4U,
        SEEN_EXEC          = 1U << 5U,
        SEEN_GENERIC_LEAKS = 1U << 6U,
        SEEN_GENERIC_BAD   = 1U << 7U,
        SEEN_MALFORMED     = 1U << 8U,
        SEEN_BAD_VERSION   = 1U << 9U,
        SEEN_REFUSED       = 1U << 10U,
        SEEN_LOG_HEALTH    = 1U << 11U,
        SEEN_REQUIRED      = (1U << 12U) - 1U
    };

    if(text == NULL || summary == NULL)
    {
        return false;
    }

    memset(summary, 0, sizeof(*summary));
    cursor.current = text;
    seen           = 0U;
    first          = true;
    schema_ok      = false;
    skip_space(&cursor);
    if(*cursor.current++ != '{')
    {
        return false;
    }

    while(true)
    {
        char key[JSON_KEY_CAPACITY];

        skip_space(&cursor);
        if(*cursor.current == '}')
        {
            cursor.current++;
            break;
        }
        if(!first)
        {
            if(*cursor.current++ != ',')
            {
                return false;
            }
            skip_space(&cursor);
        }
        first = false;
        if(!parse_string(&cursor, key, sizeof(key)))
        {
            return false;
        }
        skip_space(&cursor);
        if(*cursor.current++ != ':')
        {
            return false;
        }
        skip_space(&cursor);

#define PARSE_UNIQUE_SIZE(member, bit)                                                                                                                                                                                                                             \
    do                                                                                                                                                                                                                                                             \
    {                                                                                                                                                                                                                                                              \
        if((seen & (bit)) != 0U || !parse_size(&cursor, &summary->member))                                                                                                                                                                                         \
        {                                                                                                                                                                                                                                                          \
            return false;                                                                                                                                                                                                                                          \
        }                                                                                                                                                                                                                                                          \
        seen |= (bit);                                                                                                                                                                                                                                             \
    } while(0)

        if(strcmp(key, "schema") == 0)
        {
            char schema[JSON_KEY_CAPACITY];

            if((seen & SEEN_SCHEMA) != 0U || !parse_string(&cursor, schema, sizeof(schema)))
            {
                return false;
            }
            seen |= SEEN_SCHEMA;
            schema_ok = strcmp(schema, "p101-resource-policy-findings-v1") == 0;
        }
        else if(strcmp(key, "records") == 0)
        {
            PARSE_UNIQUE_SIZE(records, SEEN_RECORDS);
        }
        else if(strcmp(key, "fd_leaks") == 0)
        {
            PARSE_UNIQUE_SIZE(fd_leaks, SEEN_FD_LEAKS);
        }
        else if(strcmp(key, "allocation_leaks") == 0)
        {
            PARSE_UNIQUE_SIZE(allocation_leaks, SEEN_ALLOC_LEAKS);
        }
        else if(strcmp(key, "bad_releases") == 0)
        {
            PARSE_UNIQUE_SIZE(bad_releases, SEEN_BAD_RELEASES);
        }
        else if(strcmp(key, "exec_inheritances") == 0)
        {
            PARSE_UNIQUE_SIZE(exec_inheritances, SEEN_EXEC);
        }
        else if(strcmp(key, "generic_resource_leaks") == 0)
        {
            PARSE_UNIQUE_SIZE(generic_resource_leaks, SEEN_GENERIC_LEAKS);
        }
        else if(strcmp(key, "generic_bad_releases") == 0)
        {
            PARSE_UNIQUE_SIZE(generic_bad_releases, SEEN_GENERIC_BAD);
        }
        else if(strcmp(key, "malformed") == 0)
        {
            PARSE_UNIQUE_SIZE(malformed, SEEN_MALFORMED);
        }
        else if(strcmp(key, "bad_version") == 0)
        {
            PARSE_UNIQUE_SIZE(bad_version, SEEN_BAD_VERSION);
        }
        else if(strcmp(key, "refused") == 0)
        {
            PARSE_UNIQUE_SIZE(refused, SEEN_REFUSED);
        }
        else if(strcmp(key, "log_health") == 0)
        {
            if((seen & SEEN_LOG_HEALTH) != 0U || !parse_log_health(&cursor, &summary->log_complete))
            {
                return false;
            }
            seen |= SEEN_LOG_HEALTH;
        }
        else if(!skip_value(&cursor, 0U))
        {
            return false;
        }
#undef PARSE_UNIQUE_SIZE
    }

    skip_space(&cursor);
    summary->parsed = (*cursor.current == '\0' && seen == SEEN_REQUIRED && schema_ok) != 0;
    return summary->parsed;
}

size_t p101_tool_event_resource_summary_finding_count(const struct p101_tool_event_resource_summary *summary)
{
    if(summary == NULL || !summary->parsed)
    {
        return 0U;
    }
    {
        size_t count;

        count = summary->fd_leaks + summary->allocation_leaks + summary->bad_releases + summary->exec_inheritances + summary->generic_resource_leaks + summary->generic_bad_releases + summary->malformed + summary->bad_version + summary->refused;
        if(!summary->log_complete)
        {
            count++;
        }
        return count;
    }
}

static bool parse_policy_summary(struct json_cursor *cursor, struct p101_tool_event_policy_summary *summary)
{
    unsigned int seen;
    bool         first;

    enum
    {
        SEEN_RECORDS  = 1U << 0U,
        SEEN_FINDINGS = 1U << 1U,
        SEEN_REQUIRED = SEEN_FINDINGS
    };

    if(*cursor->current++ != '{')
    {
        return false;
    }
    seen  = 0U;
    first = true;

    while(true)
    {
        char key[JSON_KEY_CAPACITY];

        skip_space(cursor);
        if(*cursor->current == '}')
        {
            cursor->current++;
            break;
        }
        if(!first)
        {
            if(*cursor->current++ != ',')
            {
                return false;
            }
            skip_space(cursor);
        }
        first = false;
        if(!parse_string(cursor, key, sizeof(key)))
        {
            return false;
        }
        skip_space(cursor);
        if(*cursor->current++ != ':')
        {
            return false;
        }
        skip_space(cursor);

        if(strcmp(key, "records") == 0)
        {
            if((seen & SEEN_RECORDS) != 0U || !parse_size(cursor, &summary->records))
            {
                return false;
            }
            seen |= SEEN_RECORDS;
            summary->has_records = true;
        }
        else if(strcmp(key, "findings") == 0)
        {
            if((seen & SEEN_FINDINGS) != 0U || !parse_size(cursor, &summary->findings))
            {
                return false;
            }
            seen |= SEEN_FINDINGS;
        }
        else if(!skip_value(cursor, 0U))
        {
            return false;
        }
    }

    return (seen & SEEN_REQUIRED) == SEEN_REQUIRED;
}

static void skip_space(struct json_cursor *cursor)
{
    while(*cursor->current == ' ' || *cursor->current == '\t' || *cursor->current == '\n' || *cursor->current == '\r')
    {
        cursor->current++;
    }
}

static bool parse_string(struct json_cursor *cursor, char *output, size_t output_size)
{
    size_t used;

    if(*cursor->current++ != '"')
    {
        return false;
    }
    used = 0U;
    while(*cursor->current != '\0' && *cursor->current != '"')
    {
        unsigned char ch;

        ch = (unsigned char)*cursor->current++;
        if(ch == '\\')
        {
            ch = (unsigned char)*cursor->current++;
            if(ch == 'u')
            {
                for(size_t index = 0U; index < 4U; index++)
                {
                    char digit;

                    digit = *cursor->current++;
                    if(!is_hex_digit(digit))
                    {
                        return false;
                    }
                }
                ch = '?';
            }
            else if(strchr("\"\\/bfnrt", (int)ch) == NULL)
            {
                return false;
            }
        }
        else if(ch < JSON_CONTROL_LIMIT)
        {
            return false;
        }
        if(output != NULL && used + 1U >= output_size)
        {
            return false;
        }
        if(output != NULL)
        {
            output[used++] = (char)ch;
        }
    }
    if(*cursor->current++ != '"')
    {
        return false;
    }
    if(output != NULL)
    {
        output[used] = '\0';
    }
    return true;
}

static bool parse_size(struct json_cursor *cursor, size_t *value)
{
    size_t parsed;

    if(*cursor->current < '0' || *cursor->current > '9')
    {
        return false;
    }
    parsed = 0U;
    while(*cursor->current >= '0' && *cursor->current <= '9')
    {
        size_t digit;

        digit = (size_t)(*cursor->current - '0');
        if(parsed > (SIZE_MAX - digit) / (size_t)NUMBER_BASE)
        {
            return false;
        }
        parsed = (parsed * (size_t)NUMBER_BASE) + digit;
        cursor->current++;
    }
    *value = parsed;
    return true;
}

static bool parse_boolean(struct json_cursor *cursor, bool *value)
{
    if(strncmp(cursor->current, "true", JSON_TRUE_LENGTH) == 0)
    {
        cursor->current += JSON_TRUE_LENGTH;
        *value = true;
        return true;
    }
    if(strncmp(cursor->current, "false", JSON_FALSE_LENGTH) == 0)
    {
        cursor->current += JSON_FALSE_LENGTH;
        *value = false;
        return true;
    }
    return false;
}

static bool skip_value(struct json_cursor *cursor, size_t depth)    // NOLINT(misc-no-recursion)
{
    if(depth >= JSON_MAX_DEPTH)
    {
        return false;
    }
    skip_space(cursor);
    if(*cursor->current == '"')
    {
        return parse_string(cursor, NULL, 0U);
    }
    if(*cursor->current == '{')
    {
        return skip_object(cursor, depth + 1U);
    }
    if(*cursor->current == '[')
    {
        return skip_array(cursor, depth + 1U);
    }
    if((*cursor->current >= '0' && *cursor->current <= '9') || *cursor->current == '-')
    {
        return skip_number(cursor);
    }
    if(strncmp(cursor->current, "true", JSON_TRUE_LENGTH) == 0 || strncmp(cursor->current, "null", JSON_TRUE_LENGTH) == 0)
    {
        cursor->current += JSON_TRUE_LENGTH;
        return true;
    }
    if(strncmp(cursor->current, "false", JSON_FALSE_LENGTH) == 0)
    {
        cursor->current += JSON_FALSE_LENGTH;
        return true;
    }
    return false;
}

static bool skip_number(struct json_cursor *cursor)
{
    const char *current;

    current = cursor->current;
    if(*current == '-')
    {
        current++;
    }
    if(*current == '0')
    {
        current++;
        if(is_decimal_digit(*current))
        {
            return false;
        }
    }
    else if(*current >= '1' && *current <= '9')
    {
        do
        {
            current++;
        } while(*current >= '0' && *current <= '9');
    }
    else
    {
        return false;
    }
    if(*current == '.')
    {
        current++;
        if(*current < '0' || *current > '9')
        {
            return false;
        }
        while(*current >= '0' && *current <= '9')
        {
            current++;
        }
    }
    if(*current == 'e' || *current == 'E')
    {
        current++;
        if(*current == '+' || *current == '-')
        {
            current++;
        }
        if(*current < '0' || *current > '9')
        {
            return false;
        }
        while(*current >= '0' && *current <= '9')
        {
            current++;
        }
    }
    cursor->current = current;
    return true;
}

static bool skip_object(struct json_cursor *cursor, size_t depth)    // NOLINT(misc-no-recursion)
{
    bool first;

    cursor->current++;
    first = true;
    while(true)
    {
        char key[JSON_KEY_CAPACITY];

        skip_space(cursor);
        if(*cursor->current == '}')
        {
            cursor->current++;
            return true;
        }
        if(!first && *cursor->current++ != ',')
        {
            return false;
        }
        first = false;
        skip_space(cursor);
        if(!parse_string(cursor, key, sizeof(key)))
        {
            return false;
        }
        skip_space(cursor);
        if(*cursor->current++ != ':')
        {
            return false;
        }
        if(!skip_value(cursor, depth))
        {
            return false;
        }
    }
}

static bool skip_array(struct json_cursor *cursor, size_t depth)    // NOLINT(misc-no-recursion)
{
    bool first;

    cursor->current++;
    first = true;
    while(true)
    {
        skip_space(cursor);
        if(*cursor->current == ']')
        {
            cursor->current++;
            return true;
        }
        if(!first && *cursor->current++ != ',')
        {
            return false;
        }
        first = false;
        if(!skip_value(cursor, depth))
        {
            return false;
        }
    }
}

static bool key_text(const char *key, char output[JSON_KEY_CAPACITY])
{
    size_t length;

    length = strlen(key);
    if(length >= 2U && key[0] == '"' && key[length - 1U] == '"')
    {
        key++;
        length -= 2U;
    }
    if(length == 0U || length >= JSON_KEY_CAPACITY)
    {
        return false;
    }
    memcpy(output, key, length);
    output[length] = '\0';
    return true;
}

static bool find_top_level_size(const char *text, const char *wanted, size_t *value)
{
    struct json_cursor cursor;
    bool               first;
    bool               found;

    cursor.current = text;
    first          = true;
    found          = false;
    skip_space(&cursor);
    if(*cursor.current++ != '{')
    {
        return false;
    }
    while(true)
    {
        char key[JSON_KEY_CAPACITY];

        skip_space(&cursor);
        if(*cursor.current == '}')
        {
            cursor.current++;
            break;
        }
        if(!first && *cursor.current++ != ',')
        {
            return false;
        }
        first = false;
        skip_space(&cursor);
        if(!parse_string(&cursor, key, sizeof(key)))
        {
            return false;
        }
        skip_space(&cursor);
        if(*cursor.current++ != ':')
        {
            return false;
        }
        skip_space(&cursor);
        if(strcmp(key, wanted) == 0)
        {
            if(found || !parse_size(&cursor, value))
            {
                return false;
            }
            found = true;
        }
        else if(!skip_value(&cursor, 0U))
        {
            return false;
        }
    }
    skip_space(&cursor);
    return (found && *cursor.current == '\0') != 0;
}

static bool parse_log_health(struct json_cursor *cursor, bool *complete)
{
    bool first;
    bool found;

    if(*cursor->current++ != '{')
    {
        return false;
    }
    first = true;
    found = false;
    while(true)
    {
        char key[JSON_KEY_CAPACITY];

        skip_space(cursor);
        if(*cursor->current == '}')
        {
            cursor->current++;
            return found;
        }
        if(!first && *cursor->current++ != ',')
        {
            return false;
        }
        first = false;
        skip_space(cursor);
        if(!parse_string(cursor, key, sizeof(key)))
        {
            return false;
        }
        skip_space(cursor);
        if(*cursor->current++ != ':')
        {
            return false;
        }
        skip_space(cursor);
        if(strcmp(key, "complete") == 0)
        {
            if(found || !parse_boolean(cursor, complete))
            {
                return false;
            }
            found = true;
        }
        else if(!skip_value(cursor, 1U))
        {
            return false;
        }
    }
}
