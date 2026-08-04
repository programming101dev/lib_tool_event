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
    _Bool p101_single_result_;
    char  wanted[JSON_KEY_CAPACITY];

    if(text == NULL || key == NULL || value == NULL || !key_text(key, wanted))
    {
        p101_single_result_ = (_Bool)(false);
        goto p101_single_exit_;
    }
    p101_single_result_ = (find_top_level_size(text, wanted, value));
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

bool p101_tool_event_parse_policy_summary_json(const char *text, const char *schema, struct p101_tool_event_policy_summary *summary)
{
    _Bool              p101_single_result_;
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
        p101_single_result_ = (_Bool)(false);
        goto p101_single_exit_;
    }

    memset(summary, 0, sizeof(*summary));
    cursor.current = text;
    seen           = 0U;
    first          = true;
    schema_ok      = false;
    skip_space(&cursor);
    if(*cursor.current++ != '{')
    {
        p101_single_result_ = (_Bool)(false);
        goto p101_single_exit_;
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
                p101_single_result_ = (_Bool)(false);
                goto p101_single_exit_;
            }
            skip_space(&cursor);
        }
        first = false;
        if(!parse_string(&cursor, key, sizeof(key)))
        {
            p101_single_result_ = (_Bool)(false);
            goto p101_single_exit_;
        }
        skip_space(&cursor);
        if(*cursor.current++ != ':')
        {
            p101_single_result_ = (_Bool)(false);
            goto p101_single_exit_;
        }
        skip_space(&cursor);

        if(strcmp(key, "schema") == 0)
        {
            char actual_schema[JSON_KEY_CAPACITY];

            if((seen & SEEN_SCHEMA) != 0U || !parse_string(&cursor, actual_schema, sizeof(actual_schema)))
            {
                p101_single_result_ = (_Bool)(false);
                goto p101_single_exit_;
            }
            seen |= SEEN_SCHEMA;
            schema_ok = strcmp(actual_schema, schema) == 0;
        }
        else if(strcmp(key, "summary") == 0)
        {
            if((seen & SEEN_SUMMARY) != 0U || !parse_policy_summary(&cursor, summary))
            {
                p101_single_result_ = (_Bool)(false);
                goto p101_single_exit_;
            }
            seen |= SEEN_SUMMARY;
        }
        else if(!skip_value(&cursor, 0U))
        {
            p101_single_result_ = (_Bool)(false);
            goto p101_single_exit_;
        }
    }

    skip_space(&cursor);
    summary->parsed     = (*cursor.current == '\0' && seen == SEEN_REQUIRED && schema_ok) != 0;
    p101_single_result_ = (summary->parsed);
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

bool p101_tool_event_parse_resource_summary_json(const char *text, struct p101_tool_event_resource_summary *summary)
{
    _Bool              p101_single_result_;
    struct json_cursor cursor;
    unsigned int       seen;
    bool               first;
    bool               result;
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
        p101_single_result_ = (_Bool)(false);
        goto p101_single_exit_;
    }

    memset(summary, 0, sizeof(*summary));
    cursor.current = text;
    seen           = 0U;
    first          = true;
    schema_ok      = false;
    skip_space(&cursor);
    if(*cursor.current++ != '{')
    {
        p101_single_result_ = (_Bool)(false);
        goto p101_single_exit_;
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
                p101_single_result_ = (_Bool)(false);
                goto p101_single_exit_;
            }
            skip_space(&cursor);
        }
        first = false;
        if(!parse_string(&cursor, key, sizeof(key)))
        {
            p101_single_result_ = (_Bool)(false);
            goto p101_single_exit_;
        }
        skip_space(&cursor);
        if(*cursor.current++ != ':')
        {
            p101_single_result_ = (_Bool)(false);
            goto p101_single_exit_;
        }
        skip_space(&cursor);

#define PARSE_UNIQUE_SIZE(member, bit)                                                                                                                                                                                                                             \
    do                                                                                                                                                                                                                                                             \
    {                                                                                                                                                                                                                                                              \
        if((seen & (bit)) != 0U || !parse_size(&cursor, &summary->member))                                                                                                                                                                                         \
        {                                                                                                                                                                                                                                                          \
            result = false;                                                                                                                                                                                                                                        \
            goto done;                                                                                                                                                                                                                                             \
        }                                                                                                                                                                                                                                                          \
        seen |= (bit);                                                                                                                                                                                                                                             \
    } while(0)

        if(strcmp(key, "schema") == 0)
        {
            char schema[JSON_KEY_CAPACITY];

            if((seen & SEEN_SCHEMA) != 0U || !parse_string(&cursor, schema, sizeof(schema)))
            {
                p101_single_result_ = (_Bool)(false);
                goto p101_single_exit_;
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
                p101_single_result_ = (_Bool)(false);
                goto p101_single_exit_;
            }
            seen |= SEEN_LOG_HEALTH;
        }
        else if(!skip_value(&cursor, 0U))
        {
            p101_single_result_ = (_Bool)(false);
            goto p101_single_exit_;
        }
#undef PARSE_UNIQUE_SIZE
    }

    skip_space(&cursor);
    summary->parsed = (*cursor.current == '\0' && seen == SEEN_REQUIRED && schema_ok) != 0;
    result          = summary->parsed;

done:
    p101_single_result_ = result;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

size_t p101_tool_event_resource_summary_finding_count(const struct p101_tool_event_resource_summary *summary)
{
    size_t p101_single_result_;
    if(summary == NULL || !summary->parsed)
    {
        p101_single_result_ = 0U;
        goto p101_single_exit_;
    }
    {
        size_t count;

        count = summary->fd_leaks + summary->allocation_leaks + summary->bad_releases + summary->exec_inheritances + summary->generic_resource_leaks + summary->generic_bad_releases + summary->malformed + summary->bad_version + summary->refused;
        if(!summary->log_complete)
        {
            count++;
        }
        p101_single_result_ = count;
        goto p101_single_exit_;
    }

p101_single_exit_:
    return p101_single_result_;
}

static bool parse_policy_summary(struct json_cursor *cursor, struct p101_tool_event_policy_summary *summary)
{
    _Bool        p101_single_result_;
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
        p101_single_result_ = (_Bool)(false);
        goto p101_single_exit_;
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
                p101_single_result_ = (_Bool)(false);
                goto p101_single_exit_;
            }
            skip_space(cursor);
        }
        first = false;
        if(!parse_string(cursor, key, sizeof(key)))
        {
            p101_single_result_ = (_Bool)(false);
            goto p101_single_exit_;
        }
        skip_space(cursor);
        if(*cursor->current++ != ':')
        {
            p101_single_result_ = (_Bool)(false);
            goto p101_single_exit_;
        }
        skip_space(cursor);

        if(strcmp(key, "records") == 0)
        {
            if((seen & SEEN_RECORDS) != 0U || !parse_size(cursor, &summary->records))
            {
                p101_single_result_ = (_Bool)(false);
                goto p101_single_exit_;
            }
            seen |= SEEN_RECORDS;
            summary->has_records = true;
        }
        else if(strcmp(key, "findings") == 0)
        {
            if((seen & SEEN_FINDINGS) != 0U || !parse_size(cursor, &summary->findings))
            {
                p101_single_result_ = (_Bool)(false);
                goto p101_single_exit_;
            }
            seen |= SEEN_FINDINGS;
        }
        else if(!skip_value(cursor, 0U))
        {
            p101_single_result_ = (_Bool)(false);
            goto p101_single_exit_;
        }
    }

    p101_single_result_ = (_Bool)((seen & SEEN_REQUIRED) == SEEN_REQUIRED);
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
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
    _Bool  p101_single_result_;
    size_t used;

    if(*cursor->current++ != '"')
    {
        p101_single_result_ = (_Bool)(false);
        goto p101_single_exit_;
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
                        p101_single_result_ = (_Bool)(false);
                        goto p101_single_exit_;
                    }
                }
                ch = '?';
            }
            else if(strchr("\"\\/bfnrt", (int)ch) == NULL)
            {
                p101_single_result_ = (_Bool)(false);
                goto p101_single_exit_;
            }
        }
        else if(ch < JSON_CONTROL_LIMIT)
        {
            p101_single_result_ = (_Bool)(false);
            goto p101_single_exit_;
        }
        if(output != NULL && used + 1U >= output_size)
        {
            p101_single_result_ = (_Bool)(false);
            goto p101_single_exit_;
        }
        if(output != NULL)
        {
            output[used++] = (char)ch;
        }
    }
    if(*cursor->current++ != '"')
    {
        p101_single_result_ = (_Bool)(false);
        goto p101_single_exit_;
    }
    if(output != NULL)
    {
        output[used] = '\0';
    }
    p101_single_result_ = (_Bool)(true);
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static bool parse_size(struct json_cursor *cursor, size_t *value)
{
    _Bool  p101_single_result_;
    size_t parsed;

    if(*cursor->current < '0' || *cursor->current > '9')
    {
        p101_single_result_ = (_Bool)(false);
        goto p101_single_exit_;
    }
    parsed = 0U;
    while(*cursor->current >= '0' && *cursor->current <= '9')
    {
        size_t digit;

        digit = (size_t)(*cursor->current - '0');
        if(parsed > (SIZE_MAX - digit) / (size_t)NUMBER_BASE)
        {
            p101_single_result_ = (_Bool)(false);
            goto p101_single_exit_;
        }
        parsed = (parsed * (size_t)NUMBER_BASE) + digit;
        cursor->current++;
    }
    *value              = parsed;
    p101_single_result_ = (_Bool)(true);
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static bool parse_boolean(struct json_cursor *cursor, bool *value)
{
    _Bool p101_single_result_;
    if(strncmp(cursor->current, "true", JSON_TRUE_LENGTH) == 0)
    {
        cursor->current += JSON_TRUE_LENGTH;
        *value              = true;
        p101_single_result_ = (_Bool)(true);
        goto p101_single_exit_;
    }
    if(strncmp(cursor->current, "false", JSON_FALSE_LENGTH) == 0)
    {
        cursor->current += JSON_FALSE_LENGTH;
        *value              = false;
        p101_single_result_ = (_Bool)(true);
        goto p101_single_exit_;
    }
    p101_single_result_ = (_Bool)(false);
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static bool skip_value(struct json_cursor *cursor, size_t depth)    // NOLINT(misc-no-recursion)
{
    _Bool p101_single_result_;
    if(depth >= JSON_MAX_DEPTH)
    {
        p101_single_result_ = (_Bool)(false);
        goto p101_single_exit_;
    }
    skip_space(cursor);
    if(*cursor->current == '"')
    {
        p101_single_result_ = (parse_string(cursor, NULL, 0U));
        goto p101_single_exit_;
    }
    if(*cursor->current == '{')
    {
        p101_single_result_ = (skip_object(cursor, depth + 1U));
        goto p101_single_exit_;
    }
    if(*cursor->current == '[')
    {
        p101_single_result_ = (skip_array(cursor, depth + 1U));
        goto p101_single_exit_;
    }
    if((*cursor->current >= '0' && *cursor->current <= '9') || *cursor->current == '-')
    {
        p101_single_result_ = (skip_number(cursor));
        goto p101_single_exit_;
    }
    if(strncmp(cursor->current, "true", JSON_TRUE_LENGTH) == 0 || strncmp(cursor->current, "null", JSON_TRUE_LENGTH) == 0)
    {
        cursor->current += JSON_TRUE_LENGTH;
        p101_single_result_ = (_Bool)(true);
        goto p101_single_exit_;
    }
    if(strncmp(cursor->current, "false", JSON_FALSE_LENGTH) == 0)
    {
        cursor->current += JSON_FALSE_LENGTH;
        p101_single_result_ = (_Bool)(true);
        goto p101_single_exit_;
    }
    p101_single_result_ = (_Bool)(false);
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static bool skip_number(struct json_cursor *cursor)
{
    _Bool       p101_single_result_;
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
            p101_single_result_ = (_Bool)(false);
            goto p101_single_exit_;
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
        p101_single_result_ = (_Bool)(false);
        goto p101_single_exit_;
    }
    if(*current == '.')
    {
        current++;
        if(*current < '0' || *current > '9')
        {
            p101_single_result_ = (_Bool)(false);
            goto p101_single_exit_;
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
            p101_single_result_ = (_Bool)(false);
            goto p101_single_exit_;
        }
        while(*current >= '0' && *current <= '9')
        {
            current++;
        }
    }
    cursor->current     = current;
    p101_single_result_ = (_Bool)(true);
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static bool skip_object(struct json_cursor *cursor, size_t depth)    // NOLINT(misc-no-recursion)
{
    _Bool p101_single_result_;
    bool  first;

    cursor->current++;
    first = true;
    skip_space(cursor);
    while(*cursor->current != '}')
    {
        char key[JSON_KEY_CAPACITY];

        if(!first && *cursor->current++ != ',')
        {
            p101_single_result_ = (_Bool)(false);
            goto p101_single_exit_;
        }
        first = false;
        skip_space(cursor);
        if(!parse_string(cursor, key, sizeof(key)))
        {
            p101_single_result_ = (_Bool)(false);
            goto p101_single_exit_;
        }
        skip_space(cursor);
        if(*cursor->current++ != ':')
        {
            p101_single_result_ = (_Bool)(false);
            goto p101_single_exit_;
        }
        if(!skip_value(cursor, depth))
        {
            p101_single_result_ = (_Bool)(false);
            goto p101_single_exit_;
        }
        skip_space(cursor);
    }
    cursor->current++;
    p101_single_result_ = (_Bool)(true);
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static bool skip_array(struct json_cursor *cursor, size_t depth)    // NOLINT(misc-no-recursion)
{
    _Bool p101_single_result_;
    bool  first;

    cursor->current++;
    first = true;
    skip_space(cursor);
    while(*cursor->current != ']')
    {
        if(!first && *cursor->current++ != ',')
        {
            p101_single_result_ = (_Bool)(false);
            goto p101_single_exit_;
        }
        first = false;
        if(!skip_value(cursor, depth))
        {
            p101_single_result_ = (_Bool)(false);
            goto p101_single_exit_;
        }
        skip_space(cursor);
    }
    cursor->current++;
    p101_single_result_ = (_Bool)(true);
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static bool key_text(const char *key, char output[JSON_KEY_CAPACITY])
{
    _Bool  p101_single_result_;
    size_t length;

    length = strlen(key);
    if(length >= 2U && key[0] == '"' && key[length - 1U] == '"')
    {
        key++;
        length -= 2U;
    }
    if(length == 0U || length >= JSON_KEY_CAPACITY)
    {
        p101_single_result_ = (_Bool)(false);
        goto p101_single_exit_;
    }
    memcpy(output, key, length);
    output[length]      = '\0';
    p101_single_result_ = (_Bool)(true);
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static bool find_top_level_size(const char *text, const char *wanted, size_t *value)
{
    _Bool              p101_single_result_;
    struct json_cursor cursor;
    bool               first;
    bool               found;

    cursor.current = text;
    first          = true;
    found          = false;
    skip_space(&cursor);
    if(*cursor.current++ != '{')
    {
        p101_single_result_ = (_Bool)(false);
        goto p101_single_exit_;
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
            p101_single_result_ = (_Bool)(false);
            goto p101_single_exit_;
        }
        first = false;
        skip_space(&cursor);
        if(!parse_string(&cursor, key, sizeof(key)))
        {
            p101_single_result_ = (_Bool)(false);
            goto p101_single_exit_;
        }
        skip_space(&cursor);
        if(*cursor.current++ != ':')
        {
            p101_single_result_ = (_Bool)(false);
            goto p101_single_exit_;
        }
        skip_space(&cursor);
        if(strcmp(key, wanted) == 0)
        {
            if(found || !parse_size(&cursor, value))
            {
                p101_single_result_ = (_Bool)(false);
                goto p101_single_exit_;
            }
            found = true;
        }
        else if(!skip_value(&cursor, 0U))
        {
            p101_single_result_ = (_Bool)(false);
            goto p101_single_exit_;
        }
    }
    skip_space(&cursor);
    p101_single_result_ = (_Bool)((found && *cursor.current == '\0') != 0);
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static bool parse_log_health(struct json_cursor *cursor, bool *complete)
{
    _Bool p101_single_result_;
    bool  first;
    bool  found;

    if(*cursor->current++ != '{')
    {
        p101_single_result_ = (_Bool)(false);
        goto p101_single_exit_;
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
            p101_single_result_ = found;
            goto p101_single_exit_;
        }
        if(!first && *cursor->current++ != ',')
        {
            p101_single_result_ = (_Bool)(false);
            goto p101_single_exit_;
        }
        first = false;
        skip_space(cursor);
        if(!parse_string(cursor, key, sizeof(key)))
        {
            p101_single_result_ = (_Bool)(false);
            goto p101_single_exit_;
        }
        skip_space(cursor);
        if(*cursor->current++ != ':')
        {
            p101_single_result_ = (_Bool)(false);
            goto p101_single_exit_;
        }
        skip_space(cursor);
        if(strcmp(key, "complete") == 0)
        {
            if(found || !parse_boolean(cursor, complete))
            {
                p101_single_result_ = (_Bool)(false);
                goto p101_single_exit_;
            }
            found = true;
        }
        else if(!skip_value(cursor, 1U))
        {
            p101_single_result_ = (_Bool)(false);
            goto p101_single_exit_;
        }
    }

p101_single_exit_:
    return p101_single_result_;
}
