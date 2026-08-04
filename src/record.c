#include <errno.h>
#include <p101_record/record.h>
#include <stdarg.h>
#include <stdint.h>

enum
{
    NUMBER_BASE             = 10,
    JSON_CONTROL_BYTE_LIMIT = 0x20U
};

#ifdef P101_TOOL_EVENT_TESTING
static size_t test_write_failure_after = SIZE_MAX;
static size_t test_successful_writes;

void p101_tool_event_test_record_fail_write_after(size_t successful_writes)
{
    test_write_failure_after = successful_writes;
    test_successful_writes   = 0U;
}

static int test_write_should_fail(void)
{
    if(test_successful_writes == test_write_failure_after)
    {
        test_write_failure_after = SIZE_MAX;
        errno                    = EIO;
        return 1;
    }
    test_successful_writes++;
    return 0;
}

static int test_fprintf(FILE *stream, const char *format, ...)
{
    int     result;
    va_list arguments;

    if(test_write_should_fail() != 0)
    {
        return -1;
    }
    va_start(arguments, format);
    result = vfprintf(stream, format, arguments);
    va_end(arguments);
    return result;
}

static int test_fputc(int character, FILE *stream)
{
    return test_write_should_fail() != 0 ? EOF : fputc(character, stream);
}

static int test_fputs(const char *text, FILE *stream)
{
    return test_write_should_fail() != 0 ? EOF : fputs(text, stream);
}

    #define fprintf test_fprintf
    #define fputc test_fputc
    #define fputs test_fputs
#endif

char *p101_record_split(char **cursor)
{
    char *p101_single_result_;
    char *start;
    char *tab;

    if(cursor == NULL || *cursor == NULL)
    {
        p101_single_result_ = NULL;
        goto p101_single_exit_;
    }

    start = *cursor;
    tab   = start;
    while(*tab != '\0' && *tab != '\t')
    {
        tab++;
    }

    if(*tab == '\0')
    {
        *cursor = NULL;
    }
    else
    {
        *tab    = '\0';
        *cursor = tab + 1;
    }
    p101_single_result_ = start;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

void p101_record_unescape_field(char *field)
{
    char *read_cursor;
    char *write_cursor;

    if(field == NULL)
    {
        return;
    }

    read_cursor  = field;
    write_cursor = field;
    while(*read_cursor != '\0')
    {
        if(read_cursor[0] == '\\' && read_cursor[1] != '\0')
        {
            read_cursor++;
            if(*read_cursor == 't')
            {
                *write_cursor = '\t';
            }
            else if(*read_cursor == 'n')
            {
                *write_cursor = '\n';
            }
            else if(*read_cursor == 'r')
            {
                *write_cursor = '\r';
            }
            else
            {
                *write_cursor = *read_cursor;
            }
            read_cursor++;
            write_cursor++;
        }
        else
        {
            *write_cursor++ = *read_cursor++;
        }
    }
    *write_cursor = '\0';
}

int p101_record_parse_size(const char *text, size_t *out)
{
    int         p101_single_result_;
    const char *cursor;
    size_t      value;

    if(text == NULL || out == NULL || *text == '\0')
    {
        p101_single_result_ = 0;
        goto p101_single_exit_;
    }

    cursor = text;
    value  = 0U;
    while(*cursor != '\0')
    {
        size_t digit;

        if(*cursor < '0' || *cursor > '9')
        {
            p101_single_result_ = 0;
            goto p101_single_exit_;
        }
        digit = (size_t)(*cursor - '0');
        if(value > (SIZE_MAX - digit) / (size_t)NUMBER_BASE)
        {
            p101_single_result_ = 0;
            goto p101_single_exit_;
        }
        value = (value * (size_t)NUMBER_BASE) + digit;
        cursor++;
    }
    *out                = value;
    p101_single_result_ = 1;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

int p101_record_write_json_string(FILE *stream, const char *text)
{
    int p101_single_result_;
    if(stream == NULL || text == NULL)
    {
        errno               = EINVAL;
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    if(fputc('"', stream) == EOF || p101_record_write_json_string_contents(stream, text) != 0)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    p101_single_result_ = fputc('"', stream) == EOF ? -1 : 0;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

int p101_record_write_json_string_contents(FILE *stream, const char *text)
{
    int                  p101_single_result_;
    const unsigned char *cursor;

    if(stream == NULL || text == NULL)
    {
        errno               = EINVAL;
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    cursor = (const unsigned char *)text;
    while(*cursor != '\0')
    {
        switch(*cursor)
        {
            case '"':
                if(fputs("\\\"", stream) == EOF)
                {
                    p101_single_result_ = -1;
                    goto p101_single_exit_;
                }
                break;
            case '\\':
                if(fputs("\\\\", stream) == EOF)
                {
                    p101_single_result_ = -1;
                    goto p101_single_exit_;
                }
                break;
            case '\b':
                if(fputs("\\b", stream) == EOF)
                {
                    p101_single_result_ = -1;
                    goto p101_single_exit_;
                }
                break;
            case '\f':
                if(fputs("\\f", stream) == EOF)
                {
                    p101_single_result_ = -1;
                    goto p101_single_exit_;
                }
                break;
            case '\n':
                if(fputs("\\n", stream) == EOF)
                {
                    p101_single_result_ = -1;
                    goto p101_single_exit_;
                }
                break;
            case '\r':
                if(fputs("\\r", stream) == EOF)
                {
                    p101_single_result_ = -1;
                    goto p101_single_exit_;
                }
                break;
            case '\t':
                if(fputs("\\t", stream) == EOF)
                {
                    p101_single_result_ = -1;
                    goto p101_single_exit_;
                }
                break;
            default:
                if(*cursor < JSON_CONTROL_BYTE_LIMIT)
                {
                    if(fprintf(stream, "\\u%04x", (unsigned int)*cursor) < 0)
                    {
                        p101_single_result_ = -1;
                        goto p101_single_exit_;
                    }
                }
                else if(fputc((int)*cursor, stream) == EOF)
                {
                    p101_single_result_ = -1;
                    goto p101_single_exit_;
                }
                break;
        }
        cursor++;
    }
    p101_single_result_ = 0;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}
