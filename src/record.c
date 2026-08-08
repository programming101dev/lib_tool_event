#include <errno.h>
#include <p101_record/record.h>
#include <stdarg.h>
#include <stdint.h>
#include <string.h>

enum
{
    NUMBER_BASE             = 10,
    JSON_CONTROL_BYTE_LIMIT = 0x20U,
    JSON_UNICODE_HEX_DIGITS = 4,
    HEXADECIMAL_BASE        = 16,
    ASCII_DELETE            = 0x7F
};

static const char *const NULL_POINTER_SPELLINGS[] = {"-", "0", "0x0", "(nil)", "NULL"};

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

const char *p101_record_escape_byte(unsigned char value)
{
    const char *escaped;

    if(value == '\t')
    {
        escaped = "\\t";
    }
    else if(value == '\n')
    {
        escaped = "\\n";
    }
    else if(value == '\r')
    {
        escaped = "\\r";
    }
    else if(value == '\\')
    {
        escaped = "\\\\";
    }
    else if(value < ' ' || value == ASCII_DELETE)
    {
        escaped = "?";
    }
    else
    {
        escaped = NULL;
    }

    return escaped;
}

void p101_record_unescape_field(char *field)
{
    char *read_cursor;
    char *write_cursor;

    if(field == NULL)
    {
        goto p101_single_exit_;
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

p101_single_exit_:
    return;
}

bool p101_record_pointer_is_null(const char *text)
{
    bool p101_single_result_;

    p101_single_result_ = (text == NULL || text[0] == '\0') != 0;
    if(!p101_single_result_)
    {
        for(size_t index = 0U; index < sizeof(NULL_POINTER_SPELLINGS) / sizeof(NULL_POINTER_SPELLINGS[0]); index++)
        {
            int comparison;

            comparison = strcmp(text, NULL_POINTER_SPELLINGS[index]);
            if(comparison == 0)
            {
                p101_single_result_ = true;
                break;
            }
        }
    }
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

int p101_record_read_json_string(const char **cursor, char *output, size_t output_size)
{
    int    p101_single_result_;
    size_t unicode_remaining;
    size_t used;
    int    result;

    if(cursor == NULL || (output != NULL && output_size == 0U))
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    if(*cursor == NULL)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    used   = 0U;
    result = -1;
    /* An empty string terminates here too: byte zero is then '\0'. */
    if(**cursor != '"')
    {
        goto done;
    }
    (*cursor)++;
    while(**cursor != '\0' && **cursor != '"')
    {
        unsigned char value = (unsigned char)*(*cursor)++;
        int           escaped;

        escaped = 0;
        if(value == '\\')
        {
            escaped = 1;
            value   = (unsigned char)*(*cursor)++;
            if(value == '"' || value == '\\' || value == '/')
            {
                /* The decoded byte is already in value. */
            }
            else if(value == 'b')
            {
                value = '\b';
            }
            else if(value == 'f')
            {
                value = '\f';
            }
            else if(value == 'n')
            {
                value = '\n';
            }
            else if(value == 'r')
            {
                value = '\r';
            }
            else if(value == 't')
            {
                value = '\t';
            }
            else if(value == 'u')
            {
                unsigned char high;
                unsigned char low;

                unicode_remaining = strlen(*cursor);
                if(unicode_remaining < JSON_UNICODE_HEX_DIGITS || (*cursor)[0] != '0' || (*cursor)[1] != '0')
                {
                    goto done;
                }
                high = (unsigned char)(*cursor)[2];
                low  = (unsigned char)(*cursor)[3];
                if(high >= '0' && high <= '9')
                {
                    high = (unsigned char)(high - '0');
                }
                else if(high >= 'a' && high <= 'f')
                {
                    high = (unsigned char)(high - 'a' + NUMBER_BASE);
                }
                else
                {
                    goto done;
                }
                if(low >= '0' && low <= '9')
                {
                    low = (unsigned char)(low - '0');
                }
                else if(low >= 'a' && low <= 'f')
                {
                    low = (unsigned char)(low - 'a' + NUMBER_BASE);
                }
                else
                {
                    goto done;
                }
                value = (unsigned char)((high * HEXADECIMAL_BASE) + low);
                *cursor += JSON_UNICODE_HEX_DIGITS;
            }
            else
            {
                goto done;
            }
        }
        if(value < JSON_CONTROL_BYTE_LIMIT && escaped == 0)
        {
            goto done;
        }
        if(output != NULL)
        {
            if(used + 1U >= output_size)
            {
                goto done;
            }
            output[used++] = (char)value;
        }
    }
    if(**cursor != '"')
    {
        goto done;
    }
    (*cursor)++;
    if(output != NULL)
    {
        output[used] = '\0';
    }
    result = 0;

done:
    p101_single_result_ = result;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
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
    int write_status;
    if(stream == NULL || text == NULL)
    {
        errno               = EINVAL;
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    write_status = fputc('"', stream);
    if(write_status != EOF)
    {
        write_status = p101_record_write_json_string_contents(stream, text);
    }
    if(write_status != 0)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    write_status        = fputc('"', stream);
    p101_single_result_ = write_status == EOF ? -1 : 0;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

int p101_record_write_json_string_contents(FILE *stream, const char *text)
{
    int                  p101_single_result_;
    const unsigned char *cursor;
    int                  write_status;

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
                write_status = fputs("\\\"", stream);
                break;
            case '\\':
                write_status = fputs("\\\\", stream);
                break;
            case '\b':
                write_status = fputs("\\b", stream);
                break;
            case '\f':
                write_status = fputs("\\f", stream);
                break;
            case '\n':
                write_status = fputs("\\n", stream);
                break;
            case '\r':
                write_status = fputs("\\r", stream);
                break;
            case '\t':
                write_status = fputs("\\t", stream);
                break;
            default:
                if(*cursor < JSON_CONTROL_BYTE_LIMIT)
                {
                    write_status = fprintf(stream, "\\u%04x", (unsigned int)*cursor);
                }
                else
                {
                    write_status = fputc((int)*cursor, stream);
                }
                break;
        }
        if(write_status < 0 || write_status == EOF)
        {
            p101_single_result_ = -1;
            goto p101_single_exit_;
        }
        cursor++;
    }
    p101_single_result_ = 0;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}
