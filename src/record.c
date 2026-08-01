#include <p101_record/record.h>
#include <stdint.h>

enum
{
    NUMBER_BASE = 10
};

char *p101_record_split(char **cursor)
{
    char *start;
    char *tab;

    if(cursor == NULL || *cursor == NULL)
    {
        return NULL;
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
    return start;
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
    const char *cursor;
    size_t      value;

    if(text == NULL || out == NULL || *text == '\0')
    {
        return 0;
    }

    cursor = text;
    value  = 0U;
    while(*cursor != '\0')
    {
        size_t digit;

        if(*cursor < '0' || *cursor > '9')
        {
            return 0;
        }
        digit = (size_t)(*cursor - '0');
        if(value > (SIZE_MAX - digit) / (size_t)NUMBER_BASE)
        {
            return 0;
        }
        value = (value * (size_t)NUMBER_BASE) + digit;
        cursor++;
    }
    *out = value;
    return 1;
}
