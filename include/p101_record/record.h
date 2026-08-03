#ifndef P101_RECORD_RECORD_H
#define P101_RECORD_RECORD_H

#include <stddef.h>
#include <stdio.h>

#ifdef __cplusplus
extern "C"
{
#endif

    /*
     * Protocol-neutral helpers for bounded, tab-delimited text records.
     * These functions do not know about p101 event kinds or schema versions.
     */
    char *p101_record_split(char **cursor);
    void  p101_record_unescape_field(char *field);
    int   p101_record_parse_size(const char *text, size_t *out);
    int   p101_record_write_json_string(FILE *stream, const char *text);
    int   p101_record_write_json_string_contents(FILE *stream, const char *text);

#ifdef __cplusplus
}
#endif

#endif
