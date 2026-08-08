#ifndef P101_RECORD_RECORD_H
#define P101_RECORD_RECORD_H

#include <stdbool.h>
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
    /*
     * The escaped spelling for one field byte, or NULL when the byte is
     * written as-is. This is the inverse of p101_record_unescape_field and
     * the two must be changed together. A whole field additionally has two
     * placeholder spellings the caller applies before scanning bytes: a NULL
     * field is written as "-", and a field that is exactly "-" as "\\-".
     */
    const char *p101_record_escape_byte(unsigned char value);
    void        p101_record_unescape_field(char *field);
    bool        p101_record_pointer_is_null(const char *text);
    int         p101_record_parse_size(const char *text, size_t *out);
    int         p101_record_write_json_string(FILE *stream, const char *text);
    int         p101_record_write_json_string_contents(FILE *stream, const char *text);

    /*
     * Decode one JSON string literal starting at *cursor, advancing *cursor
     * past the closing quote on success. Only \u00xx escapes with lowercase
     * hex digits are accepted. Decoded bytes are stored in `output` when it
     * is not NULL, always NUL terminated and never exceeding output_size - 1
     * bytes; a NULL `output` validates and skips the literal instead.
     * Returns 0 on success and -1 on a malformed or oversized literal.
     */
    int p101_record_read_json_string(const char **cursor, char *output, size_t output_size);

#ifdef __cplusplus
}
#endif

#endif
