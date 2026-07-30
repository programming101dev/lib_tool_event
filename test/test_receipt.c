#include <errno.h>
#include <fcntl.h>
#include <p101_error/error.h>
#include <p101_tool_event/receipt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failures;

extern void p101_tool_event_test_force_close_error(int error_number);

#define EXPECT(condition)                                                                                                                                                                                                                                          \
    do                                                                                                                                                                                                                                                             \
    {                                                                                                                                                                                                                                                              \
        if(!(condition))                                                                                                                                                                                                                                           \
        {                                                                                                                                                                                                                                                          \
            failures++;                                                                                                                                                                                                                                            \
        }                                                                                                                                                                                                                                                          \
    } while(0)

static void reset_error(struct p101_error **err)
{
    p101_error_destroy(*err);
    *err = p101_error_create(false);
}

static void test_invalid_arguments(void)
{
    struct p101_error                 *err;
    struct p101_tool_event_fingerprint fingerprint;

    err = p101_error_create(false);
    EXPECT(p101_tool_event_fingerprint_file(err, NULL, 1U, 1U, &fingerprint) == -1);
    reset_error(&err);
    EXPECT(p101_tool_event_fingerprint_file(err, "/dev/null", 1U, 1U, NULL) == -1);
    reset_error(&err);
    EXPECT(p101_tool_event_fingerprint_file(err, "/dev/null", 0U, 1U, &fingerprint) == -1);
    reset_error(&err);
    EXPECT(p101_tool_event_fingerprint_file(err, "/dev/null", 1U, 0U, &fingerprint) == -1);
    reset_error(&err);
    EXPECT(p101_tool_event_fingerprint_file(err, "/definitely/not/present", 1U, 1U, &fingerprint) == -1);
    EXPECT(p101_error_has_error(err));
    p101_error_destroy(err);
}

static void test_empty_and_unterminated_files(void)
{
    char                               path[] = "/tmp/p101-tool-event-receipt-XXXXXX";
    int                                fd;
    struct p101_error                 *err;
    struct p101_tool_event_fingerprint fingerprint;

    fd = mkstemp(path);
    EXPECT(fd >= 0);
    EXPECT(close(fd) == 0);
    err = p101_error_create(false);
    EXPECT(p101_tool_event_fingerprint_file(err, path, 100U, 2U, &fingerprint) == 0);
    EXPECT(fingerprint.bytes == 0U);
    EXPECT(fingerprint.records == 0U);
    EXPECT(fingerprint.final_newline == 0);

    fd = open(path, O_WRONLY | O_TRUNC);
    EXPECT(fd >= 0);
    EXPECT(write(fd, "abc", 3U) == 3);
    EXPECT(close(fd) == 0);
    EXPECT(p101_tool_event_fingerprint_file(err, path, 100U, 1U, &fingerprint) == 0);
    EXPECT(fingerprint.bytes == 3U);
    EXPECT(fingerprint.records == 1U);
    EXPECT(fingerprint.final_newline == 0);
    fd = open(path, O_WRONLY | O_TRUNC);
    EXPECT(fd >= 0);
    EXPECT(write(fd, "a\nb", 3U) == 3);
    EXPECT(close(fd) == 0);
    reset_error(&err);
    EXPECT(p101_tool_event_fingerprint_file(err, path, 100U, 1U, &fingerprint) == -1);
    p101_error_destroy(err);
    EXPECT(unlink(path) == 0);
}

static void test_record_and_byte_limits(void)
{
    char                               path[] = "/tmp/p101-tool-event-receipt-XXXXXX";
    unsigned char                      block[5000];
    int                                fd;
    struct p101_error                 *err;
    struct p101_tool_event_fingerprint fingerprint;

    fd = mkstemp(path);
    EXPECT(fd >= 0);
    EXPECT(write(fd, "a\nb\n", 4U) == 4);
    EXPECT(close(fd) == 0);
    err = p101_error_create(false);
    EXPECT(p101_tool_event_fingerprint_file(err, path, 100U, 1U, &fingerprint) == -1);
    EXPECT(fingerprint.bytes == 0U);

    memset(block, 'x', sizeof(block));
    fd = open(path, O_WRONLY | O_TRUNC);
    EXPECT(fd >= 0);
    EXPECT(write(fd, block, sizeof(block)) == (ssize_t)sizeof(block));
    EXPECT(close(fd) == 0);
    reset_error(&err);
    p101_tool_event_test_force_close_error(EIO);
    EXPECT(p101_tool_event_fingerprint_file(err, path, 4500U, 2U, &fingerprint) == -1);
    EXPECT(fingerprint.bytes == 0U);
    p101_error_destroy(err);
    EXPECT(unlink(path) == 0);
}

static void test_read_failure(void)
{
    struct p101_error                 *err;
    struct p101_tool_event_fingerprint fingerprint;

    err = p101_error_create(false);
    EXPECT(p101_tool_event_fingerprint_file(err, "/tmp", 100U, 2U, &fingerprint) == -1);
    EXPECT(p101_error_has_error(err));
    p101_error_destroy(err);
}

static void test_close_failure(void)
{
    char                               path[] = "/tmp/p101-tool-event-receipt-XXXXXX";
    int                                fd;
    struct p101_error                 *err;
    struct p101_tool_event_fingerprint fingerprint;

    fd = mkstemp(path);
    EXPECT(fd >= 0);
    EXPECT(write(fd, "x\n", 2U) == 2);
    EXPECT(close(fd) == 0);
    err = p101_error_create(false);
    p101_tool_event_test_force_close_error(EIO);
    EXPECT(p101_tool_event_fingerprint_file(err, path, 100U, 2U, &fingerprint) == -1);
    EXPECT(p101_error_is_errno(err, EIO));
    EXPECT(fingerprint.bytes == 0U);
    p101_error_destroy(err);
    EXPECT(unlink(path) == 0);
}

int main(void)
{
    test_invalid_arguments();
    test_empty_and_unterminated_files();
    test_record_and_byte_limits();
    test_read_failure();
    test_close_failure();
    return failures == 0 ? 0 : 1;
}
