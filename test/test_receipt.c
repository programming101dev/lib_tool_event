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
extern void p101_tool_event_test_force_receipt_failure(int stage);
extern int  p101_tool_event_test_put_json_string(FILE *stream, const char *value);

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

static void test_tool_outcomes(void)
{
    static const char *const names[] = {
        "clean",
        "findings",
        "refused",
        "incomplete",
        "unsupported",
        "tool-error",
    };

    for(size_t index = 0U; index < sizeof(names) / sizeof(names[0]); index++)
    {
        p101_tool_outcome outcome;

        outcome = (p101_tool_outcome)index;
        EXPECT(strcmp(p101_tool_outcome_name(outcome), names[index]) == 0);
        EXPECT(p101_tool_outcome_exit_status(outcome) == (index == 0U ? 0 : (index == 1U ? 1 : 2)));
    }
    EXPECT(p101_tool_outcome_name((p101_tool_outcome)99) == NULL);
    EXPECT(p101_tool_outcome_name((p101_tool_outcome)-1) == NULL);
    EXPECT(p101_tool_outcome_exit_status((p101_tool_outcome)99) == 2);
    EXPECT(strcmp(p101_tool_failure_reason_name(P101_TOOL_FAILURE_NONE), "none") == 0);
    EXPECT(strcmp(p101_tool_failure_reason_name(P101_TOOL_FAILURE_FINDINGS_PRESENT), "findings-present") == 0);
    EXPECT(strcmp(p101_tool_failure_reason_name(P101_TOOL_FAILURE_INPUT_REFUSED), "input-refused") == 0);
    EXPECT(strcmp(p101_tool_failure_reason_name(P101_TOOL_FAILURE_EVIDENCE_INCOMPLETE), "evidence-incomplete") == 0);
    EXPECT(strcmp(p101_tool_failure_reason_name(P101_TOOL_FAILURE_UNSUPPORTED_INPUT), "unsupported-input") == 0);
    EXPECT(strcmp(p101_tool_failure_reason_name(P101_TOOL_FAILURE_TOOL_ERROR), "tool-error") == 0);
    EXPECT(p101_tool_failure_reason_name((p101_tool_failure_reason)99) == NULL);
    EXPECT(p101_tool_failure_reason_name((p101_tool_failure_reason)-1) == NULL);
}

P101_ATTR_SEMANTIC_ROLE("p101:boundary-case:boundary:durable-tool-receipt:identity_mismatch")

static void test_run_receipt_json(void)
{
    struct p101_error                      *err;
    struct p101_tool_event_fingerprint      fingerprint;
    struct p101_tool_run_receipt            receipt;
    struct p101_tool_run_receipt_validation validation;
    FILE                                   *stream;
    char                                    output[2048];
    size_t                                  count;

    err    = p101_error_create(false);
    stream = tmpfile();
    EXPECT(err != NULL);
    EXPECT(stream != NULL);
    fingerprint.bytes         = 12U;
    fingerprint.records       = 2U;
    fingerprint.fnv1a64       = UINT64_C(0x1234);
    fingerprint.final_newline = 1;
    receipt.tool_name         = "p101-test";
    receipt.tool_version      = "1";
    receipt.input_schema      = "test-v1";
    receipt.input_identity    = "file\"\\\b\f\n\r\t\x01name";
    receipt.policy_schema     = "policy-v1";
    receipt.policy_identity   = "sha256:policy";
    receipt.run_identity      = "run-1";
    receipt.outcome           = P101_TOOL_OUTCOME_FINDINGS;
    receipt.failure_reason    = P101_TOOL_FAILURE_FINDINGS_PRESENT;
    receipt.failed_stage      = "analysis";
    receipt.first_diagnostic  = "P101-FD-001 descriptor remains open";
    receipt.checks_attempted  = 3U;
    receipt.checks_completed  = 3U;
    receipt.does_not_prove    = "external truth";

    EXPECT(p101_tool_run_receipt_write_json(err, stream, &receipt, &fingerprint) == 0);
    rewind(stream);
    count         = fread(output, 1U, sizeof(output) - 1U, stream);
    output[count] = '\0';
    EXPECT(strstr(output, "\"schema\":\"p101-tool-run-receipt-v4\"") != NULL);
    EXPECT(strstr(output, "\"policy\":{\"schema\":\"policy-v1\",\"identity\":\"sha256:policy\"}") != NULL);
    EXPECT(strstr(output, "\"run_identity\":\"run-1\"") != NULL);
    EXPECT(strstr(output, "\"outcome\":\"findings\"") != NULL);
    EXPECT(strstr(output, "\"failure\":{\"reason\":\"findings-present\",\"stage\":\"analysis\",\"first_diagnostic\":\"P101-FD-001 descriptor remains open\"}") != NULL);
    EXPECT(strstr(output, "\"identity\":\"file\\\"\\\\\\b\\f\\n\\r\\t\\u0001name\"") != NULL);
    EXPECT(strstr(output, "\"value\":\"0000000000001234\"") != NULL);
    EXPECT(strstr(output, "\"receipt_digest\":{\"algorithm\":\"fnv1a64-semantic-v1\"") != NULL);
    EXPECT(count > 0U && output[count - 1U] == '\n');
    EXPECT(p101_tool_run_receipt_digest(&receipt, &fingerprint) != 0U);
    EXPECT(p101_tool_run_receipt_validate_json(err, output, &validation) == 0);
    EXPECT(validation.status == P101_TOOL_RECEIPT_VALID);
    EXPECT(validation.outcome == P101_TOOL_OUTCOME_FINDINGS);
    EXPECT(validation.failure_reason == P101_TOOL_FAILURE_FINDINGS_PRESENT);
    EXPECT(validation.checks_attempted == 3U);
    EXPECT(validation.checks_completed == 3U);
    EXPECT(validation.fingerprint_present != 0);

    {
        char *identity = strstr(output, "file");

        EXPECT(identity != NULL);
        if(identity != NULL)
        {
            identity[0] = 'g';
            EXPECT(p101_tool_run_receipt_validate_json(err, output, &validation) == 0);
            EXPECT(validation.status == P101_TOOL_RECEIPT_BAD_DIGEST);
            identity[0] = 'f';
        }
    }
    {
        char *version = strstr(output, "receipt-v4");

        EXPECT(version != NULL);
        if(version != NULL)
        {
            version[9] = '3';
            EXPECT(p101_tool_run_receipt_validate_json(err, output, &validation) == 0);
            EXPECT(validation.status == P101_TOOL_RECEIPT_BAD_VERSION);
            version[9] = '4';
        }
    }
    output[count - 2U] = '\0';
    EXPECT(p101_tool_run_receipt_validate_json(err, output, &validation) == 0);
    EXPECT(validation.status == P101_TOOL_RECEIPT_INVALID);
    output[count - 2U] = '}';
    {
        char path[] = "/tmp/p101-tool-run-receipt-XXXXXX";
        int  fd     = mkstemp(path);

        EXPECT(fd >= 0);
        if(fd >= 0)
        {
            EXPECT(write(fd, output, count) == (ssize_t)count);
            EXPECT(close(fd) == 0);
            EXPECT(p101_tool_run_receipt_validate_file(err, path, count, &validation) == 0);
            EXPECT(validation.status == P101_TOOL_RECEIPT_VALID);
            reset_error(&err);
            EXPECT(p101_tool_run_receipt_validate_file(err, path, count - 1U, &validation) == -1);
            EXPECT(p101_error_has_error(err));
            reset_error(&err);
            EXPECT(unlink(path) == 0);
        }
    }

    receipt.checks_completed = 4U;
    EXPECT(p101_tool_run_receipt_write_json(err, stream, &receipt, NULL) == -1);
    reset_error(&err);
    receipt.checks_completed = 3U;
    receipt.outcome          = (p101_tool_outcome)99;
    EXPECT(p101_tool_run_receipt_write_json(err, stream, &receipt, NULL) == -1);
    reset_error(&err);
    EXPECT(p101_tool_run_receipt_write_json(err, NULL, &receipt, NULL) == -1);

    fclose(stream);
    p101_error_destroy(err);
}

static void test_run_receipt_failures(void)
{
    struct p101_error                 *err;
    struct p101_tool_event_fingerprint fingerprint = {0};
    struct p101_tool_run_receipt       receipt;
    FILE                              *stream;
    char                              *long_text;

    err                      = p101_error_create(false);
    receipt.tool_name        = "tool";
    receipt.tool_version     = "1";
    receipt.input_schema     = "schema";
    receipt.input_identity   = "identity";
    receipt.policy_schema    = "policy";
    receipt.policy_identity  = "policy-identity";
    receipt.run_identity     = "run";
    receipt.outcome          = P101_TOOL_OUTCOME_CLEAN;
    receipt.failure_reason   = P101_TOOL_FAILURE_NONE;
    receipt.failed_stage     = "";
    receipt.first_diagnostic = "";
    receipt.checks_attempted = 1U;
    receipt.checks_completed = 1U;
    receipt.does_not_prove   = "limits";
    stream                   = tmpfile();
    EXPECT(err != NULL);
    EXPECT(stream != NULL);

    EXPECT(p101_tool_run_receipt_write_json(err, stream, NULL, NULL) == -1);
    reset_error(&err);
    receipt.tool_name = NULL;
    EXPECT(p101_tool_run_receipt_write_json(err, stream, &receipt, NULL) == -1);
    reset_error(&err);
    receipt.tool_name    = "tool";
    receipt.tool_version = NULL;
    EXPECT(p101_tool_run_receipt_write_json(err, stream, &receipt, NULL) == -1);
    reset_error(&err);
    receipt.tool_version = "1";
    receipt.input_schema = NULL;
    EXPECT(p101_tool_run_receipt_write_json(err, stream, &receipt, NULL) == -1);
    reset_error(&err);
    receipt.input_schema   = "schema";
    receipt.input_identity = NULL;
    EXPECT(p101_tool_run_receipt_write_json(err, stream, &receipt, NULL) == -1);
    reset_error(&err);
    receipt.input_identity = "identity";
    receipt.policy_schema  = NULL;
    EXPECT(p101_tool_run_receipt_write_json(err, stream, &receipt, NULL) == -1);
    reset_error(&err);
    receipt.policy_schema   = "policy";
    receipt.policy_identity = NULL;
    EXPECT(p101_tool_run_receipt_write_json(err, stream, &receipt, NULL) == -1);
    reset_error(&err);
    receipt.policy_identity = "policy-identity";
    receipt.run_identity    = NULL;
    EXPECT(p101_tool_run_receipt_write_json(err, stream, &receipt, NULL) == -1);
    reset_error(&err);
    receipt.run_identity   = "run";
    receipt.does_not_prove = NULL;
    EXPECT(p101_tool_run_receipt_write_json(err, stream, &receipt, NULL) == -1);
    reset_error(&err);
    receipt.does_not_prove = "limits";
    receipt.outcome        = P101_TOOL_OUTCOME_FINDINGS;
    EXPECT(p101_tool_run_receipt_write_json(err, stream, &receipt, NULL) == -1);
    reset_error(&err);
    receipt.failure_reason = (p101_tool_failure_reason)99;
    EXPECT(p101_tool_run_receipt_write_json(err, stream, &receipt, NULL) == -1);
    reset_error(&err);
    receipt.failure_reason = P101_TOOL_FAILURE_NONE;
    receipt.outcome        = P101_TOOL_OUTCOME_CLEAN;
    receipt.failure_reason = P101_TOOL_FAILURE_FINDINGS_PRESENT;
    EXPECT(p101_tool_run_receipt_write_json(err, stream, &receipt, NULL) == -1);
    reset_error(&err);
    receipt.failure_reason = P101_TOOL_FAILURE_NONE;
    receipt.failed_stage   = "unexpected";
    EXPECT(p101_tool_run_receipt_write_json(err, stream, &receipt, NULL) == -1);
    reset_error(&err);
    receipt.failed_stage     = "";
    receipt.first_diagnostic = "unexpected";
    EXPECT(p101_tool_run_receipt_write_json(err, stream, &receipt, NULL) == -1);
    reset_error(&err);
    receipt.first_diagnostic = "";
    receipt.outcome          = P101_TOOL_OUTCOME_FINDINGS;
    receipt.failure_reason   = P101_TOOL_FAILURE_FINDINGS_PRESENT;
    receipt.failed_stage     = "";
    EXPECT(p101_tool_run_receipt_write_json(err, stream, &receipt, NULL) == -1);
    reset_error(&err);
    receipt.failed_stage     = "analysis";
    receipt.first_diagnostic = "";
    EXPECT(p101_tool_run_receipt_write_json(err, stream, &receipt, NULL) == -1);
    reset_error(&err);
    receipt.outcome          = P101_TOOL_OUTCOME_CLEAN;
    receipt.failure_reason   = P101_TOOL_FAILURE_NONE;
    receipt.failed_stage     = "";
    receipt.first_diagnostic = "";
    receipt.failed_stage     = NULL;
    EXPECT(p101_tool_run_receipt_write_json(err, stream, &receipt, NULL) == -1);
    reset_error(&err);
    receipt.failed_stage     = "";
    receipt.first_diagnostic = NULL;
    EXPECT(p101_tool_run_receipt_write_json(err, stream, &receipt, NULL) == -1);
    reset_error(&err);
    receipt.first_diagnostic = "";

    for(int stage = 1; stage <= 3; stage++)
    {
        p101_tool_event_test_force_receipt_failure(stage);
        EXPECT(p101_tool_run_receipt_write_json(err, stream, &receipt, &fingerprint) == -1);
        EXPECT(p101_error_has_error(err));
        reset_error(&err);
    }

    long_text = malloc(P101_TOOL_EVENT_RECEIPT_TEXT_MAX_BYTES + 2U);
    EXPECT(long_text != NULL);
    if(long_text != NULL)
    {
        memset(long_text, 'x', P101_TOOL_EVENT_RECEIPT_TEXT_MAX_BYTES + 1U);
        long_text[P101_TOOL_EVENT_RECEIPT_TEXT_MAX_BYTES + 1U] = '\0';
        EXPECT(p101_tool_event_test_put_json_string(stream, long_text) == -1);
        free(long_text);
    }
    EXPECT(p101_tool_event_test_put_json_string(NULL, "value") == -1);
    EXPECT(p101_tool_event_test_put_json_string(stream, NULL) == -1);

    fclose(stream);
    stream = fopen(__FILE__, "r");
    EXPECT(stream != NULL);
    if(stream != NULL)
    {
        EXPECT(p101_tool_event_test_put_json_string(stream, "value") == -1);
        fclose(stream);
    }
    p101_error_destroy(err);
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

P101_ATTR_SEMANTIC_ROLE("p101:boundary-case:boundary:durable-tool-receipt:resource_limit")

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
    test_tool_outcomes();
    test_run_receipt_json();
    test_run_receipt_failures();
    test_invalid_arguments();
    test_empty_and_unterminated_files();
    test_record_and_byte_limits();
    test_read_failure();
    test_close_failure();
    return failures == 0 ? 0 : 1;
}
