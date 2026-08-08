#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <p101_record/record.h>
#include <p101_tool_event/receipt.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

enum
{
    READ_BUFFER_SIZE         = 4096,
    FNV_WORD_BITS            = 32,
    DIGEST_HEX_LEN           = 16,
    DECIMAL_BASE             = 10,
    BITS_PER_BYTE            = 8,
    JSON_UNICODE_HEX_DIGITS  = 4,
    RECEIPT_TOKEN_TEXT_SIZE  = 32,
    RECEIPT_SCHEMA_TEXT_SIZE = 64
};

enum receipt_text_index
{
    RECEIPT_TOOL_NAME = 0,
    RECEIPT_TOOL_VERSION,
    RECEIPT_INPUT_SCHEMA,
    RECEIPT_INPUT_IDENTITY,
    RECEIPT_POLICY_SCHEMA,
    RECEIPT_POLICY_IDENTITY,
    RECEIPT_RUN_IDENTITY,
    RECEIPT_FAILED_STAGE,
    RECEIPT_FIRST_DIAGNOSTIC,
    RECEIPT_DOES_NOT_PROVE,
    RECEIPT_TEXT_FIELD_COUNT
};

static const uint64_t FNV1A64_OFFSET = UINT64_C(14695981039346656037);

struct parsed_receipt
{
    struct p101_tool_run_receipt       receipt;
    char                               text[RECEIPT_TEXT_FIELD_COUNT][P101_TOOL_EVENT_RECEIPT_TEXT_MAX_BYTES + 1U];
    struct p101_tool_event_fingerprint fingerprint;
    int                                fingerprint_present;
    uint64_t                           claimed_digest;
};

static int      close_receipt_file(int fd);
static uint64_t digest_text(uint64_t hash, const char *label, const char *value);
static uint64_t digest_size(uint64_t hash, const char *label, size_t value);
static uint64_t digest_u64(uint64_t hash, const char *label, uint64_t value);
static uint64_t fnv1a64_bytes(uint64_t hash, const unsigned char *bytes, size_t size);
static int      receipt_is_valid(const struct p101_tool_run_receipt *receipt);
static int      receipt_parse_boolean(const char **cursor, int *value);
static int      receipt_parse_hex(const char **cursor, uint64_t *value);
static int      receipt_parse_literal(const char **cursor, const char *literal);
static int      receipt_parse_size(const char **cursor, size_t *value);
static int      receipt_parse_document(const char *text, struct parsed_receipt *parsed);
static int      receipt_put_json_string(FILE *stream, const char *value);
static int      receipt_write_failed(struct p101_error *err);

#ifdef P101_TOOL_EVENT_TESTING
static int forced_close_error;
static int forced_receipt_failure_stage;

void p101_tool_event_test_force_close_error(int error_number)
{
    forced_close_error = error_number;
}

void p101_tool_event_test_force_receipt_failure(int stage)
{
    forced_receipt_failure_stage = stage;
}

int p101_tool_event_test_put_json_string(FILE *stream, const char *value)
{
    return receipt_put_json_string(stream, value);
}
#endif

static int close_receipt_file(int fd)
{
    int result;

#ifdef P101_TOOL_EVENT_TESTING
    if(forced_close_error != 0)
    {
        int error_number;

        error_number       = forced_close_error;
        forced_close_error = 0;
        result             = close(fd);
        (void)result;
        errno  = error_number;
        result = -1;
        goto p101_single_exit_;
    }
#endif
    result = close(fd);
    goto p101_single_exit_;

p101_single_exit_:
    return result;
}

static int receipt_is_valid(const struct p101_tool_run_receipt *receipt)
{
    int         p101_single_result_;
    const char *outcome_name;
    const char *failure_name;

    if(receipt == NULL || receipt->tool_name == NULL || receipt->tool_version == NULL || receipt->input_schema == NULL || receipt->input_identity == NULL || receipt->policy_schema == NULL || receipt->policy_identity == NULL || receipt->run_identity == NULL ||
       receipt->failed_stage == NULL || receipt->first_diagnostic == NULL || receipt->does_not_prove == NULL)
    {
        p101_single_result_ = 0;
        goto p101_single_exit_;
    }
    if(receipt->checks_completed > receipt->checks_attempted)
    {
        p101_single_result_ = 0;
        goto p101_single_exit_;
    }
    outcome_name = p101_tool_outcome_name(receipt->outcome);
    failure_name = p101_tool_failure_reason_name(receipt->failure_reason);
    if(outcome_name == NULL || failure_name == NULL)
    {
        p101_single_result_ = 0;
        goto p101_single_exit_;
    }
    if((int)receipt->failure_reason != (int)receipt->outcome)
    {
        p101_single_result_ = 0;
        goto p101_single_exit_;
    }
    if(receipt->outcome == P101_TOOL_OUTCOME_CLEAN)
    {
        p101_single_result_ = receipt->failed_stage[0] == '\0' && receipt->first_diagnostic[0] == '\0';
        goto p101_single_exit_;
    }
    p101_single_result_ = receipt->failed_stage[0] != '\0' && receipt->first_diagnostic[0] != '\0';
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static int receipt_put_json_string(FILE *stream, const char *value)
{
    int    p101_single_result_;
    size_t length;

    // GCOVR_EXCL_BR_START: public receipt validation prevents null text; the
    // test-only entry point exercises this defensive helper contract.
    if(stream == NULL || value == NULL)
    {
        errno               = EINVAL;
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    // GCOVR_EXCL_BR_STOP
    length = strlen(value);
    if(length > P101_TOOL_EVENT_RECEIPT_TEXT_MAX_BYTES)
    {
        errno               = EFBIG;
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    p101_single_result_ = p101_record_write_json_string(stream, value);
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

static int receipt_parse_literal(const char **cursor, const char *literal)
{
    size_t length;
    int    comparison;
    int    result;

    length     = strlen(literal);
    result     = -1;
    comparison = strncmp(*cursor, literal, length);
    if(comparison == 0)
    {
        *cursor += length;
        result = 0;
    }
    return result;
}

static int receipt_parse_size(const char **cursor, size_t *value)
{
    size_t parsed = 0U;
    int    result = -1;

    if(**cursor < '0' || **cursor > '9')
    {
        goto done;
    }
    while(**cursor >= '0' && **cursor <= '9')
    {
        size_t digit = (size_t)(**cursor - '0');

        if(parsed > (SIZE_MAX - digit) / DECIMAL_BASE)
        {
            goto done;
        }
        parsed = (parsed * DECIMAL_BASE) + digit;
        (*cursor)++;
    }
    *value = parsed;
    result = 0;

done:
    return result;
}

static int receipt_parse_boolean(const char **cursor, int *value)
{
    int parse_status;
    int result;

    result       = 0;
    parse_status = receipt_parse_literal(cursor, "true");
    if(parse_status == 0)
    {
        *value = 1;
    }
    else
    {
        parse_status = receipt_parse_literal(cursor, "false");
        if(parse_status == 0)
        {
            *value = 0;
        }
        else
        {
            result = -1;
        }
    }
    return result;
}

static int receipt_parse_hex(const char **cursor, uint64_t *value)
{
    uint64_t parsed = 0U;
    int      result = -1;

    for(size_t index = 0U; index < DIGEST_HEX_LEN; index++)
    {
        unsigned char ch = (unsigned char)(*cursor)[index];
        unsigned int  digit;

        if(ch >= '0' && ch <= '9')
        {
            digit = (unsigned int)(ch - '0');
        }
        else if(ch >= 'a' && ch <= 'f')
        {
            digit = (unsigned int)(ch - 'a') + DECIMAL_BASE;
        }
        else
        {
            goto done;
        }
        parsed = (parsed << JSON_UNICODE_HEX_DIGITS) | digit;
    }
    *cursor += DIGEST_HEX_LEN;
    *value = parsed;
    result = 0;

done:
    return result;
}

static int receipt_parse_document(const char *text, struct parsed_receipt *parsed)
{
    const char *cursor = text;
    char        outcome[RECEIPT_TOKEN_TEXT_SIZE];
    char        failure[RECEIPT_TOKEN_TEXT_SIZE];
    char        schema[RECEIPT_SCHEMA_TEXT_SIZE];
    const char *token_name;
    size_t      literal_length;
    int         comparison;
    int         parse_status;
    int         result;

    result = -1;
    memset(parsed, 0, sizeof(*parsed));
#define REQUIRE_RECEIPT_PARSE(expression)                                                                                                                                                                                                                          \
    do                                                                                                                                                                                                                                                             \
    {                                                                                                                                                                                                                                                              \
        parse_status = (expression);                                                                                                                                                                                                                               \
        if(parse_status != 0)                                                                                                                                                                                                                                      \
        {                                                                                                                                                                                                                                                          \
            goto done;                                                                                                                                                                                                                                             \
        }                                                                                                                                                                                                                                                          \
    } while(0)

    REQUIRE_RECEIPT_PARSE(receipt_parse_literal(&cursor, "{\"schema\":"));
    REQUIRE_RECEIPT_PARSE(p101_record_read_json_string(&cursor, schema, sizeof(schema)));
    comparison = strcmp(schema, P101_TOOL_RUN_RECEIPT_SCHEMA_NAME);
    if(comparison != 0)
    {
        result = 1;
        goto done;
    }
    REQUIRE_RECEIPT_PARSE(receipt_parse_literal(&cursor, ",\"tool\":{\"name\":"));
    REQUIRE_RECEIPT_PARSE(p101_record_read_json_string(&cursor, parsed->text[RECEIPT_TOOL_NAME], sizeof(parsed->text[RECEIPT_TOOL_NAME])));
    REQUIRE_RECEIPT_PARSE(receipt_parse_literal(&cursor, ",\"version\":"));
    REQUIRE_RECEIPT_PARSE(p101_record_read_json_string(&cursor, parsed->text[RECEIPT_TOOL_VERSION], sizeof(parsed->text[RECEIPT_TOOL_VERSION])));
    REQUIRE_RECEIPT_PARSE(receipt_parse_literal(&cursor, "},\"input\":{\"schema\":"));
    REQUIRE_RECEIPT_PARSE(p101_record_read_json_string(&cursor, parsed->text[RECEIPT_INPUT_SCHEMA], sizeof(parsed->text[RECEIPT_INPUT_SCHEMA])));
    REQUIRE_RECEIPT_PARSE(receipt_parse_literal(&cursor, ",\"identity\":"));
    REQUIRE_RECEIPT_PARSE(p101_record_read_json_string(&cursor, parsed->text[RECEIPT_INPUT_IDENTITY], sizeof(parsed->text[RECEIPT_INPUT_IDENTITY])));
    REQUIRE_RECEIPT_PARSE(receipt_parse_literal(&cursor, "},\"policy\":{\"schema\":"));
    REQUIRE_RECEIPT_PARSE(p101_record_read_json_string(&cursor, parsed->text[RECEIPT_POLICY_SCHEMA], sizeof(parsed->text[RECEIPT_POLICY_SCHEMA])));
    REQUIRE_RECEIPT_PARSE(receipt_parse_literal(&cursor, ",\"identity\":"));
    REQUIRE_RECEIPT_PARSE(p101_record_read_json_string(&cursor, parsed->text[RECEIPT_POLICY_IDENTITY], sizeof(parsed->text[RECEIPT_POLICY_IDENTITY])));
    REQUIRE_RECEIPT_PARSE(receipt_parse_literal(&cursor, "},\"run_identity\":"));
    REQUIRE_RECEIPT_PARSE(p101_record_read_json_string(&cursor, parsed->text[RECEIPT_RUN_IDENTITY], sizeof(parsed->text[RECEIPT_RUN_IDENTITY])));
    REQUIRE_RECEIPT_PARSE(receipt_parse_literal(&cursor, ",\"outcome\":"));
    REQUIRE_RECEIPT_PARSE(p101_record_read_json_string(&cursor, outcome, sizeof(outcome)));
    REQUIRE_RECEIPT_PARSE(receipt_parse_literal(&cursor, ",\"failure\":{\"reason\":"));
    REQUIRE_RECEIPT_PARSE(p101_record_read_json_string(&cursor, failure, sizeof(failure)));
    REQUIRE_RECEIPT_PARSE(receipt_parse_literal(&cursor, ",\"stage\":"));
    REQUIRE_RECEIPT_PARSE(p101_record_read_json_string(&cursor, parsed->text[RECEIPT_FAILED_STAGE], sizeof(parsed->text[RECEIPT_FAILED_STAGE])));
    REQUIRE_RECEIPT_PARSE(receipt_parse_literal(&cursor, ",\"first_diagnostic\":"));
    REQUIRE_RECEIPT_PARSE(p101_record_read_json_string(&cursor, parsed->text[RECEIPT_FIRST_DIAGNOSTIC], sizeof(parsed->text[RECEIPT_FIRST_DIAGNOSTIC])));
    REQUIRE_RECEIPT_PARSE(receipt_parse_literal(&cursor, "},\"checks\":{\"attempted\":"));
    REQUIRE_RECEIPT_PARSE(receipt_parse_size(&cursor, &parsed->receipt.checks_attempted));
    REQUIRE_RECEIPT_PARSE(receipt_parse_literal(&cursor, ",\"completed\":"));
    REQUIRE_RECEIPT_PARSE(receipt_parse_size(&cursor, &parsed->receipt.checks_completed));
    REQUIRE_RECEIPT_PARSE(receipt_parse_literal(&cursor, "}"));

    parsed->receipt.tool_name        = parsed->text[RECEIPT_TOOL_NAME];
    parsed->receipt.tool_version     = parsed->text[RECEIPT_TOOL_VERSION];
    parsed->receipt.input_schema     = parsed->text[RECEIPT_INPUT_SCHEMA];
    parsed->receipt.input_identity   = parsed->text[RECEIPT_INPUT_IDENTITY];
    parsed->receipt.policy_schema    = parsed->text[RECEIPT_POLICY_SCHEMA];
    parsed->receipt.policy_identity  = parsed->text[RECEIPT_POLICY_IDENTITY];
    parsed->receipt.run_identity     = parsed->text[RECEIPT_RUN_IDENTITY];
    parsed->receipt.failed_stage     = parsed->text[RECEIPT_FAILED_STAGE];
    parsed->receipt.first_diagnostic = parsed->text[RECEIPT_FIRST_DIAGNOSTIC];

    for(int value = P101_TOOL_OUTCOME_CLEAN; value <= P101_TOOL_OUTCOME_TOOL_ERROR; value++)
    {
        token_name = p101_tool_outcome_name((p101_tool_outcome)value);
        comparison = strcmp(outcome, token_name);
        if(comparison == 0)
        {
            parsed->receipt.outcome = (p101_tool_outcome)value;
            break;
        }
    }
    for(int value = P101_TOOL_FAILURE_NONE; value <= P101_TOOL_FAILURE_TOOL_ERROR; value++)
    {
        token_name = p101_tool_failure_reason_name((p101_tool_failure_reason)value);
        comparison = strcmp(failure, token_name);
        if(comparison == 0)
        {
            parsed->receipt.failure_reason = (p101_tool_failure_reason)value;
            break;
        }
    }
    token_name = p101_tool_outcome_name(parsed->receipt.outcome);
    comparison = strcmp(outcome, token_name);
    if(comparison != 0)
    {
        goto done;
    }
    token_name = p101_tool_failure_reason_name(parsed->receipt.failure_reason);
    comparison = strcmp(failure, token_name);
    if(comparison != 0)
    {
        goto done;
    }

    literal_length = sizeof(",\"fingerprint\":") - 1U;
    comparison     = strncmp(cursor, ",\"fingerprint\":", literal_length);
    if(comparison == 0)
    {
        char algorithm[RECEIPT_SCHEMA_TEXT_SIZE];

        parsed->fingerprint_present = 1;
        REQUIRE_RECEIPT_PARSE(receipt_parse_literal(&cursor, ",\"fingerprint\":{\"algorithm\":"));
        REQUIRE_RECEIPT_PARSE(p101_record_read_json_string(&cursor, algorithm, sizeof(algorithm)));
        comparison = strcmp(algorithm, "fnv1a64-change-detector");
        if(comparison != 0)
        {
            goto done;
        }
        REQUIRE_RECEIPT_PARSE(receipt_parse_literal(&cursor, ",\"bytes\":"));
        REQUIRE_RECEIPT_PARSE(receipt_parse_size(&cursor, &parsed->fingerprint.bytes));
        REQUIRE_RECEIPT_PARSE(receipt_parse_literal(&cursor, ",\"records\":"));
        REQUIRE_RECEIPT_PARSE(receipt_parse_size(&cursor, &parsed->fingerprint.records));
        REQUIRE_RECEIPT_PARSE(receipt_parse_literal(&cursor, ",\"value\":\""));
        REQUIRE_RECEIPT_PARSE(receipt_parse_hex(&cursor, &parsed->fingerprint.fnv1a64));
        REQUIRE_RECEIPT_PARSE(receipt_parse_literal(&cursor, "\",\"final_newline\":"));
        REQUIRE_RECEIPT_PARSE(receipt_parse_boolean(&cursor, &parsed->fingerprint.final_newline));
        REQUIRE_RECEIPT_PARSE(receipt_parse_literal(&cursor, "}"));
    }
    REQUIRE_RECEIPT_PARSE(receipt_parse_literal(&cursor, ",\"receipt_digest\":{\"algorithm\":\"fnv1a64-semantic-v1\",\"value\":\""));
    REQUIRE_RECEIPT_PARSE(receipt_parse_hex(&cursor, &parsed->claimed_digest));
    REQUIRE_RECEIPT_PARSE(receipt_parse_literal(&cursor, "\"},\"does_not_prove\":"));
    REQUIRE_RECEIPT_PARSE(p101_record_read_json_string(&cursor, parsed->text[RECEIPT_DOES_NOT_PROVE], sizeof(parsed->text[RECEIPT_DOES_NOT_PROVE])));
    REQUIRE_RECEIPT_PARSE(receipt_parse_literal(&cursor, "}\n"));
    if(*cursor != '\0')
    {
        goto done;
    }
    parsed->receipt.does_not_prove = parsed->text[RECEIPT_DOES_NOT_PROVE];
    result                         = 0;

done:
#undef REQUIRE_RECEIPT_PARSE
    return result;
}

static int receipt_write_failed(struct p101_error *err)
{
    int error_number;

    error_number = errno;
    if(error_number == 0)
    {
        error_number = EIO;
    }
    P101_ERROR_RAISE_ERRNO(err, error_number);
    return -1;
}

static uint64_t fnv1a64_multiply(uint64_t value)
{
    /*
     * FNV-1a is defined modulo 2^64. Compute the low and high 32-bit words
     * separately so that the intentional wrap is not reported as undefined
     * behavior by builds that also instrument unsigned overflow.
     *
     * FNV1A64_PRIME is (256 * 2^32) + 435.
     */
    const uint64_t word_mask   = UINT64_C(0xffffffff);
    const uint64_t value_low   = value & word_mask;
    const uint64_t value_high  = value >> FNV_WORD_BITS;
    const uint64_t low_product = value_low * UINT64_C(435);
    const uint64_t high_word   = ((low_product >> FNV_WORD_BITS) + (value_low * UINT64_C(256)) + (value_high * UINT64_C(435))) & word_mask;

    return (high_word << FNV_WORD_BITS) | (low_product & word_mask);
}

static uint64_t fnv1a64_bytes(uint64_t hash, const unsigned char *bytes, size_t size)
{
    for(size_t index = 0U; index < size; index++)
    {
        hash ^= bytes[index];
        hash = fnv1a64_multiply(hash);
    }
    return hash;
}

static uint64_t digest_text(uint64_t hash, const char *label, const char *value)
{
    static const unsigned char separator = 0U;
    size_t                     length;

    length = strlen(label);
    hash   = fnv1a64_bytes(hash, (const unsigned char *)label, length);
    hash   = fnv1a64_bytes(hash, &separator, 1U);
    length = strlen(value);
    hash   = fnv1a64_bytes(hash, (const unsigned char *)value, length);
    hash   = fnv1a64_bytes(hash, &separator, 1U);
    return hash;
}

static uint64_t digest_u64(uint64_t hash, const char *label, uint64_t value)
{
    unsigned char bytes[sizeof(value)];

    for(size_t index = 0U; index < sizeof(value); index++)
    {
        size_t shift = (sizeof(value) - index - 1U) * BITS_PER_BYTE;

        bytes[index] = (unsigned char)(value >> shift);
    }
    hash = digest_text(hash, "field", label);
    hash = fnv1a64_bytes(hash, bytes, sizeof(bytes));
    return hash;
}

static uint64_t digest_size(uint64_t hash, const char *label, size_t value)
{
    hash = digest_u64(hash, label, value);
    return hash;
}

uint64_t p101_tool_run_receipt_digest(const struct p101_tool_run_receipt *receipt, const struct p101_tool_event_fingerprint *fingerprint)
{
    uint64_t    p101_single_result_;
    uint64_t    hash;
    const char *name;
    int         valid;

    valid = receipt_is_valid(receipt);
    if(!valid)
    {
        p101_single_result_ = 0U;
        goto p101_single_exit_;
    }
    hash = digest_text(FNV1A64_OFFSET, "schema", P101_TOOL_RUN_RECEIPT_SCHEMA_NAME);
    hash = digest_text(hash, "tool_name", receipt->tool_name);
    hash = digest_text(hash, "tool_version", receipt->tool_version);
    hash = digest_text(hash, "input_schema", receipt->input_schema);
    hash = digest_text(hash, "input_identity", receipt->input_identity);
    hash = digest_text(hash, "policy_schema", receipt->policy_schema);
    hash = digest_text(hash, "policy_identity", receipt->policy_identity);
    hash = digest_text(hash, "run_identity", receipt->run_identity);
    name = p101_tool_outcome_name(receipt->outcome);
    hash = digest_text(hash, "outcome", name);
    name = p101_tool_failure_reason_name(receipt->failure_reason);
    hash = digest_text(hash, "failure_reason", name);
    hash = digest_text(hash, "failed_stage", receipt->failed_stage);
    hash = digest_text(hash, "first_diagnostic", receipt->first_diagnostic);
    hash = digest_size(hash, "checks_attempted", receipt->checks_attempted);
    hash = digest_size(hash, "checks_completed", receipt->checks_completed);
    hash = digest_u64(hash, "fingerprint_present", fingerprint == NULL ? 0U : 1U);
    if(fingerprint != NULL)
    {
        hash = digest_size(hash, "fingerprint_bytes", fingerprint->bytes);
        hash = digest_size(hash, "fingerprint_records", fingerprint->records);
        hash = digest_u64(hash, "fingerprint_value", fingerprint->fnv1a64);
        hash = digest_u64(hash, "fingerprint_final_newline", fingerprint->final_newline != 0 ? 1U : 0U);
    }
    p101_single_result_ = digest_text(hash, "does_not_prove", receipt->does_not_prove);
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

int p101_tool_run_receipt_validate_json(struct p101_error *err, const char *text, struct p101_tool_run_receipt_validation *validation)
{
    int                    p101_single_result_;
    struct parsed_receipt *parsed;
    void                  *storage;
    uint64_t               actual_digest;
    int                    valid;
    int                    parse_result;
    int                    result;

    if(text == NULL || validation == NULL)
    {
        P101_ERROR_RAISE_CHECK(err);
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    memset(validation, 0, sizeof(*validation));
    validation->status = P101_TOOL_RECEIPT_INVALID;
    storage            = malloc(sizeof(*parsed));
    parsed             = (struct parsed_receipt *)storage;
    if(parsed == NULL)
    {
        P101_ERROR_RAISE_ERRNO(err, ENOMEM);
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }

    result       = 0;
    parse_result = receipt_parse_document(text, parsed);
    if(parse_result == 1)
    {
        validation->status = P101_TOOL_RECEIPT_BAD_VERSION;
        goto done;
    }
    valid = 0;
    if(parse_result == 0)
    {
        valid = receipt_is_valid(&parsed->receipt);
    }
    if(parse_result != 0 || !valid)
    {
        goto done;
    }
    actual_digest = p101_tool_run_receipt_digest(&parsed->receipt, parsed->fingerprint_present != 0 ? &parsed->fingerprint : NULL);
    if(actual_digest != parsed->claimed_digest)
    {
        validation->status = P101_TOOL_RECEIPT_BAD_DIGEST;
        goto done;
    }

    validation->status              = P101_TOOL_RECEIPT_VALID;
    validation->outcome             = parsed->receipt.outcome;
    validation->failure_reason      = parsed->receipt.failure_reason;
    validation->checks_attempted    = parsed->receipt.checks_attempted;
    validation->checks_completed    = parsed->receipt.checks_completed;
    validation->fingerprint_present = parsed->fingerprint_present;
    validation->receipt_digest      = actual_digest;

done:
    free(parsed);
    p101_single_result_ = result;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

int p101_tool_run_receipt_validate_file(struct p101_error *err, const char *path, size_t maximum_bytes, struct p101_tool_run_receipt_validation *validation)
{
    int         p101_single_result_;
    struct stat status;
    char       *text;
    size_t      file_size;
    size_t      used;
    int         fd;
    int         operation_status;
    int         result;
    void       *storage;

    if(path == NULL || maximum_bytes == 0U || validation == NULL)
    {
        P101_ERROR_RAISE_CHECK(err);
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if(fd < 0)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    text             = NULL;
    result           = -1;
    operation_status = fstat(fd, &status);
    if(operation_status != 0)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
        goto done;
    }
    if(status.st_size < 0 || (uintmax_t)status.st_size > maximum_bytes)
    {
        P101_ERROR_RAISE_ERRNO(err, EFBIG);
        goto done;
    }
    file_size = (size_t)status.st_size;
    /*
     * Zero initialization also makes an empty receipt an ordinary invalid
     * document. It avoids relying on the analyzer to connect fstat()'s size
     * with the read loop before the terminating byte is assigned below.
     */
    storage = calloc(file_size + 1U, sizeof(*text));
    text    = (char *)storage;
    if(text == NULL)
    {
        P101_ERROR_RAISE_ERRNO(err, ENOMEM);
        goto done;
    }
    used = 0U;
    while(used < file_size)
    {
        ssize_t count = read(fd, text + used, file_size - used);

        if(count < 0 && errno == EINTR)
        {
            continue;
        }
        if(count <= 0)
        {
            P101_ERROR_RAISE_ERRNO(err, count < 0 ? errno : EIO);
            goto done;
        }
        used += (size_t)count;
    }
    text[used] = '\0';
    result     = p101_tool_run_receipt_validate_json(err, text, validation);

done:
    free(text);
    operation_status = close_receipt_file(fd);
    if(operation_status != 0 && result == 0)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
        result = -1;
    }
    p101_single_result_ = result;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

int p101_tool_event_fingerprint_file(struct p101_error *err, const char *path, size_t maximum_bytes, size_t maximum_records, struct p101_tool_event_fingerprint *fingerprint)
{
    int      p101_single_result_;
    int      fd;
    uint64_t hash;
    size_t   newline_count;
    int      final_newline;
    int      operation_status;
    int      result;

    if(path == NULL || fingerprint == NULL || maximum_bytes == 0U || maximum_records == 0U)
    {
        P101_ERROR_RAISE_CHECK(err);
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }

    memset(fingerprint, 0, sizeof(*fingerprint));
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if(fd < 0)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }

    hash          = FNV1A64_OFFSET;
    newline_count = 0U;
    final_newline = 0;
    result        = 0;

    for(;;)
    {
        unsigned char buffer[READ_BUFFER_SIZE];
        ssize_t       count;
        size_t        count_size;

        count = read(fd, buffer, sizeof(buffer));
        if(count == 0)
        {
            break;
        }
        if(count < 0)
        {
            P101_ERROR_RAISE_ERRNO(err, errno);
            result = -1;
            break;
        }
        count_size = (size_t)count;
        if(count_size > maximum_bytes || fingerprint->bytes > maximum_bytes - count_size)
        {
            P101_ERROR_RAISE_ERRNO(err, EFBIG);
            result = -1;
            break;
        }

        for(size_t i = 0U; i < count_size; i++)
        {
            hash ^= buffer[i];
            hash = fnv1a64_multiply(hash);
            if(buffer[i] == '\n')
            {
                newline_count++;
                if(newline_count > maximum_records)
                {
                    P101_ERROR_RAISE_ERRNO(err, EFBIG);
                    result = -1;
                    break;
                }
            }
        }
        fingerprint->bytes += count_size;
        final_newline = buffer[count_size - 1U] == '\n';
        if(result != 0)
        {
            break;
        }
    }

    if(result == 0 && fingerprint->bytes > 0U && final_newline == 0)
    {
        newline_count++;
        if(newline_count > maximum_records)
        {
            P101_ERROR_RAISE_ERRNO(err, EFBIG);
            result = -1;
        }
    }

    operation_status = close_receipt_file(fd);
    if(operation_status != 0 && result == 0)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
        result = -1;
    }

    if(result == 0)
    {
        fingerprint->records       = newline_count;
        fingerprint->fnv1a64       = hash;
        fingerprint->final_newline = final_newline;
    }
    else
    {
        memset(fingerprint, 0, sizeof(*fingerprint));
    }

    p101_single_result_ = result;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

const char *p101_tool_outcome_name(p101_tool_outcome outcome)
{
    const char              *p101_single_result_;
    static const char *const names[] = {
        "clean",
        "findings",
        "refused",
        "incomplete",
        "unsupported",
        "tool-error",
    };

    if(outcome > P101_TOOL_OUTCOME_TOOL_ERROR)
    {
        p101_single_result_ = NULL;
        goto p101_single_exit_;
    }
    p101_single_result_ = names[outcome];
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

const char *p101_tool_failure_reason_name(p101_tool_failure_reason reason)
{
    const char              *p101_single_result_;
    static const char *const names[] = {
        "none",
        "findings-present",
        "input-refused",
        "evidence-incomplete",
        "unsupported-input",
        "tool-error",
    };

    if(reason > P101_TOOL_FAILURE_TOOL_ERROR)
    {
        p101_single_result_ = NULL;
        goto p101_single_exit_;
    }
    p101_single_result_ = names[reason];
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

const char *p101_tool_receipt_validation_status_name(p101_tool_receipt_validation_status status)
{
    const char              *p101_single_result_;
    static const char *const names[] = {
        "valid",
        "invalid",
        "bad-version",
        "bad-digest",
    };

    if(status > P101_TOOL_RECEIPT_BAD_DIGEST)
    {
        p101_single_result_ = NULL;
        goto p101_single_exit_;
    }
    p101_single_result_ = names[status];
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

int p101_tool_outcome_exit_status(p101_tool_outcome outcome)
{
    int p101_single_result_;
    if(outcome == P101_TOOL_OUTCOME_CLEAN)
    {
        p101_single_result_ = 0;
        goto p101_single_exit_;
    }
    if(outcome == P101_TOOL_OUTCOME_FINDINGS)
    {
        p101_single_result_ = 1;
        goto p101_single_exit_;
    }
    p101_single_result_ = 2;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

int p101_tool_run_receipt_write_json(struct p101_error *err, FILE *stream, const struct p101_tool_run_receipt *receipt, const struct p101_tool_event_fingerprint *fingerprint)
{
    int         p101_single_result_;
    const char *failure_reason_name;
    const char *outcome_name;
    const char *final_newline_text;
    uint64_t    receipt_digest;
    int         operation_status;
    int         valid;

    valid = receipt_is_valid(receipt);
    if(stream == NULL || !valid)
    {
        P101_ERROR_RAISE_CHECK(err);
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    outcome_name        = p101_tool_outcome_name(receipt->outcome);
    failure_reason_name = p101_tool_failure_reason_name(receipt->failure_reason);
    receipt_digest      = p101_tool_run_receipt_digest(receipt, fingerprint);
#ifdef P101_TOOL_EVENT_TESTING
    if(forced_receipt_failure_stage == 1)
    {
        forced_receipt_failure_stage = 0;
        errno                        = 0;
        p101_single_result_          = receipt_write_failed(err);
        goto p101_single_exit_;
    }
#endif
#define REQUIRE_RECEIPT_WRITE(expression)                                                                                                                                                                                                                          \
    do                                                                                                                                                                                                                                                             \
    {                                                                                                                                                                                                                                                              \
        operation_status = (expression);                                                                                                                                                                                                                           \
        if(operation_status < 0)                                                                                                                                                                                                                                   \
        {                                                                                                                                                                                                                                                          \
            goto write_failed;                                                                                                                                                                                                                                     \
        }                                                                                                                                                                                                                                                          \
    } while(0)

    // GCOVR_EXCL_BR_START: test builds inject each writer phase immediately
    // above/below these calls; individual libc write sites are not portable.
    REQUIRE_RECEIPT_WRITE(fputs("{\"schema\":\"" P101_TOOL_RUN_RECEIPT_SCHEMA_NAME "\",\"tool\":{\"name\":", stream));
    REQUIRE_RECEIPT_WRITE(receipt_put_json_string(stream, receipt->tool_name));
    REQUIRE_RECEIPT_WRITE(fputs(",\"version\":", stream));
    REQUIRE_RECEIPT_WRITE(receipt_put_json_string(stream, receipt->tool_version));
    REQUIRE_RECEIPT_WRITE(fputs("},\"input\":{\"schema\":", stream));
    REQUIRE_RECEIPT_WRITE(receipt_put_json_string(stream, receipt->input_schema));
    REQUIRE_RECEIPT_WRITE(fputs(",\"identity\":", stream));
    REQUIRE_RECEIPT_WRITE(receipt_put_json_string(stream, receipt->input_identity));
    REQUIRE_RECEIPT_WRITE(fputs("},\"policy\":{\"schema\":", stream));
    REQUIRE_RECEIPT_WRITE(receipt_put_json_string(stream, receipt->policy_schema));
    REQUIRE_RECEIPT_WRITE(fputs(",\"identity\":", stream));
    REQUIRE_RECEIPT_WRITE(receipt_put_json_string(stream, receipt->policy_identity));
    REQUIRE_RECEIPT_WRITE(fputs("},\"run_identity\":", stream));
    REQUIRE_RECEIPT_WRITE(receipt_put_json_string(stream, receipt->run_identity));
    REQUIRE_RECEIPT_WRITE(fputs(",\"outcome\":", stream));
    REQUIRE_RECEIPT_WRITE(receipt_put_json_string(stream, outcome_name));
    REQUIRE_RECEIPT_WRITE(fputs(",\"failure\":{\"reason\":", stream));
    REQUIRE_RECEIPT_WRITE(receipt_put_json_string(stream, failure_reason_name));
    REQUIRE_RECEIPT_WRITE(fputs(",\"stage\":", stream));
    REQUIRE_RECEIPT_WRITE(receipt_put_json_string(stream, receipt->failed_stage));
    REQUIRE_RECEIPT_WRITE(fputs(",\"first_diagnostic\":", stream));
    REQUIRE_RECEIPT_WRITE(receipt_put_json_string(stream, receipt->first_diagnostic));
    REQUIRE_RECEIPT_WRITE(fprintf(stream, "},\"checks\":{\"attempted\":%zu,\"completed\":%zu}", receipt->checks_attempted, receipt->checks_completed));
    // GCOVR_EXCL_BR_STOP
#ifdef P101_TOOL_EVENT_TESTING
    if(forced_receipt_failure_stage == 2)
    {
        forced_receipt_failure_stage = 0;
        errno                        = EIO;
        p101_single_result_          = receipt_write_failed(err);
        goto p101_single_exit_;
    }
#endif
    // GCOVR_EXCL_BR_START: the staged fingerprint failure above verifies this
    // phase without relying on a platform-specific failing FILE implementation.
    if(fingerprint != NULL)
    {
        final_newline_text = fingerprint->final_newline != 0 ? "true" : "false";
        operation_status =
            fprintf(stream, ",\"fingerprint\":{\"algorithm\":\"fnv1a64-change-detector\",\"bytes\":%zu,\"records\":%zu,\"value\":\"%016" PRIx64 "\",\"final_newline\":%s}", fingerprint->bytes, fingerprint->records, fingerprint->fnv1a64, final_newline_text);
        if(operation_status < 0)
        {
            goto write_failed;
        }
    }
    // GCOVR_EXCL_BR_STOP
#ifdef P101_TOOL_EVENT_TESTING
    if(forced_receipt_failure_stage == 3)
    {
        forced_receipt_failure_stage = 0;
        errno                        = EIO;
        p101_single_result_          = receipt_write_failed(err);
        goto p101_single_exit_;
    }
#endif
    // GCOVR_EXCL_BR_START: the staged final failure above verifies propagation.
    REQUIRE_RECEIPT_WRITE(fprintf(stream, ",\"receipt_digest\":{\"algorithm\":\"fnv1a64-semantic-v1\",\"value\":\"%016" PRIx64 "\"}", receipt_digest));
    REQUIRE_RECEIPT_WRITE(fputs(",\"does_not_prove\":", stream));
    REQUIRE_RECEIPT_WRITE(receipt_put_json_string(stream, receipt->does_not_prove));
    REQUIRE_RECEIPT_WRITE(fputs("}\n", stream));
    // GCOVR_EXCL_BR_STOP
    p101_single_result_ = 0;
    goto p101_single_exit_;

write_failed:
    p101_single_result_ = receipt_write_failed(err);
    goto p101_single_exit_;    // GCOVR_EXCL_LINE -- staged failure covers each output phase.

p101_single_exit_:
#undef REQUIRE_RECEIPT_WRITE
    return p101_single_result_;
}
