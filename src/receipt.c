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
    HEXADECIMAL_BASE         = 16,
    ASCII_CONTROL_LIMIT      = 32,
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
static int      receipt_parse_string(const char **cursor, char *output, size_t output_size);
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
#ifdef P101_TOOL_EVENT_TESTING
    if(forced_close_error != 0)
    {
        int error_number;

        error_number       = forced_close_error;
        forced_close_error = 0;
        (void)close(fd);
        errno = error_number;
        return -1;
    }
#endif
    return close(fd);
}

static int receipt_is_valid(const struct p101_tool_run_receipt *receipt)
{
    int p101_single_result_;
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
    if(p101_tool_outcome_name(receipt->outcome) == NULL || p101_tool_failure_reason_name(receipt->failure_reason) == NULL)
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
    size_t length = strlen(literal);
    int    result = -1;

    if(strncmp(*cursor, literal, length) == 0)
    {
        *cursor += length;
        result = 0;
    }
    return result;
}

static int receipt_parse_string(const char **cursor, char *output, size_t output_size)
{
    int    p101_single_result_;
    size_t remaining;
    size_t used;
    int    result;

    if(cursor == NULL || output == NULL || output_size == 0U)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    if(*cursor == NULL)
    {
        p101_single_result_ = -1;
        goto p101_single_exit_;
    }
    remaining = strlen(*cursor);
    used      = 0U;
    result    = -1;
    // `strlen` above proves that byte zero is initialized when remaining is
    // non-zero; CSA loses that fact across the short-circuit expression.
    if(remaining == 0U || (*cursor)[0] != '"')    // NOLINT(clang-analyzer-core.UndefinedBinaryOperatorResult)
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

                if(strlen(*cursor) < JSON_UNICODE_HEX_DIGITS || (*cursor)[0] != '0' || (*cursor)[1] != '0')
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
                    high = (unsigned char)(high - 'a' + DECIMAL_BASE);
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
                    low = (unsigned char)(low - 'a' + DECIMAL_BASE);
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
        if((value < ASCII_CONTROL_LIMIT && escaped == 0) || used + 1U >= output_size)
        {
            goto done;
        }
        output[used++] = (char)value;
    }
    if(**cursor != '"')
    {
        goto done;
    }
    (*cursor)++;
    output[used] = '\0';
    result       = 0;

done:
    p101_single_result_ = result;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
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
    int result = 0;

    if(receipt_parse_literal(cursor, "true") == 0)
    {
        *value = 1;
    }
    else if(receipt_parse_literal(cursor, "false") == 0)
    {
        *value = 0;
    }
    else
    {
        result = -1;
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
    int         result = -1;

    memset(parsed, 0, sizeof(*parsed));
    if(receipt_parse_literal(&cursor, "{\"schema\":") != 0 || receipt_parse_string(&cursor, schema, sizeof(schema)) != 0)
    {
        goto done;
    }
    if(strcmp(schema, "p101-tool-run-receipt-v4") != 0)
    {
        result = 1;
        goto done;
    }
    if(receipt_parse_literal(&cursor, ",\"tool\":{\"name\":") != 0 || receipt_parse_string(&cursor, parsed->text[RECEIPT_TOOL_NAME], sizeof(parsed->text[RECEIPT_TOOL_NAME])) != 0 || receipt_parse_literal(&cursor, ",\"version\":") != 0 ||
       receipt_parse_string(&cursor, parsed->text[RECEIPT_TOOL_VERSION], sizeof(parsed->text[RECEIPT_TOOL_VERSION])) != 0 || receipt_parse_literal(&cursor, "},\"input\":{\"schema\":") != 0 ||
       receipt_parse_string(&cursor, parsed->text[RECEIPT_INPUT_SCHEMA], sizeof(parsed->text[RECEIPT_INPUT_SCHEMA])) != 0 || receipt_parse_literal(&cursor, ",\"identity\":") != 0 ||
       receipt_parse_string(&cursor, parsed->text[RECEIPT_INPUT_IDENTITY], sizeof(parsed->text[RECEIPT_INPUT_IDENTITY])) != 0 || receipt_parse_literal(&cursor, "},\"policy\":{\"schema\":") != 0 ||
       receipt_parse_string(&cursor, parsed->text[RECEIPT_POLICY_SCHEMA], sizeof(parsed->text[RECEIPT_POLICY_SCHEMA])) != 0 || receipt_parse_literal(&cursor, ",\"identity\":") != 0 ||
       receipt_parse_string(&cursor, parsed->text[RECEIPT_POLICY_IDENTITY], sizeof(parsed->text[RECEIPT_POLICY_IDENTITY])) != 0 || receipt_parse_literal(&cursor, "},\"run_identity\":") != 0 ||
       receipt_parse_string(&cursor, parsed->text[RECEIPT_RUN_IDENTITY], sizeof(parsed->text[RECEIPT_RUN_IDENTITY])) != 0 || receipt_parse_literal(&cursor, ",\"outcome\":") != 0 || receipt_parse_string(&cursor, outcome, sizeof(outcome)) != 0 ||
       receipt_parse_literal(&cursor, ",\"failure\":{\"reason\":") != 0 || receipt_parse_string(&cursor, failure, sizeof(failure)) != 0 || receipt_parse_literal(&cursor, ",\"stage\":") != 0 ||
       receipt_parse_string(&cursor, parsed->text[RECEIPT_FAILED_STAGE], sizeof(parsed->text[RECEIPT_FAILED_STAGE])) != 0 || receipt_parse_literal(&cursor, ",\"first_diagnostic\":") != 0 ||
       receipt_parse_string(&cursor, parsed->text[RECEIPT_FIRST_DIAGNOSTIC], sizeof(parsed->text[RECEIPT_FIRST_DIAGNOSTIC])) != 0 || receipt_parse_literal(&cursor, "},\"checks\":{\"attempted\":") != 0 ||
       receipt_parse_size(&cursor, &parsed->receipt.checks_attempted) != 0 || receipt_parse_literal(&cursor, ",\"completed\":") != 0 || receipt_parse_size(&cursor, &parsed->receipt.checks_completed) != 0 || receipt_parse_literal(&cursor, "}") != 0)
    {
        goto done;
    }

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
        if(strcmp(outcome, p101_tool_outcome_name((p101_tool_outcome)value)) == 0)
        {
            parsed->receipt.outcome = (p101_tool_outcome)value;
            break;
        }
    }
    for(int value = P101_TOOL_FAILURE_NONE; value <= P101_TOOL_FAILURE_TOOL_ERROR; value++)
    {
        if(strcmp(failure, p101_tool_failure_reason_name((p101_tool_failure_reason)value)) == 0)
        {
            parsed->receipt.failure_reason = (p101_tool_failure_reason)value;
            break;
        }
    }
    if(strcmp(outcome, p101_tool_outcome_name(parsed->receipt.outcome)) != 0 || strcmp(failure, p101_tool_failure_reason_name(parsed->receipt.failure_reason)) != 0)
    {
        goto done;
    }

    if(strncmp(cursor, ",\"fingerprint\":", strlen(",\"fingerprint\":")) == 0)
    {
        char algorithm[RECEIPT_SCHEMA_TEXT_SIZE];

        parsed->fingerprint_present = 1;
        if(receipt_parse_literal(&cursor, ",\"fingerprint\":{\"algorithm\":") != 0 || receipt_parse_string(&cursor, algorithm, sizeof(algorithm)) != 0 || strcmp(algorithm, "fnv1a64-change-detector") != 0 || receipt_parse_literal(&cursor, ",\"bytes\":") != 0 ||
           receipt_parse_size(&cursor, &parsed->fingerprint.bytes) != 0 || receipt_parse_literal(&cursor, ",\"records\":") != 0 || receipt_parse_size(&cursor, &parsed->fingerprint.records) != 0 || receipt_parse_literal(&cursor, ",\"value\":\"") != 0 ||
           receipt_parse_hex(&cursor, &parsed->fingerprint.fnv1a64) != 0 || receipt_parse_literal(&cursor, "\",\"final_newline\":") != 0 || receipt_parse_boolean(&cursor, &parsed->fingerprint.final_newline) != 0 || receipt_parse_literal(&cursor, "}") != 0)
        {
            goto done;
        }
    }
    if(receipt_parse_literal(&cursor, ",\"receipt_digest\":{\"algorithm\":\"fnv1a64-semantic-v1\",\"value\":\"") != 0 || receipt_parse_hex(&cursor, &parsed->claimed_digest) != 0 || receipt_parse_literal(&cursor, "\"},\"does_not_prove\":") != 0 ||
       receipt_parse_string(&cursor, parsed->text[RECEIPT_DOES_NOT_PROVE], sizeof(parsed->text[RECEIPT_DOES_NOT_PROVE])) != 0 || receipt_parse_literal(&cursor, "}\n") != 0 || *cursor != '\0')
    {
        goto done;
    }
    parsed->receipt.does_not_prove = parsed->text[RECEIPT_DOES_NOT_PROVE];
    result                         = 0;

done:
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

    hash = fnv1a64_bytes(hash, (const unsigned char *)label, strlen(label));
    hash = fnv1a64_bytes(hash, &separator, 1U);
    hash = fnv1a64_bytes(hash, (const unsigned char *)value, strlen(value));
    return fnv1a64_bytes(hash, &separator, 1U);
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
    return fnv1a64_bytes(hash, bytes, sizeof(bytes));
}

static uint64_t digest_size(uint64_t hash, const char *label, size_t value)
{
    return digest_u64(hash, label, (uint64_t)value);
}

uint64_t p101_tool_run_receipt_digest(const struct p101_tool_run_receipt *receipt, const struct p101_tool_event_fingerprint *fingerprint)
{
    uint64_t p101_single_result_;
    uint64_t hash;

    if(!receipt_is_valid(receipt))
    {
        p101_single_result_ = 0U;
        goto p101_single_exit_;
    }
    hash = digest_text(FNV1A64_OFFSET, "schema", "p101-tool-run-receipt-v4");
    hash = digest_text(hash, "tool_name", receipt->tool_name);
    hash = digest_text(hash, "tool_version", receipt->tool_version);
    hash = digest_text(hash, "input_schema", receipt->input_schema);
    hash = digest_text(hash, "input_identity", receipt->input_identity);
    hash = digest_text(hash, "policy_schema", receipt->policy_schema);
    hash = digest_text(hash, "policy_identity", receipt->policy_identity);
    hash = digest_text(hash, "run_identity", receipt->run_identity);
    hash = digest_text(hash, "outcome", p101_tool_outcome_name(receipt->outcome));
    hash = digest_text(hash, "failure_reason", p101_tool_failure_reason_name(receipt->failure_reason));
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
    uint64_t               actual_digest;
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
    parsed             = (struct parsed_receipt *)malloc(sizeof(*parsed));
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
    if(parse_result != 0 || !receipt_is_valid(&parsed->receipt))
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
    int         result;

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
    text   = NULL;
    result = -1;
    if(fstat(fd, &status) != 0)
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
    text = (char *)calloc(file_size + 1U, sizeof(*text));
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
    if(close_receipt_file(fd) != 0 && result == 0)
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

    if(close_receipt_file(fd) != 0 && result == 0)
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
    uint64_t    receipt_digest;

    if(stream == NULL || !receipt_is_valid(receipt))
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
        return receipt_write_failed(err);
    }
#endif
    // GCOVR_EXCL_BR_START: test builds inject each writer phase immediately
    // above/below these calls; individual libc write sites are not portable.
    if(fputs("{\"schema\":\"p101-tool-run-receipt-v4\",\"tool\":{\"name\":", stream) == EOF || receipt_put_json_string(stream, receipt->tool_name) != 0 || fputs(",\"version\":", stream) == EOF || receipt_put_json_string(stream, receipt->tool_version) != 0 ||
       fputs("},\"input\":{\"schema\":", stream) == EOF || receipt_put_json_string(stream, receipt->input_schema) != 0 || fputs(",\"identity\":", stream) == EOF || receipt_put_json_string(stream, receipt->input_identity) != 0 ||
       fputs("},\"policy\":{\"schema\":", stream) == EOF || receipt_put_json_string(stream, receipt->policy_schema) != 0 || fputs(",\"identity\":", stream) == EOF || receipt_put_json_string(stream, receipt->policy_identity) != 0 ||
       fputs("},\"run_identity\":", stream) == EOF || receipt_put_json_string(stream, receipt->run_identity) != 0 || fputs(",\"outcome\":", stream) == EOF || receipt_put_json_string(stream, outcome_name) != 0 ||
       fputs(",\"failure\":{\"reason\":", stream) == EOF || receipt_put_json_string(stream, failure_reason_name) != 0 || fputs(",\"stage\":", stream) == EOF || receipt_put_json_string(stream, receipt->failed_stage) != 0 ||
       fputs(",\"first_diagnostic\":", stream) == EOF || receipt_put_json_string(stream, receipt->first_diagnostic) != 0 || fprintf(stream, "},\"checks\":{\"attempted\":%zu,\"completed\":%zu}", receipt->checks_attempted, receipt->checks_completed) < 0)
    {
        p101_single_result_ = receipt_write_failed(err);
        goto p101_single_exit_;    // GCOVR_EXCL_LINE -- staged failure covers this output phase.
    }
    // GCOVR_EXCL_BR_STOP
#ifdef P101_TOOL_EVENT_TESTING
    if(forced_receipt_failure_stage == 2)
    {
        forced_receipt_failure_stage = 0;
        errno                        = EIO;
        return receipt_write_failed(err);
    }
#endif
    // GCOVR_EXCL_BR_START: the staged fingerprint failure above verifies this
    // phase without relying on a platform-specific failing FILE implementation.
    if(fingerprint != NULL && fprintf(stream,
                                      ",\"fingerprint\":{\"algorithm\":\"fnv1a64-change-detector\",\"bytes\":%zu,\"records\":%zu,\"value\":\"%016" PRIx64 "\",\"final_newline\":%s}",
                                      fingerprint->bytes,
                                      fingerprint->records,
                                      fingerprint->fnv1a64,
                                      fingerprint->final_newline != 0 ? "true" : "false") < 0)
    {
        p101_single_result_ = receipt_write_failed(err);
        goto p101_single_exit_;    // GCOVR_EXCL_LINE -- staged failure covers this output phase.
    }
    // GCOVR_EXCL_BR_STOP
#ifdef P101_TOOL_EVENT_TESTING
    if(forced_receipt_failure_stage == 3)
    {
        forced_receipt_failure_stage = 0;
        errno                        = EIO;
        return receipt_write_failed(err);
    }
#endif
    // GCOVR_EXCL_BR_START: the staged final failure above verifies propagation.
    if(fprintf(stream, ",\"receipt_digest\":{\"algorithm\":\"fnv1a64-semantic-v1\",\"value\":\"%016" PRIx64 "\"}", receipt_digest) < 0 || fputs(",\"does_not_prove\":", stream) == EOF || receipt_put_json_string(stream, receipt->does_not_prove) != 0 ||
       fputs("}\n", stream) == EOF)
    {
        p101_single_result_ = receipt_write_failed(err);
        goto p101_single_exit_;    // GCOVR_EXCL_LINE -- staged failure covers this output phase.
    }
    // GCOVR_EXCL_BR_STOP
    p101_single_result_ = 0;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}
