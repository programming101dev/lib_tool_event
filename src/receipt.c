#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <p101_tool_event/receipt.h>
#include <string.h>
#include <unistd.h>

enum
{
    READ_BUFFER_SIZE = 4096,
    FNV_WORD_BITS    = 32,
    JSON_CONTROL_END = 0x20
};

static const uint64_t FNV1A64_OFFSET = UINT64_C(14695981039346656037);

static int close_receipt_file(int fd);
static int receipt_is_valid(const struct p101_tool_run_receipt *receipt);
static int receipt_put_json_string(FILE *stream, const char *value);
static int receipt_write_failed(struct p101_error *err);

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
    if(receipt == NULL || receipt->tool_name == NULL || receipt->tool_version == NULL || receipt->input_schema == NULL || receipt->input_identity == NULL || receipt->does_not_prove == NULL)
    {
        return 0;
    }
    if(receipt->checks_completed > receipt->checks_attempted)
    {
        return 0;
    }
    return p101_tool_outcome_name(receipt->outcome) != NULL;
}

static int receipt_put_json_string(FILE *stream, const char *value)
{
    size_t length;

    // GCOVR_EXCL_BR_START: public receipt validation prevents null text; the
    // test-only entry point exercises this defensive helper contract.
    if(stream == NULL || value == NULL)
    {
        errno = EINVAL;
        return -1;
    }
    // GCOVR_EXCL_BR_STOP
    length = strlen(value);
    if(length > P101_TOOL_EVENT_RECEIPT_TEXT_MAX_BYTES)
    {
        errno = EFBIG;
        return -1;
    }
    // GCOVR_EXCL_BR_START: individual stdio failure sites are not portable to
    // inject; the public writer's staged failures verify phase propagation.
    if(fputc('"', stream) == EOF)
    {
        return -1;
    }
    for(size_t index = 0U; index < length; index++)
    {
        unsigned char character;

        character = (unsigned char)value[index];
        switch(character)
        {
            case '"':
                if(fputs("\\\"", stream) == EOF)
                {
                    return -1;    // GCOVR_EXCL_LINE -- public staged failure covers propagation.
                }
                break;
            case '\\':
                if(fputs("\\\\", stream) == EOF)
                {
                    return -1;    // GCOVR_EXCL_LINE -- public staged failure covers propagation.
                }
                break;
            case '\b':
                if(fputs("\\b", stream) == EOF)
                {
                    return -1;    // GCOVR_EXCL_LINE -- public staged failure covers propagation.
                }
                break;
            case '\f':
                if(fputs("\\f", stream) == EOF)
                {
                    return -1;    // GCOVR_EXCL_LINE -- public staged failure covers propagation.
                }
                break;
            case '\n':
                if(fputs("\\n", stream) == EOF)
                {
                    return -1;    // GCOVR_EXCL_LINE -- public staged failure covers propagation.
                }
                break;
            case '\r':
                if(fputs("\\r", stream) == EOF)
                {
                    return -1;    // GCOVR_EXCL_LINE -- public staged failure covers propagation.
                }
                break;
            case '\t':
                if(fputs("\\t", stream) == EOF)
                {
                    return -1;    // GCOVR_EXCL_LINE -- public staged failure covers propagation.
                }
                break;
            default:
                if(character < JSON_CONTROL_END)
                {
                    if(fprintf(stream, "\\u%04x", (unsigned int)character) < 0)
                    {
                        return -1;    // GCOVR_EXCL_LINE -- public staged failure covers propagation.
                    }
                }
                else if(fputc((int)character, stream) == EOF)
                {
                    return -1;    // GCOVR_EXCL_LINE -- public staged failure covers propagation.
                }
                break;
        }
    }
    return fputc('"', stream) == EOF ? -1 : 0;
    // GCOVR_EXCL_BR_STOP
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

int p101_tool_event_fingerprint_file(struct p101_error *err, const char *path, size_t maximum_bytes, size_t maximum_records, struct p101_tool_event_fingerprint *fingerprint)
{
    int      fd;
    uint64_t hash;
    size_t   newline_count;
    int      final_newline;
    int      result;

    if(path == NULL || fingerprint == NULL || maximum_bytes == 0U || maximum_records == 0U)
    {
        P101_ERROR_RAISE_CHECK(err);
        return -1;
    }

    memset(fingerprint, 0, sizeof(*fingerprint));
    fd = open(path, O_RDONLY | O_CLOEXEC);
    if(fd < 0)
    {
        P101_ERROR_RAISE_ERRNO(err, errno);
        return -1;
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

    return result;
}

const char *p101_tool_outcome_name(p101_tool_outcome outcome)
{
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
        return NULL;
    }
    return names[outcome];
}

int p101_tool_outcome_exit_status(p101_tool_outcome outcome)
{
    if(outcome == P101_TOOL_OUTCOME_CLEAN)
    {
        return 0;
    }
    if(outcome == P101_TOOL_OUTCOME_FINDINGS)
    {
        return 1;
    }
    return 2;
}

int p101_tool_run_receipt_write_json(struct p101_error *err, FILE *stream, const struct p101_tool_run_receipt *receipt, const struct p101_tool_event_fingerprint *fingerprint)
{
    const char *outcome_name;

    if(stream == NULL || !receipt_is_valid(receipt))
    {
        P101_ERROR_RAISE_CHECK(err);
        return -1;
    }
    outcome_name = p101_tool_outcome_name(receipt->outcome);
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
    if(fputs("{\"schema\":\"p101-tool-run-receipt-v1\",\"tool\":{\"name\":", stream) == EOF || receipt_put_json_string(stream, receipt->tool_name) != 0 || fputs(",\"version\":", stream) == EOF || receipt_put_json_string(stream, receipt->tool_version) != 0 ||
       fputs("},\"input\":{\"schema\":", stream) == EOF || receipt_put_json_string(stream, receipt->input_schema) != 0 || fputs(",\"identity\":", stream) == EOF || receipt_put_json_string(stream, receipt->input_identity) != 0 ||
       fputs("},\"outcome\":", stream) == EOF || receipt_put_json_string(stream, outcome_name) != 0 || fprintf(stream, ",\"checks\":{\"attempted\":%zu,\"completed\":%zu}", receipt->checks_attempted, receipt->checks_completed) < 0)
    {
        return receipt_write_failed(err);    // GCOVR_EXCL_LINE -- staged failure covers this output phase.
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
        return receipt_write_failed(err);    // GCOVR_EXCL_LINE -- staged failure covers this output phase.
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
    if(fputs(",\"does_not_prove\":", stream) == EOF || receipt_put_json_string(stream, receipt->does_not_prove) != 0 || fputs("}\n", stream) == EOF)
    {
        return receipt_write_failed(err);    // GCOVR_EXCL_LINE -- staged failure covers this output phase.
    }
    // GCOVR_EXCL_BR_STOP
    return 0;
}
