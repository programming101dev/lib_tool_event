#include <errno.h>
#include <fcntl.h>
#include <p101_tool_event/receipt.h>
#include <string.h>
#include <unistd.h>

enum
{
    READ_BUFFER_SIZE = 4096,
    FNV_WORD_BITS    = 32
};

static const uint64_t FNV1A64_OFFSET = UINT64_C(14695981039346656037);

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

    if(close(fd) != 0 && result == 0)
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
