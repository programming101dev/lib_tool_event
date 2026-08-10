#include <inttypes.h>
#include <p101_error/error.h>
#include <p101_tool_event/receipt.h>
#include <stdio.h>
#include <string.h>

enum
{
    EXIT_VALID = 0,
    EXIT_INVALID_RECEIPT,
    EXIT_TOOL_ERROR
};

int main(int argc, char *argv[])
{
    struct p101_error                      *err;
    struct p101_tool_run_receipt_validation validation;
    int                                     status;
    int                                     require_clean;
    int                                     io_status;
    int                                     comparison;
    int                                     validation_status;
    int                                     show_help;
    const char                             *message;
    const char                             *status_name;
    const char                             *outcome_name;

    err           = p101_error_create(false);
    status        = EXIT_TOOL_ERROR;
    require_clean = 0;
    show_help     = 0;
    if(err == NULL)
    {
        io_status = fprintf(stderr, "p101-tool-receipt: cannot create error context\n");
        (void)io_status;
        goto done;
    }
    comparison = -1;
    if(argc == 2)
    {
        comparison = strcmp(argv[1], "--help");
    }
    if(argc == 2 && comparison == 0)
    {
        show_help = 1;
    }
    else
    {
        comparison = -1;
        if(argc == 2)
        {
            comparison = strcmp(argv[1], "-h");
        }
        if(argc == 2 && comparison == 0)
        {
            show_help = 1;
        }
    }
    if(show_help != 0)
    {
        io_status = printf("Usage: %s {verify|require-clean} <receipt.json>\n", argv[0]);
        (void)io_status;
        status = EXIT_VALID;
        goto done;
    }
    comparison = -1;
    if(argc == 3)
    {
        comparison = strcmp(argv[1], "require-clean");
    }
    if(argc == 3 && comparison == 0)
    {
        require_clean = 1;
    }
    else
    {
        comparison = -1;
        if(argc == 3)
        {
            comparison = strcmp(argv[1], "verify");
        }
        if(argc != 3 || comparison != 0)
        {
            io_status = fprintf(stderr, "Usage: %s {verify|require-clean} <receipt.json>\n", argv[0]);
            (void)io_status;
            goto done;
        }
    }
    validation_status = p101_tool_run_receipt_validate_file(err, argv[2], P101_TOOL_EVENT_RECEIPT_DEFAULT_MAX_BYTES, &validation);
    if(validation_status != 0)
    {
        message   = p101_error_get_message(err);
        io_status = fprintf(stderr, "p101-tool-receipt: %s\n", message);
        (void)io_status;
        goto done;
    }
    if(validation.status != P101_TOOL_RECEIPT_VALID)
    {
        status_name = p101_tool_receipt_validation_status_name(validation.status);
        io_status   = fprintf(stderr, "invalid receipt: %s\n", status_name);
        (void)io_status;
        status = EXIT_INVALID_RECEIPT;
        goto done;
    }
    outcome_name = p101_tool_outcome_name(validation.outcome);
    io_status =
        printf("valid receipt: outcome=%s checks=%zu/%zu fingerprint=%s digest=%016" PRIx64 "\n", outcome_name, validation.checks_completed, validation.checks_attempted, validation.fingerprint_present != 0 ? "present" : "absent", validation.receipt_digest);
    (void)io_status;
    status = EXIT_VALID;
    if(require_clean != 0 && validation.outcome != P101_TOOL_OUTCOME_CLEAN)
    {
        outcome_name = p101_tool_outcome_name(validation.outcome);
        io_status    = fprintf(stderr, "receipt outcome is not clean: %s\n", outcome_name);
        (void)io_status;
        status = p101_tool_outcome_exit_status(validation.outcome);
    }

done:
    p101_error_destroy(err);
    return status;
}
