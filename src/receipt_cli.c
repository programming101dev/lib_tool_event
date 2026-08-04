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

    err           = p101_error_create(false);
    status        = EXIT_TOOL_ERROR;
    require_clean = 0;
    if(err == NULL)
    {
        (void)fprintf(stderr, "p101-tool-receipt: cannot create error context\n");
        goto done;
    }
    if(argc == 3 && strcmp(argv[1], "require-clean") == 0)
    {
        require_clean = 1;
    }
    else if(argc != 3 || strcmp(argv[1], "verify") != 0)
    {
        (void)fprintf(stderr, "Usage: %s {verify|require-clean} <receipt.json>\n", argv[0]);
        goto done;
    }
    if(p101_tool_run_receipt_validate_file(err, argv[2], P101_TOOL_EVENT_RECEIPT_DEFAULT_MAX_BYTES, &validation) != 0)
    {
        (void)fprintf(stderr, "p101-tool-receipt: %s\n", p101_error_get_message(err));
        goto done;
    }
    if(validation.status != P101_TOOL_RECEIPT_VALID)
    {
        (void)fprintf(stderr, "invalid receipt: %s\n", p101_tool_receipt_validation_status_name(validation.status));
        status = EXIT_INVALID_RECEIPT;
        goto done;
    }
    (void)printf("valid receipt: outcome=%s checks=%zu/%zu fingerprint=%s digest=%016" PRIx64 "\n",
                 p101_tool_outcome_name(validation.outcome),
                 validation.checks_completed,
                 validation.checks_attempted,
                 validation.fingerprint_present != 0 ? "present" : "absent",
                 validation.receipt_digest);
    status = EXIT_VALID;
    if(require_clean != 0 && validation.outcome != P101_TOOL_OUTCOME_CLEAN)
    {
        (void)fprintf(stderr, "receipt outcome is not clean: %s\n", p101_tool_outcome_name(validation.outcome));
        status = p101_tool_outcome_exit_status(validation.outcome);
    }

done:
    p101_error_destroy(err);
    return status;
}
