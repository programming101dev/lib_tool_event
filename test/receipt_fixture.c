#include <p101_error/error.h>
#include <p101_tool_event/receipt.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
    struct p101_error           *err;
    struct p101_tool_run_receipt receipt;
    FILE                        *stream;
    int                          result;

    if(argc < 2 || argc > 3)
    {
        return 2;
    }
    err = p101_error_create(false);
    if(err == NULL)
    {
        return 2;
    }
    stream = fopen(argv[1], "w");
    if(stream == NULL)
    {
        p101_error_destroy(err);
        return 2;
    }
    receipt = (struct p101_tool_run_receipt){
        .tool_name        = "fixture",
        .tool_version     = "1",
        .input_schema     = "fixture-input-v1",
        .input_identity   = "fixture-input",
        .policy_schema    = "fixture-policy-v1",
        .policy_identity  = "fixture-policy",
        .run_identity     = "fixture-run",
        .outcome          = P101_TOOL_OUTCOME_CLEAN,
        .failure_reason   = P101_TOOL_FAILURE_NONE,
        .failed_stage     = "",
        .first_diagnostic = "",
        .checks_attempted = 1U,
        .checks_completed = 1U,
        .does_not_prove   = "The fixture proves only receipt transport.",
    };
    if(argc == 3)
    {
        receipt.outcome          = P101_TOOL_OUTCOME_FINDINGS;
        receipt.failure_reason   = P101_TOOL_FAILURE_FINDINGS_PRESENT;
        receipt.failed_stage     = "fixture";
        receipt.first_diagnostic = "fixture finding";
    }
    result = p101_tool_run_receipt_write_json(err, stream, &receipt, NULL);
    if(fclose(stream) != 0)
    {
        result = -1;
    }
    p101_error_destroy(err);
    return result == 0 ? 0 : 2;
}
