#include <errno.h>
#include <p101_record/record.h>
#include <p101_tool_event/report.h>
#include <string.h>

enum
{
    MAXIMUM_EXIT_STATUS = 255
};

static int write_literal(FILE *stream, const char *text);
static int write_json_string(FILE *stream, const char *text);
static int write_human_contract(struct p101_tool_report *report);
static int write_human_summary(struct p101_tool_report *report, const char *outcome_name, int exit_status, const struct p101_tool_report_counter counters[], size_t counter_count);
static int write_json_summary(struct p101_tool_report *report, const char *outcome_name, int exit_status, const struct p101_tool_report_counter counters[], size_t counter_count);
static int validate_counter_name(const char *name);
static int validate_counters(const struct p101_tool_report_counter counters[], size_t counter_count);

int p101_tool_report_parse_output_option(const char *argument, unsigned int *outputs)
{
    int result;

    if(argument == NULL || outputs == NULL)
    {
        errno  = EINVAL;
        result = -1;
        goto p101_single_exit_;
    }
    if(argument[0] != '-' || argument[1] != 'd' || argument[2] != ':')
    {
        errno  = EINVAL;
        result = -1;
        goto p101_single_exit_;
    }
    result = p101_tool_diagnostic_parse_outputs(&argument[3], outputs);

p101_single_exit_:
    return result;
}

int p101_tool_report_begin(struct p101_tool_report *report, FILE *standard_output, FILE *standard_error, const struct p101_tool_report_options *options)
{
    unsigned int valid_outputs;
    int          result;

    valid_outputs = P101_TOOL_DIAGNOSTIC_OUTPUT_HUMAN | P101_TOOL_DIAGNOSTIC_OUTPUT_JSON;
    if(report == NULL || standard_output == NULL || options == NULL || options->tool_name == NULL || options->admitted_inputs == NULL || options->does_not_prove == NULL || options->outputs == 0U || (options->outputs & ~valid_outputs) != 0U)
    {
        errno  = EINVAL;
        result = -1;
        goto p101_single_exit_;
    }
    if(options->outputs == valid_outputs && standard_error == NULL)
    {
        errno  = EINVAL;
        result = -1;
        goto p101_single_exit_;
    }

    memset(report, 0, sizeof(*report));
    report->options            = *options;
    report->first_json_finding = true;
    report->active             = true;
    if((options->outputs & P101_TOOL_DIAGNOSTIC_OUTPUT_JSON) != 0U)
    {
        report->json_stream = standard_output;
    }
    if(options->outputs == valid_outputs)
    {
        report->human_stream = standard_error;
    }
    else if((options->outputs & P101_TOOL_DIAGNOSTIC_OUTPUT_HUMAN) != 0U)
    {
        report->human_stream = standard_output;
    }

    result = 0;
    if(report->human_stream != NULL)
    {
        result = write_human_contract(report);
        if(result != 0)
        {
            goto p101_single_exit_;
        }
    }
    if(report->json_stream != NULL)
    {
        result = write_literal(report->json_stream, "{\"schema\":\"" P101_TOOL_REPORT_SCHEMA_NAME "\",\"tool\":");
        if(result != 0)
        {
            goto p101_single_exit_;
        }
        result = write_json_string(report->json_stream, options->tool_name);
        if(result != 0)
        {
            goto p101_single_exit_;
        }
        result = write_literal(report->json_stream, ",\"admitted_inputs\":");
        if(result != 0)
        {
            goto p101_single_exit_;
        }
        result = write_json_string(report->json_stream, options->admitted_inputs);
        if(result != 0)
        {
            goto p101_single_exit_;
        }
        result = write_literal(report->json_stream, ",\"does_not_prove\":");
        if(result != 0)
        {
            goto p101_single_exit_;
        }
        result = write_json_string(report->json_stream, options->does_not_prove);
        if(result != 0)
        {
            goto p101_single_exit_;
        }
        result = write_literal(report->json_stream, ",\"findings\":[");
    }

p101_single_exit_:
    return result;
}

int p101_tool_report_emit(struct p101_tool_report *report, const struct p101_tool_diagnostic *diagnostic)
{
    int result;

    if(report == NULL || !report->active || diagnostic == NULL)
    {
        errno  = EINVAL;
        result = -1;
        goto p101_single_exit_;
    }
    if(report->json_stream != NULL && !report->first_json_finding)
    {
        result = fputc(',', report->json_stream);
        if(result == EOF)
        {
            result = -1;
            goto p101_single_exit_;
        }
    }
    result = p101_tool_diagnostic_write_outputs(report->human_stream, report->json_stream, diagnostic);
    if(result == 0)
    {
        report->first_json_finding = false;
        report->finding_count++;
    }

p101_single_exit_:
    return result;
}

int p101_tool_report_end(struct p101_tool_report *report, p101_tool_outcome outcome, int exit_status, const struct p101_tool_report_counter counters[], size_t counter_count)
{
    const char *outcome_name;
    int         comparison;
    int         result;

    if(report == NULL || !report->active)
    {
        errno  = EINVAL;
        result = -1;
        goto p101_single_exit_;
    }
    result = validate_counters(counters, counter_count);
    if(result != 0)
    {
        goto p101_single_exit_;
    }
    outcome_name = p101_tool_outcome_name(outcome);
    comparison   = strcmp(outcome_name, "unknown");
    if(comparison == 0 || exit_status < 0 || exit_status > MAXIMUM_EXIT_STATUS)
    {
        errno  = EINVAL;
        result = -1;
        goto p101_single_exit_;
    }
    if(report->json_stream != NULL)
    {
        result = write_json_summary(report, outcome_name, exit_status, counters, counter_count);
        if(result != 0)
        {
            goto p101_single_exit_;
        }
    }
    if(report->human_stream != NULL && report->options.human_summary)
    {
        result = write_human_summary(report, outcome_name, exit_status, counters, counter_count);
        if(result != 0)
        {
            goto p101_single_exit_;
        }
    }
    report->active = false;
    result         = 0;

p101_single_exit_:
    return result;
}

static int write_literal(FILE *stream, const char *text)
{
    int result;

    result = fputs(text, stream);
    if(result == EOF)
    {
        result = -1;
    }
    else
    {
        result = 0;
    }
    return result;
}

static int write_json_string(FILE *stream, const char *text)
{
    int result;

    result = p101_record_write_json_string(stream, text);
    return result;
}

static int write_human_contract(struct p101_tool_report *report)
{
    int result;

    result = write_literal(report->human_stream, "report: tool=");
    if(result != 0)
    {
        goto p101_single_exit_;
    }
    result = write_json_string(report->human_stream, report->options.tool_name);
    if(result != 0)
    {
        goto p101_single_exit_;
    }
    result = write_literal(report->human_stream, " admitted_inputs=");
    if(result != 0)
    {
        goto p101_single_exit_;
    }
    result = write_json_string(report->human_stream, report->options.admitted_inputs);
    if(result != 0)
    {
        goto p101_single_exit_;
    }
    result = write_literal(report->human_stream, "\nreport: does_not_prove=");
    if(result != 0)
    {
        goto p101_single_exit_;
    }
    result = write_json_string(report->human_stream, report->options.does_not_prove);
    if(result != 0)
    {
        goto p101_single_exit_;
    }
    result = fputc('\n', report->human_stream);
    if(result == EOF)
    {
        result = -1;
    }
    else
    {
        result = 0;
    }

p101_single_exit_:
    return result;
}

static int write_human_summary(struct p101_tool_report *report, const char *outcome_name, int exit_status, const struct p101_tool_report_counter counters[], size_t counter_count)
{
    size_t index;
    int    result;

    result = fprintf(report->human_stream, "%s: outcome=%s exit_status=%d findings=%zu", report->options.tool_name, outcome_name, exit_status, report->finding_count);
    if(result < 0)
    {
        result = -1;
        goto p101_single_exit_;
    }
    for(index = 0U; index < counter_count; index++)
    {
        result = fprintf(report->human_stream, " %s=%zu", counters[index].name, counters[index].value);
        if(result < 0)
        {
            result = -1;
            goto p101_single_exit_;
        }
    }
    result = fputc('\n', report->human_stream);
    if(result == EOF)
    {
        result = -1;
    }
    else
    {
        result = 0;
    }

p101_single_exit_:
    return result;
}

static int write_json_summary(struct p101_tool_report *report, const char *outcome_name, int exit_status, const struct p101_tool_report_counter counters[], size_t counter_count)
{
    size_t index;
    int    result;

    result = fprintf(report->json_stream, "],\"summary\":{\"findings\":%zu", report->finding_count);
    if(result < 0)
    {
        result = -1;
        goto p101_single_exit_;
    }
    for(index = 0U; index < counter_count; index++)
    {
        result = fputc(',', report->json_stream);
        if(result == EOF)
        {
            result = -1;
            goto p101_single_exit_;
        }
        result = write_json_string(report->json_stream, counters[index].name);
        if(result != 0)
        {
            goto p101_single_exit_;
        }
        result = fprintf(report->json_stream, ":%zu", counters[index].value);
        if(result < 0)
        {
            result = -1;
            goto p101_single_exit_;
        }
    }
    result = write_literal(report->json_stream, "},\"outcome\":");
    if(result != 0)
    {
        goto p101_single_exit_;
    }
    result = write_json_string(report->json_stream, outcome_name);
    if(result != 0)
    {
        goto p101_single_exit_;
    }
    result = fprintf(report->json_stream, ",\"exit_status\":%d}\n", exit_status);
    if(result < 0)
    {
        result = -1;
    }
    else
    {
        result = 0;
    }

p101_single_exit_:
    return result;
}

static int validate_counter_name(const char *name)
{
    size_t index;
    int    result;

    if(name == NULL || name[0] == '\0')
    {
        errno  = EINVAL;
        result = -1;
        goto p101_single_exit_;
    }
    result = 0;
    for(index = 0U; name[index] != '\0'; index++)
    {
        unsigned char character;
        bool          valid_character;

        character       = (unsigned char)name[index];
        valid_character = false;
        if((character >= (unsigned char)'a' && character <= (unsigned char)'z') || (character >= (unsigned char)'0' && character <= (unsigned char)'9') || character == (unsigned char)'_')
        {
            valid_character = true;
        }
        if(!valid_character)
        {
            errno  = EINVAL;
            result = -1;
            break;
        }
    }

p101_single_exit_:
    return result;
}

static int validate_counters(const struct p101_tool_report_counter counters[], size_t counter_count)
{
    size_t index;
    size_t previous_index;
    int    result;

    if(counter_count > 0U && counters == NULL)
    {
        errno  = EINVAL;
        result = -1;
        goto p101_single_exit_;
    }
    result = 0;
    for(index = 0U; index < counter_count; index++)
    {
        int comparison;

        result = validate_counter_name(counters[index].name);
        if(result != 0)
        {
            goto p101_single_exit_;
        }
        comparison = strcmp(counters[index].name, "findings");
        if(comparison == 0)
        {
            errno  = EINVAL;
            result = -1;
            goto p101_single_exit_;
        }
        for(previous_index = 0U; previous_index < index; previous_index++)
        {
            comparison = strcmp(counters[index].name, counters[previous_index].name);
            if(comparison == 0)
            {
                errno  = EINVAL;
                result = -1;
                goto p101_single_exit_;
            }
        }
    }

p101_single_exit_:
    return result;
}
