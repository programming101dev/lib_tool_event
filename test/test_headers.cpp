#include <p101_record/record.h>
#include <p101_tool_event/event.h>
#include <p101_tool_event/lifecycle.h>
#include <p101_tool_event/model.h>
#include <p101_tool_event/receipt.h>

int main()
{
    p101_tool_event_parse_status status{P101_TOOL_EVENT_PARSE_OTHER};
    p101_tool_outcome            outcome{P101_TOOL_OUTCOME_CLEAN};

    return status == P101_TOOL_EVENT_PARSE_OTHER && outcome == P101_TOOL_OUTCOME_CLEAN ? 0 : 1;
}
