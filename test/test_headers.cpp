#include <p101_tool_event/event.h>
#include <p101_tool_event/lifecycle.h>
#include <p101_tool_event/model.h>
#include <p101_tool_event/receipt.h>

int main()
{
    p101_tool_event_parse_status status{P101_TOOL_EVENT_PARSE_OTHER};

    return status == P101_TOOL_EVENT_PARSE_OTHER ? 0 : 1;
}
