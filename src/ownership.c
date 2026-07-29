#include <p101_tool_event/ownership.h>

p101_tool_event_ownership_release_result p101_tool_event_ownership_classify_release(p101_tool_event_ownership_state state)
{
    if(state == P101_TOOL_EVENT_OWNERSHIP_LIVE)
    {
        return P101_TOOL_EVENT_OWNERSHIP_RELEASE_OK;
    }
    if(state == P101_TOOL_EVENT_OWNERSHIP_RELEASED)
    {
        return P101_TOOL_EVENT_OWNERSHIP_RELEASE_DUPLICATE;
    }
    return P101_TOOL_EVENT_OWNERSHIP_RELEASE_STRAY;
}

p101_tool_event_ownership_replace_result p101_tool_event_ownership_classify_replace(bool source_is_null, p101_tool_event_ownership_state source_state)
{
    if(source_is_null)
    {
        return P101_TOOL_EVENT_OWNERSHIP_REPLACE_NEW;
    }
    if(source_state == P101_TOOL_EVENT_OWNERSHIP_LIVE)
    {
        return P101_TOOL_EVENT_OWNERSHIP_REPLACE_OK;
    }
    return P101_TOOL_EVENT_OWNERSHIP_REPLACE_BAD;
}

bool p101_tool_event_ownership_exec_inherits(p101_tool_event_ownership_state state, bool close_on_exec)
{
    return (state == P101_TOOL_EVENT_OWNERSHIP_LIVE && !close_on_exec) != 0;
}
