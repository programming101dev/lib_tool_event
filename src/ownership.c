#include <p101_tool_event/ownership.h>

p101_tool_event_ownership_release_result p101_tool_event_ownership_classify_release(p101_tool_event_ownership_state state)
{
    p101_tool_event_ownership_release_result p101_single_result_;
    if(state == P101_TOOL_EVENT_OWNERSHIP_LIVE)
    {
        p101_single_result_ = P101_TOOL_EVENT_OWNERSHIP_RELEASE_OK;
        goto p101_single_exit_;
    }
    if(state == P101_TOOL_EVENT_OWNERSHIP_RELEASED)
    {
        p101_single_result_ = P101_TOOL_EVENT_OWNERSHIP_RELEASE_DUPLICATE;
        goto p101_single_exit_;
    }
    p101_single_result_ = P101_TOOL_EVENT_OWNERSHIP_RELEASE_STRAY;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

p101_tool_event_ownership_replace_result p101_tool_event_ownership_classify_replace(bool source_is_null, p101_tool_event_ownership_state source_state)
{
    p101_tool_event_ownership_replace_result p101_single_result_;
    if(source_is_null)
    {
        p101_single_result_ = P101_TOOL_EVENT_OWNERSHIP_REPLACE_NEW;
        goto p101_single_exit_;
    }
    if(source_state == P101_TOOL_EVENT_OWNERSHIP_LIVE)
    {
        p101_single_result_ = P101_TOOL_EVENT_OWNERSHIP_REPLACE_OK;
        goto p101_single_exit_;
    }
    p101_single_result_ = P101_TOOL_EVENT_OWNERSHIP_REPLACE_BAD;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

bool p101_tool_event_ownership_exec_inherits(p101_tool_event_ownership_state state, bool close_on_exec)
{
    return (state == P101_TOOL_EVENT_OWNERSHIP_LIVE && !close_on_exec) != 0;
}
