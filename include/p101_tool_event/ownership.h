#ifndef P101_TOOL_EVENT_OWNERSHIP_H
#define P101_TOOL_EVENT_OWNERSHIP_H

#include <stdbool.h>

#ifdef __cplusplus
extern "C"
{
#endif

    /*
     * Shared transition policy for descriptor/allocation ownership models.
     * Tools may keep different presentation state, but they must ask these
     * functions for the classification attached to the same transition.
     */
    typedef enum
    {
        P101_TOOL_EVENT_OWNERSHIP_NEVER = 0,
        P101_TOOL_EVENT_OWNERSHIP_LIVE,
        P101_TOOL_EVENT_OWNERSHIP_RELEASED
    } p101_tool_event_ownership_state;

    typedef enum
    {
        P101_TOOL_EVENT_OWNERSHIP_RELEASE_OK = 0,
        P101_TOOL_EVENT_OWNERSHIP_RELEASE_STRAY,
        P101_TOOL_EVENT_OWNERSHIP_RELEASE_DUPLICATE
    } p101_tool_event_ownership_release_result;

    typedef enum
    {
        P101_TOOL_EVENT_OWNERSHIP_REPLACE_OK = 0,
        P101_TOOL_EVENT_OWNERSHIP_REPLACE_NEW,
        P101_TOOL_EVENT_OWNERSHIP_REPLACE_BAD
    } p101_tool_event_ownership_replace_result;

    p101_tool_event_ownership_release_result p101_tool_event_ownership_classify_release(p101_tool_event_ownership_state state);
    p101_tool_event_ownership_replace_result p101_tool_event_ownership_classify_replace(bool source_is_null, p101_tool_event_ownership_state source_state);
    bool                                     p101_tool_event_ownership_exec_inherits(p101_tool_event_ownership_state state, bool close_on_exec);

#ifdef __cplusplus
}
#endif

#endif
