#include <p101_tool_event/ownership.h>
#include <p101_transition/transition.h>

enum
{
    OWNERSHIP_EVENT_RELEASE = 1,
    OWNERSHIP_EVENT_REPLACE_NULL,
    OWNERSHIP_EVENT_REPLACE_LIVE,
    OWNERSHIP_EVENT_EXEC_CLOSE,
    OWNERSHIP_EVENT_EXEC_KEEP
};

static const struct p101_transition_rule release_rules[] = {
    {P101_TOOL_EVENT_OWNERSHIP_NEVER,    OWNERSHIP_EVENT_RELEASE, P101_TOOL_EVENT_OWNERSHIP_NEVER,    P101_TOOL_EVENT_OWNERSHIP_RELEASE_STRAY    },
    {P101_TOOL_EVENT_OWNERSHIP_LIVE,     OWNERSHIP_EVENT_RELEASE, P101_TOOL_EVENT_OWNERSHIP_RELEASED, P101_TOOL_EVENT_OWNERSHIP_RELEASE_OK       },
    {P101_TOOL_EVENT_OWNERSHIP_RELEASED, OWNERSHIP_EVENT_RELEASE, P101_TOOL_EVENT_OWNERSHIP_RELEASED, P101_TOOL_EVENT_OWNERSHIP_RELEASE_DUPLICATE},
};

static const struct p101_transition_rule replace_rules[] = {
    {P101_TOOL_EVENT_OWNERSHIP_NEVER,    OWNERSHIP_EVENT_REPLACE_NULL, P101_TOOL_EVENT_OWNERSHIP_LIVE,     P101_TOOL_EVENT_OWNERSHIP_REPLACE_NEW},
    {P101_TOOL_EVENT_OWNERSHIP_LIVE,     OWNERSHIP_EVENT_REPLACE_NULL, P101_TOOL_EVENT_OWNERSHIP_LIVE,     P101_TOOL_EVENT_OWNERSHIP_REPLACE_NEW},
    {P101_TOOL_EVENT_OWNERSHIP_RELEASED, OWNERSHIP_EVENT_REPLACE_NULL, P101_TOOL_EVENT_OWNERSHIP_LIVE,     P101_TOOL_EVENT_OWNERSHIP_REPLACE_NEW},
    {P101_TOOL_EVENT_OWNERSHIP_NEVER,    OWNERSHIP_EVENT_REPLACE_LIVE, P101_TOOL_EVENT_OWNERSHIP_NEVER,    P101_TOOL_EVENT_OWNERSHIP_REPLACE_BAD},
    {P101_TOOL_EVENT_OWNERSHIP_LIVE,     OWNERSHIP_EVENT_REPLACE_LIVE, P101_TOOL_EVENT_OWNERSHIP_LIVE,     P101_TOOL_EVENT_OWNERSHIP_REPLACE_OK },
    {P101_TOOL_EVENT_OWNERSHIP_RELEASED, OWNERSHIP_EVENT_REPLACE_LIVE, P101_TOOL_EVENT_OWNERSHIP_RELEASED, P101_TOOL_EVENT_OWNERSHIP_REPLACE_BAD},
};

static const struct p101_transition_rule exec_rules[] = {
    {P101_TOOL_EVENT_OWNERSHIP_NEVER,    OWNERSHIP_EVENT_EXEC_CLOSE, P101_TOOL_EVENT_OWNERSHIP_NEVER,    0U},
    {P101_TOOL_EVENT_OWNERSHIP_LIVE,     OWNERSHIP_EVENT_EXEC_CLOSE, P101_TOOL_EVENT_OWNERSHIP_RELEASED, 0U},
    {P101_TOOL_EVENT_OWNERSHIP_RELEASED, OWNERSHIP_EVENT_EXEC_CLOSE, P101_TOOL_EVENT_OWNERSHIP_RELEASED, 0U},
    {P101_TOOL_EVENT_OWNERSHIP_NEVER,    OWNERSHIP_EVENT_EXEC_KEEP,  P101_TOOL_EVENT_OWNERSHIP_NEVER,    0U},
    {P101_TOOL_EVENT_OWNERSHIP_LIVE,     OWNERSHIP_EVENT_EXEC_KEEP,  P101_TOOL_EVENT_OWNERSHIP_LIVE,     1U},
    {P101_TOOL_EVENT_OWNERSHIP_RELEASED, OWNERSHIP_EVENT_EXEC_KEEP,  P101_TOOL_EVENT_OWNERSHIP_RELEASED, 0U},
};

p101_tool_event_ownership_release_result p101_tool_event_ownership_classify_release(p101_tool_event_ownership_state state)
{
    p101_tool_event_ownership_release_result p101_single_result_;
    struct p101_transition_result            result;
    p101_transition_status                   status;
    p101_transition_id                       transition_state;

    transition_state = (p101_transition_id)state;
    status           = p101_transition_rules_find(release_rules, sizeof(release_rules) / sizeof(release_rules[0]), transition_state, OWNERSHIP_EVENT_RELEASE, &result);
    if(status == P101_TRANSITION_OK)
    {
        p101_single_result_ = (p101_tool_event_ownership_release_result)result.rule->value;
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
    struct p101_transition_result            result;
    p101_transition_status                   status;
    p101_transition_id                       event;
    p101_transition_id                       transition_state;

    if(source_is_null)
    {
        event = OWNERSHIP_EVENT_REPLACE_NULL;
    }
    else
    {
        event = OWNERSHIP_EVENT_REPLACE_LIVE;
    }
    transition_state = (p101_transition_id)source_state;
    status           = p101_transition_rules_find(replace_rules, sizeof(replace_rules) / sizeof(replace_rules[0]), transition_state, event, &result);
    if(status == P101_TRANSITION_OK)
    {
        p101_single_result_ = (p101_tool_event_ownership_replace_result)result.rule->value;
        goto p101_single_exit_;
    }
    p101_single_result_ = P101_TOOL_EVENT_OWNERSHIP_REPLACE_BAD;
    goto p101_single_exit_;

p101_single_exit_:
    return p101_single_result_;
}

bool p101_tool_event_ownership_exec_inherits(p101_tool_event_ownership_state state, bool close_on_exec)
{
    bool                          p101_single_result_;
    struct p101_transition_result result;
    p101_transition_status        status;
    p101_transition_id            event;
    p101_transition_id            transition_state;

    if(close_on_exec)
    {
        event = OWNERSHIP_EVENT_EXEC_CLOSE;
    }
    else
    {
        event = OWNERSHIP_EVENT_EXEC_KEEP;
    }
    transition_state    = (p101_transition_id)state;
    status              = p101_transition_rules_find(exec_rules, sizeof(exec_rules) / sizeof(exec_rules[0]), transition_state, event, &result);
    p101_single_result_ = false;
    if(status == P101_TRANSITION_OK)
    {
        p101_single_result_ = result.rule->value != 0U;
    }

    return p101_single_result_;
}
