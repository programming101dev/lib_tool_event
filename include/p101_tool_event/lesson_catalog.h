#ifndef P101_TOOL_EVENT_LESSON_CATALOG_H
#define P101_TOOL_EVENT_LESSON_CATALOG_H

/* Generated from playgrounds/lessons/manifest.json; do not edit. */

#ifdef __cplusplus
extern "C"
{
#endif

    // clang-format off
    typedef enum
    {
        P101_TOOL_FINDING_WRAP_001 = 0,
        P101_TOOL_FINDING_WRAP_002 = 1,
        P101_TOOL_FINDING_WRAP_003 = 2,
        P101_TOOL_FINDING_WRAP_004 = 3,
        P101_TOOL_FINDING_WRAP_900 = 4,
        P101_TOOL_FINDING_ERR_001 = 5,
        P101_TOOL_FINDING_ERR_002 = 6,
        P101_TOOL_FINDING_ERR_003 = 7,
        P101_TOOL_FINDING_ERR_004 = 8,
        P101_TOOL_FINDING_ERR_005 = 9,
        P101_TOOL_FINDING_ERR_006 = 10,
        P101_TOOL_FINDING_ERR_007 = 11,
        P101_TOOL_FINDING_ERR_008 = 12,
        P101_TOOL_FINDING_ERR_009 = 13,
        P101_TOOL_FINDING_MOD_002 = 14,
        P101_TOOL_FINDING_MOD_003 = 15,
        P101_TOOL_FINDING_MOD_004 = 16,
        P101_TOOL_FINDING_MOD_006 = 17,
        P101_TOOL_FINDING_MOD_007 = 18,
        P101_TOOL_FINDING_MOD_008 = 19,
        P101_TOOL_FINDING_MOD_009 = 20,
        P101_TOOL_FINDING_MOD_010 = 21,
        P101_TOOL_FINDING_MOD_011 = 22,
        P101_TOOL_FINDING_MOD_012 = 23,
        P101_TOOL_FINDING_MOD_013 = 24,
        P101_TOOL_FINDING_MOD_014 = 25,
        P101_TOOL_FINDING_MOD_015 = 26,
        P101_TOOL_FINDING_MOD_016 = 27,
        P101_TOOL_FINDING_MOD_017 = 28,
        P101_TOOL_FINDING_MOD_018 = 29,
        P101_TOOL_FINDING_MOD_019 = 30,
        P101_TOOL_FINDING_MOD_020 = 31,
        P101_TOOL_FINDING_MOD_021 = 32,
        P101_TOOL_FINDING_MOD_022 = 33,
        P101_TOOL_FINDING_MOD_027 = 34,
        P101_TOOL_FINDING_ALLOC_004 = 35,
        P101_TOOL_FINDING_RESOURCE_001 = 36,
        P101_TOOL_FINDING_RESOURCE_002 = 37,
        P101_TOOL_FINDING_RESOURCE_003 = 38,
        P101_TOOL_FINDING_RESOURCE_004 = 39,
        P101_TOOL_FINDING_RESOURCE_005 = 40,
        P101_TOOL_FINDING_SYNC_001 = 41,
        P101_TOOL_FINDING_SYNC_002 = 42,
        P101_TOOL_FINDING_SYNC_003 = 43,
        P101_TOOL_FINDING_TRACE_001 = 44,
        P101_TOOL_FINDING_TRACE_002 = 45,
        P101_TOOL_FINDING_TRACE_003 = 46,
        P101_TOOL_FINDING_SAN_001 = 47,
        P101_TOOL_FINDING_SAN_002 = 48,
        P101_TOOL_FINDING_SAN_003 = 49,
        P101_TOOL_FINDING_SAN_004 = 50,
        P101_TOOL_FINDING_MUTATION_001 = 51,
        P101_TOOL_FINDING_API_001 = 52,
        P101_TOOL_FINDING_API_002 = 53,
        P101_TOOL_FINDING_API_003 = 54,
        P101_TOOL_FINDING_API_004 = 55,
        P101_TOOL_FINDING_POLICY_RESOURCE_001 = 56,
        P101_TOOL_FINDING_POLICY_RESOURCE_002 = 57,
        P101_TOOL_FINDING_POLICY_RESOURCE_003 = 58,
        P101_TOOL_FINDING_COUNT = 59
    } p101_tool_finding;

    struct p101_tool_rule_definition
    {
        const char *id;
        const char *lesson_id;
        const char *lesson_path;
        const char *lesson_url;
    };

    // clang-format on

    const struct p101_tool_rule_definition *p101_tool_rule_definition_lookup(p101_tool_finding finding);

#ifdef __cplusplus
}
#endif

#endif
