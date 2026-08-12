#include <errno.h>
#include <p101_tool_event/lesson_catalog.h>
#include <stddef.h>
#include <string.h>

/* Generated from playgrounds/lessons/manifest.json; do not edit. */

const struct p101_tool_rule_definition *p101_tool_rule_definition_lookup(p101_tool_finding finding)
{
    // clang-format off
    static const struct p101_tool_rule_definition rules[] = {
        {"P101-WRAP-001", "P101-LESSON-WRAPPER-BOUNDARIES", "lessons/wrapper-boundaries.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/wrapper-boundaries.md"},
        {"P101-WRAP-002", "P101-LESSON-WRAPPER-BOUNDARIES", "lessons/wrapper-boundaries.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/wrapper-boundaries.md"},
        {"P101-WRAP-003", "P101-LESSON-WRAPPER-BOUNDARIES", "lessons/wrapper-boundaries.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/wrapper-boundaries.md"},
        {"P101-WRAP-004", "P101-LESSON-WRAPPER-BOUNDARIES", "lessons/wrapper-boundaries.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/wrapper-boundaries.md"},
        {"P101-WRAP-900", "P101-LESSON-WRAPPER-BOUNDARIES", "lessons/wrapper-boundaries.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/wrapper-boundaries.md"},
        {"P101-ERR-001", "P101-LESSON-ERROR-CONTRACTS", "lessons/error-contracts.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/error-contracts.md"},
        {"P101-ERR-002", "P101-LESSON-ERROR-CONTRACTS", "lessons/error-contracts.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/error-contracts.md"},
        {"P101-ERR-003", "P101-LESSON-ERROR-CONTRACTS", "lessons/error-contracts.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/error-contracts.md"},
        {"P101-ERR-004", "P101-LESSON-ERROR-CONTRACTS", "lessons/error-contracts.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/error-contracts.md"},
        {"P101-ERR-005", "P101-LESSON-ERROR-CONTRACTS", "lessons/error-contracts.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/error-contracts.md"},
        {"P101-ERR-006", "P101-LESSON-ERROR-CONTRACTS", "lessons/error-contracts.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/error-contracts.md"},
        {"P101-ERR-007", "P101-LESSON-ERROR-CONTRACTS", "lessons/error-contracts.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/error-contracts.md"},
        {"P101-ERR-008", "P101-LESSON-ERROR-CONTRACTS", "lessons/error-contracts.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/error-contracts.md"},
        {"P101-ERR-009", "P101-LESSON-ERROR-CONTRACTS", "lessons/error-contracts.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/error-contracts.md"},
        {"P101-MOD-002", "P101-LESSON-MODULE-BOUNDARIES", "lessons/module-boundaries.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/module-boundaries.md"},
        {"P101-MOD-003", "P101-LESSON-MODULE-BOUNDARIES", "lessons/module-boundaries.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/module-boundaries.md"},
        {"P101-MOD-004", "P101-LESSON-MODULE-BOUNDARIES", "lessons/module-boundaries.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/module-boundaries.md"},
        {"P101-MOD-006", "P101-LESSON-MODULE-BOUNDARIES", "lessons/module-boundaries.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/module-boundaries.md"},
        {"P101-MOD-007", "P101-LESSON-MODULE-BOUNDARIES", "lessons/module-boundaries.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/module-boundaries.md"},
        {"P101-MOD-008", "P101-LESSON-MODULE-BOUNDARIES", "lessons/module-boundaries.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/module-boundaries.md"},
        {"P101-MOD-009", "P101-LESSON-MODULE-BOUNDARIES", "lessons/module-boundaries.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/module-boundaries.md"},
        {"P101-MOD-010", "P101-LESSON-MODULE-BOUNDARIES", "lessons/module-boundaries.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/module-boundaries.md"},
        {"P101-MOD-011", "P101-LESSON-MODULE-BOUNDARIES", "lessons/module-boundaries.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/module-boundaries.md"},
        {"P101-MOD-012", "P101-LESSON-MODULE-BOUNDARIES", "lessons/module-boundaries.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/module-boundaries.md"},
        {"P101-MOD-013", "P101-LESSON-MODULE-BOUNDARIES", "lessons/module-boundaries.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/module-boundaries.md"},
        {"P101-MOD-014", "P101-LESSON-MODULE-BOUNDARIES", "lessons/module-boundaries.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/module-boundaries.md"},
        {"P101-MOD-015", "P101-LESSON-MODULE-BOUNDARIES", "lessons/module-boundaries.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/module-boundaries.md"},
        {"P101-MOD-016", "P101-LESSON-MODULE-BOUNDARIES", "lessons/module-boundaries.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/module-boundaries.md"},
        {"P101-MOD-017", "P101-LESSON-MODULE-BOUNDARIES", "lessons/module-boundaries.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/module-boundaries.md"},
        {"P101-MOD-018", "P101-LESSON-MODULE-BOUNDARIES", "lessons/module-boundaries.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/module-boundaries.md"},
        {"P101-MOD-019", "P101-LESSON-MODULE-BOUNDARIES", "lessons/module-boundaries.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/module-boundaries.md"},
        {"P101-MOD-020", "P101-LESSON-MODULE-BOUNDARIES", "lessons/module-boundaries.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/module-boundaries.md"},
        {"P101-MOD-021", "P101-LESSON-MODULE-BOUNDARIES", "lessons/module-boundaries.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/module-boundaries.md"},
        {"P101-MOD-022", "P101-LESSON-MODULE-BOUNDARIES", "lessons/module-boundaries.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/module-boundaries.md"},
        {"P101-MOD-027", "P101-LESSON-MODULE-BOUNDARIES", "lessons/module-boundaries.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/module-boundaries.md"},
        {"P101-ALLOC-004", "P101-LESSON-GENERIC-RESOURCES", "lessons/generic-resources.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/generic-resources.md"},
        {"P101-RESOURCE-000", "P101-LESSON-GENERIC-RESOURCES", "lessons/generic-resources.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/generic-resources.md"},
        {"P101-RESOURCE-001", "P101-LESSON-GENERIC-RESOURCES", "lessons/generic-resources.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/generic-resources.md"},
        {"P101-RESOURCE-002", "P101-LESSON-GENERIC-RESOURCES", "lessons/generic-resources.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/generic-resources.md"},
        {"P101-RESOURCE-003", "P101-LESSON-GENERIC-RESOURCES", "lessons/generic-resources.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/generic-resources.md"},
        {"P101-RESOURCE-004", "P101-LESSON-GENERIC-RESOURCES", "lessons/generic-resources.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/generic-resources.md"},
        {"P101-RESOURCE-005", "P101-LESSON-GENERIC-RESOURCES", "lessons/generic-resources.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/generic-resources.md"},
        {"P101-SYNC-001", "P101-LESSON-SYNCHRONIZATION", "lessons/synchronization.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/synchronization.md"},
        {"P101-SYNC-002", "P101-LESSON-SYNCHRONIZATION", "lessons/synchronization.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/synchronization.md"},
        {"P101-SYNC-003", "P101-LESSON-SYNCHRONIZATION", "lessons/synchronization.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/synchronization.md"},
        {"P101-TRACE-001", "P101-LESSON-TRACE-INTEGRITY", "lessons/trace-integrity.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/trace-integrity.md"},
        {"P101-TRACE-002", "P101-LESSON-TRACE-INTEGRITY", "lessons/trace-integrity.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/trace-integrity.md"},
        {"P101-TRACE-003", "P101-LESSON-TRACE-INTEGRITY", "lessons/trace-integrity.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/trace-integrity.md"},
        {"P101-SAN-001", "P101-LESSON-SANITIZERS", "lessons/sanitizer-findings.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/sanitizer-findings.md"},
        {"P101-SAN-002", "P101-LESSON-SANITIZERS", "lessons/sanitizer-findings.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/sanitizer-findings.md"},
        {"P101-SAN-003", "P101-LESSON-SANITIZERS", "lessons/sanitizer-findings.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/sanitizer-findings.md"},
        {"P101-SAN-004", "P101-LESSON-SANITIZERS", "lessons/sanitizer-findings.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/sanitizer-findings.md"},
        {"P101-MUTATION-001", "P101-LESSON-MUTATION-STRENGTH", "lessons/mutation-strength.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/mutation-strength.md"},
        {"P101-API-001", "P101-LESSON-API-COMPATIBILITY", "lessons/api-compatibility.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/api-compatibility.md"},
        {"P101-API-002", "P101-LESSON-API-COMPATIBILITY", "lessons/api-compatibility.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/api-compatibility.md"},
        {"P101-API-003", "P101-LESSON-API-COMPATIBILITY", "lessons/api-compatibility.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/api-compatibility.md"},
        {"P101-API-004", "P101-LESSON-API-COMPATIBILITY", "lessons/api-compatibility.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/api-compatibility.md"},
        {"P101-EXPECT-001", "P101-LESSON-POLICY-EXPECTATIONS", "lessons/policy-expectations.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/policy-expectations.md"},
        {"P101-POLICY-RESOURCE-001", "P101-LESSON-POLICY-EXPECTATIONS", "lessons/policy-expectations.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/policy-expectations.md"},
        {"P101-POLICY-RESOURCE-002", "P101-LESSON-POLICY-EXPECTATIONS", "lessons/policy-expectations.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/policy-expectations.md"},
        {"P101-POLICY-RESOURCE-003", "P101-LESSON-POLICY-EXPECTATIONS", "lessons/policy-expectations.md", "https://github.com/programming101dev/playgrounds/blob/main/lessons/policy-expectations.md"}
    };

    // clang-format on
    const struct p101_tool_rule_definition *rule;

    if(finding >= P101_TOOL_FINDING_COUNT)
    {
        errno = EINVAL;
        rule  = NULL;
    }
    else
    {
        rule = &rules[finding];
    }
    return rule;
}

const struct p101_tool_rule_definition *p101_tool_rule_definition_lookup_id(const char *diagnostic_id)
{
    const struct p101_tool_rule_definition *p101_single_result_;

    p101_single_result_ = NULL;
    if(diagnostic_id == NULL)
    {
        errno = EINVAL;
        goto p101_single_exit_;
    }
    for(p101_tool_finding finding = P101_TOOL_FINDING_WRAP_001; finding < P101_TOOL_FINDING_COUNT; finding++)
    {
        const struct p101_tool_rule_definition *definition;
        int                                     comparison;

        definition = p101_tool_rule_definition_lookup(finding);
        comparison = strcmp(definition->id, diagnostic_id);
        if(comparison == 0)
        {
            p101_single_result_ = definition;
            break;
        }
    }

p101_single_exit_:
    return p101_single_result_;
}
