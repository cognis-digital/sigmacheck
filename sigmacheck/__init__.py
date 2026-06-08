"""SIGMACHECK — Sigma rule validator + unit-test runner (pySigma-spirit).

Stdlib-only. Parses Sigma detection rules, validates them against the Sigma
specification, compiles the ``detection`` block into a real boolean matcher,
and runs each rule's inline positive/negative unit tests against sample
events — reporting pass/fail just like the SigmaHQ test harness.
"""

from .core import (
    TOOL_NAME,
    TOOL_VERSION,
    Finding,
    TestResult,
    RuleResult,
    CheckResult,
    SEVERITY_ORDER,
    VALID_LEVELS,
    VALID_STATUS,
    SUPPORTED_MODIFIERS,
    parse_yaml,
    validate_rule,
    match_event,
    run_rule_tests,
    eval_condition,
    tokenize_condition,
    check_rule,
    check_text,
    check_rules,
    check_bundled,
    load_bundled_rules,
    BUNDLED_RULES,
)

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "Finding",
    "TestResult",
    "RuleResult",
    "CheckResult",
    "SEVERITY_ORDER",
    "VALID_LEVELS",
    "VALID_STATUS",
    "SUPPORTED_MODIFIERS",
    "parse_yaml",
    "validate_rule",
    "match_event",
    "run_rule_tests",
    "eval_condition",
    "tokenize_condition",
    "check_rule",
    "check_text",
    "check_rules",
    "check_bundled",
    "load_bundled_rules",
    "BUNDLED_RULES",
]
