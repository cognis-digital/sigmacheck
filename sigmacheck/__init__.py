"""SIGMACHECK - Lint and unit-test Sigma detection rules against sample events.

Defensive / authorized-testing tool. Analysis, triage and detection only:
it parses Sigma rule YAML, lints it for structural and best-practice issues,
and evaluates the detection logic against sample events to confirm the rule
matches what it is supposed to (and does NOT match what it shouldn't).

No network access, standard library only.
"""
from .core import (
    Finding,
    LintReport,
    TestResult,
    lint_rule,
    evaluate_detection,
    run_unit_tests,
    parse_yaml,
)

TOOL_NAME = "sigmacheck"
TOOL_VERSION = "1.0.0"

__all__ = [
    "TOOL_NAME",
    "TOOL_VERSION",
    "Finding",
    "LintReport",
    "TestResult",
    "lint_rule",
    "evaluate_detection",
    "run_unit_tests",
    "parse_yaml",
]
