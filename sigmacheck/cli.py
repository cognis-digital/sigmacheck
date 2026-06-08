"""Command-line interface for SIGMACHECK.

Subcommands:
  lint   RULE.yml                 Lint one or more Sigma rules.
  test   RULE.yml --cases C.json  Run unit-test cases against a rule.
  match  RULE.yml --event E.json  Evaluate a single event against a rule.

Global: --version, --format {table,json}
Exit codes: 0 = clean, 1 = findings/test failures, 2 = usage/parse error.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    lint_rule,
    run_unit_tests,
    evaluate_detection,
    parse_yaml,
    YamlError,
)


def _load_rule(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return parse_yaml(fh.read())


def _load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _emit(obj: Any, fmt: str, table_fn) -> None:
    if fmt == "json":
        print(json.dumps(obj, indent=2))
    else:
        table_fn(obj)


def _lint_table(report: Dict[str, Any]) -> None:
    print(f"errors={report['errors']} warnings={report['warnings']}")
    for f in report["findings"]:
        print(f"  [{f['level'].upper():7}] {f['code']}: {f['message']}")
    if not report["findings"]:
        print("  (clean)")


def _test_table(payload: Dict[str, Any]) -> None:
    print(f"passed={payload['passed']}/{payload['total']}")
    for r in payload["results"]:
        status = "PASS" if r["passed"] else "FAIL"
        detail = f"expected={r['expected']} actual={r['actual']}"
        if r["error"]:
            detail = f"error={r['error']}"
        print(f"  [{status}] {r['name']}: {detail}")


def cmd_lint(args: argparse.Namespace) -> int:
    total_errors = 0
    reports: List[Dict[str, Any]] = []
    for path in args.rules:
        try:
            rule = _load_rule(path)
        except (OSError, YamlError) as exc:
            print(f"error: cannot parse {path}: {exc}", file=sys.stderr)
            return 2
        rep = lint_rule(rule).to_dict()
        rep["rule"] = path
        total_errors += rep["errors"]
        reports.append(rep)

    if args.format == "json":
        print(json.dumps({"tool": TOOL_NAME, "reports": reports}, indent=2))
    else:
        for rep in reports:
            print(f"== {rep['rule']} ==")
            _lint_table(rep)
    return 1 if total_errors else 0


def cmd_test(args: argparse.Namespace) -> int:
    try:
        rule = _load_rule(args.rule)
        cases = _load_json(args.cases)
    except (OSError, YamlError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if isinstance(cases, dict) and "tests" in cases:
        cases = cases["tests"]
    if not isinstance(cases, list):
        print("error: cases file must be a JSON list (or {\"tests\": [...]})", file=sys.stderr)
        return 2
    results = run_unit_tests(rule, cases)
    passed = sum(1 for r in results if r.passed)
    payload = {
        "tool": TOOL_NAME,
        "rule": args.rule,
        "total": len(results),
        "passed": passed,
        "results": [r.to_dict() for r in results],
    }
    _emit(payload, args.format, _test_table)
    return 0 if passed == len(results) and results else (0 if not results else 1)


def cmd_match(args: argparse.Namespace) -> int:
    try:
        rule = _load_rule(args.rule)
        event = _load_json(args.event)
    except (OSError, YamlError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    if not isinstance(event, dict):
        print("error: event file must be a JSON object", file=sys.stderr)
        return 2
    try:
        matched = evaluate_detection(rule, event)
    except YamlError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    payload = {"tool": TOOL_NAME, "rule": args.rule, "matched": matched}
    _emit(payload, args.format, lambda p: print(f"matched={p['matched']}"))
    # A non-match is a normal/clean result; only return 1 to flag a detection hit
    return 1 if matched else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Lint and unit-test Sigma detection rules against sample events.",
    )
    parser.add_argument("--version", action="version", version=f"{TOOL_NAME} {TOOL_VERSION}")
    parser.add_argument(
        "--format", choices=("table", "json"), default="table", help="output format"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_lint = sub.add_parser("lint", help="lint Sigma rule files")
    p_lint.add_argument("rules", nargs="+", help="Sigma rule YAML file(s)")
    p_lint.set_defaults(func=cmd_lint)

    p_test = sub.add_parser("test", help="run unit-test cases against a rule")
    p_test.add_argument("rule", help="Sigma rule YAML file")
    p_test.add_argument("--cases", required=True, help="JSON file of test cases")
    p_test.set_defaults(func=cmd_test)

    p_match = sub.add_parser("match", help="evaluate a single event against a rule")
    p_match.add_argument("rule", help="Sigma rule YAML file")
    p_match.add_argument("--event", required=True, help="JSON file with a single event object")
    p_match.set_defaults(func=cmd_match)

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
