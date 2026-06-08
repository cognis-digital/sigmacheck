"""Command-line interface for SIGMACHECK."""

from __future__ import annotations

import argparse
import glob
import json
import os
import sys
from typing import List, Optional

from . import TOOL_NAME, TOOL_VERSION
from .core import (
    SEVERITY_ORDER,
    CheckResult,
    RuleResult,
    check_text,
    check_bundled,
    load_bundled_rules,
    match_event,
)


def _read(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    with open(path, "r", encoding="utf-8") as fh:
        return fh.read()


def _gather(paths: List[str]) -> str:
    """Concatenate rule files (multi-doc) into a single ``---``-joined text."""
    docs: List[str] = []
    expanded: List[str] = []
    for p in paths:
        if p == "-":
            expanded.append(p)
        elif os.path.isdir(p):
            for ext in ("*.yml", "*.yaml"):
                expanded.extend(sorted(glob.glob(os.path.join(p, "**", ext),
                                                  recursive=True)))
        elif any(ch in p for ch in "*?[]"):
            expanded.extend(sorted(glob.glob(p, recursive=True)))
        else:
            expanded.append(p)
    for p in expanded:
        docs.append(_read(p))
    return "\n---\n".join(docs)


def _icon(ok: bool) -> str:
    return "PASS" if ok else "FAIL"


def _render_check_table(result: CheckResult) -> str:
    lines: List[str] = []
    lines.append(f"SIGMACHECK {TOOL_VERSION} — Sigma rule validator + test runner")
    lines.append(f"rules={result.total_rules}  "
                 f"invalid={result.invalid_rules}  "
                 f"findings={result.total_findings}  "
                 f"tests={result.total_tests}  "
                 f"tests_failed={result.tests_failed}")
    lines.append("-" * 76)
    for r in result.rules:
        head = f"[{_icon(r.ok)}] {r.title}"
        if r.rule_id:
            head += f"  ({r.rule_id})"
        lines.append(head)
        if r.error:
            lines.append(f"      ERROR: {r.error}")
        for f in sorted(r.findings,
                        key=lambda x: -SEVERITY_ORDER.get(x.severity, 0)):
            lines.append(f"      - {f.severity:<8} [{f.check}] {f.message}")
        for t in r.tests:
            mark = "ok" if t.passed else "XX"
            lines.append(f"        {mark} test {t.name}: "
                         f"expected={t.expected} actual={t.actual}")
        if r.tests:
            lines.append(f"      tests: {r.tests_passed} passed, "
                         f"{r.tests_failed} failed")
    lines.append("-" * 76)
    lines.append("RESULT: " + ("ALL PASS" if result.ok else "FAILURES PRESENT"))
    return "\n".join(lines)


def _render_match_table(rule_title: str, matched: bool, event_idx: int) -> str:
    return f"event[{event_idx}] vs '{rule_title}': " + (
        "MATCH" if matched else "no match")


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="Sigma rule validator + unit-test runner (pySigma-spirit).",
    )
    p.add_argument("--version", action="version",
                   version=f"{TOOL_NAME} {TOOL_VERSION}")
    p.add_argument("--format", choices=["table", "json"], default="table",
                   help="output format (default: table)")

    sub = p.add_subparsers(dest="command", required=True)

    c = sub.add_parser("check", help="validate + self-test rule file(s)/dir(s)")
    c.add_argument("paths", nargs="*", default=["-"],
                   help="rule files, directories, or globs ('-' = stdin)")
    c.add_argument("--fail-on", default="high", choices=list(SEVERITY_ORDER),
                   help="min finding-severity that fails the run (default: high)")

    sub.add_parser("demo", help="validate + self-test the bundled rule library")

    ls = sub.add_parser("list", help="list bundled detection rules")

    m = sub.add_parser("match", help="match a rule file against JSON event(s)")
    m.add_argument("rule", help="path to a single Sigma rule file")
    m.add_argument("events", help="path to a JSON array or JSONL of events "
                                  "('-' = stdin)")

    return p


def _run_check(result: CheckResult, fmt: str, fail_on: str) -> int:
    if fmt == "json":
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print(_render_check_table(result))
    threshold = SEVERITY_ORDER[fail_on]
    sev_fail = any(
        SEVERITY_ORDER.get(f.severity, 0) >= threshold
        for r in result.rules for f in r.findings)
    failed = (not result.ok) or sev_fail or result.tests_failed > 0
    return 1 if failed else 0


def _load_events(text: str) -> List[dict]:
    text = text.strip()
    if not text:
        return []
    try:
        obj = json.loads(text)
        if isinstance(obj, list):
            return [e for e in obj if isinstance(e, dict)]
        if isinstance(obj, dict):
            return [obj]
    except json.JSONDecodeError:
        pass
    events = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        events.append(json.loads(line))
    return [e for e in events if isinstance(e, dict)]


def main(argv: Optional[list] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "check":
        try:
            text = _gather(args.paths or ["-"])
        except OSError as exc:
            print(f"sigmacheck: error: {exc}", file=sys.stderr)
            return 2
        result = check_text(text)
        return _run_check(result, args.format, args.fail_on)

    if args.command == "demo":
        result = check_bundled()
        return _run_check(result, args.format, "high")

    if args.command == "list":
        rules = load_bundled_rules()
        if args.format == "json":
            print(json.dumps([
                {"title": r.get("title"), "id": r.get("id"),
                 "level": r.get("level"), "status": r.get("status"),
                 "logsource": r.get("logsource")}
                for r in rules], indent=2))
        else:
            print(f"SIGMACHECK bundled rules ({len(rules)}):")
            for r in rules:
                ls = r.get("logsource") or {}
                src = "/".join(str(ls.get(k)) for k in
                               ("product", "category", "service") if ls.get(k))
                print(f"  - [{r.get('level','?'):<8}] {r.get('title')}  ({src})")
        return 0

    if args.command == "match":
        try:
            rule_text = _read(args.rule)
            events = _load_events(_read(args.events))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"sigmacheck: error: {exc}", file=sys.stderr)
            return 2
        from .core import parse_yaml, _split_documents
        docs = _split_documents(rule_text)
        if not docs:
            print("sigmacheck: error: no rule found", file=sys.stderr)
            return 2
        rule = parse_yaml(docs[0])
        title = (rule or {}).get("title", "<rule>")
        results = []
        any_match = False
        for i, ev in enumerate(events):
            try:
                matched = match_event(rule, ev)
            except Exception as exc:
                print(f"sigmacheck: error evaluating event {i}: {exc}",
                      file=sys.stderr)
                return 2
            any_match = any_match or matched
            results.append({"index": i, "match": matched})
            if args.format == "table":
                print(_render_match_table(title, matched, i))
        if args.format == "json":
            print(json.dumps({"rule": title, "results": results,
                              "any_match": any_match}, indent=2))
        return 1 if any_match else 0

    parser.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
