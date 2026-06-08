"""Core engine for SIGMACHECK.

Implements a small, dependency-free YAML subset parser (enough for Sigma
rules), a Sigma detection evaluator (selections, modifiers, condition
expressions) and a linter plus a unit-test runner.

The detection evaluator supports the common Sigma constructs:
  - selection maps: {field: value} / {field: [v1, v2]}
  - field modifiers: |contains, |startswith, |endswith, |re, |all
  - keyword lists (list of strings matched against any field value)
  - condition expressions: and / or / not, parentheses, '1 of selection*',
    'all of selection*', '1 of them', 'all of them'.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

MANDATORY_FIELDS = ("title", "logsource", "detection")
VALID_LEVELS = {"informational", "low", "medium", "high", "critical"}
VALID_STATUS = {"stable", "test", "experimental", "deprecated", "unsupported"}


# --------------------------------------------------------------------------
# Minimal YAML parser (indentation-based subset sufficient for Sigma rules)
# --------------------------------------------------------------------------
class YamlError(ValueError):
    pass


def _scalar(token: str) -> Any:
    token = token.strip()
    if token == "" or token in ("~", "null", "Null", "NULL"):
        return None
    if token in ("true", "True", "TRUE"):
        return True
    if token in ("false", "False", "FALSE"):
        return False
    if len(token) >= 2 and token[0] in "'\"" and token[-1] == token[0]:
        return token[1:-1]
    # inline flow list: [a, b, c]
    if token.startswith("[") and token.endswith("]"):
        inner = token[1:-1].strip()
        if not inner:
            return []
        return [_scalar(p) for p in _split_flow(inner)]
    try:
        return int(token)
    except ValueError:
        pass
    try:
        return float(token)
    except ValueError:
        pass
    return token


def _split_flow(inner: str) -> List[str]:
    parts, depth, cur = [], 0, []
    quote = None
    for ch in inner:
        if quote:
            cur.append(ch)
            if ch == quote:
                quote = None
            continue
        if ch in "'\"":
            quote = ch
            cur.append(ch)
        elif ch in "[{":
            depth += 1
            cur.append(ch)
        elif ch in "]}":
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            parts.append("".join(cur))
            cur = []
        else:
            cur.append(ch)
    if cur:
        parts.append("".join(cur))
    return parts


def _strip_comment(line: str) -> str:
    quote = None
    for i, ch in enumerate(line):
        if quote:
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
        elif ch == "#" and (i == 0 or line[i - 1] in " \t"):
            return line[:i]
    return line


def parse_yaml(text: str) -> Any:
    """Parse the YAML subset used by Sigma rules into Python objects."""
    raw_lines = text.splitlines()
    lines: List[Tuple[int, str]] = []
    for ln in raw_lines:
        body = _strip_comment(ln)
        if body.strip() == "" or body.strip() == "---":
            continue
        indent = len(body) - len(body.lstrip(" "))
        lines.append((indent, body.strip()))

    pos = 0

    def parse_block(indent: int) -> Any:
        nonlocal pos
        if pos >= len(lines):
            return None
        cur_indent = lines[pos][0]
        if lines[pos][1].startswith("- "):
            return parse_list(cur_indent)
        return parse_map(cur_indent)

    def parse_list(indent: int) -> List[Any]:
        nonlocal pos
        items: List[Any] = []
        while pos < len(lines):
            ind, content = lines[pos]
            if ind < indent or not content.startswith("- "):
                break
            if ind > indent:
                raise YamlError(f"bad list indentation: {content!r}")
            item_body = content[2:].strip()
            pos += 1
            if ":" in item_body and not _looks_scalar(item_body):
                # inline map start on the dash line
                k, _, v = item_body.partition(":")
                m: Dict[str, Any] = {}
                if v.strip():
                    m[k.strip()] = _scalar(v)
                else:
                    m[k.strip()] = _maybe_nested(indent + 2)
                # continuation keys belong to deeper indent
                while pos < len(lines) and lines[pos][0] > indent and not lines[pos][1].startswith("- "):
                    k2, _, v2 = lines[pos][1].partition(":")
                    nxt = lines[pos][0]
                    pos += 1
                    if v2.strip():
                        m[k2.strip()] = _scalar(v2)
                    else:
                        m[k2.strip()] = _maybe_nested(nxt + 1)
                items.append(m)
            else:
                items.append(_scalar(item_body))
        return items

    def _looks_scalar(body: str) -> bool:
        # e.g. 'http://x' has ':' but is a scalar; treat key:val where key has no space oddities
        key = body.split(":", 1)[0]
        return " " in key and not key.replace(" ", "").isalnum()

    def parse_map(indent: int) -> Dict[str, Any]:
        nonlocal pos
        result: Dict[str, Any] = {}
        while pos < len(lines):
            ind, content = lines[pos]
            if ind < indent:
                break
            if ind > indent:
                raise YamlError(f"bad mapping indentation: {content!r}")
            if content.startswith("- "):
                break
            if ":" not in content:
                raise YamlError(f"expected key: value, got {content!r}")
            key, _, val = content.partition(":")
            key = key.strip()
            val = val.strip()
            pos += 1
            if val:
                result[key] = _scalar(val)
            else:
                result[key] = _maybe_nested(indent + 1)
        return result

    def _maybe_nested(min_indent: int) -> Any:
        nonlocal pos
        if pos >= len(lines):
            return None
        ind = lines[pos][0]
        if ind >= min_indent:
            return parse_block(ind)
        return None

    if not lines:
        return {}
    return parse_block(lines[0][0])


# --------------------------------------------------------------------------
# Detection evaluation
# --------------------------------------------------------------------------
def _as_list(v: Any) -> List[Any]:
    return v if isinstance(v, list) else [v]


def _match_field(event_val: Any, expected: Any, modifier: Optional[str]) -> bool:
    if event_val is None:
        return expected is None
    sval = str(event_val)
    exp = str(expected)
    if modifier is None:
        # case-insensitive exact, Sigma default semantics
        return sval.lower() == exp.lower()
    if modifier == "contains":
        return exp.lower() in sval.lower()
    if modifier == "startswith":
        return sval.lower().startswith(exp.lower())
    if modifier == "endswith":
        return sval.lower().endswith(exp.lower())
    if modifier == "re":
        try:
            return re.search(exp, sval) is not None
        except re.error:
            return False
    # unknown modifier -> fall back to exact
    return sval.lower() == exp.lower()


def _eval_selection(sel: Any, event: Dict[str, Any]) -> bool:
    # keyword list: list of bare strings -> match against any event value
    if isinstance(sel, list):
        for kw in sel:
            for ev in event.values():
                if str(kw).lower() in str(ev).lower():
                    return True
        return False
    if not isinstance(sel, dict):
        return False
    # all key constraints must hold (AND)
    for raw_key, expected in sel.items():
        parts = raw_key.split("|")
        field_name = parts[0]
        mods = parts[1:]
        all_mod = "all" in mods
        value_mods = [m for m in mods if m in ("contains", "startswith", "endswith", "re")]
        modifier = value_mods[0] if value_mods else None
        ev_val = event.get(field_name)
        candidates = _as_list(expected)
        if all_mod:
            ok = all(_match_field(ev_val, c, modifier) for c in candidates)
        else:
            ok = any(_match_field(ev_val, c, modifier) for c in candidates)
        if not ok:
            return False
    return True


def _resolve_named(name: str, detection: Dict[str, Any], event: Dict[str, Any]) -> bool:
    if name not in detection:
        raise YamlError(f"condition references unknown selection '{name}'")
    return _eval_selection(detection[name], event)


def _selection_names(detection: Dict[str, Any]) -> List[str]:
    return [k for k in detection.keys() if k != "condition"]


def _expand_pattern(pattern: str, detection: Dict[str, Any]) -> List[str]:
    if pattern == "them":
        return _selection_names(detection)
    if pattern.endswith("*"):
        prefix = pattern[:-1]
        return [n for n in _selection_names(detection) if n.startswith(prefix)]
    return [pattern] if pattern in detection else []


def _tokenize_condition(expr: str) -> List[str]:
    tokens = re.findall(r"\(|\)|\b1 of\b|\ball of\b|\bof\b|\band\b|\bor\b|\bnot\b|[A-Za-z0-9_*]+", expr)
    return [t.strip() for t in tokens if t.strip()]


def _eval_condition(expr: str, detection: Dict[str, Any], event: Dict[str, Any]) -> bool:
    tokens = _tokenize_condition(expr)
    pos = 0

    def peek() -> Optional[str]:
        return tokens[pos] if pos < len(tokens) else None

    def advance() -> str:
        nonlocal pos
        tok = tokens[pos]
        pos += 1
        return tok

    def parse_or() -> bool:
        val = parse_and()
        while peek() == "or":
            advance()
            rhs = parse_and()
            val = val or rhs
        return val

    def parse_and() -> bool:
        val = parse_not()
        while peek() == "and":
            advance()
            rhs = parse_not()
            val = val and rhs
        return val

    def parse_not() -> bool:
        if peek() == "not":
            advance()
            return not parse_not()
        return parse_atom()

    def parse_atom() -> bool:
        tok = peek()
        if tok == "(":
            advance()
            val = parse_or()
            if peek() != ")":
                raise YamlError("unbalanced parentheses in condition")
            advance()
            return val
        if tok in ("1 of", "all of"):
            quant = advance()
            pat = advance()
            names = _expand_pattern(pat, detection)
            if not names:
                raise YamlError(f"condition pattern '{pat}' matched no selections")
            results = [_resolve_named(n, detection, event) for n in names]
            return all(results) if quant == "all of" else any(results)
        # bare selection name
        if tok is None:
            raise YamlError("unexpected end of condition")
        advance()
        return _resolve_named(tok, detection, event)

    result = parse_or()
    if pos != len(tokens):
        raise YamlError(f"trailing tokens in condition: {tokens[pos:]}")
    return result


def evaluate_detection(rule: Dict[str, Any], event: Dict[str, Any]) -> bool:
    """Return True if the Sigma rule's detection matches the given event."""
    detection = rule.get("detection")
    if not isinstance(detection, dict):
        raise YamlError("rule has no usable 'detection' mapping")
    condition = detection.get("condition")
    if not isinstance(condition, str):
        raise YamlError("detection has no string 'condition'")
    return _eval_condition(condition, detection, event)


# --------------------------------------------------------------------------
# Linter
# --------------------------------------------------------------------------
@dataclass
class Finding:
    level: str  # "error" | "warning"
    code: str
    message: str

    def to_dict(self) -> Dict[str, str]:
        return {"level": self.level, "code": self.code, "message": self.message}


@dataclass
class LintReport:
    findings: List[Finding] = field(default_factory=list)

    @property
    def errors(self) -> List[Finding]:
        return [f for f in self.findings if f.level == "error"]

    @property
    def warnings(self) -> List[Finding]:
        return [f for f in self.findings if f.level == "warning"]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "errors": len(self.errors),
            "warnings": len(self.warnings),
            "findings": [f.to_dict() for f in self.findings],
        }


def lint_rule(rule: Any) -> LintReport:
    """Lint a parsed Sigma rule for structural and best-practice issues."""
    report = LintReport()
    add = lambda lv, c, m: report.findings.append(Finding(lv, c, m))

    if not isinstance(rule, dict):
        add("error", "SIG001", "rule is not a YAML mapping")
        return report

    for f in MANDATORY_FIELDS:
        if f not in rule:
            add("error", "SIG002", f"missing mandatory field '{f}'")

    if "id" not in rule:
        add("warning", "SIG010", "rule has no 'id' (UUID) for stable tracking")
    if "level" in rule and str(rule["level"]) not in VALID_LEVELS:
        add("warning", "SIG011", f"unusual level '{rule['level']}' (expected one of {sorted(VALID_LEVELS)})")
    if "status" in rule and str(rule["status"]) not in VALID_STATUS:
        add("warning", "SIG012", f"unusual status '{rule['status']}'")
    if "title" in rule and isinstance(rule["title"], str) and len(rule["title"]) > 120:
        add("warning", "SIG013", "title exceeds 120 characters")

    logsource = rule.get("logsource")
    if logsource is not None and not isinstance(logsource, dict):
        add("error", "SIG003", "'logsource' must be a mapping")
    elif isinstance(logsource, dict) and not any(
        k in logsource for k in ("product", "category", "service")
    ):
        add("warning", "SIG014", "logsource has none of product/category/service")

    detection = rule.get("detection")
    if detection is None:
        return report
    if not isinstance(detection, dict):
        add("error", "SIG004", "'detection' must be a mapping")
        return report

    condition = detection.get("condition")
    sel_names = _selection_names(detection)
    if not sel_names:
        add("error", "SIG005", "detection defines no selections")
    if condition is None:
        add("error", "SIG006", "detection has no 'condition'")
    elif not isinstance(condition, str):
        add("error", "SIG007", "'condition' must be a string expression")
    else:
        # referenced names must exist; named ones should be used
        referenced = set()
        for tok in _tokenize_condition(condition):
            if tok in detection and tok != "condition":
                referenced.add(tok)
            elif tok.endswith("*"):
                referenced.update(_expand_pattern(tok, detection))
            elif tok == "them":
                referenced.update(sel_names)
        # validate refs that look like selection names
        for tok in _tokenize_condition(condition):
            kw = {"and", "or", "not", "1 of", "all of", "of", "them", "(", ")"}
            if tok in kw or tok.endswith("*"):
                continue
            if tok not in detection:
                add("error", "SIG008", f"condition references unknown selection '{tok}'")
        for name in sel_names:
            if name not in referenced:
                add("warning", "SIG015", f"selection '{name}' is never used by the condition")

    for name in sel_names:
        sel = detection[name]
        if isinstance(sel, dict):
            for key in sel:
                mods = key.split("|")[1:]
                for m in mods:
                    if m not in ("contains", "startswith", "endswith", "re", "all"):
                        add("warning", "SIG016", f"selection '{name}' uses unrecognized modifier '|{m}'")
                if key.split("|")[1:] and "re" in mods:
                    pat = sel[key]
                    for p in _as_list(pat):
                        try:
                            re.compile(str(p))
                        except re.error as exc:
                            add("error", "SIG009", f"selection '{name}' has invalid regex: {exc}")
    return report


# --------------------------------------------------------------------------
# Unit-test runner
# --------------------------------------------------------------------------
@dataclass
class TestResult:
    name: str
    passed: bool
    expected: bool
    actual: Optional[bool]
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "passed": self.passed,
            "expected": self.expected,
            "actual": self.actual,
            "error": self.error,
        }


def run_unit_tests(rule: Dict[str, Any], cases: List[Dict[str, Any]]) -> List[TestResult]:
    """Evaluate the rule against test cases.

    Each case: {name, event:{...}, expect_match: bool}.
    """
    results: List[TestResult] = []
    for i, case in enumerate(cases):
        name = str(case.get("name", f"case-{i}"))
        expected = bool(case.get("expect_match", False))
        event = case.get("event", {})
        if not isinstance(event, dict):
            results.append(TestResult(name, False, expected, None, "event is not an object"))
            continue
        try:
            actual = evaluate_detection(rule, event)
            results.append(TestResult(name, actual == expected, expected, actual))
        except Exception as exc:  # noqa: BLE001 - report any eval error as test failure
            results.append(TestResult(name, False, expected, None, str(exc)))
    return results
