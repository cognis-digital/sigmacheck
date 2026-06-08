"""Deep tests for SIGMACHECK. No network. Stdlib unittest only."""

import io
import json
import os
import sys
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# package dir is .../sigmacheck ; its parent must be importable as 'sigmacheck'
_PKG = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.dirname(_PKG))

from sigmacheck import (  # noqa: E402
    TOOL_NAME,
    TOOL_VERSION,
    parse_yaml,
    validate_rule,
    match_event,
    run_rule_tests,
    eval_condition,
    check_text,
    check_bundled,
    load_bundled_rules,
    SUPPORTED_MODIFIERS,
)
from sigmacheck.cli import main  # noqa: E402

DEEP = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "demos", "02-deep", "rules.yml")
EVENTS = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                      "demos", "02-deep", "events.jsonl")


class TestMeta(unittest.TestCase):
    def test_identity(self):
        self.assertEqual(TOOL_NAME, "sigmacheck")
        self.assertRegex(TOOL_VERSION, r"^\d+\.\d+\.\d+$")


class TestYamlParser(unittest.TestCase):
    def test_nested_and_lists(self):
        doc = parse_yaml(
            "title: X\n"
            "logsource:\n"
            "    product: windows\n"
            "detection:\n"
            "    selection:\n"
            "        Image|endswith:\n"
            "            - '\\a.exe'\n"
            "            - '\\b.exe'\n"
            "    condition: selection\n")
        self.assertEqual(doc["title"], "X")
        self.assertEqual(doc["logsource"]["product"], "windows")
        self.assertEqual(doc["detection"]["selection"]["Image|endswith"],
                         ["\\a.exe", "\\b.exe"])

    def test_block_scalar(self):
        doc = parse_yaml("description: |\n  line one\n  line two\nlevel: high\n")
        self.assertIn("line one", doc["description"])
        self.assertEqual(doc["level"], "high")

    def test_booleans_ints(self):
        doc = parse_yaml("a: true\nb: 1024\nc: false\n")
        self.assertIs(doc["a"], True)
        self.assertEqual(doc["b"], 1024)
        self.assertIs(doc["c"], False)


class TestMatching(unittest.TestCase):
    def test_endswith_and_contains_all(self):
        rule = {"detection": {
            "selection_tool": {
                "Image|endswith": "\\sc.exe",
                "CommandLine|contains|all": ["create", "binPath"]},
            "condition": "selection_tool"}}
        self.assertTrue(match_event(rule, {
            "Image": "C:\\Windows\\System32\\sc.exe",
            "CommandLine": "sc.exe create EvilSvc binPath= x"}))
        # missing one of the 'all' substrings -> no match
        self.assertFalse(match_event(rule, {
            "Image": "C:\\Windows\\System32\\sc.exe",
            "CommandLine": "sc.exe query EvilSvc"}))

    def test_cidr_modifier(self):
        rule = {"detection": {
            "sel": {"DestinationIp|cidr": "10.0.0.0/8"},
            "condition": "sel"}}
        self.assertTrue(match_event(rule, {"DestinationIp": "10.1.2.3"}))
        self.assertFalse(match_event(rule, {"DestinationIp": "203.0.113.1"}))

    def test_numeric_gte(self):
        rule = {"detection": {
            "sel": {"DestinationPort|gte": 1024}, "condition": "sel"}}
        self.assertTrue(match_event(rule, {"DestinationPort": 8443}))
        self.assertFalse(match_event(rule, {"DestinationPort": 443}))

    def test_regex_modifier(self):
        rule = {"detection": {
            "sel": {"msg|re": ".*privileged.*true.*"}, "condition": "sel"}}
        self.assertTrue(match_event(rule, {"msg": "x privileged=true y"}))
        self.assertFalse(match_event(rule, {"msg": "restricted"}))

    def test_wildcard(self):
        rule = {"detection": {
            "sel": {"CommandLine": "*-enc*"}, "condition": "sel"}}
        self.assertTrue(match_event(rule, {"CommandLine": "powershell -enc AAA"}))
        self.assertFalse(match_event(rule, {"CommandLine": "powershell -File x"}))


class TestConditionGrammar(unittest.TestCase):
    sels = {"a": {"x": 1}, "b": {"y": 2}, "selection_p1": {"p": 1},
            "selection_p2": {"q": 1}}

    def test_and_or_not(self):
        ev = {"x": 1, "y": 9}
        self.assertTrue(eval_condition("a and not b", self.sels, ev))
        self.assertTrue(eval_condition("a or b", self.sels, ev))
        self.assertFalse(eval_condition("a and b", self.sels, ev))

    def test_parens(self):
        ev = {"x": 1, "y": 2}
        self.assertTrue(eval_condition("(a or b) and a", self.sels, ev))

    def test_one_of_wildcard(self):
        self.assertTrue(eval_condition("1 of selection_p*", self.sels, {"p": 1}))
        self.assertFalse(eval_condition("all of selection_p*", self.sels, {"p": 1}))
        self.assertTrue(eval_condition("all of selection_p*", self.sels,
                                       {"p": 1, "q": 1}))

    def test_them(self):
        self.assertTrue(eval_condition("1 of them", {"a": {"x": 1}}, {"x": 1}))


class TestValidation(unittest.TestCase):
    def test_missing_required_keys(self):
        findings = validate_rule({"detection": {"condition": "sel"}})
        checks = {f.check for f in findings}
        self.assertIn("missing-title", checks)
        self.assertIn("missing-logsource", checks)
        # condition references selection 'sel' which is not defined
        self.assertIn("unknown-selection", checks)

    def test_unknown_modifier_flagged(self):
        rule = parse_yaml(
            "title: T\nid: 11111111-1111-1111-1111-111111111111\n"
            "logsource:\n    product: windows\n"
            "detection:\n    sel:\n        f|bogus: x\n    condition: sel\n")
        findings = validate_rule(rule)
        self.assertIn("unknown-modifier", {f.check for f in findings})

    def test_bad_regex_flagged(self):
        rule = parse_yaml(
            "title: T\nid: 11111111-1111-1111-1111-111111111111\n"
            "logsource:\n    product: windows\n"
            "detection:\n    sel:\n        f|re: '([a'\n    condition: sel\n")
        findings = validate_rule(rule)
        self.assertIn("regex-error", {f.check for f in findings})

    def test_bad_level(self):
        rule = parse_yaml(
            "title: T\nid: 11111111-1111-1111-1111-111111111111\n"
            "level: ultra\nlogsource:\n    product: windows\n"
            "detection:\n    sel:\n        f: x\n    condition: sel\n")
        self.assertIn("bad-level", {f.check for f in validate_rule(rule)})

    def test_supported_modifiers_present(self):
        for m in ("contains", "startswith", "endswith", "re", "cidr", "all"):
            self.assertIn(m, SUPPORTED_MODIFIERS)


class TestUnitTestRunner(unittest.TestCase):
    def test_deep_rules_self_tests_pass(self):
        with open(DEEP, encoding="utf-8") as fh:
            result = check_text(fh.read())
        self.assertEqual(result.total_rules, 2)
        # every rule valid and all inline tests pass
        self.assertEqual(result.tests_failed, 0,
                         msg=json.dumps(result.to_dict(), indent=2))
        self.assertTrue(result.total_tests >= 8)
        self.assertTrue(result.ok)

    def test_bundled_library_all_pass(self):
        result = check_bundled()
        self.assertGreaterEqual(result.total_rules, 6)
        self.assertEqual(result.invalid_rules, 0,
                         msg=json.dumps(result.to_dict(), indent=2))
        self.assertEqual(result.tests_failed, 0)
        self.assertTrue(result.ok)

    def test_run_rule_tests_detects_broken_rule(self):
        # A rule whose negative test would actually MATCH -> a failing test
        rule = parse_yaml(
            "title: Broken\nid: 22222222-2222-2222-2222-222222222222\n"
            "logsource:\n    product: windows\n"
            "detection:\n    sel:\n        f|contains: bad\n    condition: sel\n"
            "tests:\n    negative:\n        - f: 'this is bad'\n")
        results = run_rule_tests(rule)
        self.assertEqual(len(results), 1)
        self.assertFalse(results[0].passed)


class TestCLI(unittest.TestCase):
    def _run(self, argv):
        buf = io.StringIO()
        with redirect_stdout(buf):
            code = main(argv)
        return code, buf.getvalue()

    def test_demo_passes(self):
        code, out = self._run(["demo"])
        self.assertEqual(code, 0, msg=out)
        self.assertIn("ALL PASS", out)

    def test_check_deep_json(self):
        code, out = self._run(["--format", "json", "check", DEEP])
        self.assertEqual(code, 0, msg=out)
        data = json.loads(out)
        self.assertEqual(data["tests_failed"], 0)
        self.assertEqual(data["total_rules"], 2)

    def test_list(self):
        code, out = self._run(["list"])
        self.assertEqual(code, 0)
        self.assertIn("PowerShell", out)

    def test_match_events_nonzero_on_match(self):
        code, out = self._run(["--format", "json", "match", DEEP, EVENTS])
        # at least one event matches -> exit 1
        self.assertEqual(code, 1, msg=out)
        data = json.loads(out)
        self.assertTrue(data["any_match"])
        matched = [r["index"] for r in data["results"] if r["match"]]
        self.assertIn(0, matched)  # \Users\Public\ service install
        self.assertIn(2, matched)  # \Temp\ service install
        self.assertNotIn(1, matched)  # sc query
        self.assertNotIn(3, matched)  # net start

    def test_check_failing_rule_exit_nonzero(self):
        import tempfile
        txt = (
            "title: Bad\nid: 33333333-3333-3333-3333-333333333333\n"
            "logsource:\n    product: windows\n"
            "detection:\n    sel:\n        f|contains: x\n    condition: sel\n"
            "tests:\n    negative:\n        - f: 'has x inside'\n")
        with tempfile.NamedTemporaryFile("w", suffix=".yml", delete=False,
                                         encoding="utf-8") as tf:
            tf.write(txt)
            path = tf.name
        try:
            code, out = self._run(["check", path])
            self.assertEqual(code, 1, msg=out)
            self.assertIn("FAILURES", out)
        finally:
            os.unlink(path)

    def test_version(self):
        with self.assertRaises(SystemExit) as ctx:
            main(["--version"])
        self.assertEqual(ctx.exception.code, 0)


if __name__ == "__main__":
    unittest.main()
