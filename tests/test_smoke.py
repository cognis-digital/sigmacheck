"""Smoke tests for SIGMACHECK. Standard library only, no network."""
import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sigmacheck import (  # noqa: E402
    TOOL_NAME,
    TOOL_VERSION,
    parse_yaml,
    validate_rule,
    match_event,
    run_rule_tests,
)
from sigmacheck.cli import main  # noqa: E402

GOOD_RULE = """
title: Suspicious PowerShell Encoded Command
id: 6e2a4b1c-9f3d-4a77-8c21-0b9d1e2f3a44
status: test
level: high
logsource:
  category: process_creation
  product: windows
detection:
  selection_img:
    Image|endswith: \\powershell.exe
  selection_enc:
    CommandLine|contains:
      - ' -enc '
      - ' -ec '
  condition: selection_img and selection_enc
"""

BAD_RULE = """
title: Broken rule
detection:
  selection:
    Image|endswith: \\evil.exe
  condition: selection and missing_sel
"""


class TestParser(unittest.TestCase):
    def test_parse_nested_and_lists(self):
        rule = parse_yaml(GOOD_RULE)
        self.assertEqual(rule["title"], "Suspicious PowerShell Encoded Command")
        self.assertEqual(rule["logsource"]["product"], "windows")
        enc = rule["detection"]["selection_enc"]["CommandLine|contains"]
        self.assertIn(" -enc ", enc)
        self.assertEqual(rule["detection"]["condition"], "selection_img and selection_enc")


class TestLint(unittest.TestCase):
    def test_clean_rule_has_no_errors(self):
        findings = validate_rule(parse_yaml(GOOD_RULE))
        # Only low-severity findings allowed (e.g. missing description, no tests)
        high_errors = [f for f in findings if f.severity in ("high", "critical")]
        self.assertEqual(high_errors, [])

    def test_unknown_selection_is_error(self):
        findings = validate_rule(parse_yaml(BAD_RULE))
        codes = {f.check for f in findings}
        self.assertIn("unknown-selection", codes)

    def test_missing_mandatory_fields(self):
        findings = validate_rule(parse_yaml("title: x\n"))
        self.assertTrue(any(f.check == "missing-detection" for f in findings))


class TestDetection(unittest.TestCase):
    def setUp(self):
        self.rule = parse_yaml(GOOD_RULE)

    def test_match_encoded(self):
        event = {
            "Image": "C:\\...\\powershell.exe",
            "CommandLine": "powershell.exe -nop -enc ABC",
        }
        self.assertTrue(match_event(self.rule, event))

    def test_no_match_benign(self):
        event = {
            "Image": "C:\\...\\powershell.exe",
            "CommandLine": "powershell.exe -File backup.ps1",
        }
        self.assertFalse(match_event(self.rule, event))

    def test_no_match_wrong_process(self):
        event = {"Image": "C:\\windows\\cmd.exe", "CommandLine": "cmd -enc x"}
        self.assertFalse(match_event(self.rule, event))

    def test_condition_or_and_not(self):
        rule = parse_yaml(
            "title: t\nlogsource:\n  product: windows\n"
            "detection:\n  a:\n    F: '1'\n  b:\n    G: '2'\n"
            "  condition: a or not b\n"
        )
        self.assertTrue(match_event(rule, {"F": "1", "G": "9"}))
        self.assertFalse(match_event(rule, {"F": "0", "G": "2"}))

    def test_one_of_them(self):
        rule = parse_yaml(
            "title: t\nlogsource:\n  product: windows\n"
            "detection:\n  sel_a:\n    F: '1'\n  sel_b:\n    G: '2'\n"
            "  condition: 1 of sel_*\n"
        )
        self.assertTrue(match_event(rule, {"F": "1"}))
        self.assertFalse(match_event(rule, {"F": "x", "G": "y"}))


class TestUnitRunner(unittest.TestCase):
    def test_run_cases(self):
        # Build a rule with embedded tests in the standard Sigma format
        rule = parse_yaml(GOOD_RULE + """
tests:
  positive:
    - Image: 'a\\powershell.exe'
      CommandLine: 'x -enc y'
  negative:
    - Image: 'a\\powershell.exe'
      CommandLine: 'clean'
""")
        results = run_rule_tests(rule)
        self.assertTrue(all(r.passed for r in results))


class TestCli(unittest.TestCase):
    def _write(self, suffix, content):
        fd, path = tempfile.mkstemp(suffix=suffix)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
        self.addCleanup(lambda: os.remove(path))
        return path

    def test_version(self):
        buf = io.StringIO()
        with self.assertRaises(SystemExit) as ctx:
            with redirect_stdout(buf):
                main(["--version"])
        self.assertEqual(ctx.exception.code, 0)
        self.assertIn(TOOL_VERSION, buf.getvalue())
        self.assertIn(TOOL_NAME, buf.getvalue())

    def test_check_clean_exit_zero(self):
        path = self._write(".yml", GOOD_RULE)
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["--format", "json", "check", path])
        self.assertEqual(rc, 0)
        data = json.loads(buf.getvalue())
        # CheckResult JSON: invalid_rules == 0 means no high-severity failures
        self.assertEqual(data["invalid_rules"], 0)

    def test_check_bad_exit_one(self):
        path = self._write(".yml", BAD_RULE)
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["check", path])
        self.assertEqual(rc, 1)

    def test_match_subcommand(self):
        rule_path = self._write(".yml", GOOD_RULE)
        event_path = self._write(
            ".json",
            json.dumps({"Image": "a\\powershell.exe", "CommandLine": "x -enc y"}),
        )
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["--format", "json", "match", rule_path, event_path])
        self.assertEqual(rc, 1)  # match => detection hit => non-zero
        self.assertTrue(json.loads(buf.getvalue())["any_match"])

    def test_match_no_hit_exit_zero(self):
        rule_path = self._write(".yml", GOOD_RULE)
        event_path = self._write(
            ".json",
            json.dumps({"Image": "a\\notepad.exe", "CommandLine": "clean"}),
        )
        buf = io.StringIO()
        with redirect_stdout(buf):
            rc = main(["--format", "json", "match", rule_path, event_path])
        self.assertEqual(rc, 0)
        self.assertFalse(json.loads(buf.getvalue())["any_match"])


if __name__ == "__main__":
    unittest.main()
