"""Tests for input-validation and error-handling paths added during hardening."""

from __future__ import annotations

import io
import json
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from sigmacheck.cli import _load_events, main  # noqa: E402
from sigmacheck.core import load_bundled_rules  # noqa: E402

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


class TestCliMissingFile(unittest.TestCase):
    """check and match subcommands with a non-existent file must exit 2 and
    print a clear message to stderr — never a raw traceback."""

    def test_check_missing_file_exits_2(self):
        buf_err = io.StringIO()
        with redirect_stderr(buf_err):
            rc = main(["check", "/nonexistent/path/rule.yml"])
        self.assertEqual(rc, 2)
        err = buf_err.getvalue()
        self.assertIn("error", err.lower())
        # must mention the missing path in some form
        self.assertTrue("nonexistent" in err or "not found" in err.lower())

    def test_match_missing_rule_exits_2(self):
        fd, ev_path = tempfile.mkstemp(suffix=".json")
        with os.fdopen(fd, "w") as fh:
            fh.write(json.dumps({"x": 1}))
        try:
            buf_err = io.StringIO()
            with redirect_stderr(buf_err):
                rc = main(["match", "/nonexistent/rule.yml", ev_path])
            self.assertEqual(rc, 2)
            self.assertIn("error", buf_err.getvalue().lower())
        finally:
            os.remove(ev_path)

    def test_match_missing_events_file_exits_2(self):
        fd, rule_path = tempfile.mkstemp(suffix=".yml")
        with os.fdopen(fd, "w") as fh:
            fh.write(GOOD_RULE)
        try:
            buf_err = io.StringIO()
            with redirect_stderr(buf_err):
                rc = main(["match", rule_path, "/nonexistent/events.json"])
            self.assertEqual(rc, 2)
            self.assertIn("error", buf_err.getvalue().lower())
        finally:
            os.remove(rule_path)


class TestLoadEvents(unittest.TestCase):
    """_load_events() edge-case and error paths."""

    def test_empty_string_returns_empty_list(self):
        self.assertEqual(_load_events(""), [])

    def test_whitespace_only_returns_empty_list(self):
        self.assertEqual(_load_events("   \n  \t  "), [])

    def test_single_json_object(self):
        result = _load_events('{"a": 1}')
        self.assertEqual(result, [{"a": 1}])

    def test_json_array_of_objects(self):
        result = _load_events('[{"a": 1}, {"b": 2}]')
        self.assertEqual(result, [{"a": 1}, {"b": 2}])

    def test_jsonl_multiple_lines(self):
        data = '{"a": 1}\n{"b": 2}\n'
        result = _load_events(data)
        self.assertEqual(result, [{"a": 1}, {"b": 2}])

    def test_jsonl_blank_lines_ignored(self):
        data = '{"a": 1}\n\n{"b": 2}\n'
        result = _load_events(data)
        self.assertEqual(result, [{"a": 1}, {"b": 2}])

    def test_malformed_jsonl_raises_json_decode_error(self):
        data = '{"a": 1}\nnot json\n{"b": 2}'
        with self.assertRaises(json.JSONDecodeError) as ctx:
            _load_events(data)
        # error message should mention the line number
        self.assertIn("2", str(ctx.exception))

    def test_non_array_non_object_json_returns_empty(self):
        # A bare JSON scalar (string, number, etc.) is neither an object nor
        # an array of objects, so _load_events gracefully returns an empty list
        # rather than raising or crashing.
        result = _load_events('"just a string"')
        self.assertEqual(result, [])

    def test_malformed_top_level_json_raises(self):
        # Completely invalid JSON that can't be parsed at all must raise.
        with self.assertRaises(json.JSONDecodeError):
            _load_events('{broken json')


class TestCliMatchEdgeCases(unittest.TestCase):
    """CLI match subcommand edge cases."""

    def _write(self, suffix, content):
        fd, path = tempfile.mkstemp(suffix=suffix)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
        self.addCleanup(lambda: os.remove(path))
        return path

    def test_match_malformed_events_exits_2(self):
        rule_path = self._write(".yml", GOOD_RULE)
        ev_path = self._write(".json", "this is not json at all")
        buf_err = io.StringIO()
        with redirect_stderr(buf_err):
            rc = main(["match", rule_path, ev_path])
        self.assertEqual(rc, 2)
        self.assertIn("error", buf_err.getvalue().lower())

    def test_match_empty_events_returns_0_with_warning(self):
        rule_path = self._write(".yml", GOOD_RULE)
        ev_path = self._write(".json", "[]")
        buf_out = io.StringIO()
        buf_err = io.StringIO()
        with redirect_stdout(buf_out), redirect_stderr(buf_err):
            rc = main(["match", rule_path, ev_path])
        # no events to match => no detection hit => exit 0
        self.assertEqual(rc, 0)
        self.assertIn("warning", buf_err.getvalue().lower())

    def test_match_empty_rule_file_exits_2(self):
        rule_path = self._write(".yml", "")
        ev_path = self._write(".json", '[{"x": 1}]')
        buf_err = io.StringIO()
        with redirect_stderr(buf_err):
            rc = main(["match", rule_path, ev_path])
        self.assertEqual(rc, 2)


class TestLoadBundledRules(unittest.TestCase):
    """load_bundled_rules() must always return a list of dicts."""

    def test_all_entries_are_dicts(self):
        rules = load_bundled_rules()
        self.assertGreater(len(rules), 0)
        for r in rules:
            self.assertIsInstance(r, dict,
                                  f"Expected dict, got {type(r)}: {r!r}")

    def test_no_none_entries(self):
        rules = load_bundled_rules()
        self.assertNotIn(None, rules)


class TestCheckEmptyInput(unittest.TestCase):
    """check subcommand with empty/whitespace-only rule content exits 2."""

    def _write(self, suffix, content):
        fd, path = tempfile.mkstemp(suffix=suffix)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(content)
        self.addCleanup(lambda: os.remove(path))
        return path

    def test_check_empty_file_exits_2(self):
        path = self._write(".yml", "")
        buf_err = io.StringIO()
        with redirect_stderr(buf_err):
            rc = main(["check", path])
        self.assertEqual(rc, 2)
        self.assertIn("error", buf_err.getvalue().lower())

    def test_check_comment_only_file_exits_1(self):
        # A file whose only content is YAML comments produces a parse-error
        # rule (not a valid Sigma mapping), so the run reports failures -> exit 1.
        path = self._write(".yml", "# just a comment\n# nothing else\n")
        buf_out = io.StringIO()
        with redirect_stdout(buf_out):
            rc = main(["check", path])
        self.assertEqual(rc, 1)


if __name__ == "__main__":
    unittest.main()
