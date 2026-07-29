"""Tests for the GUI's display/caching helpers (TASK-B-018).

The widgets themselves need a display and are exercised by hand, but the pure
functions behind the session list are testable here — they are what keep the
window responsive.
"""

import os
import tempfile
import unittest

import main


class HumanSizeTests(unittest.TestCase):
    def test_scales_units(self):
        self.assertEqual(main.human_size(0), "0 B")
        self.assertEqual(main.human_size(512), "512 B")
        self.assertEqual(main.human_size(2177754), "2.1 MB")
        self.assertTrue(main.human_size(5_000_000_000).endswith("GB"))


class FormatElapsedTests(unittest.TestCase):
    def test_hms(self):
        self.assertEqual(main.format_elapsed(0), "0:00:00")
        self.assertEqual(main.format_elapsed(61), "0:01:01")
        self.assertEqual(main.format_elapsed(3725), "1:02:05")


class CacheKeyTests(unittest.TestCase):
    def test_stable_until_the_file_changes(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "s.jsonl")
            with open(path, "w") as fh:
                fh.write("a\n")
            first = main.cache_key(path)
            self.assertEqual(first, main.cache_key(path))
            with open(path, "a") as fh:
                fh.write("b\n")
            self.assertNotEqual(first, main.cache_key(path))

    def test_missing_file_has_no_key(self):
        self.assertIsNone(main.cache_key("/nonexistent/session.jsonl"))


class CountNewLinesTests(unittest.TestCase):
    def test_counts_only_the_delta(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "s.jsonl")
            with open(path, "w") as fh:
                fh.write("a\nb\nc\n")
            n, off = main.count_new_lines(path, 0)
            self.assertEqual(n, 3)
            with open(path, "a") as fh:
                fh.write("d\ne\n")
            n2, off2 = main.count_new_lines(path, off)
            self.assertEqual(n2, 2)
            self.assertGreater(off2, off)

    def test_partial_line_is_counted_once_complete(self):
        # The collector appends as it goes, so a half-written record must not be
        # counted twice (or missed) when the newline lands.
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "s.jsonl")
            with open(path, "w") as fh:
                fh.write("a\n")
            _, off = main.count_new_lines(path, 0)
            with open(path, "a") as fh:
                fh.write("partial-no-newline")
            n, off2 = main.count_new_lines(path, off)
            self.assertEqual(n, 0)
            self.assertEqual(off2, off)
            with open(path, "a") as fh:
                fh.write("\n")
            n2, _ = main.count_new_lines(path, off2)
            self.assertEqual(n2, 1)

    def test_missing_or_truncated_file_is_safe(self):
        self.assertEqual(main.count_new_lines("/nonexistent", 0), (0, 0))
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "s.jsonl")
            with open(path, "w") as fh:
                fh.write("a\n")
            self.assertEqual(main.count_new_lines(path, 999), (0, 999))


class VerdictSortOrderTests(unittest.TestCase):
    def test_worst_verdict_sorts_first(self):
        order = main.SysGuardApp._VERDICT_ORDER
        self.assertLess(order["UNSAFE"], order["REVIEW_NEEDED"])
        self.assertLess(order["REVIEW_NEEDED"], order["SAFE"])


class SessionTimestampTests(unittest.TestCase):
    def test_parses_the_name_not_the_mtime(self):
        # mtime is when collection ended and shifts if the file is touched, so
        # the column comes from the name.
        self.assertEqual(
            main.session_timestamp("session_claude_20260728_193352.jsonl"),
            "07-28 19:33")
        self.assertEqual(main.session_timestamp("session_20260701_001500.jsonl"),
                         "07-01 00:15")

    def test_returns_none_for_names_without_a_timestamp(self):
        for name in ["weird.jsonl", "session_x.jsonl", "session_2026_99.jsonl"]:
            with self.subTest(name=name):
                self.assertIsNone(main.session_timestamp(name))
