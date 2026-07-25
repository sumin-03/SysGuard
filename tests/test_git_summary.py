"""Tests for the stdlib git summary helper."""

import unittest
from unittest import mock

import git_summary


class GitSummaryTests(unittest.TestCase):
    @mock.patch("git_summary.subprocess.run")
    def test_success_uses_expected_subprocess_calls_and_keys(self, run):
        run.side_effect = [
            mock.Mock(returncode=0, stdout=" M app.py\n"),
            mock.Mock(returncode=0, stdout=" app.py | 1 +\n"),
        ]
        result = git_summary.get_git_summary("/project")
        self.assertEqual(set(result), {"status", "diff_stat"})
        self.assertEqual(result["status"], "M app.py")
        self.assertEqual(result["diff_stat"], "app.py | 1 +")
        self.assertEqual(run.call_args_list, [
            mock.call(["git", "status", "--short"], cwd="/project",
                      capture_output=True, text=True, timeout=10),
            mock.call(["git", "diff", "--stat"], cwd="/project",
                      capture_output=True, text=True, timeout=10),
        ])

    @mock.patch("git_summary.subprocess.run")
    def test_failures_and_exceptions_return_strings_without_raising(self, run):
        run.side_effect = [mock.Mock(returncode=1, stdout=""), OSError("no git")]
        result = git_summary.get_git_summary("/project")
        self.assertIsInstance(result["status"], str)
        self.assertIsInstance(result["diff_stat"], str)
