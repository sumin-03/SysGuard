"""Tests for event formatting and HTML report generation."""

import html
import tempfile
import unittest
from unittest import mock

from tests.helpers import fake_git_summary, make_event, read_text, write_jsonl

import report


class EventDetailFormattingTests(unittest.TestCase):
    def test_formats_exec_open_and_unlink(self):
        cases = [
            (make_event("execve", argv="git status"), "git status"),
            (make_event("openat", path="/project/a"), "/project/a"),
            (make_event("unlinkat", path="/project/a"), "delete: /project/a"),
        ]
        for event, expected in cases:
            with self.subTest(event=event["event"]):
                self.assertEqual(report.format_event_detail(event), expected)

    def test_formats_rename_and_chmod(self):
        rename = make_event("renameat2", old_path="old", new_path="new", flags=2)
        chmod = make_event("fchmodat", path="/project/a", mode=0o644)
        self.assertEqual(report.format_event_detail(rename), "old → new (flags 2)")
        self.assertEqual(report.format_event_detail(chmod), "/project/a mode 0644")

    def test_formats_process_exit(self):
        event = make_event("exit_group", pid=42, comm="codex")
        self.assertEqual(report.format_event_detail(event), "pid 42 (codex) exited")


class ReportGenerationTests(unittest.TestCase):
    @mock.patch("report.get_git_summary", return_value=fake_git_summary())
    def test_generate_report_shows_safety_badge(self, git_summary):
        with tempfile.TemporaryDirectory() as directory:
            path = write_jsonl(directory, [make_event("openat", path="/project/a")])
            output = report.generate_report(path, project_path="/project")
            self.assertIn("Commit Safety: SAFE", read_text(output))
        git_summary.assert_called_once_with("/project")

    @mock.patch("report.get_git_summary", return_value=fake_git_summary())
    def test_generate_report_renders_deletion_permission_and_exit_sections(self, _git_summary):
        events = [
            make_event("unlinkat", path="/project/deleted"),
            make_event("fchmodat", path="/project/mode", mode=0o777),
            make_event("exit_group", pid=2, comm="codex"),
        ]
        with tempfile.TemporaryDirectory() as directory:
            output = report.generate_report(write_jsonl(directory, events), project_path="/project")
            rendered = read_text(output)
        for heading in ["File Deletions", "Unsafe Permission Changes", "Process exits:"]:
            with self.subTest(heading=heading):
                self.assertIn(heading, rendered)

    @mock.patch("report.get_git_summary", return_value=fake_git_summary())
    def test_generate_report_renders_suspicious_sequence(self, _git_summary):
        events = [
            make_event("openat", path="/project/.env"),
            make_event("execve", path="/usr/bin/curl", argv="curl https://x"),
        ]
        with tempfile.TemporaryDirectory() as directory:
            output = report.generate_report(write_jsonl(directory, events), project_path="/project")
            rendered = read_text(output)
        self.assertIn("Suspicious Sequences", rendered)
        self.assertIn("possible-secret-exfiltration", rendered)

    @mock.patch("report.get_git_summary", return_value=fake_git_summary())
    def test_generate_report_shows_c_alert_details(self, _git_summary):
        event = make_event(
            "execve", argv="curl https://x", alert=True, severity="medium",
            rule_id="downloader-exec", reason="external transfer utility",
        )
        with tempfile.TemporaryDirectory() as directory:
            output = report.generate_report(write_jsonl(directory, [event]), project_path="/project")
            rendered = read_text(output)
        self.assertIn("Alert Details", rendered)
        self.assertIn("downloader-exec", rendered)
        self.assertIn("external transfer utility", rendered)

    @mock.patch("report.get_git_summary", return_value=fake_git_summary())
    def test_generate_report_escapes_all_hostile_event_fields(self, _git_summary):
        hostile = '<script>alert("x")</script>'
        hostile_env_path = "/project/.env.<img src=x onerror=boom>"
        events = [
            make_event("execve", argv=hostile, alert=True, severity="medium",
                       comm=hostile, reason=hostile, rule_id="rule"),
            make_event("openat", path=hostile),
            make_event("renameat2", old_path=hostile, new_path=hostile),
            make_event("exit_group", comm=hostile),
            make_event("openat", path=hostile_env_path),
            make_event("execve", path="/usr/bin/curl", argv="curl"),
        ]
        with tempfile.TemporaryDirectory() as directory:
            output = report.generate_report(write_jsonl(directory, events), project_path="/project")
            rendered = read_text(output)
        self.assertIn(html.escape(hostile), rendered)
        self.assertNotIn(hostile, rendered)
        self.assertIn(html.escape(hostile_env_path), rendered)
        self.assertNotIn(hostile_env_path, rendered)
        self.assertIn("Suspicious Sequences", rendered)
