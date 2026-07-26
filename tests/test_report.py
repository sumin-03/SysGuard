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


class ReviewNeededReportTests(unittest.TestCase):
    """The git summary feeds the REVIEW_NEEDED heuristics and renders (B-003)."""

    @mock.patch("report.get_git_summary")
    def test_build_config_change_renders_review_needed(self, git_summary):
        git_summary.return_value = fake_git_summary(status=" M pyproject.toml", diff_stat="")
        with tempfile.TemporaryDirectory() as directory:
            path = write_jsonl(directory, [make_event("openat", path="/project/a")])
            rendered = read_text(report.generate_report(path, project_path="/project"))
        self.assertIn("Commit Safety: REVIEW_NEEDED", rendered)
        self.assertIn("Review Needed", rendered)
        self.assertIn("pyproject.toml", rendered)

    @mock.patch("report.get_git_summary")
    def test_hostile_git_path_is_escaped(self, git_summary):
        hostile = "<script>x</script>"
        git_summary.return_value = fake_git_summary(status=f" D {hostile}/gone.py", diff_stat="")
        with tempfile.TemporaryDirectory() as directory:
            path = write_jsonl(directory, [make_event("openat", path="/project/a")])
            rendered = read_text(report.generate_report(path, project_path="/project"))
        self.assertIn("Review Needed", rendered)
        self.assertIn(html.escape(hostile), rendered)
        self.assertNotIn(hostile, rendered)


class B005ReportConformanceTests(unittest.TestCase):
    """README section-9 conformance: canonical order, Recent Events, payloads."""

    SECTION_ORDER = [
        "Session Metadata", "Commit Safety:", "Normal Development Activity",
        "Boundary Violations", "Protected Path Access", "Dangerous Commands",
        "Git Status/Diff Summary", "Alert Details", "Recent Events",
        "Recommended Actions",
    ]

    def _render(self, events, status="", diff_stat=""):
        with mock.patch("report.get_git_summary",
                        return_value=fake_git_summary(status=status, diff_stat=diff_stat)):
            with tempfile.TemporaryDirectory() as directory:
                path = write_jsonl(directory, events)
                return read_text(report.generate_report(path, project_path="/project"))

    def test_all_ten_sections_present_in_canonical_order(self):
        rendered = self._render([
            make_event("openat", path="/project/src/a.py"),
            make_event("execve", argv="git reset --hard", alert=True,
                       severity="high", rule_id="git-reset-hard", reason="x"),
        ])
        positions = [rendered.index(marker) for marker in self.SECTION_ORDER]
        self.assertEqual(positions, sorted(positions), positions)

    def test_metadata_precedes_badge(self):
        rendered = self._render([make_event("openat", path="/project/a")])
        self.assertLess(rendered.index("Session Metadata"), rendered.index("Commit Safety:"))

    def test_canonical_sections_render_with_empty_state(self):
        rendered = self._render([make_event("openat", path="/project/a")])
        for heading in ["Boundary Violations", "Protected Path Access",
                        "Dangerous Commands", "Alert Details", "Recent Events"]:
            self.assertIn(heading, rendered)
        self.assertIn("No boundary violations.", rendered)
        self.assertIn("No alerts or findings.", rendered)

    def test_recent_events_renders_every_event_type(self):
        rendered = self._render([
            make_event("execve", argv="git status"),
            make_event("openat", path="/project/a"),
            make_event("unlinkat", path="/project/gone"),
            make_event("renameat2", old_path="/project/o", new_path="/project/n", flags=1),
            make_event("fchmodat", path="/project/s", mode=0o644),
            make_event("exit_group", pid=7, comm="codex"),
        ])
        self.assertIn("Recent Events", rendered)
        for token in ["git status", "/project/a", "delete: /project/gone",
                      "/project/o → /project/n", "/project/s mode 0644",
                      "(codex) exited"]:
            with self.subTest(token=token):
                self.assertIn(token, rendered)

    def test_recent_events_caps_at_50_newest_first(self):
        rendered = self._render([make_event("openat", path=f"/project/f{i:03d}.py")
                                 for i in range(55)])
        recent = rendered[rendered.index("Recent Events"):]
        self.assertNotIn("/project/f004.py", recent)   # oldest 5 dropped
        self.assertIn("/project/f054.py", recent)        # newest kept
        self.assertIn("/project/f005.py", recent)
        self.assertLess(recent.index("/project/f054.py"), recent.index("/project/f005.py"))

    def test_findings_are_subsections_inside_alert_details(self):
        rendered = self._render([
            make_event("openat", path="/project/.env"),
            make_event("execve", path="/usr/bin/curl", argv="curl https://x"),
            make_event("fchmodat", path="/project/s", mode=0o777),
        ])
        alert_details = rendered.index("Alert Details")
        recent_events = rendered.index("Recent Events")
        for subsection in ["Suspicious Sequences", "Unsafe Permission Changes"]:
            with self.subTest(subsection=subsection):
                self.assertIn(subsection, rendered)
                self.assertLess(alert_details, rendered.index(subsection))
                self.assertLess(rendered.index(subsection), recent_events)

    def test_recent_events_escapes_hostile_fields(self):
        hostile = "<script>x</script>"
        rendered = self._render([make_event("openat", path=hostile, comm=hostile)])
        recent = rendered[rendered.index("Recent Events"):]
        self.assertIn(html.escape(hostile), recent)
        self.assertNotIn(hostile, rendered)


class A002ConnectReportTests(unittest.TestCase):
    """CONNECT event rendering + JSONL back-compat (TASK-A-002)."""

    def _render(self, events, status="", diff_stat=""):
        with mock.patch("report.get_git_summary",
                        return_value=fake_git_summary(status=status, diff_stat=diff_stat)):
            with tempfile.TemporaryDirectory() as directory:
                return read_text(report.generate_report(
                    write_jsonl(directory, events), project_path="/project"))

    def test_format_event_detail_connect_ipv4_and_ipv6(self):
        self.assertEqual(
            report.format_event_detail(
                make_event("connect", dest_addr="203.0.113.10", dest_port=443)),
            "203.0.113.10:443")
        self.assertEqual(
            report.format_event_detail(
                make_event("connect", dest_addr="2001:db8::1", dest_port=443)),
            "[2001:db8::1]:443")

    def test_format_event_detail_connect_missing_address(self):
        detail = report.format_event_detail(make_event("connect", dest_addr="", addr_family=1))
        self.assertIn("connect", detail)
        self.assertIn("family 1", detail)

    def test_connect_alert_endpoint_rendered_in_report(self):
        rendered = self._render([make_event(
            "connect", comm="curl", addr_family=2, dest_addr="203.0.113.10",
            dest_port=443, alert=True, severity="medium",
            rule_id="outbound-connect", reason="Outbound connection attempt")])
        self.assertIn("outbound-connect", rendered)
        self.assertIn("203.0.113.10:443", rendered)

    def test_legacy_jsonl_without_connect_keys_still_renders(self):
        legacy = {"event": "openat", "path": "/project/a", "pid": 1, "ppid": 0,
                  "uid": 1, "comm": "claude", "project_path": "/project",
                  "target_comm": ""}
        rendered = self._render([legacy])
        self.assertIn("Commit Safety:", rendered)
