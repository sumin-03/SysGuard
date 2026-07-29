"""Tests for event formatting and HTML report generation."""

import html
import os
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
        # "Process exits" is now a collapsed <details> summary (lifecycle
        # bookkeeping), so it no longer carries the "<b>label:</b>" colon.
        for heading in ["File Deletions", "Unsafe Permission Changes", "Process exits"]:
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
        "Outside-Project Mutations", "Protected Path Access", "Dangerous Commands",
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
        for heading in ["Outside-Project Mutations", "Protected Path Access",
                        "Dangerous Commands", "Alert Details", "Recent Events"]:
            self.assertIn(heading, rendered)
        self.assertIn("No review-worthy writes outside the project.", rendered)
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


class B010AggregationTests(unittest.TestCase):
    """Report-layer aggregation of repeated rows (TASK-B-010) — display only."""

    def _render(self, events, status="", diff_stat=""):
        with mock.patch("report.get_git_summary",
                        return_value=fake_git_summary(status=status, diff_stat=diff_stat)):
            with tempfile.TemporaryDirectory() as directory:
                return read_text(report.generate_report(
                    write_jsonl(directory, events), project_path="/project"))

    # --- pure helper ---
    def test_helper_empty(self):
        self.assertEqual(report.aggregate_for_display([], lambda x: x), [])

    def test_helper_counts_and_first_seen_order(self):
        out = report.aggregate_for_display(["a", "b", "a", "a", "c", "b"], lambda x: x)
        self.assertEqual(out, [("a", 3), ("b", 2), ("c", 1)])

    def test_helper_representative_is_first_and_no_mutation(self):
        items = [{"k": 1, "v": "first"}, {"k": 1, "v": "second"}]
        snapshot = [dict(d) for d in items]
        out = report.aggregate_for_display(items, lambda d: d["k"])
        self.assertEqual(out[0][0]["v"], "first")
        self.assertEqual(out[0][1], 2)
        self.assertEqual(items, snapshot)  # inputs untouched

    # --- alert aggregation ---
    def _alert(self, **over):
        base = dict(event="execve", path="/usr/bin/curl", argv="curl http://x",
                    alert=True, severity="medium", rule_id="downloader-exec",
                    reason="Downloader executed", pid=100, ppid=1, uid=1,
                    comm="bash", project_path="/project", target_comm="")
        base.update(over)
        return base

    def test_identical_alerts_collapse_to_one_row_with_count(self):
        rendered = self._render([self._alert() for _ in range(20)])
        self.assertIn("&times;20", rendered)                    # aggregated marker
        self.assertEqual(rendered.count("downloader-exec"), 1)  # one alert row
        self.assertIn(">Total Events</span>20</div>", rendered)  # raw metadata kept
        self.assertIn(">Alerts</span>20</div>", rendered)

    def test_distinct_alerts_stay_separate(self):
        events = [
            self._alert(rule_id="destructive-rm", argv="rm -rf a", reason="r1", pid=1, comm="bash", severity="high"),
            self._alert(rule_id="git-reset-hard", argv="git reset --hard", reason="r2", pid=1, comm="bash", severity="high"),
            self._alert(rule_id="destructive-rm", argv="rm -rf a", reason="r1", pid=1, comm="sh", severity="high"),   # diff comm
            self._alert(rule_id="destructive-rm", argv="rm -rf a", reason="r1", pid=2, comm="bash", severity="high"), # diff pid
        ]
        rendered = self._render(events)
        # Count within the Alert Details section only (Recent Events is a raw,
        # unaggregated tail and also shows these events).
        alert_region = rendered[rendered.index("Alert Details"):rendered.index("Recent Events")]
        # The target cell now carries the reason as a second line, so count the
        # target itself rather than an exact cell string.
        self.assertEqual(alert_region.count("rm -rf a<br>"), 3)  # not merged (comm/pid differ)
        self.assertIn("git-reset-hard", rendered)
        self.assertNotIn("&times;", alert_region)                # all distinct -> no counts

    def test_each_alert_key_field_independently_prevents_collapse(self):
        # base + a variant differing in EXACTLY one key field must NOT collapse.
        # Varying each field alone catches a regression that drops any single
        # field from _alert_key.
        base = dict(severity="high", rule_id="destructive-rm", argv="rm -rf a",
                    reason="r", pid=1, comm="bash")
        variants = {
            "severity": dict(base, severity="medium"),
            "rule_id":  dict(base, rule_id="git-reset-hard"),
            "pid":      dict(base, pid=2),
            "comm":     dict(base, comm="sh"),
            "detail":   dict(base, argv="rm -rf b"),   # changes format_event_detail
            "reason":   dict(base, reason="different"),
        }
        for field, variant in variants.items():
            with self.subTest(field=field):
                rendered = self._render([self._alert(**base), self._alert(**variant)])
                region = rendered[rendered.index("Alert Details"):rendered.index("Recent Events")]
                # two distinct alerts -> two separate rows, never a "×2"
                self.assertNotIn("&times;", region)

    # --- normal activity ---
    def test_repeated_normal_command_collapses(self):
        rendered = self._render([make_event("execve", argv="git status") for _ in range(5)])
        self.assertEqual(rendered.count("<code>git status</code>"), 1)
        self.assertIn("&times;5", rendered)

    def test_normal_activity_aggregates_before_20_cap(self):
        events = [make_event("execve", argv="dup") for _ in range(25)]
        events.append(make_event("execve", argv="unique_cmd"))
        rendered = self._render(events)
        self.assertIn("unique_cmd", rendered)   # not pushed past the 20-cap by 25 dups
        self.assertIn("&times;25", rendered)

    # --- recent events NOT aggregated ---
    def test_recent_events_not_aggregated(self):
        rendered = self._render([make_event("openat", path="/project/same.py") for _ in range(4)])
        recent = rendered[rendered.index("Recent Events"):]
        self.assertEqual(recent.count("/project/same.py"), 4)   # raw 4 rows, not collapsed

    # --- verdict integrity ---
    def test_aggregation_does_not_change_verdict_badge(self):
        import re
        events = [self._alert() for _ in range(15)]

        def badge(html_text):
            return re.search(r'<div class="safety-badge">.*?</div>', html_text).group(0)

        agg = self._render(events)
        with mock.patch("report.aggregate_for_display",
                        side_effect=lambda items, key_fn: [(i, 1) for i in items]):
            noagg = self._render(events)
        self.assertEqual(badge(agg), badge(noagg))               # verdict badge identical
        self.assertIn(">Total Events</span>15</div>", agg)
        self.assertIn(">Total Events</span>15</div>", noagg)

    # --- escaping ---
    def test_repeated_hostile_value_escaped_once_with_count(self):
        hostile = "<script>x</script>"
        rendered = self._render([make_event("execve", argv=hostile) for _ in range(3)])
        # In Normal Activity the 3 duplicates collapse to a SINGLE escaped row
        # + a safe count (no double-escaping / duplicate rendering there).
        normal = rendered[rendered.index("Normal Development Activity"):
                          rendered.index("Outside-Project Mutations")]
        self.assertEqual(normal.count(html.escape(hostile)), 1)
        self.assertIn("&times;3", normal)
        self.assertNotIn(hostile, rendered)   # raw markup never appears anywhere


class B011OutsideProjectReportTests(unittest.TestCase):
    """Report shows outside-project WRITES as findings and READS informationally."""

    def _render(self, events, status="", diff_stat=""):
        with mock.patch("report.get_git_summary",
                        return_value=fake_git_summary(status=status, diff_stat=diff_stat)):
            with tempfile.TemporaryDirectory() as directory:
                return read_text(report.generate_report(
                    write_jsonl(directory, events), project_path="/project"))

    def test_writes_section_and_read_info_line(self):
        import os
        events = [make_event("openat", path=f"/home/u/.cache/r{i}.js", comm="claude")
                  for i in range(5)]                                   # 5 outside reads
        events.append(make_event("openat", path="/home/u/.claude/plugins/p",
                                 flags=os.O_WRONLY, comm="claude"))    # 1 outside write
        rendered = self._render(events)
        self.assertIn("Outside-Project Mutations", rendered)
        self.assertIn("plugins/p", rendered)                          # write finding rendered
        self.assertIn("Non-sensitive outside-project reads: 5", rendered)


class B012MutationSectionTests(unittest.TestCase):
    """TASK-B-012: the mutations section splits writes by effect."""

    @mock.patch("report.get_git_summary", return_value=fake_git_summary())
    def test_runtime_noise_and_persistence_sections(self, _git):
        # The report resolves the monitored home from the session's uid, so build
        # the fixture paths under the running user's real home.
        import pwd
        uid = os.getuid()
        home = pwd.getpwuid(uid).pw_dir.rstrip("/")
        noise_path = f"{home}/.claude/projects/s.jsonl"
        persist_path = f"{home}/.bashrc"
        with tempfile.TemporaryDirectory() as d:
            events = [
                # runtime bookkeeping write (informational)
                make_event("openat", path=noise_path, project_path="/project",
                           comm="claude", uid=uid, flags=os.O_WRONLY | os.O_CREAT),
                # persistence write (UNSAFE)
                make_event("openat", path=persist_path, project_path="/project",
                           comm="claude", uid=uid, flags=os.O_WRONLY),
            ]
            path = write_jsonl(d, events)
            out = report.generate_report(path, project_path="/project")
            rendered = read_text(out)

        self.assertIn("Outside-Project Mutations", rendered)
        self.assertIn("Runtime bookkeeping", rendered)
        self.assertIn("did not target protected, persistence-sensitive", rendered)
        self.assertIn("Persistence-Sensitive Writes", rendered)
        self.assertIn(html.escape(persist_path), rendered)
        # The noise write must not appear as a review-worthy violation.
        self.assertIn("No review-worthy writes outside the project.", rendered)

    @mock.patch("report.get_git_summary", return_value=fake_git_summary())
    def test_no_persistence_section_when_absent(self, _git):
        with tempfile.TemporaryDirectory() as d:
            path = write_jsonl(d, [make_event("openat", path="/project/a",
                                              project_path="/project")])
            out = report.generate_report(path, project_path="/project")
            rendered = read_text(out)
        self.assertNotIn("Persistence-Sensitive Writes", rendered)

    @mock.patch("report.get_git_summary", return_value=fake_git_summary())
    def test_runtime_scratch_deletions_are_rendered(self, _git):
        uid = os.getuid()
        scratch = f"/tmp/claude-{uid}/proj/uuid/scratchpad/hello"
        with tempfile.TemporaryDirectory() as d:
            path = write_jsonl(d, [make_event("unlinkat", path=scratch,
                                              project_path="/project", comm="rm",
                                              uid=uid)])
            rendered = read_text(report.generate_report(path, project_path="/project"))
        self.assertIn("Runtime bookkeeping", rendered)
        self.assertIn("scratch deletion", rendered)
        self.assertIn(html.escape(scratch), rendered)
        self.assertNotIn("File Deletions", rendered)


class B019ReadabilityTests(unittest.TestCase):
    """TASK-B-019: the verdict must be explainable without scrolling, and the
    bulky low-signal blocks must not bury the findings."""

    @mock.patch("report.get_git_summary", return_value=fake_git_summary())
    def test_summary_chips_and_reason_appear_before_the_sections(self, _git):
        events = [
            make_event("openat", path="/tmp/x", project_path="/project",
                       comm="claude", uid=os.getuid(), flags=os.O_WRONLY | os.O_CREAT),
            make_event("unlinkat", path="/project/a.c", project_path="/project",
                       comm="rm", uid=os.getuid()),
        ]
        with tempfile.TemporaryDirectory() as d:
            rendered = read_text(report.generate_report(
                write_jsonl(d, events), project_path="/project"))

        self.assertIn('class="summary"', rendered)
        self.assertIn("Why this verdict:", rendered)
        self.assertIn("outside-project write", rendered)
        self.assertIn("file deletion", rendered)
        # The explanation must precede the detail sections it summarizes.
        self.assertLess(rendered.index("Why this verdict:"),
                        rendered.index("Outside-Project Mutations"))

    @mock.patch("report.get_git_summary", return_value=fake_git_summary())
    def test_clean_session_says_so_instead_of_listing_nothing(self, _git):
        with tempfile.TemporaryDirectory() as d:
            rendered = read_text(report.generate_report(
                write_jsonl(d, [make_event("openat", path="/project/a",
                                           project_path="/project")]),
                project_path="/project"))
        self.assertIn("no policy findings", rendered)

    @mock.patch("report.get_git_summary", return_value=fake_git_summary())
    def test_network_evidence_is_split_out_and_collapsed(self, _git):
        # Dozens of connects per run visually swamped the findings that actually
        # drive the verdict, so they get their own collapsed block.
        events = [make_event("connect", path="", project_path="/project",
                             comm="curl", alert=True, severity="medium",
                             rule_id="outbound-connect", reason="conn",
                             dest_addr=f"10.0.0.{i}", dest_port=443)
                  for i in range(3)]
        events.append(make_event("execve", argv="rm -rf x", project_path="/project",
                                 comm="bash", alert=True, severity="high",
                                 rule_id="destructive-rm", reason="danger"))
        with tempfile.TemporaryDirectory() as d:
            rendered = read_text(report.generate_report(
                write_jsonl(d, events), project_path="/project"))
        self.assertIn("Outbound connections (evidence only)", rendered)
        alert_region = rendered[rendered.index("Alert Details"):]
        # The real finding is rendered before the collapsed evidence block.
        self.assertLess(alert_region.index("destructive-rm"),
                        alert_region.index("Outbound connections"))

    @mock.patch("report.get_git_summary", return_value=fake_git_summary())
    def test_print_stylesheet_expands_collapsed_blocks(self, _git):
        # A PDF/print copy must not hide evidence behind a closed <details>.
        with tempfile.TemporaryDirectory() as d:
            rendered = read_text(report.generate_report(
                write_jsonl(d, [make_event("exit_group", pid=2, comm="codex",
                                           project_path="/project")]),
                project_path="/project"))
        self.assertIn("@media print", rendered)
        self.assertIn("display: block !important", rendered)

    @mock.patch("report.get_git_summary", return_value=fake_git_summary())
    def test_unmatched_critical_alert_is_still_explained(self, _git):
        # A critical alert forces UNSAFE on its own; the summary must not claim
        # there were no findings.
        ev = make_event("openat", path="/project/a", project_path="/project",
                        comm="x", alert=True, severity="critical",
                        rule_id="future-rule", reason="r")
        with tempfile.TemporaryDirectory() as d:
            rendered = read_text(report.generate_report(
                write_jsonl(d, [ev]), project_path="/project"))
        self.assertIn("Commit Safety: UNSAFE", rendered)
        self.assertIn("critical alert", rendered)
        self.assertNotIn("no policy findings", rendered)

    @mock.patch("report.get_git_summary", return_value=fake_git_summary())
    def test_critical_is_listed_even_when_review_findings_exist(self, _git):
        # Otherwise an UNSAFE badge could be explained by a deletion alone,
        # which on its own would only be REVIEW_NEEDED.
        events = [
            make_event("openat", path="/project/a", project_path="/project",
                       comm="x", alert=True, severity="critical",
                       rule_id="future-rule", reason="r"),
            make_event("unlinkat", path="/project/b.c", project_path="/project",
                       comm="rm"),
        ]
        with tempfile.TemporaryDirectory() as d:
            rendered = read_text(report.generate_report(
                write_jsonl(d, events), project_path="/project"))
        why = rendered[rendered.index("Why this verdict:"):][:200]
        self.assertIn("critical alert", why)
        self.assertIn("file deletion", why)

    @mock.patch("report.get_git_summary", return_value=fake_git_summary())
    def test_critical_outbound_is_a_finding_not_evidence(self, _git):
        # A critical outbound alert drives UNSAFE, so it must not be filed under
        # "evidence only" where the report says it does not affect the verdict.
        ev = make_event("connect", path="", project_path="/project", comm="curl",
                        alert=True, severity="critical", rule_id="outbound-connect",
                        reason="exfil", dest_addr="10.0.0.1", dest_port=443)
        with tempfile.TemporaryDirectory() as d:
            rendered = read_text(report.generate_report(
                write_jsonl(d, [ev]), project_path="/project"))
        self.assertIn("Commit Safety: UNSAFE", rendered)
        self.assertNotIn("evidence only", rendered)
        self.assertNotIn("do not affect the verdict", rendered)
