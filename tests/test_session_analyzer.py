"""Tests for JSONL loading, target filtering, and session summaries."""

import os
import tempfile
import unittest

from tests.helpers import make_event, write_jsonl

import session_analyzer


class LoadEventsTests(unittest.TestCase):
    def test_load_events_reads_jsonl_and_skips_blanks(self):
        with tempfile.TemporaryDirectory() as directory:
            path = write_jsonl(directory, [make_event("execve"), make_event("openat")])
            with open(path, "a", encoding="utf-8") as stream:
                stream.write("\n")
            self.assertEqual(len(session_analyzer.load_events(path)), 2)

    def test_load_events_ignores_invalid_json(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "session.jsonl")
            with open(path, "w", encoding="utf-8") as stream:
                stream.write('{"event": "openat"}\nnot-json\n')
            self.assertEqual(session_analyzer.load_events(path), [{"event": "openat"}])


class TargetFilterTests(unittest.TestCase):
    def test_empty_target_returns_original_events(self):
        events = [make_event("openat")]
        self.assertIs(session_analyzer.filter_target_events(events), events)

    def test_filter_includes_target_agents_and_descendants(self):
        events = [
            make_event("execve", pid=10, ppid=1, comm="worker"),
            make_event("openat", pid=11, ppid=10, comm="child"),
            make_event("openat", pid=20, ppid=1, comm="codex"),
            make_event("openat", pid=30, ppid=1, comm="other"),
        ]
        filtered = session_analyzer.filter_target_events(events, "worker")
        self.assertEqual([event["pid"] for event in filtered], [10, 11, 20])


class SessionSummaryTests(unittest.TestCase):
    def test_summary_recognizes_all_six_event_names(self):
        events = [
            make_event("execve", argv="git status"),
            make_event("openat", path="/project/a"),
            make_event("unlinkat", path="/project/b"),
            make_event("renameat2", old_path="a", new_path="b", flags=1),
            make_event("fchmodat", path="/project/c", mode=0o644),
            make_event("exit_group", pid=9, comm="codex"),
        ]
        summary = session_analyzer.summarize_session(events)
        self.assertEqual(summary["event_counts"], {
            "execve": 1, "openat": 1, "unlinkat": 1,
            "renameat2": 1, "fchmodat": 1, "exit_group": 1,
        })

    def test_summary_returns_mutation_and_lifecycle_shapes(self):
        summary = session_analyzer.summarize_session([
            make_event("unlinkat", path="/project/deleted"),
            make_event("renameat2", old_path="old", new_path="new", flags=2),
            make_event("fchmodat", path="mode", mode=0o600),
            make_event("exit_group", pid=4, comm="agent"),
        ])
        self.assertEqual(summary["files_deleted"], ["/project/deleted"])
        self.assertEqual(summary["files_renamed"], [{"old_path": "old", "new_path": "new", "flags": 2}])
        self.assertEqual(summary["permission_changes"], [{"path": "mode", "mode": 0o600}])
        self.assertEqual(summary["process_exits"], [{"pid": 4, "comm": "agent"}])

    def test_summary_counts_connect_events(self):
        summary = session_analyzer.summarize_session([
            make_event("connect", dest_addr="203.0.113.10", dest_port=443),
        ])
        self.assertEqual(summary["event_counts"].get("connect"), 1)

    def test_summary_preserves_prior_keys_and_alerts(self):
        events = [
            make_event("execve", argv="python -m unittest", alert=True),
            make_event("openat", path="/project/test.py"),
        ]
        summary = session_analyzer.summarize_session(events)
        self.assertEqual(summary["total_events"], 2)
        self.assertEqual(summary["commands_executed"], ["python -m unittest"])
        self.assertEqual(summary["files_accessed"], ["/project/test.py"])
        self.assertEqual(summary["alert_count"], 1)
        self.assertEqual(summary["alerts"], [events[0]])
