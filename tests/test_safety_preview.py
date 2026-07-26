"""Tests for the headless GUI safety-preview helper (TASK-B-007).

Covers the SAFE/REVIEW_NEEDED/UNSAFE pipeline, the failure-to-"UNKNOWN"
behavior, and the no-git / no-Tkinter boundary — the automated evidence for
B-007, since the Tkinter widget wiring itself needs a display and is verified
manually.
"""

import json
import os
import tempfile
import unittest
from unittest import mock

from tests.helpers import make_event, write_jsonl

import safety_preview


class SafetyPreviewTests(unittest.TestCase):
    def _verdict(self, events, **kwargs):
        with tempfile.TemporaryDirectory() as directory:
            path = write_jsonl(directory, events)
            return safety_preview.compute_session_safety(path, **kwargs)

    def test_benign_session_is_safe(self):
        self.assertEqual(
            self._verdict([make_event("openat", path="/project/src/a.py")],
                          project_path="/project"),
            "SAFE")

    def test_deletion_is_review_needed(self):
        self.assertEqual(
            self._verdict([make_event("unlinkat", path="/project/x")], project_path="/project"),
            "REVIEW_NEEDED")

    def test_env_access_is_unsafe(self):
        self.assertEqual(
            self._verdict([make_event("openat", path="/project/.env")], project_path="/project"),
            "UNSAFE")

    def test_missing_file_is_unknown(self):
        self.assertEqual(
            safety_preview.compute_session_safety("/no/such/session.jsonl"), "UNKNOWN")

    def test_empty_file_is_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "empty.jsonl")
            open(path, "w").close()
            self.assertEqual(safety_preview.compute_session_safety(path), "UNKNOWN")

    def test_malformed_only_is_unknown(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "bad.jsonl")
            with open(path, "w", encoding="utf-8") as stream:
                stream.write("not json\n{also not valid\n")
            self.assertEqual(safety_preview.compute_session_safety(path), "UNKNOWN")

    def test_valid_line_amid_malformed_still_classifies(self):
        with tempfile.TemporaryDirectory() as directory:
            path = os.path.join(directory, "mixed.jsonl")
            with open(path, "w", encoding="utf-8") as stream:
                stream.write("garbage\n")
                stream.write(json.dumps(make_event("openat", path="/project/.env")) + "\n")
            self.assertEqual(
                safety_preview.compute_session_safety(path, project_path="/project"), "UNSAFE")

    def test_derives_project_path_from_first_event(self):
        # No project_path passed -> taken from the event's own project_path.
        self.assertEqual(
            self._verdict([make_event("openat", path="/proj/.env", project_path="/proj")]),
            "UNSAFE")

    def test_derives_target_comm_and_filters(self):
        # target_comm is derived as "claude" from events[0]; the non-target
        # "cat" process's .env access is then filtered out, so the session is
        # SAFE. A broken target_comm fallback would skip filtering, include the
        # .env access, and report UNSAFE.
        events = [
            make_event("openat", comm="claude", path="/proj/src/a.py",
                       target_comm="claude", project_path="/proj"),
            make_event("openat", comm="cat", pid=999, ppid=999,
                       path="/proj/.env", target_comm="claude", project_path="/proj"),
        ]
        self.assertEqual(self._verdict(events), "SAFE")

    def test_preview_never_invokes_git(self):
        with mock.patch("git_summary.subprocess.run") as run:
            self._verdict([make_event("openat", path="/project/src/a.py")],
                          project_path="/project")
            run.assert_not_called()
