"""Behavioral tests for the Python policy engine."""

import unittest

from tests.helpers import make_event

import policy


class PolicyPredicateTests(unittest.TestCase):
    def test_boundary_violation_outside_project(self):
        self.assertTrue(policy.is_boundary_violation("/tmp/data", "/project"))

    def test_boundary_violation_inside_project(self):
        self.assertFalse(policy.is_boundary_violation("/project/src/a.py", "/project"))

    def test_boundary_violation_ignores_dot_or_empty(self):
        for path, project in [("", "/project"), ("/tmp/x", ""), ("/tmp/x", ".")]:
            with self.subTest(path=path, project=project):
                self.assertFalse(policy.is_boundary_violation(path, project))

    def test_system_path_matrix(self):
        for path in ["/usr/bin/git", "/lib/libc.so", "/etc/passwd", "/home/u/.gitconfig"]:
            with self.subTest(path=path):
                self.assertTrue(policy.is_system_path(path))
        self.assertFalse(policy.is_system_path("/project/file.py"))

    def test_protected_path_matrix(self):
        for path in ["/project/.env", "/home/u/.ssh/id_rsa", "/etc/shadow"]:
            with self.subTest(path=path):
                self.assertTrue(policy.is_protected_path(path))
        for path in ["", "/project/readme.md"]:
            with self.subTest(path=path):
                self.assertFalse(policy.is_protected_path(path))

    def test_inside_project_accepts_root_and_child(self):
        for path in ["/project", "/project/src/main.py"]:
            with self.subTest(path=path):
                self.assertTrue(policy.is_inside_project(path, "/project"))
        self.assertFalse(policy.is_inside_project("/project-other/x", "/project"))

    def test_env_file_path_matrix(self):
        for path in [".env", "/project/.env.local", "/x/.env.production"]:
            with self.subTest(path=path):
                self.assertTrue(policy.is_env_file_path(path))
        for path in ["", "foo.env", ".environment"]:
            with self.subTest(path=path):
                self.assertFalse(policy.is_env_file_path(path))

    def test_external_transfer_tool_exact_matching(self):
        cases = [
            (make_event("execve", path="/usr/bin/curl"), "curl"),
            (make_event("execve", path="", argv="/usr/bin/wget https://x"), "wget"),
            (make_event("execve", path="/usr/bin/curl-helper"), None),
            (make_event("openat", path="/usr/bin/curl"), None),
            (make_event("execve", path="", argv=None), None),
        ]
        for event, expected in cases:
            with self.subTest(event=event):
                self.assertEqual(policy.external_transfer_tool(event), expected)


class DangerousCommandTests(unittest.TestCase):
    def test_canonical_command_list_is_exact(self):
        self.assertEqual(policy.DANGEROUS_COMMANDS, [
            "rm -rf", "rm -r", "git reset --hard", "git clean -fd",
            "git clean -f", "chmod 777", "chmod a+rwx",
        ])

    def test_each_canonical_command_is_dangerous(self):
        for command in policy.DANGEROUS_COMMANDS:
            with self.subTest(command=command):
                self.assertTrue(policy.is_dangerous_command(command))

    def test_standalone_downloaders_are_not_dangerous(self):
        for command in ["curl https://example.test", "wget https://example.test"]:
            with self.subTest(command=command):
                self.assertFalse(policy.is_dangerous_command(command))

    def test_empty_command_is_not_dangerous(self):
        self.assertFalse(policy.is_dangerous_command(""))

    def test_classify_dangerous_execve(self):
        result = policy.classify_event(make_event("execve", argv="git reset --hard"))
        self.assertEqual(result["findings"][0]["type"], "dangerous_command")


class SequenceDetectionTests(unittest.TestCase):
    def test_ordered_env_then_curl_detected(self):
        events = [
            make_event("openat", path="/project/.env"),
            make_event("execve", path="/usr/bin/curl", argv="curl https://x"),
        ]
        findings = policy.detect_suspicious_sequences(events)
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "critical")

    def test_reversed_order_not_detected(self):
        events = [
            make_event("execve", path="/usr/bin/wget", argv="wget https://x"),
            make_event("openat", path="/project/.env"),
        ]
        self.assertEqual(policy.detect_suspicious_sequences(events), [])

    def test_standalone_precursors_not_detected(self):
        for events in [
            [make_event("openat", path="/project/.env")],
            [make_event("execve", path="/usr/bin/curl", argv="curl https://x")],
        ]:
            with self.subTest(events=events):
                self.assertEqual(policy.detect_suspicious_sequences(events), [])

    def test_detection_is_deduplicated(self):
        events = [
            make_event("openat", path="/project/.env"),
            make_event("openat", path="/project/.env.local"),
            make_event("execve", path="/usr/bin/curl"),
            make_event("execve", path="/usr/bin/wget"),
        ]
        self.assertEqual(len(policy.detect_suspicious_sequences(events)), 1)

    def test_detection_is_pid_independent(self):
        events = [
            make_event("openat", pid=10, path="/project/.env"),
            make_event("execve", pid=20, ppid=10, path="/usr/bin/wget"),
        ]
        self.assertEqual(policy.detect_suspicious_sequences(events)[0]["tool"], "wget")

    def test_detection_is_call_local_and_does_not_leak_contents(self):
        first = policy.detect_suspicious_sequences([
            make_event("openat", path="/project/.env", contents="TOP_SECRET"),
            make_event("execve", path="/usr/bin/curl"),
        ])
        second = policy.detect_suspicious_sequences([make_event("execve", path="/usr/bin/curl")])
        self.assertEqual(second, [])
        self.assertNotIn("TOP_SECRET", repr(first))


class SafetyVerdictTests(unittest.TestCase):
    def test_isolated_unlink_requires_review(self):
        result = policy.evaluate_commit_safety([make_event("unlinkat", path="/project/a")])
        self.assertEqual(result["safety"], "REVIEW_NEEDED")

    def test_world_writable_chmod_is_unsafe(self):
        result = policy.evaluate_commit_safety([make_event("fchmodat", path="/project/a", mode=0o777)])
        self.assertEqual(result["safety"], "UNSAFE")

    def test_safe_chmod_is_safe(self):
        result = policy.evaluate_commit_safety([make_event("fchmodat", path="/project/a", mode=0o644)])
        self.assertEqual(result["safety"], "SAFE")

    def test_rename_and_exit_are_safe(self):
        events = [
            make_event("renameat2", old_path="/project/a", new_path="/project/b"),
            make_event("exit_group"),
        ]
        self.assertEqual(policy.evaluate_commit_safety(events)["safety"], "SAFE")

    def test_standalone_downloader_is_safe(self):
        event = make_event("execve", path="/usr/bin/curl", argv="curl https://example.test")
        self.assertEqual(policy.evaluate_commit_safety([event])["safety"], "SAFE")

    def test_medium_downloader_alert_does_not_force_unsafe(self):
        event = make_event(
            "execve", path="/usr/bin/curl", argv="curl https://example.test",
            alert=True, severity="medium", rule_id="downloader-exec",
        )
        self.assertEqual(policy.evaluate_commit_safety([event])["safety"], "SAFE")
