"""Behavioral tests for the Python policy engine."""

import os
import unittest

from tests.helpers import make_event

import policy


class PolicyPredicateTests(unittest.TestCase):
    def test_boundary_write_outside_project_is_violation(self):
        # Only mutating opens outside the project are boundary violations.
        for flags in (os.O_WRONLY, os.O_RDWR, os.O_RDONLY | os.O_CREAT,
                      os.O_RDONLY | os.O_TRUNC, os.O_WRONLY | os.O_APPEND):
            with self.subTest(flags=flags):
                self.assertTrue(policy.is_boundary_violation("/tmp/data", "/project", flags))

    def test_boundary_read_outside_project_is_not_violation(self):
        # Routine read-only outside-project access is not a violation.
        self.assertFalse(policy.is_boundary_violation("/tmp/data", "/project", os.O_RDONLY))

    def test_boundary_missing_flags_is_not_violation(self):
        # Legacy record without flags -> operation unknown -> not a violation.
        self.assertFalse(policy.is_boundary_violation("/tmp/data", "/project"))

    def test_boundary_inside_project_never_violation(self):
        self.assertFalse(policy.is_boundary_violation("/project/src/a.py", "/project", os.O_WRONLY))

    def test_boundary_system_path_write_is_violation(self):
        # The system allowlist suppresses reads only; writing to /usr, /etc, ...
        # is a persistence/tampering signal and must still be a violation.
        for path in ("/usr/lib/x.so", "/etc/passwd", "/opt/app/bin", "/run/x"):
            with self.subTest(path=path):
                self.assertTrue(policy.is_boundary_violation(path, "/project", os.O_WRONLY))
        # ...but reading those same system paths is not a violation.
        self.assertFalse(policy.is_boundary_violation("/usr/lib/x.so", "/project", os.O_RDONLY))

    def test_boundary_ignores_dot_or_empty(self):
        for path, project in [("", "/project"), ("/tmp/x", ""), ("/tmp/x", ".")]:
            with self.subTest(path=path, project=project):
                self.assertFalse(policy.is_boundary_violation(path, project, os.O_WRONLY))

    def test_open_flags_may_mutate(self):
        self.assertIs(policy.open_flags_may_mutate(os.O_RDONLY), False)
        self.assertIs(policy.open_flags_may_mutate(os.O_WRONLY), True)
        self.assertIs(policy.open_flags_may_mutate(os.O_RDONLY | os.O_CREAT), True)
        self.assertIsNone(policy.open_flags_may_mutate(None))
        self.assertIsNone(policy.open_flags_may_mutate("bad"))

    def test_open_flags_readonly_directory_scan_is_not_mutation(self):
        # O_TMPFILE embeds O_DIRECTORY on Linux; a plain read-only directory
        # open must NOT be misread as a temp-file creation.
        directory = getattr(os, "O_DIRECTORY", 0)
        self.assertIs(policy.open_flags_may_mutate(os.O_RDONLY | directory), False)
        tmpfile = getattr(os, "O_TMPFILE", 0)
        if tmpfile:  # a genuine O_TMPFILE creation is still a mutation
            self.assertIs(policy.open_flags_may_mutate(os.O_WRONLY | tmpfile), True)
            self.assertIs(policy.open_flags_may_mutate(tmpfile), True)

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

    def test_standalone_outbound_connect_medium_is_safe(self):
        event = make_event(
            "connect", comm="curl", addr_family=2,
            dest_addr="203.0.113.10", dest_port=443,
            alert=True, severity="medium", rule_id="outbound-connect",
        )
        self.assertEqual(policy.evaluate_commit_safety([event])["safety"], "SAFE")


class ReviewNeededTests(unittest.TestCase):
    """README section 7 REVIEW_NEEDED heuristics (TASK-B-003)."""

    def _status(self, *paths, code=" M"):
        return {"status": "\n".join(f"{code} {p}" for p in paths), "diff_stat": ""}

    def test_two_arg_call_is_backward_compatible(self):
        result = policy.evaluate_commit_safety([make_event("openat", path="/project/a")], "/project")
        self.assertEqual(result["safety"], "SAFE")
        self.assertEqual(result["review_findings"], [])

    def test_high_volume_threshold_boundary(self):
        nineteen = self._status(*[f"/project/src/f{i}.py" for i in range(19)])
        twenty = self._status(*[f"/project/src/f{i}.py" for i in range(20)])
        self.assertEqual(policy.evaluate_commit_safety([], "/project", nineteen)["safety"], "SAFE")
        self.assertEqual(policy.evaluate_commit_safety([], "/project", twenty)["safety"], "REVIEW_NEEDED")

    def test_build_config_files_trigger_review(self):
        for path in ["pyproject.toml", "src/build/CMakeLists.txt",
                     "requirements-dev.txt", "poetry.lock", "sub/Cargo.lock"]:
            with self.subTest(path=path):
                result = policy.evaluate_commit_safety([], "/project", self._status(path))
                self.assertEqual(result["safety"], "REVIEW_NEEDED")
                self.assertTrue(any(f["type"] == "build_config_change" for f in result["review_findings"]))

    def test_ordinary_single_edit_is_safe(self):
        result = policy.evaluate_commit_safety([], "/project", self._status("src/widget.py"))
        self.assertEqual(result["safety"], "SAFE")
        self.assertEqual(result["review_findings"], [])

    def test_git_reported_deletion_triggers_review(self):
        result = policy.evaluate_commit_safety([], "/project", self._status("src/gone.py", code=" D"))
        self.assertEqual(result["safety"], "REVIEW_NEEDED")
        self.assertTrue(any(f["type"] == "sandbox_deletion" for f in result["review_findings"]))

    def test_in_project_unlinkat_still_review(self):
        result = policy.evaluate_commit_safety([make_event("unlinkat", path="/project/x")], "/project")
        self.assertEqual(result["safety"], "REVIEW_NEEDED")

    def test_rename_entry_uses_destination_path(self):
        status = {"status": "R  old_name.py -> pyproject.toml", "diff_stat": ""}
        result = policy.evaluate_commit_safety([], "/project", status)
        self.assertEqual(result["safety"], "REVIEW_NEEDED")
        self.assertTrue(any("pyproject.toml" in f["detail"] for f in result["review_findings"]))

    def test_unavailable_or_malformed_git_summary_is_inert(self):
        for summary in [None, {}, {"status": ""}, {"status": None}, "not-a-dict",
                        {"status": 123}, {"status": []}, {"status": {"x": 1}},
                        {"status": "(git not available)"},
                        {"status": "(git status unavailable)"}]:
            with self.subTest(summary=summary):
                result = policy.evaluate_commit_safety(
                    [make_event("openat", path="/project/a")], "/project", summary)
                self.assertEqual(result["safety"], "SAFE")
                self.assertEqual(result["review_findings"], [])

    def test_review_signals_never_downgrade_unsafe(self):
        review_git = self._status(*[f"/project/src/f{i}.py" for i in range(25)])
        unsafe_cases = {
            "dangerous": [make_event("execve", argv="git reset --hard")],
            "protected": [make_event("openat", path="/project/.env")],
            "chmod": [make_event("fchmodat", path="/project/x", mode=0o777)],
            "sequence": [make_event("openat", path="/project/.env"),
                         make_event("execve", path="/usr/bin/curl", argv="curl x")],
        }
        for name, events in unsafe_cases.items():
            with self.subTest(case=name):
                self.assertEqual(
                    policy.evaluate_commit_safety(events, "/project", review_git)["safety"],
                    "UNSAFE")

    def test_review_verdict_has_no_safe_message(self):
        result = policy.evaluate_commit_safety([], "/project", self._status("Makefile"))
        self.assertEqual(result["safety"], "REVIEW_NEEDED")
        self.assertTrue(result["recommendations"])
        self.assertNotIn("No issues detected. Safe to commit.", result["recommendations"])


class OperationAwareBoundaryTests(unittest.TestCase):
    """TASK-B-011: outside-project READs are informational; WRITEs are review."""

    def _openat(self, path, flags=0, **kw):
        return make_event("openat", path=path, project_path="/project",
                          comm="claude", flags=flags, **kw)

    def test_outside_reads_only_is_safe(self):
        events = [
            self._openat("/home/u/.cache/node/x.js"),
            self._openat("/etc/ssl/certs/ca.pem"),
            self._openat("/home/u/.claude/config.json"),
            self._openat("/project/src/main.py"),   # inside project
        ]
        r = policy.evaluate_commit_safety(events, "/project")
        self.assertEqual(r["safety"], "SAFE")
        self.assertEqual(r["boundary_violations"], [])
        self.assertEqual(r["outside_project_reads"], 3)

    def test_outside_writes_are_review_needed_not_unsafe(self):
        events = [self._openat("/home/u/.cache/r%d" % i) for i in range(10)]  # 10 reads
        events += [
            self._openat("/home/u/.claude/plugins/p", flags=os.O_WRONLY),
            self._openat("/tmp/other/new", flags=os.O_RDONLY | os.O_CREAT),
        ]
        r = policy.evaluate_commit_safety(events, "/project")
        self.assertEqual(r["safety"], "REVIEW_NEEDED")
        self.assertEqual(len(r["boundary_violations"]), 2)
        self.assertEqual(r["outside_project_reads"], 10)

    def test_protected_outside_is_unsafe_with_single_finding(self):
        r = policy.evaluate_commit_safety(
            [self._openat("/home/u/.ssh/id_rsa")], "/project")
        self.assertEqual(r["safety"], "UNSAFE")
        self.assertEqual(len(r["protected_accesses"]), 1)
        self.assertEqual(r["boundary_violations"], [])   # no double finding

    def test_legacy_openat_without_flags_is_review_not_safe(self):
        # A flag-less legacy open outside the project has an unknown operation:
        # it may be a write, so it is REVIEW_NEEDED, not SAFE. It is still not a
        # confirmed boundary-write finding.
        ev = make_event("openat", path="/home/u/.cache/x",
                        project_path="/project", comm="claude")
        del ev["flags"]                                   # legacy record
        r = policy.evaluate_commit_safety([ev], "/project")
        self.assertEqual(r["safety"], "REVIEW_NEEDED")
        self.assertEqual(r["outside_project_unknown_opens"], 1)
        self.assertEqual(r["boundary_violations"], [])

    def test_unknown_open_of_system_path_still_counts_for_review(self):
        # The read-noise allowlist must be applied only AFTER flags prove the op
        # is a read: an unknown-operation open of a system/tool-config path may
        # be a write, so it must still be counted and drive REVIEW_NEEDED.
        for p in ("/etc/passwd", "/usr/lib/x", "/home/u/.gitconfig"):
            with self.subTest(path=p):
                ev = make_event("openat", path=p, project_path="/project",
                                comm="claude")
                del ev["flags"]
                r = policy.evaluate_commit_safety([ev], "/project")
                self.assertEqual(r["safety"], "REVIEW_NEEDED")
                self.assertEqual(r["outside_project_unknown_opens"], 1)

    def test_read_of_system_path_stays_informational_noise(self):
        # A proven read of a system path is still dropped as noise (not counted).
        ev = make_event("openat", path="/usr/lib/libc.so",
                        project_path="/project", comm="claude", flags=os.O_RDONLY)
        r = policy.evaluate_commit_safety([ev], "/project")
        self.assertEqual(r["safety"], "SAFE")
        self.assertEqual(r["outside_project_reads"], 0)
        self.assertEqual(r["outside_project_unknown_opens"], 0)
