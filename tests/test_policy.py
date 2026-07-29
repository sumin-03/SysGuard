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


class B012EffectAwareWriteTests(unittest.TestCase):
    """TASK-B-012: outside writes classified by EFFECT, not just location.

    runtime bookkeeping -> informational | persistence/activation -> UNSAFE |
    anything else outside the project -> REVIEW_NEEDED.
    """

    HOME = "/home/u"

    UID = 4242

    def _open(self, path, flags=os.O_RDONLY, **kw):
        kw.setdefault("uid", self.UID)
        return make_event("openat", path=path, project_path="/project",
                          comm="claude", flags=flags, **kw)

    def _verdict(self, events, home=None):
        return policy.evaluate_commit_safety(
            events, "/project", home_path=self.HOME if home is None else home)

    # --- runtime bookkeeping noise -> SAFE ---------------------------------
    def test_runtime_noise_writes_are_safe(self):
        for p in [
            "/home/u/.claude/projects/s.jsonl", "/home/u/.claude/sessions/1.json",
            "/home/u/.claude/backups/b", "/home/u/.claude/history.jsonl",
            "/home/u/.claude/file-history/uuid/6ccb9ea1740990e8@v2",
            "/home/u/.claude/jobs/6a96f49b/timeline.jsonl",
            "/home/u/.claude/jobs/6a96f49b/state.json",
            "/home/u/.claude/jobs/6a96f49b/state.json.tmp.ed3aa3b4",
            "/home/u/.claude/jobs/pins.json",
            "/home/u/.claude/session-env/x/hook.sh", "/home/u/.claude/plugins/cache/p",
            "/home/u/.npm/_cacache/x", "/home/u/.npm/_logs/x.log",
            "/home/u/.cache/claude-cli-nodejs/x.jsonl",
            "/home/u/.config/Code/logs/x/cli.log",
            "/home/u/.claude.json.tmp.426628.ba9822eb",
            "/home/u/.claude/shell-snapshots/snapshot-bash-123-abc.sh",
            "/dev/null", "/dev/tty", "/sys/kernel/debug/tracing/trace_marker",
            "/tmp/claude-4242/-home-u-proj/tasks/x.output", "/tmp/claude-c8bd-cwd",
        ]:
            with self.subTest(path=p):
                r = self._verdict([self._open(p, os.O_WRONLY | os.O_CREAT)])
                self.assertEqual(r["safety"], "SAFE")
                self.assertEqual(r["boundary_violations"], [])
                self.assertEqual(len(r["runtime_noise_writes"]), 1)

    # --- near misses must NOT be exempted ----------------------------------
    def test_near_miss_paths_stay_review_needed(self):
        for p in [
            "/home/u/.npmrc", "/home/u/.cache/other/x", "/home/u/evil.tmp",
            "/home/u/.claude/plugins/evil", "/home/u/.claude/x",
            "/home/u/.claude/jobs/x/payload",        # not a known job file
            "/home/u/.claude/jobs/x/y/timeline.jsonl",  # too deeply nested
            "/home/u/.claude/jobs/evil.json",        # only pins.json at this level
            "/home/u/.claude.json.tmp.notapid.zz",
            "/dev/sda", "/proc/sys/kernel/x", "/sys/class/net/x", "/tmp/x",
            "/usr/lib/x.so",
            "/tmp/claude-evil/x", "/tmp/claude-4242", "/tmp/claude-x-cwd/sub",
            "/tmp/claude-9999/payload",   # wrong uid -> not the writer's own dir
            "/tmp/claude-evil-cwd",       # non-hex token -> not the marker shape
            "/tmp/claude-c8bd-cwd/sub",   # marker is a file, not a directory
            "/home/u/.claude/shell-snapshots",
        ]:
            with self.subTest(path=p):
                r = self._verdict([self._open(p, os.O_WRONLY | os.O_CREAT)])
                self.assertEqual(r["safety"], "REVIEW_NEEDED")
                self.assertEqual(len(r["boundary_violations"]), 1)

    # --- persistence / activation -> UNSAFE --------------------------------
    def test_persistence_writes_are_unsafe(self):
        for p in [
            "/home/u/.bashrc", "/home/u/.zshrc", "/home/u/.profile", "/home/u/.zshenv",
            "/home/u/.gitconfig", "/home/u/.config/git/config",
            "/home/u/.claude.json", "/home/u/.claude/settings.json",
            "/home/u/.claude/settings.local.json", "/home/u/.ssh/authorized_keys",
            "/home/u/.config/autostart/x.desktop",
            "/home/u/.config/systemd/user/x.service",
            "/home/u/.local/share/systemd/user/x.service",
            "/home/u/.config/environment.d/x.conf",
            "/etc/crontab", "/etc/cron.d/x", "/var/spool/cron/crontabs/u",
            "/etc/systemd/system/x.service", "/etc/profile", "/etc/profile.d/x.sh",
            "/etc/ld.so.preload", "/etc/ld.so.conf.d/x.conf",
            "/project/.git/hooks/pre-commit",
        ]:
            with self.subTest(path=p):
                r = self._verdict([self._open(p, os.O_WRONLY)])
                self.assertEqual(r["safety"], "UNSAFE")
                self.assertEqual(len(r["persistence_writes"]), 1)

    def test_persistence_reads_are_ordinary(self):
        # A shell reads .bashrc on every invocation — reading is not a signal.
        for p in ["/home/u/.bashrc", "/home/u/.zshrc", "/home/u/.claude.json"]:
            with self.subTest(path=p):
                r = self._verdict([self._open(p, os.O_RDONLY)])
                self.assertEqual(r["safety"], "SAFE")
                self.assertEqual(r["persistence_writes"], [])

    # --- precedence ---------------------------------------------------------
    def test_protected_beats_persistence_and_noise(self):
        r = self._verdict([self._open("/home/u/.ssh/id_rsa", os.O_WRONLY)])
        self.assertEqual(r["safety"], "UNSAFE")
        self.assertEqual(len(r["protected_accesses"]), 1)
        self.assertEqual(r["persistence_writes"], [])
        self.assertEqual(r["boundary_violations"], [])

    def test_unknown_operation_on_noise_path_is_not_exempted(self):
        ev = self._open("/home/u/.claude/projects/s.jsonl")
        del ev["flags"]
        r = self._verdict([ev])
        self.assertEqual(r["safety"], "REVIEW_NEEDED")
        self.assertEqual(r["outside_project_unknown_opens"], 1)
        self.assertEqual(r["runtime_noise_writes"], [])

    # --- atomic replace -----------------------------------------------------
    def test_rename_onto_persistence_target_is_unsafe(self):
        # A staged file renamed onto a persistence target that is NOT the agent's
        # own config still escalates.
        ev = make_event("renameat2", path="", project_path="/project", comm="claude",
                        old_path="/home/u/.bashrc.staged",
                        new_path="/home/u/.bashrc")
        r = self._verdict([ev])
        self.assertEqual(r["safety"], "UNSAFE")
        self.assertEqual(len(r["persistence_writes"]), 1)

    def test_rename_within_noise_is_not_a_finding(self):
        ev = make_event("renameat2", path="", project_path="/project", comm="claude",
                        old_path="/home/u/.claude/projects/a",
                        new_path="/home/u/.claude/projects/b")
        self.assertEqual(self._verdict([ev])["safety"], "SAFE")

    # --- fail-closed home ---------------------------------------------------
    def test_untrusted_home_disables_home_relative_exemptions(self):
        # No trusted home -> a bookkeeping write is reported, never silently
        # dropped. Absolute persistence paths still apply.
        noise = self._open("/home/u/.claude/projects/s.jsonl", os.O_WRONLY)
        self.assertEqual(self._verdict([noise], home="")["safety"], "REVIEW_NEEDED")
        cron = self._open("/etc/cron.d/x", os.O_WRONLY)
        self.assertEqual(self._verdict([cron], home="")["safety"], "UNSAFE")
        # /dev/null is absolute, so it stays exempt with no home.
        devnull = self._open("/dev/null", os.O_WRONLY)
        self.assertEqual(self._verdict([devnull], home="")["safety"], "SAFE")

    def test_home_resolution_ignores_root_only_sessions(self):
        # Only root activity -> no trusted monitored home -> fail closed.
        self.assertIsNone(policy.resolve_monitored_home(
            [make_event("openat", uid=0, path="/home/u/.claude/projects/x")]))
        # A normal uid resolves to that user's passwd home.
        import pwd
        uid = os.getuid()
        if uid > 0:
            self.assertEqual(
                policy.resolve_monitored_home([make_event("openat", uid=uid)]),
                pwd.getpwuid(uid).pw_dir.rstrip("/"))

    # --- the protected-verdict bug fixed in this task -----------------------
    def test_every_protected_path_forces_unsafe(self):
        # Previously only .env/.ssh/shadow were promoted; AWS creds and sudoers
        # leaked through as REVIEW_NEEDED.
        for p in ["/home/u/.aws/credentials", "/etc/sudoers",
                  "/project/config/secrets.json", "/project/.env"]:
            with self.subTest(path=p):
                r = self._verdict([self._open(p, os.O_RDONLY)])
                self.assertEqual(r["safety"], "UNSAFE")
                self.assertTrue(r["recommendations"])

    # --- path traversal must not defeat the exemption (Codex review) --------
    def test_traversal_cannot_win_a_runtime_exemption(self):
        # A noise prefix followed by ".." resolves somewhere else entirely.
        r = self._verdict([self._open(
            "/home/u/.claude/projects/../../.bashrc", os.O_WRONLY)])
        self.assertEqual(r["safety"], "UNSAFE")          # resolves to ~/.bashrc
        self.assertEqual(r["runtime_noise_writes"], [])
        r = self._verdict([self._open(
            "/home/u/.claude/projects/../evil", os.O_WRONLY | os.O_CREAT)])
        self.assertEqual(r["safety"], "REVIEW_NEEDED")   # exemption refused
        self.assertEqual(r["runtime_noise_writes"], [])
        r = self._verdict([self._open(
            "/home/u/.npm/_logs/../../.ssh/authorized_keys", os.O_WRONLY)])
        self.assertEqual(r["safety"], "UNSAFE")

    def test_recorded_home_from_collector_wins(self):
        # The collector's home_path must drive the report so live alerts and the
        # rendered verdict cannot disagree (e.g. when --home-path was used).
        ev = make_event("openat", path="/opt/agent/.claude/projects/s.jsonl",
                        project_path="/project", comm="claude", uid=os.getuid(),
                        flags=os.O_WRONLY, home_path="/opt/agent")
        r = policy.evaluate_commit_safety([ev], "/project")
        self.assertEqual(r["monitored_home"], "/opt/agent")
        self.assertEqual(r["safety"], "SAFE")          # classified as noise
    def test_collector_fail_closed_home_is_authoritative(self):
        # An EMPTY recorded home means the collector deliberately failed closed;
        # the report must not re-derive a home from uid and become more
        # permissive than the live engine.
        ev = make_event("openat", path="/opt/agent/.claude/projects/s.jsonl",
                        project_path="/project", comm="claude", uid=os.getuid(),
                        flags=os.O_WRONLY, home_path="")
        r = policy.evaluate_commit_safety([ev], "/project")
        self.assertIsNone(r["monitored_home"])
        self.assertEqual(r["safety"], "REVIEW_NEEDED")
        # A malformed recorded value is likewise authoritative (fail closed).
        ev2 = make_event("openat", path="/x", project_path="/project",
                         comm="claude", uid=os.getuid(), home_path="relative")
        self.assertIsNone(policy.resolve_monitored_home([ev2]))
        # Only a record with NO home_path field at all falls back to uid.
        ev3 = make_event("openat", path="/x", project_path="/project",
                         comm="claude", uid=os.getuid())
        ev3.pop("home_path", None)
        self.assertEqual(policy.resolve_monitored_home([ev3]),
                         __import__("pwd").getpwuid(os.getuid()).pw_dir.rstrip("/"))

    def test_rename_onto_protected_destination_is_unsafe(self):
        # Staging inside an exempt runtime dir then renaming onto credentials
        # must not slip through: protected precedence applies to the destination.
        for dest in ["/home/u/.aws/credentials", "/project/.env", "/etc/sudoers",
                     "/home/u/.ssh/id_rsa"]:
            with self.subTest(dest=dest):
                ev = make_event("renameat2", path="", project_path="/project",
                                comm="claude",
                                old_path="/home/u/.claude/projects/stage",
                                new_path=dest)
                r = self._verdict([ev])
                self.assertEqual(r["safety"], "UNSAFE")
                self.assertEqual(len(r["protected_accesses"]), 1)

    def test_claude_config_writes_stay_unsafe_despite_dot_claude_exemptions(self):
        # Bookkeeping under ~/.claude is noise, but the SETTINGS files are not:
        # they can define hooks / MCP servers, i.e. code that runs on the next
        # session. Exempting all of ~/.claude would hide an agent backdoor.
        for p in ["/home/u/.claude/settings.json",
                  "/home/u/.claude/settings.local.json",
                  "/home/u/.claude.json"]:
            with self.subTest(path=p):
                r = self._verdict([self._open(p, os.O_WRONLY)])
                self.assertEqual(r["safety"], "UNSAFE")
                self.assertEqual(len(r["persistence_writes"]), 1)
                self.assertEqual(r["runtime_noise_writes"], [])

    def test_tmp_scratch_requires_the_writers_own_uid(self):
        # A predictable numeric directory must not grant an exemption to anyone.
        own = self._open("/tmp/claude-4242/tasks/x.output", os.O_WRONLY)
        self.assertEqual(self._verdict([own])["safety"], "SAFE")
        other = self._open("/tmp/claude-9999/payload", os.O_WRONLY)
        self.assertEqual(self._verdict([other])["safety"], "REVIEW_NEEDED")
        # No uid recorded -> fail closed.
        legacy = self._open("/tmp/claude-4242/tasks/x.output", os.O_WRONLY)
        legacy.pop("uid")
        self.assertEqual(self._verdict([legacy])["safety"], "REVIEW_NEEDED")

    def test_tmp_scratch_uid_cannot_be_forged_by_overflow(self):
        # Mirrors the C bound: an over-long numeric component must never match.
        for p in ["/tmp/claude-18446744073709556538/x",   # wraps in 64-bit C
                  "/tmp/claude-00000000004242/x",         # over-long padding
                  "/tmp/claude-04242/x"]:                 # zero-padded spelling
            with self.subTest(path=p):
                self.assertEqual(
                    self._verdict([self._open(p, os.O_WRONLY)])["safety"],
                    "REVIEW_NEEDED")

    def test_symlinked_tmp_scratch_loses_its_exemption(self):
        # /tmp is world-writable and the uid in the NAME authenticates nothing:
        # linking an exempt-looking scratch path at a persistence target must not
        # suppress the write.
        import tempfile, pathlib
        with tempfile.TemporaryDirectory() as d:
            target = pathlib.Path(d) / "bashrc-standin"
            target.write_text("x")
            link = pathlib.Path(f"/tmp/claude-{os.getuid()}-symlink-test")
            real_dir = pathlib.Path(f"/tmp/claude-{os.getuid()}")
            real_dir.mkdir(exist_ok=True)
            probe = real_dir / "redirected"
            try:
                if probe.is_symlink() or probe.exists():
                    probe.unlink()
                probe.symlink_to(target)
                # Same path shape as the exempt scratch dir, but redirected.
                self.assertFalse(policy.is_runtime_noise_write(
                    str(probe), "/home/u", os.getuid()))
                # A plain (non-symlink) file in the same dir stays exempt.
                plain = real_dir / "plain-output"
                plain.write_text("x")
                self.assertTrue(policy.is_runtime_noise_write(
                    str(plain), "/home/u", os.getuid()))
                plain.unlink()
            finally:
                if probe.is_symlink():
                    probe.unlink()
                link.unlink(missing_ok=True)


class B014DeletionPrecedenceTests(unittest.TestCase):
    """TASK-B-014: deletions get the same precedence as opens, with a narrower
    disposable set than the write allowlist (director's correction)."""

    HOME = "/home/u"
    UID = 4242

    def _unlink(self, path, uid=None):
        return make_event("unlinkat", path=path, project_path="/project",
                          comm="rm", uid=self.UID if uid is None else uid)

    def _verdict(self, events):
        return policy.evaluate_commit_safety(events, "/project", home_path=self.HOME)

    def test_own_scratch_deletion_is_informational(self):
        r = self._verdict([self._unlink(
            f"/tmp/claude-{self.UID}/-home-u-proj/uuid/scratchpad/hello")])
        self.assertEqual(r["safety"], "SAFE")
        self.assertEqual(len(r["runtime_noise_deletions"]), 1)
        self.assertEqual(r["file_deletions"], [])

    def test_other_uid_scratch_deletion_is_reviewable(self):
        r = self._verdict([self._unlink(
            "/tmp/claude-9999/-home-u-proj/uuid/scratchpad/hello")])
        self.assertEqual(r["safety"], "REVIEW_NEEDED")
        self.assertEqual(len(r["file_deletions"]), 1)

    def test_protected_and_persistence_deletions_are_unsafe(self):
        r = self._verdict([self._unlink("/project/.env")])
        self.assertEqual(r["safety"], "UNSAFE")
        self.assertEqual(len(r["protected_accesses"]), 1)
        self.assertEqual(r["file_deletions"], [])
        for p in ["/home/u/.bashrc", "/home/u/.ssh/authorized_keys",
                  "/etc/cron.d/x", "/home/u/.claude/settings.json"]:
            with self.subTest(path=p):
                r = self._verdict([self._unlink(p)])
                self.assertEqual(r["safety"], "UNSAFE")
                self.assertEqual(len(r["persistence_writes"]), 1)

    def test_write_allowlist_is_not_reused_wholesale_for_deletion(self):
        # Deleting history/backups/file-history is destructive even though
        # WRITING to them is routine bookkeeping.
        for p in ["/home/u/.claude/history.jsonl", "/home/u/.claude/backups/b",
                  "/home/u/.claude/file-history/uuid/h@v2",
                  "/home/u/.claude/projects/s.jsonl", "/dev/null"]:
            with self.subTest(path=p):
                r = self._verdict([self._unlink(p)])
                self.assertEqual(r["safety"], "REVIEW_NEEDED")
                self.assertEqual(len(r["file_deletions"]), 1)
                self.assertEqual(r["runtime_noise_deletions"], [])
        # Caches/logs the agent recreates freely are disposable.
        r = self._verdict([self._unlink("/home/u/.npm/_logs/x.log")])
        self.assertEqual(r["safety"], "SAFE")

    def test_in_project_source_deletion_stays_reviewable(self):
        # create -> delete inside the session leaves no git evidence; that is
        # exactly the signal worth surfacing, regardless of git trackedness.
        events = [
            make_event("openat", path="/project/docs/hello.c",
                       project_path="/project", comm="claude", uid=self.UID,
                       flags=os.O_WRONLY | os.O_CREAT),
            self._unlink("/project/docs/hello.c"),
        ]
        r = self._verdict(events)
        self.assertEqual(r["safety"], "REVIEW_NEEDED")
        self.assertEqual(len(r["file_deletions"]), 1)

    def test_compiler_temps_are_not_exempt(self):
        # Recognizing forgeable gcc temp filenames would be an attacker-
        # controllable allowlist; the build noise is accepted instead.
        r = self._verdict([make_event("openat", path="/tmp/ccQ3Au8q.s",
                                      project_path="/project", comm="cc1",
                                      uid=self.UID, flags=os.O_WRONLY | os.O_CREAT)])
        self.assertEqual(r["safety"], "REVIEW_NEEDED")
        self.assertEqual(len(r["boundary_violations"]), 1)

    def test_rename_to_ordinary_outside_target_is_a_boundary_write(self):
        # Staging in an exempt location then renaming out must not bypass it.
        ev = make_event("renameat2", path="", project_path="/project",
                        comm="claude", uid=self.UID,
                        old_path=f"/tmp/claude-{self.UID}/stage",
                        new_path="/tmp/payload")
        r = self._verdict([ev])
        self.assertEqual(r["safety"], "REVIEW_NEEDED")
        self.assertEqual(len(r["boundary_violations"]), 1)

    def test_rename_exchange_classifies_both_paths(self):
        # RENAME_EXCHANGE swaps the files, so old_path is a destination too.
        for src, expect_bucket in [("/home/u/.bashrc", "persistence_writes"),
                                   ("/project/.env", "protected_accesses"),
                                   ("/tmp/payload", "boundary_violations")]:
            with self.subTest(src=src):
                ev = make_event("renameat2", path="", project_path="/project",
                                comm="claude", uid=self.UID, old_path=src,
                                new_path="/project/benign.txt",
                                flags=policy.RENAME_EXCHANGE)
                r = self._verdict([ev])
                self.assertEqual(len(r[expect_bucket]), 1)
                self.assertNotEqual(r["safety"], "SAFE")

    def test_plain_rename_only_classifies_the_destination(self):
        ev = make_event("renameat2", path="", project_path="/project",
                        comm="claude", uid=self.UID, old_path="/home/u/.bashrc",
                        new_path="/project/benign.txt", flags=0)
        self.assertEqual(self._verdict([ev])["safety"], "SAFE")


class B015ToolTmpTests(unittest.TestCase):
    """TASK-B-015: a trusted per-session toolchain temp root (--tool-tmp).

    Compiler intermediates are classified by an exact root agreed in advance,
    never by forgeable /tmp/cc* filenames.
    """

    HOME = "/home/u"
    UID = 4242
    ROOT = "/tmp/sg-tool-tmp"

    def _open(self, path, flags=os.O_WRONLY | os.O_CREAT, **kw):
        kw.setdefault("uid", self.UID)
        return make_event("openat", path=path, project_path="/project",
                          comm="cc1", flags=flags, **kw)

    def _verdict(self, events, root=None):
        return policy.evaluate_commit_safety(
            events, "/project", home_path=self.HOME,
            tool_tmp=self.ROOT if root is None else root)

    def test_build_temps_inside_the_root_are_informational(self):
        for p in [f"{self.ROOT}/ccWOZK5O.s", f"{self.ROOT}/sub/cc4hnobq.o"]:
            with self.subTest(path=p):
                r = self._verdict([self._open(p)])
                self.assertEqual(r["safety"], "SAFE")
                self.assertEqual(len(r["runtime_noise_writes"]), 1)

    def test_same_filenames_outside_the_root_stay_reported(self):
        # A forged /tmp/cc* name buys nothing — membership is by exact root.
        r = self._verdict([self._open("/tmp/ccWOZK5O.s")])
        self.assertEqual(r["safety"], "REVIEW_NEEDED")
        self.assertEqual(len(r["boundary_violations"]), 1)

    def test_traversal_and_the_root_itself_are_not_members(self):
        for p in [f"{self.ROOT}/../escape", self.ROOT, f"{self.ROOT}/"]:
            with self.subTest(path=p):
                self.assertFalse(policy.path_in_tool_tmp(p, self.ROOT))

    def test_without_a_configured_root_the_exemption_is_off(self):
        r = self._verdict([self._open(f"{self.ROOT}/ccWOZK5O.s")], root="")
        self.assertEqual(r["safety"], "REVIEW_NEEDED")

    def test_protected_and_persistence_win_inside_the_root(self):
        r = self._verdict([self._open(f"{self.ROOT}/.env")])
        self.assertEqual(r["safety"], "UNSAFE")
        r = self._verdict([self._open(f"{self.ROOT}/x", flags=os.O_RDONLY)])
        self.assertEqual(r["safety"], "SAFE")

    def test_deletion_inside_the_root_is_informational(self):
        ev = make_event("unlinkat", path=f"{self.ROOT}/ccWOZK5O.s",
                        project_path="/project", comm="gcc", uid=self.UID)
        r = self._verdict([ev])
        self.assertEqual(r["safety"], "SAFE")
        self.assertEqual(len(r["runtime_noise_deletions"]), 1)

    def test_recorded_tool_tmp_from_the_collector_is_used(self):
        ev = self._open(f"{self.ROOT}/ccWOZK5O.s")
        ev["tool_tmp"] = self.ROOT
        r = policy.evaluate_commit_safety([ev], "/project", home_path=self.HOME)
        self.assertEqual(r["tool_tmp"], self.ROOT)
        self.assertEqual(r["safety"], "SAFE")
        # An empty recorded value is authoritative: no trusted root.
        ev2 = self._open(f"{self.ROOT}/ccWOZK5O.s")
        ev2["tool_tmp"] = ""
        r2 = policy.evaluate_commit_safety([ev2], "/project", home_path=self.HOME)
        self.assertEqual(r2["safety"], "REVIEW_NEEDED")

    def test_filesystem_root_is_never_a_valid_tool_tmp(self):
        # "/" would strip to "" and match every absolute path, turning the
        # exemption into blanket suppression.
        for bad in ["/", "//", "///"]:
            with self.subTest(root=bad):
                self.assertFalse(policy.path_in_tool_tmp("/tmp/payload", bad))
                r = self._verdict([self._open("/tmp/payload")], root=bad)
                self.assertEqual(r["safety"], "REVIEW_NEEDED")

    def test_trailing_newline_never_wins_an_exemption(self):
        # Python's "$" also matches before a trailing newline; the C engine uses
        # strcmp, so a lenient anchor would split the two classifications.
        for p in ["/home/u/.claude/jobs/x/state.json\n",
                  "/home/u/.claude/jobs/pins.json\n",
                  "/home/u/.claude.json.tmp.42.ab\n",
                  "/tmp/claude-c8bd-cwd\n"]:
            with self.subTest(path=p):
                self.assertFalse(policy.is_runtime_noise_write(p, "/home/u", self.UID))

    def test_outside_write_is_medium_not_high(self):
        # It fires only after protected / persistence / bookkeeping have been
        # ruled out, so it means "an unexplained mutation" — review, not alarm.
        # Same tier as file-unlink; the verdict is unaffected (only `critical`
        # escalates), so this is a triage-accuracy change.
        r = self._verdict([self._open("/tmp/unexplained", os.O_WRONLY | os.O_CREAT)])
        self.assertEqual(r["safety"], "REVIEW_NEEDED")
        self.assertEqual(len(r["boundary_violations"]), 1)
        self.assertEqual(r["boundary_violations"][0]["severity"], "medium")

    def test_severity_never_changes_the_verdict_except_critical(self):
        # A medium/high alert must not escalate on its own; only `critical` does.
        base = make_event("openat", path="/project/a", project_path="/project",
                          comm="claude", uid=self.UID, flags=os.O_RDONLY)
        for sev in ("medium", "high"):
            with self.subTest(severity=sev):
                ev = dict(base, alert=True, severity=sev, rule_id="x")
                self.assertEqual(self._verdict([ev])["safety"], "SAFE")
        ev = dict(base, alert=True, severity="critical", rule_id="x")
        self.assertEqual(self._verdict([ev])["safety"], "UNSAFE")


class B022AgentConfigRestageTests(unittest.TestCase):
    """TASK-B-022: Claude Code rewrites its own config through an atomic staging
    file several times per session — measured on a session that did nothing but
    read a file: four staging+rename pairs, zero direct writes. That exact shape
    is informational; anything else about these files still escalates.
    """

    HOME = "/home/u"
    UID = 4242

    def _rename(self, old, new):
        return make_event("renameat2", path="", project_path="/project",
                          comm="claude", uid=self.UID, old_path=old, new_path=new)

    def _open(self, path, flags):
        return make_event("openat", path=path, project_path="/project",
                          comm="claude", uid=self.UID, flags=flags)

    def _verdict(self, events):
        return policy.evaluate_commit_safety(events, "/project", home_path=self.HOME)

    def test_self_restage_is_informational(self):
        for cfg, stage in [
            ("/home/u/.claude.json", "/home/u/.claude.json.tmp.727731.2ab5a0f5"),
            ("/home/u/.claude/settings.json", "/home/u/.claude/settings.json.tmp.42.beef"),
            ("/home/u/.claude/settings.local.json",
             "/home/u/.claude/settings.local.json.tmp.7.aa"),
        ]:
            with self.subTest(cfg=cfg):
                r = self._verdict([self._rename(stage, cfg)])
                self.assertEqual(r["safety"], "SAFE")
                self.assertEqual(len(r["agent_config_changes"]), 1)
                self.assertEqual(r["persistence_writes"], [])

    def test_staging_name_must_belong_to_the_destination(self):
        # Otherwise any file could be renamed into place unnoticed.
        for old in ["/home/u/evil",
                    "/home/u/.claude.json.tmp.notapid.zz",
                    "/home/u/.claude/settings.json.tmp.42.beef"]:
            with self.subTest(old=old):
                r = self._verdict([self._rename(old, "/home/u/.claude.json")])
                self.assertEqual(r["safety"], "UNSAFE")
                self.assertEqual(len(r["persistence_writes"]), 1)

    def test_the_rule_does_not_extend_to_other_persistence_targets(self):
        r = self._verdict([self._rename("/home/u/.bashrc.tmp.42.ab", "/home/u/.bashrc")])
        self.assertEqual(r["safety"], "UNSAFE")

    def test_only_the_owning_agent_may_restage_the_config(self):
        stage, cfg = "/home/u/.claude.json.tmp.42.ab", "/home/u/.claude.json"
        for comm, expect_safe in [("claude", True), ("Bun Pool 3", True),
                                  ("MainThread", True), ("codex", False),
                                  ("gemini", False), ("bash", False)]:
            with self.subTest(comm=comm):
                ev = self._rename(stage, cfg)
                ev["comm"] = comm
                r = self._verdict([ev])
                self.assertEqual(r["safety"], "SAFE" if expect_safe else "UNSAFE")

    def test_exchange_does_not_qualify_as_a_routine_restage(self):
        # RENAME_EXCHANGE swaps the two files instead of replacing one, so it is
        # not the atomic-replace pattern being exempted.
        ev = self._rename("/home/u/.claude.json.tmp.42.ab", "/home/u/.claude.json")
        ev["flags"] = policy.RENAME_EXCHANGE
        r = self._verdict([ev])
        self.assertEqual(r["safety"], "UNSAFE")
        self.assertEqual(len(r["persistence_writes"]), 1)
        self.assertEqual(r["agent_config_changes"], [])

    def test_direct_write_to_agent_config_still_escalates(self):
        # The attack shape. It does not occur in a normal session.
        for flags in (os.O_WRONLY, os.O_WRONLY | os.O_TRUNC, os.O_RDWR):
            with self.subTest(flags=flags):
                r = self._verdict([self._open("/home/u/.claude.json", flags)])
                self.assertEqual(r["safety"], "UNSAFE")
                self.assertEqual(len(r["persistence_writes"]), 1)

    def test_reading_agent_config_stays_silent(self):
        r = self._verdict([self._open("/home/u/.claude.json", os.O_RDONLY)])
        self.assertEqual(r["safety"], "SAFE")
        self.assertEqual(r["agent_config_changes"], [])
