"""Tests for the GUI's trusted-TMPDIR preparation (TASK-B-015).

The GUI may run under sudo, so it must create the toolchain temp root on the
monitored user's behalf with exactly the ownership and mode `sysguard` requires,
and refuse anything it cannot make trustworthy.
"""

import os
import shutil
import tempfile
import unittest

import main


class PrepareToolTmpTests(unittest.TestCase):
    def setUp(self):
        # Creation is confined to the monitored user's own run root, so the
        # fixtures live there rather than in an arbitrary temp dir.
        self.base = os.path.join(f"/tmp/claude-{main.REAL_UID}", "gui-test")
        shutil.rmtree(self.base, ignore_errors=True)

    def tearDown(self):
        shutil.rmtree(self.base, ignore_errors=True)

    def test_creates_directory_with_0700_and_real_uid(self):
        target = os.path.join(self.base, "tool-tmp")
        path, reason = main.prepare_tool_tmp(target)
        self.assertEqual(path, target, reason)
        st = os.stat(target)
        self.assertEqual(st.st_mode & 0o7777, 0o700)
        self.assertEqual(st.st_uid, main.REAL_UID)

    def test_is_idempotent_and_repairs_a_loose_mode(self):
        target = os.path.join(self.base, "tool-tmp")
        main.prepare_tool_tmp(target)
        os.chmod(target, 0o755)
        path, reason = main.prepare_tool_tmp(target)
        self.assertEqual(path, target, reason)
        self.assertEqual(os.stat(target).st_mode & 0o7777, 0o700)

    def test_rejects_paths_that_cannot_be_trusted(self):
        for bad in ["", "/", "//", "relative/x"]:
            with self.subTest(path=bad):
                path, reason = main.prepare_tool_tmp(bad)
                self.assertIsNone(path)
                self.assertTrue(reason)

    def test_rejects_a_symlink_target(self):
        real = os.path.join(self.base, "real")
        link = os.path.join(self.base, "link")
        os.makedirs(real, mode=0o700)
        os.symlink(real, link)
        path, reason = main.prepare_tool_tmp(link)
        self.assertIsNone(path)
        self.assertIn("symlink", reason)

    def test_rejects_a_symlinked_parent_component(self):
        # The component walk rejects the symlinked parent before creating
        # anything through it, so nothing is mutated on the far side.
        real = os.path.join(self.base, "real")
        link = os.path.join(self.base, "link")
        os.makedirs(os.path.join(real, "tool-tmp"), mode=0o700)
        os.symlink(real, link)
        path, reason = main.prepare_tool_tmp(os.path.join(link, "tool-tmp"))
        self.assertIsNone(path)
        self.assertIn("symlink", reason)
        self.assertFalse(os.path.exists(os.path.join(real, "tool-tmp", "x")))

    def test_refuses_to_touch_anything_outside_the_user_run_root(self):
        # The GUI runs as root: a typo must be rejected, never chmod'ed.
        before = os.stat("/etc").st_mode & 0o7777
        path, reason = main.prepare_tool_tmp("/etc")
        self.assertIsNone(path)
        self.assertIn("must be inside", reason)
        self.assertEqual(os.stat("/etc").st_mode & 0o7777, before)

    def test_normalizes_a_trailing_slash(self):
        # sysguard refuses --tool-tmp values ending in '/', so the GUI must not
        # report such a path as active.
        target = os.path.join(self.base, "tool-tmp")
        path, reason = main.prepare_tool_tmp(target + "/")
        self.assertEqual(path, target, reason)

    def test_default_root_sits_under_the_agent_run_root(self):
        # Matches the /tmp/claude-<uid>/ scratch root the policy already knows.
        self.assertTrue(main.DEFAULT_TOOL_TMP.startswith(f"/tmp/claude-{main.REAL_UID}/"))

    def test_creates_nested_paths_with_traversable_parents(self):
        # A sudo-run GUI must chown every directory it creates, or the monitored
        # user cannot traverse into the TMPDIR it was told to use.
        target = os.path.join(self.base, "a", "b", "tool-tmp")
        path, reason = main.prepare_tool_tmp(target)
        self.assertEqual(path, target, reason)
        probe = target
        while probe.startswith(f"/tmp/claude-{main.REAL_UID}"):
            self.assertEqual(os.stat(probe).st_uid, main.REAL_UID, probe)
            probe = os.path.dirname(probe)

    def test_rejects_a_symlinked_run_root_without_creating_anything(self):
        # If an existing parent is a symlink, nothing may be created through it.
        victim = os.path.join(self.base, "victim")
        os.makedirs(victim, mode=0o700)
        link = os.path.join(self.base, "linkroot")
        os.symlink(victim, link)
        target = os.path.join(link, "tool-tmp")
        path, reason = main.prepare_tool_tmp(target)
        self.assertIsNone(path)
        self.assertIn("symlink", reason)
        self.assertFalse(os.path.exists(os.path.join(victim, "tool-tmp")))

    def test_rejects_dot_components_the_collector_would_refuse(self):
        # Accepting these would tell the user the TMPDIR is active while
        # sysguard silently ignores it.
        base = f"/tmp/claude-{main.REAL_UID}"
        for bad in [f"{base}/./tool-tmp", f"{base}/x/../tool-tmp", f"{base}/.."]:
            with self.subTest(path=bad):
                path, reason = main.prepare_tool_tmp(bad)
                self.assertIsNone(path)
                self.assertIn("'.'", reason)
