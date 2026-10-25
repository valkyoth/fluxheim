#!/usr/bin/env python3
"""Fixture setup must fail closed before writing configuration or launching Fluxheim."""
from pathlib import Path
import subprocess
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import patch

import smoke_log_file_rotation as smoke


class FixtureTests(unittest.TestCase):
    def test_windows_helper_changes_only_access_rules(self):
        helper = (smoke.ROOT / 'scripts' / 'protect_windows_smoke_directory.ps1').read_text()
        self.assertIn('[Security.AccessControl.AccessControlSections]::Access)', helper)
        self.assertIn('$item.SetAccessControl($acl)', helper)
        self.assertNotIn('Set-Acl -LiteralPath', helper)
        self.assertIn('if (-not $actual.AreAccessRulesProtected', helper)

    def test_arbitrary_quota_path_option_is_rejected(self):
        result = subprocess.run([
            smoke.sys.executable, str(smoke.ROOT / "scripts" / "smoke_log_file_rotation.py"),
            "--binary", smoke.sys.executable, "--quota-dir", "untrusted-directory",
        ], capture_output=True, text=True, timeout=10, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertIn("unrecognized arguments: --quota-dir", result.stderr)

    def test_deletion_requires_exact_recreation_or_retention_and_no_write_failure(self):
        before = {"reopens": 3, "reopen_errors": 2, "write_errors": 0, "failed": False}
        self.assertIsNone(smoke.deletion_result(before, dict(before)))
        self.assertEqual(smoke.deletion_result(before, dict(before, reopens=4)), "recreated")
        self.assertEqual(smoke.deletion_result(before, dict(before, reopen_errors=3)), "pending")
        for changes in ({"failed": True}, {"write_errors": 1}, {"reopens": 5},
                        {"reopens": 4, "reopen_errors": 3}, {"reopen_errors": 4}):
            with self.subTest(changes=changes), self.assertRaises(AssertionError):
                smoke.deletion_result(before, dict(before, **changes))

    def test_deletion_without_progress_times_out(self):
        with patch.object(smoke.time, "monotonic", side_effect=[0, 11]):
            with self.assertRaisesRegex(AssertionError, "timed out"):
                smoke.wait_for(lambda: None)

    def test_quota_mount_is_fixed_empty_small_and_never_created(self):
        with patch.object(smoke.sys, "platform", "linux"), \
             patch.object(smoke.Path, "is_symlink", return_value=False), \
             patch.object(smoke.Path, "is_mount", return_value=True), \
             patch.object(smoke.Path, "iterdir", return_value=iter([])), \
             patch.object(smoke.Path, "mkdir") as mkdir, \
             patch.object(smoke.os, "statvfs", create=True,
                          return_value=SimpleNamespace(f_blocks=256, f_frsize=4096)) as stat:
            self.assertEqual(smoke.fixture_parent(True), Path("/quota"))
            stat.assert_called_once_with(Path("/quota"))
            mkdir.assert_not_called()
            stat.return_value.f_blocks = 4096
            with self.assertRaisesRegex(ValueError, "at most 8 MiB"):
                smoke.fixture_parent(True)
            stat.return_value.f_blocks = 0
            with self.assertRaisesRegex(ValueError, "at most 8 MiB"):
                smoke.fixture_parent(True)
            stat.return_value.f_blocks = 256
            with patch.object(smoke.Path, "iterdir", return_value=iter([Path("existing")])):
                with self.assertRaisesRegex(ValueError, "empty"):
                    smoke.fixture_parent(True)

    def test_quota_refuses_symlinks_non_mounts_and_other_platforms(self):
        for platform, symlink, mount in [("win32", False, True),
                                         ("linux", True, True), ("linux", False, False)]:
            with self.subTest(platform=platform, symlink=symlink, mount=mount), \
                 patch.object(smoke.sys, "platform", platform), \
                 patch.object(smoke.Path, "is_symlink", return_value=symlink), \
                 patch.object(smoke.Path, "is_mount", return_value=mount), \
                 patch.object(smoke.os, "statvfs", create=True) as stat:
                with self.assertRaisesRegex(ValueError, "disposable Linux"):
                    smoke.fixture_parent(True)
                stat.assert_not_called()

    def test_unix_does_not_invoke_windows_tools(self):
        with patch.object(smoke.sys, "platform", "linux"), patch.object(smoke.subprocess, "run") as run:
            smoke.protect_directory(Path("unused"))
            run.assert_not_called()

    def test_windows_path_is_a_literal_file_argument_and_errors_propagate(self):
        root = Path("fixture with spaces ' and $characters")
        with patch.object(smoke.sys, "platform", "win32"), patch.object(smoke.subprocess, "run") as run:
            smoke.protect_directory(root)
            command = run.call_args.args[0]
            self.assertEqual(command[0], "powershell.exe")
            self.assertNotIn("-Command", command)
            self.assertEqual(command[command.index("-ExecutionPolicy") + 1], "RemoteSigned")
            self.assertLess(command.index("-ExecutionPolicy"), command.index("-File"))
            self.assertNotIn("Bypass", command)
            self.assertEqual(command[-2:], ["-Directory", str(root)])
            self.assertEqual(command[command.index("-File") + 1],
                             str(smoke.ROOT / "scripts" / "protect_windows_smoke_directory.ps1"))
            self.assertEqual(run.call_args.kwargs, {"check": True, "timeout": 30})
            run.side_effect = subprocess.CalledProcessError(1, command)
            with self.assertRaises(subprocess.CalledProcessError):
                smoke.protect_directory(root)

    def test_protection_precedes_child_files_and_failure_cleans_fixture(self):
        def fail(root):
            self.assertEqual(list(root.iterdir()), [])
            raise RuntimeError("ACL rejected")

        with tempfile.TemporaryDirectory() as parent:
            with patch.object(smoke, "protect_directory", side_effect=fail):
                with self.assertRaisesRegex(RuntimeError, "ACL rejected"):
                    with smoke.private_fixture(Path(parent)):
                        self.fail("unsafe fixture reached caller")
            self.assertEqual(list(Path(parent).iterdir()), [])

    def test_private_fixture_is_usable_and_removed(self):
        # On Windows this executes the real ACL helper, including readback.
        with tempfile.TemporaryDirectory() as parent:
            with smoke.private_fixture(Path(parent)) as root:
                (root / "child").write_bytes(b"fixture")
                self.assertEqual((root / "child").read_bytes(), b"fixture")
            self.assertFalse(root.exists())


if __name__ == "__main__":
    unittest.main()
