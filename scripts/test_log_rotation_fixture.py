#!/usr/bin/env python3
"""Fixture setup must fail closed before writing configuration or launching Fluxheim."""
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import smoke_log_file_rotation as smoke


class FixtureTests(unittest.TestCase):
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
