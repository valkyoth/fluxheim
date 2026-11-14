#!/usr/bin/env python3
"""Read-only upgrade preflight regression coverage."""

from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import check_cache_recovery_capacity as check


class CapacityPreflightTests(unittest.TestCase):
    def test_counts_root_shards_leftovers_and_metadata_without_modification(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "aa").mkdir()
            paths = [root / "metadata", root / "aa/object.fhc", root / "aa/.partial.tmp"]
            for path in paths:
                path.write_bytes(b"preserve")
            before = {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in paths}
            self.assertEqual(check.check_capacity(root, limit=4), (True, 4))
            self.assertEqual(check.check_capacity(root, limit=3), (False, 4))
            self.assertEqual(before, {p: (p.read_bytes(), p.stat().st_mtime_ns) for p in paths})

    def test_refuses_linked_shard_and_root(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            target = root / "target"
            target.mkdir()
            alias = root / "aa"
            try:
                alias.symlink_to(target, target_is_directory=True)
            except OSError:
                self.skipTest("symlink creation unavailable")
            with self.assertRaises(ValueError):
                check.check_capacity(alias)
            with self.assertRaises(ValueError):
                check.check_capacity(root)

    def test_limits_enumeration_without_reading_payloads(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            for index in range(20):
                (root / f"file-{index}").write_bytes(b"x")
            with patch.object(Path, "read_bytes", side_effect=AssertionError("payload read")):
                self.assertEqual(check.check_capacity(root, limit=2), (False, 3))
            with self.assertRaises(TimeoutError):
                check.check_capacity(root, seconds=-1)

    def test_constants_track_runtime_policy(self):
        source = (Path(__file__).resolve().parents[1] / "crates/fluxheim-server/src/native_http1_cache_recovery.rs").read_text()
        self.assertIn("RECOVERY_ENTRY_LIMIT: usize = 65_536;", source)
        self.assertIn("RECOVERY_ENTRY_RESERVE: usize = 8_192;", source)
        self.assertIn("FILESYSTEM_OBJECT_LIMIT: usize = RECOVERY_ENTRY_LIMIT - RECOVERY_ENTRY_RESERVE;", source)
        self.assertEqual(check.OBJECT_LIMIT, check.ENTRY_LIMIT - 8192)

    def test_reparse_point_is_not_a_real_directory(self):
        from types import SimpleNamespace
        import stat
        self.assertFalse(check.is_real_directory(SimpleNamespace(
            st_mode=stat.S_IFDIR, st_file_attributes=0x400)))

    def test_cli_fails_closed_without_echoing_private_paths(self):
        import contextlib
        import io
        for outcome in ((True, 2), (False, 57_345), PermissionError("private-path")):
            output = io.StringIO()
            kwargs = {"side_effect": outcome} if isinstance(outcome, Exception) else {"return_value": outcome}
            with patch("sys.argv", ["preflight", "private-path"]), \
                    patch.object(check, "check_capacity", **kwargs), contextlib.redirect_stdout(output):
                self.assertEqual(check.main(), 0 if outcome == (True, 2) else 1)
            self.assertNotIn("private-path", output.getvalue())


if __name__ == "__main__":
    unittest.main()
