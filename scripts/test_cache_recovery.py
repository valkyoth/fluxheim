#!/usr/bin/env python3
"""Check the recovery smoke's file creation and native CI coverage."""

from pathlib import Path
import tempfile
import unittest

import smoke_cache_recovery as smoke
import test_cache_recovery_capacity


def load_tests(loader, tests, _pattern):
    tests.addTests(loader.loadTestsFromModule(test_cache_recovery_capacity))
    return tests


class RecoverySmokeTests(unittest.TestCase):
    def test_fixture_create_is_exclusive(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "fixture"
            smoke.write_fixture(path, smoke.MAGIC, True)
            self.assertEqual(path.read_bytes(), smoke.MAGIC)
            self.assertLess(path.stat().st_mtime, 100)
            with self.assertRaises(FileExistsError):
                smoke.write_fixture(path, b"replacement")
            self.assertEqual(path.read_bytes(), smoke.MAGIC)

    def test_fixture_does_not_follow_existing_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            original = Path(directory) / "original"
            alias = Path(directory) / "alias"
            original.write_bytes(b"preserve")
            try:
                alias.symlink_to(original)
            except OSError:
                self.skipTest("symlink creation unavailable for this account")
            with self.assertRaises(FileExistsError):
                smoke.write_fixture(alias, smoke.MAGIC)
            self.assertEqual(original.read_bytes(), b"preserve")

    def test_live_smoke_is_wired_on_all_native_platforms(self):
        workflow = (smoke.ROOT / ".github/workflows/ci.yml").read_text()
        self.assertIn('python3 scripts/smoke_cache_recovery.py "$HOME/.fluxheim-lb-smoke"', workflow)
        self.assertIn("python scripts/smoke_cache_recovery.py $env:TEMP", workflow)
        linux = (smoke.ROOT / "scripts/smoke_proxy_cache.sh").read_text()
        self.assertIn('python3 "$ROOT_DIR/scripts/smoke_cache_recovery.py" "$TMP_DIR"', linux)


if __name__ == "__main__":
    unittest.main()
