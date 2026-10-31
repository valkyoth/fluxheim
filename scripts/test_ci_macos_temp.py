#!/usr/bin/env python3
"""Check the macOS CI fixture root without weakening runtime path policy."""

import os
from pathlib import Path
import stat
import subprocess
import tempfile
import unittest


@unittest.skipIf(os.name == "nt", "POSIX CI setup")
class MacosTemporaryRootTests(unittest.TestCase):
    def test_symlinked_home_and_temporary_root_are_canonicalized(self):
        script = Path(__file__).resolve().with_name("ci_macos_temp.sh")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            home = root / "home with spaces"
            home.mkdir()
            alias = root / "alias"
            alias.symlink_to(home, target_is_directory=True)
            environment_file = root / "github-env"
            environment = dict(os.environ, HOME=str(alias), TMPDIR=str(alias),
                               GITHUB_ENV=str(environment_file))
            subprocess.run(["bash", str(script)], env=environment, check=True, timeout=10)
            entry = environment_file.read_text().strip()
            self.assertTrue(entry.startswith("TMPDIR="))
            directory = Path(entry.removeprefix("TMPDIR="))
            self.assertEqual(directory, directory.resolve(strict=True))
            self.assertEqual(directory.parent, home)
            self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)
            subprocess.run(["bash", str(script)], env=environment, check=True, timeout=10)
            entries = environment_file.read_text().splitlines()
            self.assertEqual(len(entries), 2)
            self.assertNotEqual(entries[0], entries[1])


if __name__ == "__main__":
    unittest.main()
