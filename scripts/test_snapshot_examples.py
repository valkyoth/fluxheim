#!/usr/bin/env python3
"""Guard the user-facing snapshot workflow and its qualification contract."""
import unittest

from smoke_operational_events import ROOT


class SnapshotGuideTests(unittest.TestCase):
    def test_all_cli_actions_and_options_have_usage(self):
        guide = (ROOT / "docs/guides/config-snapshots.md").read_text()
        for action in ("snapshot", "rollback", "snapshots", "show", "diff", "verify", "doctor", "prune"):
            self.assertIn(action, guide)
        for option in ("--config", "--store", "--integrity-key-file", "--message", "--to",
                       "--keep", "--older-than-days", "--reload-from", "--validate-config",
                       "FLUXHEIM_SNAPSHOT_STORE", "FLUXHEIM_SNAPSHOT_INTEGRITY_KEY_FILE"):
            self.assertIn(option, guide)
        self.assertNotIn("--test", (ROOT / "docs/guides/admin.md").read_text())

    def test_live_script_uses_trusted_binary_and_bounded_processes(self):
        source = (ROOT / "scripts/smoke_snapshot_examples.py").read_text()
        for control in ("timeout=20", "capture_output=True", "private_fixture", "--integrity-key-file",
                        'success=False', 'request(public, "/")', "wait_for"):
            self.assertIn(control, source)
        self.assertNotIn("shell=True", source)


    def test_important_operator_boundaries_are_explicit(self):
        guide = (ROOT / "docs/guides/config-snapshots.md").read_text()
        for phrase in ("not edits on disk", "does **not** automatically boot", "no dry-run",
                       "OR, not AND", "strictly", "zero exit", "not one atomic",
                       "does not inherit", "unverified", "not a backup"):
            self.assertIn(phrase, guide)


if __name__ == "__main__":
    unittest.main()
