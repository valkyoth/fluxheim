#!/usr/bin/env python3
"""Offline checkpoint/restore safety tests using tiny synthetic VM files."""
import json
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import windows_qemu_state as state
from windows_qemu import vm_lock


class CheckpointTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / "vm"
        self.root.mkdir(mode=0o700)
        for name in state.STATE:
            if name == "tpm":
                (self.root / name).mkdir()
                (self.root / name / "state").write_bytes(b"tpm state")
            else:
                (self.root / name).write_bytes(name.encode())
        self.target = self.base / "baselines/clean"
        # Restore write permissions on synthetic read-only baseline for cleanup.
        self.addCleanup(self.writable)

    def writable(self):
        for path in self.base.rglob("*"):
            if not path.is_symlink():
                path.chmod(0o700 if path.is_dir() else 0o600)

    def test_checkpoint_restore_retains_current_state_and_baseline(self):
        state.checkpoint(self.root, self.target)
        expected = state.verify(self.target)
        self.assertFalse(self.target.stat().st_mode & 0o222)
        (self.root / "windows.qcow2").write_bytes(b"new working data")
        (self.root / "test.log").write_text("retain evidence")
        state.restore(self.root, self.target)
        self.assertEqual(state.inventory(self.root), expected)
        self.assertEqual(state.verify(self.target), expected)
        retained, = self.base.glob("vm-retained-*")
        self.assertEqual((retained / "windows.qcow2").read_bytes(), b"new working data")
        self.assertEqual((retained / "test.log").read_text(), "retain evidence")

    def test_active_vm_blocks_checkpoint_and_restore(self):
        with vm_lock(self.root):
            for action in (state.checkpoint, state.restore):
                with self.assertRaisesRegex(RuntimeError, "already running"):
                    action(self.root, self.target)

    def test_never_overwrites_baseline(self):
        state.checkpoint(self.root, self.target)
        with self.assertRaises(FileExistsError):
            state.checkpoint(self.root, self.target)

    def test_corruption_rejected_before_restore(self):
        state.checkpoint(self.root, self.target)
        disk = self.target / "windows.qcow2"
        disk.chmod(0o600)
        disk.write_bytes(b"corrupt")
        with self.assertRaisesRegex(ValueError, "checksum"):
            state.restore(self.root, self.target)
        self.assertEqual((self.root / "windows.qcow2").read_bytes(), b"windows.qcow2")

    def test_manifest_path_traversal_rejected(self):
        state.checkpoint(self.root, self.target)
        manifest = self.target / "manifest.json"
        manifest.chmod(0o600)
        manifest.write_text(json.dumps({"../outside": "a" * 64}))
        with self.assertRaisesRegex(ValueError, "path"):
            state.verify(self.target)

    def test_linked_state_rejected(self):
        (self.root / "tpm/link").symlink_to(self.root / "identity.json")
        with self.assertRaises(ValueError):
            state.checkpoint(self.root, self.target)
        self.assertFalse(self.target.exists())

    def test_copy_failure_keeps_live_state_and_no_valid_baseline(self):
        with patch.object(state, "copy_file", side_effect=OSError("interrupted copy")):
            with self.assertRaises(OSError):
                state.checkpoint(self.root, self.target)
        self.assertTrue(self.root.exists())
        self.assertFalse(self.target.exists())

    def test_copy_and_hash_are_paced_and_preserve_content(self):
        source, destination = self.base / 'input', self.base / 'output'
        content = b'a' * (state.IO_CHUNK + 37)
        source.write_bytes(content)
        with patch.object(state.IOBudget, 'charge') as charge:
            state.copy_file(source, destination)
            self.assertEqual(sum(call.args[0] for call in charge.call_args_list), 2 * len(content))
        with patch.object(state.IOBudget, 'charge') as charge:
            self.assertEqual(state.digest(destination), hashlib.sha256(content).hexdigest())
            self.assertEqual(sum(call.args[0] for call in charge.call_args_list), len(content))
        self.assertEqual(destination.read_bytes(), content)

    def test_budget_does_not_accumulate_idle_credit(self):
        with patch.object(state.time, 'monotonic', side_effect=[0, 0, 10, 10]), \
                patch.object(state.time, 'sleep') as sleep:
            budget = state.IOBudget()
            budget.charge(state.IO_BYTES_PER_SECOND)
            budget.charge(state.IO_BYTES_PER_SECOND)
            budget.charge(state.IO_BYTES_PER_SECOND)
            self.assertEqual([call.args[0] for call in sleep.call_args_list], [1, 1])

    def test_unthrottled_copy_and_hash_still_preserve_and_verify_content(self):
        source, destination = self.base / 'input', self.base / 'output'
        content = b'qualification' * 1024
        source.write_bytes(content)
        with patch.object(state, 'IO_BYTES_PER_SECOND', 0), patch.object(state.time, 'sleep') as sleep:
            state.copy_file(source, destination)
            self.assertEqual(state.digest(destination), hashlib.sha256(content).hexdigest())
            sleep.assert_not_called()
        self.assertEqual(destination.read_bytes(), content)

    def test_low_space_preserves_live_state(self):
        with patch.object(state.shutil, "disk_usage") as usage:
            usage.return_value.free = 0
            with self.assertRaisesRegex(RuntimeError, "space"):
                state.checkpoint(self.root, self.target)
        self.assertTrue(self.root.exists())
        self.assertFalse(self.target.exists())


if __name__ == "__main__":
    unittest.main()
