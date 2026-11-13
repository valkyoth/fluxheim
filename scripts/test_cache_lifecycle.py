#!/usr/bin/env python3
"""Regression checks for the required-cache lifecycle qualification harness."""

from pathlib import Path
import subprocess
import tomllib
import unittest
from unittest.mock import patch

import smoke_cache_lifecycle as smoke


class CacheLifecycleTests(unittest.TestCase):
    def test_matrix_requires_disk_and_private_authenticated_admin(self):
        for backend in ("filesystem", "storage-bin"):
            for memory in (False, True):
                for encrypted in (False, True):
                    config = tomllib.loads(smoke.source_for(12345, 12346, 12347, backend, memory, encrypted))
                    cache = config["vhosts"][0]["cache"]
                    self.assertTrue(cache["disk"]["enabled"])
                    self.assertEqual(cache["disk"]["backend"], backend)
                    self.assertEqual(cache["memory"]["enabled"], memory)
                    self.assertEqual(cache["disk"].get("encryption", {}).get("enabled", False), encrypted)
                    self.assertEqual(config["admin"]["listen"], "127.0.0.1:12347")
                    self.assertTrue(config["admin"]["require_loopback"])
                    self.assertEqual(config["admin"]["token_file"], "control-token")
                    self.assertEqual(config["admin"]["snapshot_integrity_key_file"], "snapshot-key")
                    self.assertFalse(config["admin"]["self_healing"]["enabled"])

    def test_rejects_non_disk_and_untrusted_backend_names(self):
        for backend in ("memory", "../filesystem", "unknown"):
            with self.assertRaises(ValueError):
                smoke.source_for(1, 2, 3, backend, False, False)

    def test_failed_start_requires_cache_error_not_port_collision(self):
        for code, error, valid in ((1, b"proxy cache initialization failed", True),
                                   (1, b"address already in use", False),
                                   (0, b"proxy cache initialization failed", False)):
            with self.subTest(code=code, error=error), patch.object(smoke.subprocess, "run", return_value=
                    subprocess.CompletedProcess([], code, b"", error)) as run:
                if valid:
                    smoke.rejected_start(Path("fixture.toml"))
                else:
                    with self.assertRaises(AssertionError):
                        smoke.rejected_start(Path("fixture.toml"))
                self.assertEqual(run.call_args.kwargs["timeout"], 20)
                self.assertNotIn("shell", run.call_args.kwargs)


if __name__ == "__main__":
    unittest.main()
