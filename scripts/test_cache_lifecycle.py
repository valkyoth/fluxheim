#!/usr/bin/env python3
"""Regression checks for the required-cache lifecycle qualification harness."""

from pathlib import Path
import subprocess
import tempfile
import tomllib
import unittest
from unittest.mock import Mock, patch

import smoke_cache_lifecycle as smoke


class CacheLifecycleTests(unittest.TestCase):
    def test_pressure_allows_only_verified_hits_or_explicit_saturation(self):
        for status, body, headers, valid in (
            (200, smoke.BODY, {"x-cache-status": "HIT"}, True),
            (503, b"cache temporarily unavailable\n", {"x-cache-reason": "disk-cache-saturated"}, True),
            (200, smoke.BODY, {"x-cache-status": "MISS"}, False),
            (200, b"wrong", {"x-cache-status": "HIT"}, False),
            (503, b"cache temporarily unavailable\n", {}, False),
            (502, b"bad gateway", {}, False),
        ):
            with self.subTest(status=status, headers=headers), patch.object(smoke.http.client, "HTTPConnection") as constructor:
                response = Mock(status=status)
                response.read.return_value = body
                response.getheader.side_effect = headers.get
                connection = constructor.return_value
                connection.getresponse.return_value = response
                if valid:
                    self.assertEqual(smoke.request_under_bin_pressure(12345, "/asset.css"), status)
                else:
                    with self.assertRaises(AssertionError):
                        smoke.request_under_bin_pressure(12345, "/asset.css")
                constructor.assert_called_once_with("127.0.0.1", 12345, timeout=3)
                response.read.assert_called_once_with(4097)
                connection.close.assert_called_once()

    def test_policy_restart_requires_both_checkpoint_entries(self):
        with tempfile.TemporaryDirectory() as directory:
            index = Path(directory) / "index"
            self.assertFalse(smoke.policy_checkpoint_ready(index))
            entry = b"identity\t0\t0\t100\t1\n"
            for contents, expected in (
                (b"FLUXHEIM-STORAGE-BIN-INDEX-v1\n" + entry, False),
                (b"FLUXHEIM-STORAGE-BIN-INDEX-v1\n" + entry * 2, True),
                (b"wrong-version\n" + entry * 2, False),
                (b"FLUXHEIM-STORAGE-BIN-INDEX-v1\ninvalid\ninvalid\n", False),
            ):
                index.write_bytes(contents)
                self.assertEqual(smoke.policy_checkpoint_ready(index), expected)

    def test_matrix_requires_disk_and_private_authenticated_admin(self):
        for backend in ("filesystem", "storage-bin"):
            for memory in (False, True):
                for encrypted in (False, True):
                    config = tomllib.loads(smoke.source_for(12345, 12346, 12347, backend, memory, encrypted))
                    cache = config["vhosts"][0]["cache"]
                    self.assertTrue(cache["disk"]["enabled"])
                    self.assertEqual(cache["disk"]["backend"], backend)
                    if backend == "storage-bin":
                        self.assertEqual(cache["disk"]["storage_bin"]["max_open_bins"], 1)
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
