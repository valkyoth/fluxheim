#!/usr/bin/env python3
"""Check the slice qualification fixtures without starting a server."""

import tomllib
import unittest

import smoke_slice_storage as smoke


class SliceStorageTests(unittest.TestCase):
    def test_storage_matrix(self):
        for backend in (None, "filesystem", "storage-bin"):
            for disk_only in ((False, True) if backend else (False,)):
                config = tomllib.loads(smoke.configuration(18080, 19001, backend, disk_only, False))
                cache = config["cache"]
                self.assertEqual(cache["memory"]["enabled"], not disk_only)
                self.assertEqual(cache["vary_request_headers"], ["accept-language"])
                self.assertEqual(cache["range"]["slice"], {"enabled": True, "size_bytes": 4, "max_slices": 2})
                self.assertEqual(cache["range"]["max_bytes"], 8)
                if backend:
                    self.assertEqual(cache["disk"]["backend"], backend)
                    self.assertEqual(cache["disk"]["path"], "state/cache")

    def test_container_cache_is_guest_owned(self):
        config = tomllib.loads(smoke.configuration(18080, 19001, "filesystem", True, True))
        self.assertEqual(config["cache"]["disk"]["path"], "/var/cache/fluxheim/slices")
        self.assertTrue(all(path.startswith("/run/fluxheim/") for name, path in config["server"]["process"].items() if name.endswith(("file", "sock"))))

    def test_invalid_backend_rejected(self):
        with self.assertRaises(ValueError):
            smoke.configuration(18080, 19001, "invalid", False, False)
        with self.assertRaises(ValueError):
            smoke.configuration(18080, 19001, None, True, False)


if __name__ == "__main__":
    unittest.main()
