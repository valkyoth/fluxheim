#!/usr/bin/env python3
"""Check the slice qualification fixtures without starting a server."""

import tomllib
import unittest
import http.client

import smoke_slice_storage as smoke


class SliceStorageTests(unittest.TestCase):
    def test_origin_uses_only_fixed_representation_validators(self):
        with smoke.origin() as (port, count):
            for language in ("en", "sv", "unknown", 'en", "injected', "x" * 512):
                with self.subTest(language=language):
                    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
                    try:
                        connection.request("GET", "/asset.css", headers={
                            "Accept-Language": language, "Range": "bytes=2-5",
                        })
                        response = connection.getresponse()
                        self.assertEqual(response.status, 206)
                        self.assertEqual(response.getheader("ETag"), '"en-v1"' if language == "en" else '"sv-v1"')
                        self.assertEqual(response.getheader("Content-Range"), "bytes 2-5/8")
                        self.assertEqual(response.read(4097), b"2345" if language == "en" else b"cdef")
                    finally:
                        connection.close()
            self.assertEqual(count(), 5)

    def test_origin_never_reflects_folded_request_header(self):
        with smoke.origin() as (port, count):
            connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
            try:
                connection.request("GET", "/asset.css", headers={
                    "Accept-Language": "en\r\n\tX-Injected: true",
                })
                response = connection.getresponse()
                self.assertEqual(response.status, 200)
                self.assertEqual(response.getheader("ETag"), '"sv-v1"')
                self.assertIsNone(response.getheader("X-Injected"))
                self.assertTrue(all("\r" not in value and "\n" not in value for _, value in response.getheaders()))
                self.assertEqual(response.read(4097), b"abcdefgh")
            finally:
                connection.close()
            self.assertEqual(count(), 1)

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
