#!/usr/bin/env python3
"""Keep runnable cache guide templates aligned with the live harness."""

import tomllib
import socket
import unittest
import tempfile
from contextlib import nullcontext
from unittest.mock import mock_open, patch
from pathlib import Path

import smoke_cache_examples as smoke
import smoke_cache_operations as operations
import test_cache_lifecycle


def load_tests(loader, tests, _pattern):
    tests.addTests(loader.loadTestsFromModule(test_cache_lifecycle))
    return tests


class CacheGuideTests(unittest.TestCase):
    def test_origin_language_header_uses_only_fixed_fixture_values(self):
        cases = (
            (b"", b"none"),
            (b"Accept-Language: en\r\n", b"en"),
            (b"Accept-Language: sv\r\n", b"sv"),
            (b"Accept-Language: unrecognized\r\n", b"none"),
            (b"Accept-Language: en, sv\r\n", b"none"),
            (b"Accept-Language: en\r\nAccept-Language: sv\r\n", b"none"),
            (b"Accept-Language: en\r\n X-Injected: marker\r\n", b"none"),
            (b"Accept-Language: en\n\tX-Injected: marker\r\n", b"none"),
        )
        with smoke.origin_server() as (port, count):
            for headers, expected in cases:
                with self.subTest(headers=headers):
                    with socket.create_connection(("127.0.0.1", port), timeout=3) as connection:
                        connection.sendall(b"GET /variant.css HTTP/1.0\r\nHost: cache.test\r\n"
                                           + headers + b"\r\n")
                        response = bytearray()
                        while chunk := connection.recv(4096):
                            response.extend(chunk)
                            self.assertLessEqual(len(response), 16384)
                    head, body = bytes(response).split(b"\r\n\r\n", 1)
                    self.assertTrue(head.startswith(b"HTTP/1.0 200 "))
                    self.assertIn(b"Vary: Accept-Language", head.split(b"\r\n"))
                    language = [line for line in head.split(b"\r\n")
                                if line.startswith(b"Content-Language:")]
                    self.assertEqual(language, [b"Content-Language: " + expected])
                    self.assertNotIn(b"X-Injected", head)
                    self.assertEqual(body, smoke.BODY)
            self.assertEqual(count("/variant.css"), len(cases))

    def test_admin_fixture_uses_platform_private_directory_before_writing(self):
        with patch.object(operations, "private_fixture", side_effect=RuntimeError("ACL setup failed")) as private, \
                patch.object(operations, "origin_server") as origin, self.assertRaisesRegex(RuntimeError, "ACL setup failed"):
            operations.run_case(Path("fixture"), "memory")
        private.assert_called_once_with(Path("fixture"))
        origin.assert_not_called()

    def test_admin_fixture_protects_each_cache_parent_before_creating_credentials(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch.object(operations, "private_fixture", return_value=nullcontext(directory)), \
                    patch.object(operations, "origin_server", return_value=nullcontext((12345, None))), \
                    patch.object(operations, "protect_directory", side_effect=[None, RuntimeError("child ACL")]) as protect, \
                    self.assertRaisesRegex(RuntimeError, "child ACL"):
                operations.run_case(root, "filesystem")
            self.assertEqual([call.args[0] for call in protect.call_args_list],
                             [root / "state", root / "state/cache"])
            self.assertFalse((root / "control-token").exists())

    def test_inspection_matrix_keeps_cache_scopes_and_encryption_explicit(self):
        for named in (False, True):
            for backend in ("filesystem", "storage-bin"):
                for disk_only in (False, True):
                    source = smoke.inspection_configuration(smoke.prepare(12345, 12346, backend, disk_only), named, True)
                    config = tomllib.loads(source)
                    scope = config["vhosts"][0] if named else config
                    self.assertEqual(scope["cache"]["memory"]["enabled"], not disk_only)
                    self.assertEqual(scope["cache"]["disk"]["backend"], backend)
                    self.assertEqual(scope["cache"]["disk"]["encryption"]["key_file"], "cache-key")
                    self.assertEqual(scope["proxy"]["upstreams"], ["127.0.0.1:12346"])
                    if named:
                        self.assertNotIn("cache", config)

    def test_storage_checkpoint_retries_transient_sharing_denial(self):
        reader = mock_open(read_data=b"/asset.css".hex().encode("ascii"))
        with patch.object(Path, "open", side_effect=[PermissionError("sharing"), reader.return_value]), \
                patch.object(smoke.time, "sleep"):
            smoke.wait_for_storage_index(Path("fixture"))

    def test_encrypted_checkpoint_requires_all_six_warmed_entries(self):
        header = b"FLUXHEIM-STORAGE-BIN-INDEX-v1\n"
        entry = b"012345\t0\t0\t10\t1\n"
        with patch.object(Path, "open", mock_open(read_data=header + entry * 6)):
            smoke.wait_for_storage_index(Path("fixture"), encrypted=True)
        with patch.object(Path, "open", mock_open(read_data=header + entry * 5)), \
                patch.object(smoke.time, "monotonic", side_effect=[0, 0, 11]), \
                patch.object(smoke.time, "sleep"), self.assertRaises(AssertionError):
            smoke.wait_for_storage_index(Path("fixture"), encrypted=True)

    def test_storage_checkpoint_wait_requires_the_asset_and_is_bounded(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            index = root / ".fluxheim-storage-bin-index-v1"
            index.write_bytes(b"/asset.css".hex().encode("ascii"))
            smoke.wait_for_storage_index(root)
            index.write_bytes(b"/different.css".hex().encode("ascii"))
            with patch.object(smoke.time, "monotonic", side_effect=[0, 0, 11]), \
                    patch.object(smoke.time, "sleep"), self.assertRaises(AssertionError):
                smoke.wait_for_storage_index(root)

    def test_backend_reference_separates_native_storage_and_history(self):
        root = Path(__file__).resolve().parents[1]
        guide = (root / "docs/guides/cache-backends.md").read_text()
        current, history = guide.split("## Historical Memory Cache Evaluation", 1)
        prose = " ".join(current.replace("**", "").split())
        for boundary in ("not a precise measurement", "not the disk backend's access-time LRU",
                         "not a filesystem quota", "not enforced", "local/static caching requires memory enabled and disk disabled",
                         "not proof of disk initialization",
                         "not guaranteed read-only",
                         "instead of treating a header as a storage receipt"):
            self.assertTrue(boundary in prose, f"missing backend boundary: {boundary}")
        self.assertIn("Fixed-slice proxy caching supports memory, disk-only and tiered policies", prose)
        for name in ("HttpCacheDigest", "ForcedFreshness", "CachePut"):
            self.assertNotIn(name, current)
            self.assertIn(name, history)
        self.assertIn("not public TOML or CLI", history)
        self.assertNotIn("future admin API", guide)

    def test_backend_reference_uses_existing_recipe_and_recovery_contract(self):
        root = Path(__file__).resolve().parents[1]
        guide = (root / "docs/guides/cache-backends.md").read_text()
        for name in ("local.toml", "filesystem.toml", "storage-bin.toml", "static.toml"):
            self.assertIn(f"../../examples/cache/{name}", guide)
            tomllib.loads((smoke.EXAMPLES / name).read_text())
        self.assertIn("append exactly **one**", guide)
        self.assertIn("new cache root", guide)
        self.assertIn("first-fit", guide)
        self.assertIn("does not compact live objects", guide)
        self.assertIn("one-second debounce", guide)
        self.assertIn("Cache storage is not a durable database", guide)
        operations_guide = (root / "docs/guides/cache-operations.md").read_text()
        self.assertIn("does not undo", operations_guide)
        self.assertIn("not guaranteed read-only", operations_guide)

    def test_unified_reference_keeps_native_cache_limits(self):
        root = Path(__file__).resolve().parents[1]
        reference = (root / "docs/reference/config-reference.md").read_text()
        cache = reference.split("## Cache\n", 1)[1].split("## TLS\n", 1)[0]
        prose = " ".join(cache.split())
        for boundary in ("not a guaranteed LRU table", "not proof of disk initialization",
                         "not `Set-Cookie`", "not a guaranteed read-only preview"):
            self.assertTrue(boundary in prose, f"missing unified cache boundary: {boundary}")
        self.assertNotIn("OriginNotCache", cache)
        self.assertNotIn("ResponseTooLarge", cache)
        self.assertNotIn("stale purges rotate scanned fresh entries", cache)

    def test_admin_fixture_is_loopback_authenticated_and_single_tier(self):
        for backend in ("memory", "filesystem", "storage-bin"):
            rendered = tomllib.loads(operations.configuration(12345, 12346, 12347, backend))
            self.assertFalse(rendered["cache"]["enabled"])
            self.assertEqual(rendered["logging"]["level"], "info")
            self.assertEqual(rendered["admin"]["listen"], "127.0.0.1:12347")
            self.assertTrue(rendered["admin"]["require_loopback"])
            self.assertEqual(rendered["admin"]["token_file"], "control-token")
            self.assertEqual(rendered["admin"]["operational_token_file"], "observer-token")
            cache = rendered["vhosts"][0]["cache"]
            self.assertEqual(cache["memory"]["enabled"], backend == "memory")
            self.assertEqual(cache["disk"]["enabled"], backend != "memory")
        with self.assertRaises(ValueError):
            operations.configuration(12345, 12346, 12347, "../untrusted")

    def test_memory_template_preserves_public_content_boundary(self):
        original = tomllib.loads((smoke.EXAMPLES / "local.toml").read_text())
        rendered = tomllib.loads(smoke.prepare(12345, 12346))
        self.assertEqual(rendered["cache"], original["cache"])
        self.assertEqual(rendered["server"]["listen"], ["127.0.0.1:12345"])
        self.assertEqual(rendered["proxy"]["upstreams"], ["127.0.0.1:12346"])
        self.assertEqual(rendered["cache"]["bypass_request_headers"], ["cookie"])
        self.assertTrue(rendered["cache"]["include_query"])
        self.assertFalse(rendered["logging"]["access"]["enabled"])

    def test_disk_examples_preserve_backend_options(self):
        for backend in ("filesystem", "storage-bin"):
            fragment = tomllib.loads((smoke.EXAMPLES / f"{backend}.toml").read_text())
            for disk_only in (False, True):
                rendered = tomllib.loads(smoke.prepare(12345, 12346, backend, disk_only))
                self.assertEqual(rendered["cache"]["disk"], fragment["cache"]["disk"])
                self.assertEqual(rendered["cache"]["memory"]["enabled"], not disk_only)
                self.assertEqual(rendered["cache"]["status_ttls"], {"200": 120})

    def test_static_is_an_independent_memory_only_recipe(self):
        rendered = tomllib.loads(smoke.prepare(12345, 12346, static=True))
        self.assertNotIn("proxy", rendered)
        self.assertEqual(rendered["web"]["root"], "site")
        self.assertTrue(rendered["cache"]["local_static"])
        self.assertFalse(rendered["cache"]["disk"]["enabled"])

    def test_operations_overlay_preserves_root_cache_policy(self):
        root = tomllib.loads(smoke.prepare(12345, 12346, "filesystem"))
        rendered = tomllib.loads(smoke.prepare(12345, 12346, "filesystem", operations=True))
        self.assertEqual(root["cache"], rendered["cache"])
        self.assertEqual(rendered["vhosts"][0]["name"], "assets")
        self.assertEqual(rendered["vhosts"][0]["hosts"], ["cache.test"])
        self.assertEqual(rendered["vhosts"][0]["proxy"]["upstreams"], ["127.0.0.1:12346"])
        self.assertTrue(rendered["vhosts"][0]["cache"]["enabled"])
        self.assertEqual(rendered["vhosts"][0]["cache"]["disk"], root["cache"]["disk"])

    def test_renderer_rejects_unsupported_combinations_and_template_drift(self):
        for options in ({"backend": "../local"}, {"disk_only": True},
                        {"static": True, "backend": "filesystem"},
                        {"static": True, "operations": True}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                smoke.prepare(12345, 12346, **options)
        for text in ("missing", "needle needle"):
            with self.assertRaises(ValueError):
                smoke.replace_once(text, "needle", "replacement")


if __name__ == "__main__":
    unittest.main()
