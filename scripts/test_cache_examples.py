#!/usr/bin/env python3
"""Keep runnable cache guide templates aligned with the live harness."""

import tomllib
import unittest
from pathlib import Path

import smoke_cache_examples as smoke
import smoke_cache_operations as operations


class CacheGuideTests(unittest.TestCase):
    def test_backend_reference_separates_native_storage_and_history(self):
        root = Path(__file__).resolve().parents[1]
        guide = (root / "docs/guides/cache-backends.md").read_text()
        current, history = guide.split("## Historical Memory Cache Evaluation", 1)
        prose = " ".join(current.replace("**", "").split())
        for boundary in ("not a precise measurement", "not the disk backend's access-time LRU",
                         "not a filesystem quota", "not enforced", "currently memory-only",
                         "not proof that its configured disk tier initialized",
                         "not guaranteed read-only",
                         "instead of treating a header as a storage receipt"):
            self.assertTrue(boundary in prose, f"missing backend boundary: {boundary}")
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
