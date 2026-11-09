import tomllib
import unittest
from pathlib import Path

import smoke_cache_error_phase as smoke


class CacheErrorPhaseTests(unittest.TestCase):
    def test_documentation_explains_precedence_and_compatibility(self):
        root = Path(__file__).resolve().parents[1]
        guide = (root / "docs/guides/cache.md").read_text()
        for category in ("connect", "timeout", "read", "write", "tls", "connection-closed", "protocol", "http-status", "other"):
            self.assertIn(f"| `{category}` |", guide)
        for contract in ("read timeout requires `timeout`", "does **not** disable certificate verification", "**Compatibility:**", "expired stale window"):
            self.assertIn(contract, guide)
        for name in ("cache-options.md", "config-reference.md"):
            reference = (root / "docs/reference" / name).read_text()
            self.assertNotIn("never emits `read`", reference)
            self.assertIn("choose-the-failure-categories", reference)

    def test_exact_allowlist_and_separate_status_gate(self):
        for fault in ("connection-closed", "protocol", "timeout", "http-status"):
            for allowed in (False, True):
                config = tomllib.loads(smoke.configuration(18080, 19001, fault, allowed, False))
                self.assertEqual(config["cache"]["stale_if_error_on"], [fault if allowed else "read"])
                self.assertEqual(config["cache"]["stale_if_error_statuses"], [503])
                self.assertEqual(config["cache"]["stale_if_error_secs"], 2)
                self.assertEqual(config["cache"]["status_ttls"], {"200": 1})
                self.assertEqual(config["server"]["listen"], ["127.0.0.1:18080"])

    def test_container_state_is_not_written_into_configuration_mount(self):
        config = tomllib.loads(smoke.configuration(18080, 19001, "protocol", True, True))
        for name in ("pid_file", "upgrade_sock", "certificate_reload_sock"):
            self.assertTrue(config["server"]["process"][name].startswith("/run/fluxheim/"))

    def test_unknown_fault_is_rejected(self):
        with self.assertRaises(ValueError):
            smoke.configuration(18080, 19001, '"\n[server]', True, False)


if __name__ == "__main__":
    unittest.main()
