#!/usr/bin/env python3
"""Keep privacy examples and their stated boundaries aligned with the code."""
from pathlib import Path
import re
import tempfile
import tomllib
import unittest
from unittest.mock import Mock, patch

import smoke_privacy_examples as smoke


class PrivacyGuideTests(unittest.TestCase):
    def test_non_listener_accepts_refusal_or_timeout_but_not_success_or_other_errors(self):
        for error in (ConnectionRefusedError(), TimeoutError()):
            with patch.object(smoke.socket, "create_connection", side_effect=error) as connect:
                smoke.assert_no_listener(12345)
                connect.assert_called_once_with(("127.0.0.1", 12345), timeout=1)
        with patch.object(smoke.socket, "create_connection", side_effect=PermissionError()):
            with self.assertRaises(PermissionError):
                smoke.assert_no_listener(12345)
        stream = Mock()
        with patch.object(smoke.socket, "create_connection", return_value=stream):
            with self.assertRaises(AssertionError):
                smoke.assert_no_listener(12345)
        stream.close.assert_called_once_with()

    def test_local_example_has_no_proposed_privacy_schema_or_enabled_collectors(self):
        config = tomllib.loads(smoke.EXAMPLE.read_text())
        self.assertNotIn("privacy", config)
        self.assertEqual(config["server"]["listen"], ["127.0.0.1:8080"])
        for section in ("cache", "metrics", "tracing", "admin"):
            self.assertFalse(config[section]["enabled"])
        self.assertFalse(config["logging"]["access"]["enabled"])
        self.assertFalse(config["logging"]["access"]["request_id"])
        self.assertFalse(config["logging"]["file"]["enabled"])
        self.assertEqual(config["vhosts"][0]["web"]["cache_control"], "no-store")
        self.assertEqual(config["vhosts"][1]["proxy"]["upstream"], "127.0.0.1:3000")

    def test_header_inventory_matches_runtime_and_guide(self):
        source = (smoke.ROOT / "crates/fluxheim-headers/src/lib.rs").read_text()
        values = source.split("pub const SPOOFABLE_CLIENT_IP_HEADERS:", 1)[1].split("];", 1)[0]
        names = set(re.findall(r'"([a-z-]+)"', values))
        self.assertEqual(names, set(smoke.STRIPPED))
        guide = (smoke.ROOT / "docs/guides/zero-retention-privacy-mode.md").read_text()
        for name in names:
            self.assertIn(f"`{name}`", guide)

    def test_log_checker_rejects_canaries_access_events_and_large_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "output"
            for contents in (smoke.CANARY, '{"data":{"kind":"access"}}\n', "x" * (1024 * 1024 + 1)):
                path.write_text(contents)
                with self.assertRaises(AssertionError):
                    smoke.check_log(path)
            path.write_text('{"data":{"kind":"audit"},"correlation":{}}\n')
            self.assertEqual(len(smoke.check_log(path)), 1)

    def test_guide_does_not_claim_total_retention_prevention(self):
        guide = (smoke.ROOT / "docs/guides/zero-retention-privacy-mode.md").read_text()
        for boundary in ("not an anonymity service", "not removed from the binary",
                         "not a general", "not secure erasure", "not automatically removed",
                         "HMAC authentication does not encrypt", "not silence",
                         "not all", "no metrics listener"):
            self.assertIn(boundary, guide)
        self.assertNotIn("[privacy]\nenabled = true", guide)



if __name__ == "__main__":
    unittest.main()
