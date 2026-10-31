#!/usr/bin/env python3
"""Guard the exact guide recipe, bounded fields and live-smoke parser."""
import json
import re
from pathlib import Path
import tempfile
import tomllib
import unittest
from unittest.mock import Mock, patch

from smoke_logging_examples import ACCESS_KEYS, EXAMPLE, INCLUDES, ROOT, access_records, has_complete_access, replace_once, wait_for_connection


class LoggingGuideTests(unittest.TestCase):
    def test_readiness_retries_only_connection_refusal_and_timeout(self):
        process, client, stderr = Mock(), Mock(), Mock()
        process.poll.return_value = None
        client.connect.side_effect = [ConnectionRefusedError(), TimeoutError(), None]
        with patch("smoke_logging_examples.time.sleep"):
            wait_for_connection(process, client, stderr)
        self.assertEqual(client.connect.call_count, 3)
        client.request.assert_not_called()
        client.getresponse.assert_not_called()

    def test_readiness_stops_at_deadline(self):
        process, client = Mock(), Mock()
        process.poll.return_value = None
        client.connect.side_effect = TimeoutError()
        with patch("smoke_logging_examples.time.monotonic", side_effect=[0, 0, 16]), \
                patch("smoke_logging_examples.time.sleep"):
            with self.assertRaisesRegex(AssertionError, "did not listen"):
                wait_for_connection(process, client, Mock())
        client.connect.assert_called_once()

    def test_readiness_fails_on_child_exit(self):
        process, client, stderr = Mock(), Mock(), Mock()
        process.poll.return_value = 1
        stderr.read_text.return_value = "fixture stopped"
        with self.assertRaisesRegex(AssertionError, "fixture exited"):
            wait_for_connection(process, client, stderr)
        client.connect.assert_not_called()

    def test_readiness_does_not_hide_other_errors(self):
        process, client = Mock(), Mock()
        process.poll.return_value = None
        client.connect.side_effect = PermissionError()
        with self.assertRaises(PermissionError):
            wait_for_connection(process, client, Mock())
        client.connect.assert_called_once()

    def test_recipe_uses_loopback_and_no_automatic_admin_or_export(self):
        config = tomllib.loads(EXAMPLE.read_text())
        self.assertEqual(config["server"]["listen"], ["127.0.0.1:8080"])
        self.assertEqual(config["server"]["trusted_proxies"], [])
        self.assertEqual(config["logging"]["format"], "json")
        self.assertFalse(config["logging"]["file"]["enabled"])
        self.assertTrue(config["logging"]["access"]["enabled"])
        self.assertFalse({"admin", "metrics", "tracing"} & config.keys())
        for name in INCLUDES:
            self.assertTrue(config["logging"]["access"][f"include_{name}"])

    def test_documented_options_cover_configuration_structs(self):
        source = (ROOT / "crates/fluxheim-config/src/config_logging.rs").read_text()
        guide = (ROOT / "docs/guides/logging.md").read_text()
        count = 0
        for struct, prefix in [("LoggingConfig", "logging"), ("LoggingFileConfig", "logging.file"),
                               ("AccessLoggingConfig", "logging.access")]:
            body = source.split(f"pub struct {struct} {{", 1)[1].split("\n}", 1)[0]
            for field in re.findall(r"pub (\w+):", body):
                if struct == "LoggingConfig" and field in {"access", "file"}:
                    continue
                self.assertIn(f"| `{prefix}.{field}` |", guide)
                count += 1
        self.assertEqual(count, 16)

    def test_live_parser_distinguishes_typed_json_text_and_legacy(self):
        event = {"schema_version": 1, "data": {"kind": "access"}}
        encoded = json.dumps(event)
        for content in [encoded + "\n", "INFO access " + encoded + "\n"]:
            self.assertEqual(access_records(content), [event])
        self.assertEqual(access_records('{"message":"legacy"}\n'), [])
        self.assertEqual(access_records('{"data":{"kind":"security"}}\n'), [])
        with self.assertRaises(json.JSONDecodeError):
            access_records('INFO access {"data":')


    def test_worker_readiness_waits_for_complete_record(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "events.log"
            self.assertFalse(has_complete_access(path))
            path.write_text('{"data":{"kind":"access"}}')
            self.assertFalse(has_complete_access(path))
            path.write_text('{"data":{"kind":"access"}}\n')
            self.assertTrue(has_complete_access(path))

    def test_fixture_substitution_fails_on_missing_or_ambiguous_marker(self):
        self.assertEqual(replace_once("one", "one", "two"), "two")
        for source in ["", "one one"]:
            with self.assertRaises(ValueError):
                replace_once(source, "one", "two")


if __name__ == "__main__":
    unittest.main()
