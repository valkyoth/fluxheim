#!/usr/bin/env python3
"""Guard the exact guide recipe, bounded fields and live-smoke parser."""
import json
import re
from pathlib import Path
import tempfile
import tomllib
import unittest

from smoke_logging_examples import ACCESS_KEYS, EXAMPLE, INCLUDES, ROOT, access_records, has_complete_access, replace_once


class LoggingGuideTests(unittest.TestCase):
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
