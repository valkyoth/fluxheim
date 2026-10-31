#!/usr/bin/env python3
"""Keep the tracing option inventory and executable example honest."""
import re
import tomllib
import unittest

from smoke_tracing_examples import EXAMPLE, MISSING_ATTRIBUTES, ROOT, check_native_attributes, spans


class TracingGuideTests(unittest.TestCase):
    def test_complete_recipe_has_deliberate_loopback_trust(self):
        value = tomllib.loads(EXAMPLE.read_text())
        self.assertEqual(value["server"]["trusted_proxies"], ["127.0.0.1"])
        self.assertEqual(value["server"]["listen"], ["127.0.0.1:8080"])
        self.assertEqual(value["tracing"]["otlp"]["endpoint"], "http://127.0.0.1:4318/v1/traces")
        self.assertTrue(value["metrics"]["require_loopback"])
        self.assertNotIn("admin", value)

    def test_all_eleven_options_have_a_reference_row(self):
        source = (ROOT / "crates/fluxheim-config/src/config_observability.rs").read_text()
        guide = (ROOT / "docs/guides/opentelemetry-tracing.md").read_text()
        count = 0
        for struct, prefix in [("TracingConfig", "tracing"), ("OtlpTraceExportConfig", "tracing.otlp")]:
            body = source.split(f"pub struct {struct} {{", 1)[1].split("\n}", 1)[0]
            for field in re.findall(r"pub (\w+):", body):
                if field != "otlp":
                    self.assertIn(f"| `{prefix}.{field}` |", guide)
                    count += 1
        self.assertEqual(count, 11)

    def test_native_attribute_characterization_cannot_silently_become_stale(self):
        span = {"name": "HTTP request", "attributes": [{"key": "fluxheim.vhost", "value": {"stringValue": ""}}]}
        check_native_attributes(span)
        for name in MISSING_ATTRIBUTES:
            with self.assertRaises(AssertionError):
                check_native_attributes({**span, "attributes": span["attributes"] + [{"key": name, "value": {}}]})
        self.assertEqual(spans([{"resourceSpans": [{"scopeSpans": [{"spans": [span]}]}]}]), [span])



if __name__ == "__main__":
    unittest.main()
