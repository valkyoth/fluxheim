#!/usr/bin/env python3
"""Pin guide completeness and the bounded live proof's sample matching."""
import re
import tomllib
import unittest

from smoke_metrics_examples import EXAMPLE, MAX_RESPONSE, ROOT, samples


class MetricsGuideTests(unittest.TestCase):
    def test_recipe_requires_private_token_and_loopback(self):
        config = tomllib.loads(EXAMPLE.read_text())
        self.assertEqual(config["metrics"], {"enabled": True, "listen": "127.0.0.1:9091",
                                          "require_loopback": True, "token_file": "metrics-token"})
        self.assertEqual(config["server"]["listen"], ["127.0.0.1:8080"])
        self.assertFalse({"admin", "tracing"} & config.keys())
        self.assertEqual(config["vhosts"][0]["routes"][0]["proxy"]["upstreams"], ["127.0.0.1:9001"])

    def test_documented_table_covers_all_twelve_fields(self):
        source = (ROOT / "crates/fluxheim-config/src/config_observability.rs").read_text()
        guide = (ROOT / "docs/guides/metrics.md").read_text()
        count = 0
        for struct, prefix in [("MetricsConfig", "metrics"), ("MetricsOtlpExportConfig", "metrics.otlp")]:
            body = source.split(f"pub struct {struct} {{", 1)[1].split("\n}", 1)[0]
            for field in re.findall(r"pub (\w+):", body):
                if field != "otlp":
                    self.assertIn(f"| `{prefix}.{field}` |", guide)
                    count += 1
        self.assertEqual(count, 12)

    def test_samples_match_only_exact_family_not_help_or_buckets(self):
        text = '# HELP requests comment\nrequests{method="GET"} 2\nrequests 3\nrequests_extra 99\nrequests_bucket 100\n'
        self.assertEqual(samples(text, "requests"), [2, 3])
        self.assertEqual(samples(text, "absent"), [])
        self.assertEqual(samples("requests{method=\"POST\"} 1e+3\n", "requests"), [1000])
        self.assertLessEqual(MAX_RESPONSE, 2 * 1024 * 1024)



if __name__ == "__main__":
    unittest.main()
