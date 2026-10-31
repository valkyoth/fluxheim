#!/usr/bin/env python3
"""Check documented panels, signal paths and the outstanding alert/dashboard gaps."""
import json
from pathlib import Path
import tempfile
import unittest

import collector_configs
from collector_stack import ASSETS, ROOT
from generate_observability_dashboards import PANELS, grafana, signoz
from smoke_collector_guide import HEALTH, exported_names


class CollectorGuideTests(unittest.TestCase):
    def test_all_seventeen_panels_are_explained(self):
        guide = (ROOT / "docs/guides/collector-integrations.md").read_text()
        self.assertEqual(len(PANELS), 17)
        for title, _, _ in PANELS:
            self.assertIn(f"| {title} |", guide)

    def test_exporter_panel_still_queries_local_only_health(self):
        # Characterize the present signal-path contract, without overstating coverage.
        for dashboard in (grafana(), signoz()):
            self.assertIn(HEALTH, json.dumps(dashboard))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            collector_configs.collector(root, signoz=True)
            collector_configs.grafana_configs(root, "fixture-not-a-real-credential")
            collector = json.loads((root / "collector.json").read_text())
            prometheus = json.loads((root / "prometheus.json").read_text())
            self.assertEqual(collector["service"]["pipelines"]["metrics"]["receivers"], ["otlp"])
            self.assertEqual({job["job_name"] for job in prometheus["scrape_configs"]},
                             {"fluxheim-scrape", "fluxheim-otlp"})
            self.assertNotIn("rule_files", prometheus)

    def test_wire_name_reader_checks_actual_metrics_not_resource_attributes(self):
        payload = {"resourceMetrics": [{"resource": {"attributes": [{"key": HEALTH}]},
                    "scopeMetrics": [{"metrics": [{"name": "fluxheim_http_requests_total"}]}]}]}
        self.assertEqual(exported_names(payload), {"fluxheim_http_requests_total"})
        with self.assertRaises(KeyError):
            exported_names({"resourceSpans": []})



if __name__ == "__main__":
    unittest.main()
