#!/usr/bin/env python3
"""Keep deferred protocol research separate from the production release gates."""

import json
from pathlib import Path
import tomllib
import unittest

import yaml


ROOT = Path(__file__).resolve().parent.parent
RESEARCH_COMMANDS = (
    "validate_http3_source_lock.py",
    "test_http3_source_lock.py",
    "validate_http3_probe_features.sh",
    "tools/http3-source-probe/Cargo.toml",
    "check_http3_research.sh",
)


def assert_manual_research(test, text):
    workflow = yaml.load(text, Loader=yaml.BaseLoader)
    test.assertEqual(set(workflow["on"]), {"workflow_dispatch"})
    test.assertEqual(workflow["permissions"], {"contents": "read"})
    test.assertIn("sh scripts/check_http3_research.sh", text)


class DevelopmentScopeTests(unittest.TestCase):
    def test_research_workflow_is_manual_and_read_only(self):
        assert_manual_research(
            self, (ROOT / ".github/workflows/http3-research.yml").read_text()
        )

    def test_automatic_trigger_is_rejected(self):
        source = (ROOT / ".github/workflows/http3-research.yml").read_text()
        for trigger in ("push", "pull_request", "schedule", "workflow_call"):
            with self.subTest(trigger=trigger), self.assertRaises(AssertionError):
                assert_manual_research(
                    self, source.replace("  workflow_dispatch:", f"  {trigger}:\n  workflow_dispatch:")
                )

    def test_normal_workflows_do_not_run_research(self):
        for path in (ROOT / ".github/workflows").glob("*.yml"):
            if path.name == "http3-research.yml":
                continue
            source = path.read_text()
            for command in RESEARCH_COMMANDS:
                with self.subTest(path=path.name, command=command):
                    self.assertNotIn(command, source)

    def test_normal_local_checks_do_not_run_research(self):
        source = (ROOT / "scripts/checks.sh").read_text()
        for command in RESEARCH_COMMANDS:
            self.assertNotIn(command, source)

    def test_production_graph_has_no_deferred_protocol_or_crypto(self):
        lock = tomllib.loads((ROOT / "Cargo.lock").read_text())
        names = {package["name"] for package in lock["package"]}
        self.assertFalse(names & {"quinn", "quinn-proto", "h3", "h3-quinn", "brynja", "vef"})
        root = tomllib.loads((ROOT / "Cargo.toml").read_text())
        self.assertNotIn("tools/http3-source-probe", root["workspace"]["members"])

    def test_historical_toolchain_and_unresolved_gate_are_preserved(self):
        contract = json.loads((ROOT / "docs/evidence/http3-source-lock.json").read_text())
        probe = ROOT / "tools/http3-source-probe"
        toolchain = tomllib.loads((probe / "rust-toolchain.toml").read_text())
        self.assertEqual(toolchain["toolchain"]["channel"], contract["rust"])
        self.assertEqual(contract["address_policy_evidence"], "blocked-api-gap")
        script = (ROOT / "scripts/check_http3_research.sh").read_text()
        self.assertIn(f"cargo +{contract['rust']} test --locked", script)
        self.assertIn("--no-default-features --features aws-lc", script)
        self.assertIn("cargo deny", script)

    def test_active_plan_and_release_metadata_agree(self):
        manifest = tomllib.loads((ROOT / "Cargo.toml").read_text())
        self.assertEqual(manifest["package"]["version"], "1.9.0")
        for relative in ("README.md", "ROADMAP.md", "docs/roadmap/versioning-plan.md",
                         "release-notes/RELEASE_NOTES_1.9.0.md"):
            with self.subTest(path=relative):
                text = (ROOT / relative).read_text()
                self.assertIn("observability-commit-plan.md", text)
                self.assertIn("deferred", text.lower())


if __name__ == "__main__":
    unittest.main()
