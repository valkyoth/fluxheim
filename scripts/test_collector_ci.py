#!/usr/bin/env python3
"""Keep the pinned browser driver on its qualified CI operating system."""

import json
from pathlib import Path
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]


class CollectorCiTests(unittest.TestCase):
    def test_browser_job_uses_qualified_runner_and_locked_install(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/ci.yml").read_text())
        job = workflow["jobs"]["collectors"]
        self.assertEqual(job["runs-on"], "ubuntu-24.04",
                         "Requalify the pinned Playwright before changing the runner OS")
        install = next(step for step in job["steps"]
                       if step.get("name") == "Install pinned browser driver")
        self.assertEqual(install["run"].strip().splitlines(), [
            "npm ci --ignore-scripts --prefix tools/collector-browser",
            "tools/collector-browser/node_modules/.bin/playwright install --with-deps chromium",
        ])

    def test_driver_version_matches_both_locked_packages(self):
        directory = ROOT / "tools/collector-browser"
        manifest = json.loads((directory / "package.json").read_text())
        lock = json.loads((directory / "package-lock.json").read_text())["packages"]
        version = manifest["devDependencies"]["playwright"]
        self.assertRegex(version, r"^\d+\.\d+\.\d+$")
        self.assertEqual(lock[""]["devDependencies"]["playwright"], version)
        for name in ("playwright", "playwright-core"):
            self.assertEqual(lock[f"node_modules/{name}"]["version"], version)


if __name__ == "__main__":
    unittest.main()
