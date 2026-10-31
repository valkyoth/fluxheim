#!/usr/bin/env python3
"""Check shipped core limits; opt in to a real user-systemd limit test."""

import configparser
import os
from pathlib import Path
import re
import subprocess
import unittest

import yaml

from smoke_container_refresh import check_core_limit


ROOT = Path(__file__).resolve().parents[1]
UNITS = ("fluxheim.service", "fluxheim-acme.service")
GUIDES = ("build-and-podman.md", "certificate-renewal.md", "release-runbook.md")


def service_limit(name):
    unit = configparser.ConfigParser(interpolation=None)
    unit.read(ROOT / "packaging/systemd" / name)
    return unit["Service"]["LimitCORE"]


class CoreDumpPolicyTests(unittest.TestCase):
    def check_compose(self, document):
        services = document.get("services", {})
        checked = 0
        for name, service in services.items():
            if name in {"fluxheim", "fluxheim-acme"}:
                with self.subTest(service=name):
                    self.assertEqual(service["ulimits"]["core"], {"soft": 0, "hard": 0})
                checked += 1
        return checked

    def test_both_packaged_services_disable_soft_and_hard_core_limits(self):
        for name in UNITS:
            with self.subTest(unit=name):
                # A single systemd LimitCORE value sets both limits.
                self.assertEqual(service_limit(name), "0")

    def test_compose_examples_include_gateway_and_companion_limits(self):
        checked = 0
        for name in ("podman-compose.yml", "podman-compose-acme.yml"):
            with self.subTest(example=name):
                checked += self.check_compose(yaml.safe_load((ROOT / "examples" / name).read_text()))
        self.assertEqual(checked, 3)

    def test_documented_compose_and_run_commands_keep_limits(self):
        checked = 0
        for name in GUIDES:
            text = (ROOT / "docs/guides" / name).read_text()
            commands = 0
            for block in re.findall(r"```yaml\n(.*?)```", text, re.S):
                checked += self.check_compose(yaml.safe_load(block))
            for line in text.splitlines():
                if line.startswith("podman run "):
                    self.assertIn("--ulimit core=0:0", line, name)
                    commands += 1
            # Each guide still has a direct-run example; duplicated ACME
            # recipes need not be retained just to satisfy a global count.
            self.assertGreater(commands, 0, name)
        self.assertEqual(checked, 3)

    def test_live_limit_parser_rejects_missing_nonzero_or_unlimited_limits(self):
        check_core_limit("Max core file size        0          0          bytes\n")
        for soft, hard in (("0", "unlimited"), ("1", "0"), ("1", "1"), ("unlimited", "unlimited")):
            with self.subTest(soft=soft, hard=hard), self.assertRaises(ValueError):
                check_core_limit(f"Max core file size   {soft}   {hard}   bytes\n")
        for output in ("", "Max file size 0 0 bytes", "Max core file size 0 0"):
            with self.subTest(output=output), self.assertRaises(ValueError):
                check_core_limit(output)

    @unittest.skipUnless(os.environ.get("FLUXHEIM_TEST_SYSTEMD") == "1",
                         "set FLUXHEIM_TEST_SYSTEMD=1 for a real user-systemd service")
    def test_effective_systemd_limits(self):
        for name in UNITS:
            with self.subTest(unit=name):
                # Exercise each shipped setting through the service manager,
                # without starting production services or changing host policy.
                subprocess.run([
                    "systemd-run", "--user", "--wait", "--pipe", "--collect",
                    "--property", f"LimitCORE={service_limit(name)}",
                    "--", "/usr/bin/python3", "-c",
                    "import resource; limits = resource.getrlimit(resource.RLIMIT_CORE); "
                    "print(limits); assert limits == (0, 0), limits",
                ], check=True, timeout=30)


if __name__ == "__main__":
    unittest.main()
