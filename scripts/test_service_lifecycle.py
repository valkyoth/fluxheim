#!/usr/bin/env python3
"""Keep process recipes and current packaging limitations explicit."""

from pathlib import Path
import re
import tomllib
import unittest
from unittest.mock import patch

from smoke_service_lifecycle import EXAMPLE, child_environment, prepare

ROOT = Path(__file__).resolve().parents[1]


class ServiceLifecycleTests(unittest.TestCase):
    def test_recipe_and_characterization_keep_private_paths(self):
        for inactive in (False, True):
            config = tomllib.loads(prepare(EXAMPLE.read_text(), 54321, inactive=inactive))
            self.assertEqual(config["server"]["listen"], ["127.0.0.1:54321"])
            process = config["server"]["process"]
            self.assertEqual(process["graceful_shutdown_timeout_seconds"], 1)
            for field in ("pid_file", "upgrade_sock", "certificate_reload_sock"):
                self.assertEqual(Path(process[field]).parent, Path("."))
            self.assertEqual(process.get("daemon", False), inactive)
            self.assertFalse(config["cache"]["enabled"])
            self.assertEqual(config["vhosts"][0]["web"]["root"], "site")

    def test_listener_and_timeout_drift_rejected(self):
        original = EXAMPLE.read_text()
        for source in (original.replace("127.0.0.1:8080", "0.0.0.0:8080"),
                       original.replace("graceful_shutdown_timeout_seconds = 5",
                                        "graceful_shutdown_timeout_seconds = 4")):
            with self.assertRaises(ValueError):
                prepare(source, 54321)

    def test_child_does_not_inherit_supervisor_metadata(self):
        values = {"LISTEN_PID": "123", "LISTEN_FDS": "1", "LISTEN_FDS_FIRST_FD": "9",
                  "NOTIFY_SOCKET": "/wrong", "FLUXHEIM_CONFIG": "/wrong",
                  "RUST_LOG": "off", "PATH": "/usr/bin"}
        with patch.dict("os.environ", values, clear=True):
            environment = child_environment("fixture")
            self.assertEqual(environment, {"PATH": "/usr/bin", "NOTIFY_SOCKET": "@fixture"})

    def test_guide_covers_every_process_field(self):
        source = (ROOT / "crates/fluxheim-config/src/config_server.rs").read_text()
        fields = re.findall(r"pub (\w+):", source.split("pub struct ServerProcessConfig {", 1)[1]
                            .split("\n}", 1)[0])
        self.assertEqual(len(fields), 12)
        guide = (ROOT / "docs/guides/service-lifecycle.md").read_text()
        for field in fields:
            self.assertIn(f"| `{field}` |", guide)
        for requirement in ("not a total process-exit deadline",
                            "CTRL_BREAK", "SIGHUP", "exit status zero"):
            self.assertIn(requirement, guide)

    def test_current_unit_budget_has_no_default_drain_margin(self):
        # Characterize the packaged service budget without claiming a drain margin.
        unit = (ROOT / "packaging/systemd/fluxheim.service").read_text()
        runtime = (ROOT / "src/runtime_shutdown.rs").read_text()
        stop = int(re.search(r"^TimeoutStopSec=(\d+)s$", unit, re.MULTILINE)[1])
        drain = int(re.search(r"DEFAULT_GRACEFUL_SHUTDOWN_TIMEOUT_SECONDS: u64 = (\d+)", runtime)[1])
        self.assertEqual(stop, drain)
        self.assertIn("TimeoutStopSec=45s", (ROOT / "docs/guides/systemd.md").read_text())


if __name__ == "__main__":
    unittest.main()
