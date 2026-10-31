#!/usr/bin/env python3
"""Check the CLI guide's fixtures, option inventory and subprocess boundaries."""
from pathlib import Path
import subprocess
import tomllib
import unittest
from unittest.mock import patch

import smoke_cli_examples as smoke


class CliGuideTests(unittest.TestCase):
    def test_fixture_is_local_and_small(self):
        config = tomllib.loads(smoke.EXAMPLE.read_text())
        self.assertEqual(config["server"]["listen"], ["127.0.0.1:8080"])
        self.assertEqual(config["vhosts"][0]["proxy"]["upstream"], "127.0.0.1:18080")
        self.assertFalse(config["cache"]["enabled"])
        self.assertEqual(config["server"]["process"]["threads"], 1)

    def test_help_inventory_rejects_an_undocumented_option(self):
        smoke.documented_options("  -h, --help  Help\n      --config <PATH>  Config\n", "--help --config")
        with self.assertRaises(AssertionError):
            smoke.documented_options("      --new-option <X>\n", "--help")
        with self.assertRaises(AssertionError):
            smoke.documented_options("no option lines", "--help")

    def test_invocation_has_timeout_no_shell_and_clean_config_environment(self):
        result = subprocess.CompletedProcess([], 0, b"ok", b"")
        with patch.dict(smoke.os.environ, {"FlUxHeIm_Config": "not-the-fixture", "Rust_Log": "trace"}), \
                patch.object(smoke.subprocess, "run", return_value=result) as run:
            self.assertEqual(smoke.invoke(Path("trusted"), Path("private"), "--help"), ("ok", ""))
        args, options = run.call_args
        self.assertEqual(args[0], ["trusted", "--help"])
        self.assertEqual(options["timeout"], 20)
        self.assertEqual(options["stdin"], subprocess.DEVNULL)
        self.assertTrue(options["capture_output"])
        self.assertFalse(options.get("shell", False))
        self.assertFalse(any(key.casefold().startswith("fluxheim_") or key.casefold() == "rust_log"
                             for key in options["env"]))

    def test_failure_expectations_are_checked(self):
        result = subprocess.CompletedProcess([], 1, b"", b"expected rejection")
        with patch.object(smoke.subprocess, "run", return_value=result):
            smoke.invoke(Path("trusted"), Path("private"), success=False)
            with self.assertRaises(AssertionError):
                smoke.invoke(Path("trusted"), Path("private"))


    def test_diagnostic_boundaries_are_not_overclaimed(self):
        guide = smoke.GUIDE.read_text()
        for boundary in ("not a dry-run", "not a release feature matrix", "not a sanitized export",
                         "native-runtime-launch-plan-error", "even with", "exact deployed",
                         "no separate DNS deadline", "FLUXHEIM_CONFIG"):
            self.assertIn(boundary, guide)


if __name__ == "__main__":
    unittest.main()
