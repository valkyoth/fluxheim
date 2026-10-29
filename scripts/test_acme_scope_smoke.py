#!/usr/bin/env python3
"""Regression checks for the local-only ACME qualification harness."""
import json
from pathlib import Path
import subprocess
import tempfile
import tomllib
import unittest
from unittest.mock import patch

import acme_pebble_frontend as frontend
import smoke_acme_scope as smoke


class AcmeSmokeTests(unittest.TestCase):
    def test_renewal_fixture_keeps_both_reported_requirements(self):
        config = tomllib.loads(smoke.configuration())
        self.assertTrue(config["cache"]["enabled"])
        self.assertEqual(config["vhosts"][0]["php"]["fpm"]["php_fpm_binary"], "/usr/bin/php-fpm")
        self.assertEqual(config["tls"]["acme"]["automation"], "external")
        self.assertEqual(config["tls"]["acme"]["issuers"][0]["directory_url"], "https://localhost:14000/dir")

    def test_gateway_fixture_does_not_enable_background_renewal(self):
        config = tomllib.loads(smoke.configuration(renewal=False))
        self.assertNotIn("php", config["vhosts"][0])
        self.assertNotIn("cache", config)
        self.assertEqual(config["tls"]["acme"]["automation"], "external")

    def test_adapter_changes_only_expected_terms_metadata(self):
        original = {"newOrder": "https://localhost:14000/order-plz", "meta": {
            "termsOfService": frontend.PEBBLE_TERMS, "externalAccountRequired": False}}
        actual = json.loads(frontend.directory_body(json.dumps(original).encode()))
        expected = json.loads(json.dumps(original))
        expected["meta"]["termsOfService"] = frontend.TERMS
        self.assertEqual(actual, expected)

    def test_adapter_rejects_changed_or_missing_terms(self):
        for metadata in ({}, {"termsOfService": "https://unexpected.test"}):
            with self.assertRaises((KeyError, ValueError)):
                frontend.directory_body(json.dumps({"meta": metadata}).encode())

    def test_helpers_use_timeout_and_never_invoke_a_shell(self):
        with patch.object(smoke.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "ok", "")) as run:
            smoke.command(["tool", "literal argument"])
            self.assertEqual(run.call_args.args[0], ["tool", "literal argument"])
            self.assertEqual(run.call_args.kwargs["timeout"], 180)
            self.assertNotIn("shell", run.call_args.kwargs)

    def test_ca_evidence_requires_distinct_challenges_and_success(self):
        attempts = ["Attempting to validate w/ HTTP: http://scope.example.test:5002/"
                    f".well-known/acme-challenge/token_{index}\n" for index in range(4)]
        success = "authz set VALID by completed challenge\n"
        smoke.verify_ca_validations("".join(attempts) + success * 4)
        for logs in ("", attempts[0] * 12 + success * 4,
                     "".join(attempts) + success * 3,
                     "".join(attempts).replace("scope.example.test", "other.test") + success * 4):
            with self.assertRaises(AssertionError):
                smoke.verify_ca_validations(logs)

    def test_unsafe_image_reference_is_rejected_before_execution(self):
        instance = smoke.Smoke.__new__(smoke.Smoke)
        instance.runtime = "podman"
        with patch.object(smoke, "command") as run:
            for value in ("--privileged", "image;command", "image\n", "../ image"):
                with self.assertRaises(ValueError):
                    instance.image(value)
            run.assert_not_called()

    def test_engine_identity_must_be_an_immutable_digest(self):
        instance = smoke.Smoke.__new__(smoke.Smoke)
        instance.runtime = "podman"
        with patch.object(smoke, "command", return_value=subprocess.CompletedProcess([], 0, '[{"Id":"--privileged"}]', "")):
            with self.assertRaises(ValueError):
                instance.image("candidate")

    def test_ca_checks_real_authorizations_and_exposes_only_loopback(self):
        with tempfile.TemporaryDirectory() as temporary:
            instance = smoke.Smoke.__new__(smoke.Smoke)
            instance.runtime = "podman"
            instance.control = Path(temporary)
            instance.prefix = "test"
            instance.names = []
            with patch.object(smoke, "command") as run:
                instance.launch("ca", smoke.PEBBLE, [], ca=True, wait=False)
            arguments = run.call_args.args[0]
            self.assertIn("PEBBLE_AUTHZREUSE=0", arguments)
            self.assertIn("127.0.0.1::14000", arguments)
            self.assertFalse(any("VA_ALWAYS_VALID" in value for value in arguments))
            self.assertIn("65532:65532", arguments)
            self.assertFalse(any(value.endswith(":rw,z") for value in arguments))


if __name__ == "__main__":
    unittest.main()
