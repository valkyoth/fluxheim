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
    def instance(self, runtime="podman"):
        with patch.object(smoke, "fixtures", return_value=Path("/fixture-input")):
            return smoke.Smoke(runtime, Path("/unused"))

    def test_runtime_is_selected_from_literals_before_fixture_execution(self):
        for runtime in ("podman", "docker"):
            self.assertEqual(self.instance(runtime).runtime, runtime)
        with patch.object(smoke, "fixtures") as fixtures:
            for runtime in ("sh", "/tmp/docker", "docker --privileged", "podman\n"):
                with self.assertRaises(KeyError):
                    smoke.Smoke(runtime, Path("/unused"))
            fixtures.assert_not_called()

    def test_fixture_copy_does_not_preserve_host_owner_or_modify_host_files(self):
        instance = self.instance()
        with patch.object(smoke, "command") as run:
            instance.prepare_state("sha256:" + "a" * 64)
        args = run.call_args.args[0]
        self.assertIn("--network=none", args)
        self.assertIn("--user=0", args)
        self.assertIn("--entrypoint=/bin/cp", args)
        self.assertNotIn("-p", args)
        self.assertNotIn("-a", args)
        self.assertEqual(args[-5:], ["/input/renew.toml", "/input/server.toml",
                                    "/input/cache.toml", "/input/ca.pem", "/control/"])
        host_mounts = [arg for arg in args if arg.startswith("/fixture-input/")]
        self.assertEqual(len(host_mounts), 4)
        self.assertTrue(all(arg.endswith(":ro,z") for arg in host_mounts))
        self.assertEqual(instance.volumes, [instance.volume, instance.control_volume])

    def test_server_uses_read_only_control_volume_and_non_root_identity(self):
        instance = self.instance("docker")
        with patch.object(smoke, "command") as run:
            instance.launch("gateway", "candidate", [], config="server.toml", wait=False)
        args = run.call_args.args[0]
        self.assertIn(instance.control_volume + ":/etc/fluxheim:ro", args)
        self.assertIn("65532:65532", args)
        self.assertEqual(args[-2:], ["--config", "/etc/fluxheim/server.toml"])
        self.assertFalse(any(arg.startswith("/fixture-input/") for arg in args))

    def test_cleanup_attempts_both_owned_volumes_after_container_failure(self):
        instance = self.instance()
        instance.names = [instance.prefix + "-failed"]
        instance.volumes = [instance.volume, instance.control_volume]
        with patch.object(smoke, "command", side_effect=[RuntimeError("failed"), None, None]) as run:
            with self.assertRaises(RuntimeError):
                instance.close()
        self.assertEqual(run.call_args_list[-2].args[0],
                         ["podman", "volume", "rm", instance.control_volume])
        self.assertEqual(run.call_args_list[-1].args[0], ["podman", "volume", "rm", instance.volume])

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
            smoke.command(["openssl", "literal argument"])
            self.assertEqual(run.call_args.args[0], ["openssl", "literal argument"])
            self.assertEqual(run.call_args.kwargs["timeout"], 180)
            self.assertNotIn("shell", run.call_args.kwargs)

    def test_command_boundary_rejects_unlisted_executables(self):
        with patch.object(smoke.subprocess, "run") as run:
            for executable in ("sh", "/tmp/docker", "docker --privileged", "openssl\n"):
                with self.assertRaises(KeyError):
                    smoke.command([executable, "argument"])
            run.assert_not_called()

    def test_image_reference_is_only_an_operand_and_returns_engine_identity(self):
        instance = self.instance()
        identity = "sha256:" + "a" * 64
        with patch.object(smoke, "command", return_value=subprocess.CompletedProcess(
                [], 0, json.dumps([{"Id": identity}]), "")) as run:
            self.assertEqual(instance.image("registry.test/image:tag"), identity)
        self.assertEqual(run.call_args.args[0],
                         ["podman", "image", "inspect", "--", "registry.test/image:tag"])

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
