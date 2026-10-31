#!/usr/bin/env python3
"""Regression checks for the local-only ACME qualification harness."""
import json
from pathlib import Path
import re
import subprocess
import tempfile
import tomllib
import unittest
from unittest.mock import patch

import yaml

import acme_pebble_frontend as frontend
import smoke_acme_scope as smoke

ROOT = Path(__file__).resolve().parents[1]
GUIDE = ROOT / "docs/guides/certificate-renewal.md"


class AcmeDeploymentDocumentationTests(unittest.TestCase):
    def compose_documents(self):
        yield yaml.safe_load((ROOT / "examples/podman-compose-acme.yml").read_text())
        blocks = re.findall(r"```yaml\n(.*?)```", GUIDE.read_text(), re.S)
        self.assertEqual(len(blocks), 1)
        yield yaml.safe_load(blocks[0])

    def test_companion_is_opt_in_and_requires_explicit_image_selection(self):
        for document in self.compose_documents():
            services = document["services"]
            companion = services["fluxheim-acme"]
            self.assertEqual(companion["profiles"], ["renewal"])
            self.assertEqual(companion["restart"], "no")
            self.assertEqual(companion["entrypoint"], ["/usr/local/bin/fluxheim-acme"])
            self.assertEqual(companion["command"],
                             ["--config", "/etc/fluxheim/fluxheim.toml", "renew"])
            self.assertIn("${FLUXHEIM_GATEWAY_IMAGE:?", services["fluxheim"]["image"])
            self.assertIn("${FLUXHEIM_RENEWAL_IMAGE:?", companion["image"])
            for service in services.values():
                self.assertEqual(service["ulimits"]["core"], {"soft": 0, "hard": 0})

    def test_shared_mounts_keep_shared_labels_without_live_chown(self):
        expected = {"/etc/fluxheim/fluxheim.toml", "/etc/fluxheim/conf.d",
                    "/run/fluxheim", "/var/lib/fluxheim",
                    "/run/secrets/actalis-eab-kid", "/run/secrets/actalis-eab-hmac-key"}
        for document in self.compose_documents():
            services = document["services"]
            gateway = {entry.split(":")[1]: entry for entry in services["fluxheim"]["volumes"]}
            companion = {entry.split(":")[1]: entry for entry in services["fluxheim-acme"]["volumes"]}
            self.assertEqual(set(companion), expected)
            for target, entry in companion.items():
                self.assertEqual(gateway[target], entry)
                modes = entry.rsplit(":", 1)[1].split(",")
                self.assertIn("z", modes)
                self.assertNotIn("Z", modes)
                self.assertNotIn("U", modes)
                self.assertEqual("ro" in modes, target not in {"/run/fluxheim", "/var/lib/fluxheim"})

    def test_each_systemd_service_gets_its_own_credentials(self):
        guide = GUIDE.read_text().split("## Packaged Actalis Credentials\n", 1)[1].split("\n## ", 1)[0]
        for unit, dropin in (("fluxheim", "actalis-eab.conf"),
                             ("fluxheim-acme", "actalis-eab-acme.conf")):
            self.assertIn(f"/etc/systemd/system/{unit}.service.d/actalis-eab.conf", guide)
            self.assertIn(f"/usr/share/doc/fluxheim/systemd/{dropin}", guide)
            source = (ROOT / "packaging/systemd" / dropin).read_text()
            for name in ("actalis-eab-kid", "actalis-eab-hmac-key"):
                self.assertIn(f"LoadCredential={name}:/etc/fluxheim/secrets/{name}", source)
        self.assertIn("does not inherit", guide)
        self.assertIn("not a complete ready-to-register policy", guide)

    def test_initializer_commands_require_deliberate_terms_acceptance(self):
        section = GUIDE.read_text().split("## Initialize ACME\n", 1)[1].split("\n## ", 1)[0]
        commands = section.replace("\\\n", " ").splitlines()
        initializers = [line for line in commands if line.startswith("sudo fluxheim acme-init ")]
        self.assertEqual(len(initializers), 4)
        for command in initializers:
            self.assertIn("--accept-terms-of-service", command)
            self.assertIn('--terms-of-service-url "${ACME_TERMS_URL:?', command)
        self.assertIn("sudo systemctl start fluxheim-acme.service", section)
        self.assertNotIn("sudo fluxheim-acme --config", section)

    def test_renewal_does_not_claim_installation_is_activation(self):
        guide = GUIDE.read_text()
        for boundary in ("separate steps", "may already be", "renew --no-reload",
                         "not available on Windows", "actually served after activation",
                         "not challenge readiness", "A one-shot container is not a timer"):
            self.assertIn(boundary, guide)
        self.assertIn("run --rm --no-deps fluxheim-acme", guide)
        self.assertNotIn("source-identical local copy with one narrow", guide)


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
        sources = ["renew.toml", "server.toml", "cache.toml", *smoke.RENEWAL_CONFIGS, "ca.pem"]
        self.assertEqual(args[-len(sources)-1:],
                         ["/input/" + name for name in sources] + ["/control/"])
        host_mounts = [arg for arg in args if arg.startswith("/fixture-input/")]
        self.assertEqual(len(host_mounts), len(sources))
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

    def test_each_renewal_has_a_fresh_account_but_the_same_certificate_store(self):
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(smoke, "command"):
                control = smoke.fixtures(Path(temporary))
            configs = [tomllib.loads((control / name).read_text())
                       for name in smoke.RENEWAL_CONFIGS]
        self.assertEqual(len(configs), 4)
        issuers = set()
        baseline = tomllib.loads(smoke.configuration())
        for config in configs:
            acme = config["tls"]["acme"]
            self.assertEqual(acme["default_issuer"], acme["issuers"][0]["name"])
            issuers.add(acme["default_issuer"])
            acme["default_issuer"] = "pebble"
            acme["issuers"][0]["name"] = "pebble"
            self.assertEqual(config, baseline)
        self.assertEqual(len(issuers), 4)

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
            # Always reuse eligible authorizations, so accidental shared
            # accounts fail the four-distinct-challenges evidence check.
            self.assertIn("PEBBLE_AUTHZREUSE=100", arguments)
            self.assertIn("127.0.0.1::14000", arguments)
            self.assertFalse(any("VA_ALWAYS_VALID" in value for value in arguments))
            self.assertIn("65532:65532", arguments)
            self.assertFalse(any(value.endswith(":rw,z") for value in arguments))


if __name__ == "__main__":
    unittest.main()
