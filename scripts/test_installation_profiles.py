#!/usr/bin/env python3
"""Check package documentation against Cargo and the actual release matrices."""

from pathlib import Path
import re
import subprocess
import tomllib
import unittest

import yaml

from portable_release_plan import PROFILES, release_plan

ROOT = Path(__file__).resolve().parents[1]
FEATURES = tomllib.loads((ROOT / "Cargo.toml").read_text())["features"]


def expanded(selection):
    pending = list(selection)
    result = set()
    while pending:
        feature = pending.pop()
        if feature in result:
            continue
        if feature not in FEATURES:
            raise ValueError("unknown root feature")
        result.add(feature)
        pending.extend(dependency for dependency in FEATURES[feature] if dependency in FEATURES)
    return result


def shell_accepts(selection):
    result = subprocess.run(["sh", "scripts/validate-features.sh", selection], cwd=ROOT,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=10,
                            check=False)
    return result.returncode == 0


class InstallationProfileTests(unittest.TestCase):
    def deployment_documents(self):
        guide = (ROOT / "docs/guides/build-and-podman.md").read_text()
        section = guide.split("## Volume Mapping\n", 1)[1]
        blocks = re.findall(r"```yaml\n(.*?)```", section, re.S)
        self.assertEqual(len(blocks), 1)
        return (yaml.safe_load(blocks[0]),
                yaml.safe_load((ROOT / "examples/podman-compose.yml").read_text()))

    def test_inline_and_shipped_gateway_deployment_agree(self):
        inline, shipped = self.deployment_documents()
        self.assertEqual(inline["services"], shipped["services"])
        self.assertEqual(inline["networks"], shipped["networks"])
        gateway = shipped["services"]["fluxheim"]
        self.assertIn("${FLUXHEIM_GATEWAY_IMAGE:?", gateway["image"])
        self.assertEqual(gateway["command"], ["--config", "/etc/fluxheim/fluxheim.toml"])
        self.assertEqual(gateway["stop_signal"], "SIGTERM")
        self.assertEqual(gateway["ulimits"]["core"], {"soft": 0, "hard": 0})

    def test_gateway_stop_budget_exceeds_both_documented_drain_settings(self):
        runtime = (ROOT / "src/runtime_shutdown.rs").read_text()
        default = int(re.search(r"DEFAULT_GRACEFUL_SHUTDOWN_TIMEOUT_SECONDS: u64 = (\d+)",
                                runtime)[1])
        recipe = tomllib.loads((ROOT / "examples/container/fluxheim.toml").read_text())
        process = recipe["server"]["process"]
        for document in self.deployment_documents():
            budget = int(document["services"]["fluxheim"]["stop_grace_period"].removesuffix("s"))
            self.assertGreater(budget, default)
            self.assertGreater(budget, process["grace_period_seconds"] +
                               process["graceful_shutdown_timeout_seconds"])
        guide = (ROOT / "docs/guides/build-and-podman.md").read_text()
        self.assertIn(f"--stop-timeout {budget}", guide)
        self.assertIn("not a total process-exit deadline", guide)

    def test_documented_state_paths_match_writable_mounts(self):
        guide = (ROOT / "docs/guides/build-and-podman.md").read_text()
        section = guide.split("Matching config paths", 1)[1].split("Podman run example:", 1)[0]
        blocks = re.findall(r"```toml\n(.*?)```", section, re.S)
        self.assertEqual(len(blocks), 1)
        inline = tomllib.loads(blocks[0])
        shipped = tomllib.loads((ROOT / "examples/container/fluxheim.toml").read_text())
        for recipe in (inline, shipped):
            self.assertTrue(recipe["cache"]["enabled"])
            self.assertTrue(recipe["cache"]["disk"]["enabled"])
            self.assertEqual(recipe["cache"]["disk"]["path"], "/var/cache/fluxheim")
            self.assertEqual(recipe["tls"]["certificates"],
                             [{"cert_path": "/etc/fluxheim/tls/fullchain.pem",
                               "key_path": "/etc/fluxheim/tls/key.pem"}])
        self.assertEqual(shipped["tls"]["acme"]["storage"], "/var/lib/fluxheim/acme")
        for document in self.deployment_documents():
            mounts = {entry.split(":")[1]: entry.rsplit(":", 1)[1].split(",")
                      for entry in document["services"]["fluxheim"]["volumes"]}
            for target in ("/var/cache/fluxheim", "/var/lib/fluxheim", "/var/log/fluxheim"):
                self.assertNotIn("ro", mounts[target])
            self.assertIn("ro", mounts["/etc/fluxheim/tls"])

    def test_build_guide_reuses_reviewed_acme_workflow(self):
        guide = (ROOT / "docs/guides/build-and-podman.md").read_text()
        section = guide.split("For managed ACME in containers,", 1)[1].split(
            "Optional mounted error pages", 1)[0]
        self.assertIn("certificate-renewal.md#container-renewal", section)
        self.assertIn("acme.md#first-http-01-deployment", section)
        self.assertIn("--profile renewal run --rm --no-deps fluxheim-acme", section)
        self.assertNotIn("```toml", section)
        self.assertNotIn("podman run", section)
        self.assertIn("not challenge readiness", section)
        self.assertIn("certificate installation is not proof", section)
        self.assertIn("runtime user", guide)

    def test_public_server_capability_table_matches_cargo(self):
        guide = (ROOT / "docs/guides/installation.md").read_text()
        columns = ({"web"}, {"cache"}, {"load-balancer"}, {"php-fpm"}, {"wasm"},
                   {"metrics", "metrics-otlp", "otel-tracing", "otel-otlp"},
                   {"geoip", "stream-proxy", "traffic-mirror"})
        for profile, selection in PROFILES.items():
            features = expanded(selection.split(","))
            self.assertNotIn("udp-proxy", features)
            if profile == "config-tester":
                self.assertNotIn("wasm", features)
                continue
            common = {"proxy", "tls-rustls", "acme-client", "compression-gzip",
                      "compression-zstd", "compression-brotli"}
            self.assertTrue(common <= features)
            cells = ["Yes" if group <= features else "No" for group in columns]
            self.assertIn(f"| `{profile}` | " + " | ".join(cells) + " |", guide)

    def test_every_cargo_profile_alias_is_documented(self):
        reference = (ROOT / "docs/reference/features.md").read_text()
        for name, children in FEATURES.items():
            if name.startswith("profile-"):
                expansion = ", ".join(f"`{child}`" for child in children)
                self.assertIn(f"| `{name}` | {expansion} |", reference)

    def test_image_and_archive_feature_selections_agree(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/images.yml").read_text())
        profiles = workflow["jobs"]["images"]["strategy"]["matrix"]["profile"]
        self.assertEqual({item["name"] for item in profiles}, set(PROFILES) - {"config-tester"})
        for item in profiles:
            self.assertEqual(item["features"], PROFILES[item["name"]])
            self.assertTrue((ROOT / item["config"]).is_file())
            if item["name"] == "php":
                self.assertEqual(item["managed_config"], "packaging/container/php-managed.toml")
                for variant in ("wolfi", "alpine", "debian", "suse_bci"):
                    self.assertTrue((ROOT / item[f"{variant}_runtime_packages_file"]).is_file())

    def test_profile_binary_names_are_portable(self):
        for kind, target, suffix in (("linux", "aarch64-unknown-linux-gnu", ""),
                                      ("macos", "aarch64-apple-darwin", ""),
                                      ("windows", "x86_64-pc-windows-msvc", ".exe")):
            for profile in PROFILES:
                rows = release_plan("1.9.0", kind, target, profile)
                self.assertEqual(len(rows), 1)
                expected = (f"fluxheim-config-tester{suffix}" if profile == "config-tester"
                            else f"fluxheim{suffix},fluxheim-acme{suffix}")
                self.assertEqual(rows[0][2], expected)

    def test_shell_validator_admits_official_profiles(self):
        for selection in PROFILES.values():
            self.assertTrue(shell_accepts(selection))

    def test_shell_policy_gaps_remain_explicit(self):
        # Characterization of the current profile preflight, not approval.
        self.assertTrue(shell_accepts("profile-fips-openssl,tls-rustls"))
        self.assertFalse(shell_accepts("tls-openssl-fips,tls-rustls"))
        self.assertTrue(shell_accepts("privacy-mode,geoip"))
        self.assertFalse(shell_accepts("privacy-mode,cache"))
        selection = expanded(["profile-fips-openssl", "tls-rustls"])
        self.assertTrue({"tls-openssl", "tls-rustls"} <= selection)
        source = (ROOT / "src/lib.rs").read_text()
        self.assertIn('all(feature = "privacy-mode", feature = "geoip")', source)
        self.assertIn('all(feature = "tls-rustls-backend", feature = "tls-openssl")', source)

    def test_recipe_has_bounded_stop_and_no_optional_services(self):
        recipe = tomllib.loads((ROOT / "examples/installation/container.toml").read_text())
        self.assertEqual(recipe["server"]["listen"], ["0.0.0.0:8080"])
        self.assertEqual(recipe["server"]["process"]["graceful_shutdown_timeout_seconds"], 5)
        self.assertFalse(recipe["cache"]["enabled"])
        self.assertEqual(recipe["vhosts"][0]["web"]["root"], "/srv/fluxheim")
        for service in ("tls", "metrics", "tracing", "admin", "wasm"):
            self.assertNotIn(service, recipe)


if __name__ == "__main__":
    unittest.main()
