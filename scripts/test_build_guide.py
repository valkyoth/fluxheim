#!/usr/bin/env python3
"""Compare build-guide recipes with repository tooling without publishing images."""

from pathlib import Path
import re
import shlex
import tomllib
import unittest
from unittest.mock import patch

import yaml

import build_fluxheim_rpm as rpm
from smoke_build_profiles import relocate
from test_installation_profiles import expanded

ROOT = Path(__file__).resolve().parents[1]
GUIDE = (ROOT / "docs/guides/build-and-podman.md").read_text()


def shell_commands():
    for block in re.findall(r"```bash\n(.*?)```", GUIDE, re.S):
        yield from block.replace("\\\n", " ").splitlines()


def image_builds():
    builds = {}
    for command in shell_commands():
        if not command.startswith("podman build "):
            continue
        args = shlex.split(command)
        tag = args[args.index("-t") + 1]
        options = {args[index + 1].split("=", 1)[0]: args[index + 1].split("=", 1)[1]
                   for index, arg in enumerate(args) if arg == "--build-arg"}
        builds[tag] = options
    return builds


class BuildGuideTests(unittest.TestCase):
    def test_local_quick_start_uses_the_qualified_loopback_recipe(self):
        section = GUIDE.split("## Codex And Rootless Podman\n", 1)[1]
        blocks = re.findall(r"```bash\n(.*?)```", section, re.S)
        self.assertEqual(len(blocks), 1)
        args = shlex.split(blocks[0].replace("\\\n", " "))
        self.assertEqual(args[:2], ["podman", "run"])
        self.assertEqual(args[args.index("-p") + 1], "127.0.0.1:8080:8080")
        self.assertIn("no-new-privileges", args)
        self.assertIn("core=0:0", args)
        self.assertIn("$PWD/examples/installation/container.toml:/etc/fluxheim/fluxheim.toml:ro,Z", args)
        self.assertEqual(args[-2:], ["--config", "/etc/fluxheim/fluxheim.toml"])
        config = tomllib.loads((ROOT / "examples/installation/container.toml").read_text())
        self.assertEqual(config["vhosts"][0]["web"]["root"], "/srv/fluxheim")
        self.assertGreater(int(args[args.index("--stop-timeout") + 1]),
                           config["server"]["process"]["graceful_shutdown_timeout_seconds"])
        self.assertNotIn("sandbox_workspace_write.network_access=true", section)
        self.assertIn("not merely inside the current checkout", section)

    def test_publication_reference_matches_workflow_entry_points(self):
        workflow = yaml.load((ROOT / ".github/workflows/images.yml").read_text(), Loader=yaml.BaseLoader)
        self.assertEqual(set(workflow["on"]), {"push", "workflow_dispatch"})
        self.assertEqual(workflow["on"]["push"], {"tags": ["v*"]})
        self.assertEqual(workflow["on"]["workflow_dispatch"]["inputs"]["platforms"]["default"],
                         "linux/amd64")
        steps = workflow["jobs"]["images"]["steps"]
        tags = next(step["run"] for step in steps if step["name"] == "Prepare tags")
        self.assertIn('${GITHUB_SHA::12}', tags)
        self.assertIn('if [[ "${GITHUB_REF_NAME}" == "${DEFAULT_BRANCH}" ]]; then', tags)
        section = GUIDE.split("## Publishing Images\n", 1)[1].split("\n## ", 1)[0]
        for boundary in ("not a dry-run", "does\nnot automatically update `latest`",
                         "mutable registry tags", "naming patterns", "12-character-commit",
                         "do not rename profile tags", "does not\nrewrite"):
            self.assertIn(boundary, section)
        self.assertIn("container-runtime-refresh.md", section)

    def test_profile_smoke_only_relocates_runtime_paths_and_rejects_drift(self):
        source = (ROOT / "packaging/container/proxy.toml").read_text()
        before = tomllib.loads(source)
        after = tomllib.loads(relocate(source))
        for field, value in (("pid_file", "fluxheim.pid"),
                             ("upgrade_sock", "upgrade.sock"),
                             ("certificate_reload_sock", "reload.sock")):
            before["server"]["process"][field] = value
        self.assertEqual(after, before)
        with self.assertRaises(ValueError):
            relocate(source.replace("/run/fluxheim/fluxheim.pid", "/unexpected/pid"))

    def test_source_builds_lock_dependencies_and_select_existing_features(self):
        count = 0
        for command in shell_commands():
            args = shlex.split(command)
            if "cargo" not in args or "build" not in args:
                continue
            count += 1
            self.assertIn("--locked", args)
            self.assertNotIn("--all-features", args)
            if "--features" in args:
                features = args[args.index("--features") + 1].split(",")
                self.assertTrue(expanded(features))
                self.assertIn("--no-default-features", args)
        self.assertGreaterEqual(count, 15)

    def test_runtime_base_table_matches_digest_pinned_containerfiles(self):
        rows = re.findall(r"^\| `([^`]+)` \| `([^`]+)` \| `([^`]+)` \|", GUIDE, re.M)
        self.assertEqual(len(rows), 5)
        for variant, file, readable_base in rows:
            source = (ROOT / file).read_text()
            match = re.search(r"^ARG RUNTIME_IMAGE=(.+)@sha256:([a-f0-9]{64})$", source, re.M)
            self.assertIsNotNone(match, variant)
            self.assertEqual(match[1].removeprefix("docker.io/library/"), readable_base)
            self.assertRegex(source, r"ARG RUST_IMAGE=.+@sha256:[a-f0-9]{64}")
        root = (ROOT / "Containerfile").read_text()
        self.assertIn("debian:bookworm-slim@sha256:", root)
        self.assertIn("root `Containerfile` uses `debian:bookworm-slim`", GUIDE)
        self.assertIn("does\nnot automatically fetch a newer base", GUIDE)

    def test_documented_profile_exceptions_match_real_selection(self):
        dev = expanded(["profile-development"])
        self.assertTrue({"php-fpm", "cache", "load-balancer", "metrics"} <= dev)
        self.assertFalse({"wasm", "udp-proxy"} & dev)
        self.assertIn("Wasm and beta\nUDP are not included", GUIDE)
        bci = (ROOT / "containers/Containerfile.suse-bci").read_text()
        self.assertIn("ARG FLUXHEIM_FEATURES=profile-web-server,php-fpm,acme-client", bci)
        self.assertIn("PHP-only SUSE BCI recipe is the exception", GUIDE)

    def test_reduced_image_examples_pair_features_and_config(self):
        builds = image_builds()
        expected = {
            "fluxheim:proxy": ("proxy", "packaging/container/proxy.toml"),
            "fluxheim:proxy-wolfi": ("profile-proxy-edge,acme-client", "packaging/container/proxy.toml"),
            "fluxheim:cache-wolfi": ("profile-cache-edge,acme-client", "packaging/container/cache.toml"),
            "fluxheim:php-fpm-wolfi": ("profile-web-server,php-fpm,acme-client", "packaging/container/php.toml"),
            "fluxheim:php-wolfi": ("profile-web-server,php-fpm,acme-client", "packaging/container/php-managed.toml"),
            "fluxheim:privacy": ("profile-privacy", "examples/privacy.toml"),
        }
        for name, (features, config) in expected.items():
            self.assertEqual(builds[name]["FLUXHEIM_FEATURES"], features)
            self.assertEqual(builds[name]["FLUXHEIM_CONFIG"], config)
            self.assertTrue((ROOT / config).is_file())
        self.assertNotIn("FLUXHEIM_RUNTIME_PACKAGES", builds["fluxheim:php-fpm-wolfi"])
        self.assertIn("packaging/container/php-wolfi-runtime-packages.txt",
                      builds["fluxheim:php-wolfi"]["FLUXHEIM_RUNTIME_PACKAGES"])
        self.assertIn("this does not install PHP-FPM", GUIDE)

    def test_rpm_recipe_arguments_match_helper_without_running_builds(self):
        commands = [line for line in shell_commands() if line.startswith("scripts/build_fluxheim_rpm.py")]
        self.assertEqual(len(commands), 4)
        for command in commands:
            args = shlex.split(command)
            args = ["1.8.3" if arg.startswith("${RELEASE_VERSION:?") else arg for arg in args]
            with patch("sys.argv", args):
                parsed = rpm.parse_args()
            self.assertEqual(parsed.build_type, "generic")
            rpm.validate_version_tag(parsed.version_tag)
            rpm.validate_features(parsed.features)
            if not parsed.list_targets:
                self.assertIn(parsed.target, rpm.OS_CONTAINERS)
        for boundary in ("not your working tree", "can include unpublished edits",
                         "not a publication or source-authenticity", "not a qualified release target"):
            self.assertIn(boundary, GUIDE)

    def test_config_checks_are_not_documented_as_runtime_qualification(self):
        for phrase in ("does not start an HTTP", "not every filesystem read",
                       "not a strict readiness gate", "not complete release-profile models",
                       "not a complete expansion of Cargo", "does not install an external daemon"):
            self.assertIn(phrase, GUIDE)
        self.assertIn("command-line.md#standalone-configuration-tester", GUIDE)


if __name__ == "__main__":
    unittest.main()
