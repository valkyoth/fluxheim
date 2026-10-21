#!/usr/bin/env python3
"""Regression coverage for runtime-only refresh selection and publication."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import yaml

import container_refresh as refresh
import container_refresh_platforms as platforms
from smoke_container_refresh import check_php


ROOT = Path(__file__).resolve().parents[1]


class RefreshTests(unittest.TestCase):
    def test_only_stable_published_versions(self):
        self.assertEqual(refresh.stable_tag({"tag_name": "v1.8.2"}), "v1.8.2")
        for tag in ["main", "v1.9.0-rc1", "v1.8.2\nextra", "--help", "v1.8.2-release"]:
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                refresh.stable_tag({"tag_name": tag})
        for field in ["draft", "prerelease"]:
            with self.assertRaises(ValueError):
                refresh.stable_tag({"tag_name": "v1.8.2", field: True})

    def test_full_released_matrix_is_preserved(self):
        matrix = refresh.matrix(ROOT)["include"]
        self.assertEqual(len(matrix), 24)
        self.assertEqual(len({(x["profile"], x["variant"]) for x in matrix}), 24)
        self.assertNotIn({"profile": "php", "variant": "suse-micro"}, matrix)
        self.assertIn({"profile": "php", "variant": "suse-bci"}, matrix)
        self.assertIn({"profile": "load-balancer", "variant": "wolfi"}, matrix)

    def test_refresh_only_changes_runtime_stage(self):
        for variant in refresh.VARIANTS:
            with self.subTest(variant=variant):
                original = (ROOT / "containers" / f"Containerfile.{variant}").read_text()
                generated = refresh.refresh_containerfile(original, variant)
                self.assertEqual(original.split("\nFROM ${RUNTIME_IMAGE}\n")[0],
                                 generated.split("\nFROM ${RUNTIME_IMAGE} AS runtime\n")[0])
                self.assertIn(refresh.UPGRADES[variant], generated)
                self.assertEqual(original.count("cargo build --locked"), generated.count("cargo build --locked"))
                self.assertNotIn("@sha256:", refresh.base_reference(original))

    def test_recipe_shape_changes_fail_closed(self):
        for text in ["FROM alpine:latest", "FROM ${RUNTIME_IMAGE}\n", "\nFROM ${RUNTIME_IMAGE}\n\nFROM ${RUNTIME_IMAGE}\n"]:
            with self.assertRaises(ValueError):
                refresh.refresh_containerfile(text, "wolfi")

    def test_base_must_be_pinned_in_release_recipe(self):
        with self.assertRaises(ValueError):
            refresh.base_reference("ARG RUNTIME_IMAGE=alpine:latest\n")

    def test_existing_version_aliases_and_unique_refresh_tag(self):
        candidate, aliases = refresh.tags("v1.8.2", "php", "wolfi", "123-2")
        self.assertEqual(candidate, "v1.8.2-rebuild-123-2-php-wolfi")
        self.assertEqual(aliases, ["v1.8.2-php-wolfi", "v1.8.2-php"])
        self.assertEqual(refresh.tags("v1.8.2", "full", "wolfi", "123-2")[1],
                         ["v1.8.2-wolfi", "v1.8.2", "v1.8.2-base"])
        for entry in refresh.matrix(ROOT)["include"]:
            _, names = refresh.tags("v1.8.2", **entry, revision="123-2")
            self.assertTrue(all(name.startswith("v1.8.2") for name in names))
            self.assertFalse(any(name.startswith(("sha-", "latest", "dev")) for name in names))

    def test_untrusted_tag_components_rejected(self):
        for revision in ["latest", "1-2\nfoo", "1;echo hi", ""]:
            with self.assertRaises(ValueError):
                refresh.tags("v1.8.2", "php", "wolfi", revision)

    def test_version_mismatch_fails_before_network_or_writes(self):
        with patch.object(refresh, "capture") as network:
            with self.assertRaisesRegex(ValueError, "Cargo version"):
                refresh.prepare(ROOT, "php", "wolfi", "v0.0.0")
            network.assert_not_called()

    def test_resolver_uses_latest_release_commit_not_workflow_sha(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "output"
            commit = "a" * 40
            with patch.dict(os.environ, {"GITHUB_REPOSITORY": "valkyoth/fluxheim", "GITHUB_OUTPUT": str(output),
                                         "GITHUB_SHA": "b" * 40}), \
                 patch("sys.argv", ["container_refresh.py", "resolve"]), \
                 patch.object(refresh, "capture", side_effect=[json.dumps({"tag_name": "v1.8.2"}), commit]) as capture, \
                 patch.object(refresh.subprocess, "run") as run, \
                 patch.object(refresh, "matrix", return_value={"include": []}):
                refresh.main()
            self.assertIn("commit=" + commit, output.read_text())
            self.assertIn("releases/latest", capture.call_args_list[0].args[-1])
            self.assertEqual(run.call_args_list[0].args[0][-1], "refs/tags/v1.8.2")
            self.assertEqual(run.call_args_list[1].args[0][-1], commit)

    def test_prepare_uses_release_features_and_resolved_base(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ["Cargo.toml", ".github/workflows/images.yml", "containers/Containerfile.wolfi",
                         "packaging/container/php-wolfi-runtime-packages.txt"]:
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((ROOT / name).read_bytes())
            version = refresh.tomllib.loads((root / "Cargo.toml").read_text())["package"]["version"]
            with patch.object(refresh, "capture", return_value="sha256:" + "a" * 64), patch.object(refresh, "output") as output:
                refresh.prepare(root, "php", "wolfi", "v" + version)
            values = output.call_args.args[0]
            self.assertTrue(values["base"].endswith("@sha256:" + "a" * 64))
            self.assertEqual(values["config"], "packaging/container/php-managed.toml")
            self.assertIn("php-8.5-mysqli", values["packages"])
            self.assertIn("AS runtime", (root / "containers/Containerfile.refresh").read_text())

    def test_platform_protection(self):
        platforms.validate({"manifests": [{"platform": {"os": "linux", "architecture": "amd64"}},
                                           {"platform": {"os": "unknown", "architecture": "unknown"}}]})
        platforms.validate({}, {"Os": "linux", "Architecture": "amd64"})
        for manifest, config in [({}, None), ({}, {"Os": "linux", "Architecture": "arm64"}),
                                 ({"manifests": []}, None),
                                 ({"manifests": [{"platform": {"os": "linux", "architecture": "arm64"}},
                                                  {"platform": {"os": "linux", "architecture": "amd64"}}]}, None)]:
            with self.assertRaises(ValueError):
                platforms.validate(manifest, config)

    def test_php_rejects_old_wolfi_and_broken_extensions(self):
        check_php("PHP 8.5.12 (fpm-fcgi)", "mysqli\nmysqlnd", "mysqli\nmysqlnd\n", "wolfi")
        for version, modules in [("PHP 8.5.10", "mysqli\nmysqlnd"), ("PHP 8.5.12", "mysqli"),
                                 ("PHP 8.5.12", "mysqli\nmysqlnd\nPHP Warning: bad"), ("unknown", "mysqli\nmysqlnd")]:
            with self.assertRaises(ValueError):
                check_php(version, modules, "mysqli\nmysqlnd", "wolfi")
        # Vendor backports cannot be judged by an upstream version floor alone.
        check_php("PHP 8.4.11", "mysqli", "mysqli", "debian")

    def test_workflow_never_publishes_an_untested_build(self):
        workflow = yaml.safe_load((ROOT / ".github/workflows/container-refresh.yml").read_text())
        jobs = workflow["jobs"]
        self.assertEqual(jobs["promote"]["needs"], ["release", "build"])
        steps = jobs["build"]["steps"]
        names = [step.get("name", "") for step in steps]
        self.assertLess(names.index("Live HTTP and PHP runtime smoke"), names.index("Publish tested candidate only"))
        build = next(step for step in steps if step.get("name") == "Build locally before publishing")
        self.assertFalse(build["with"]["push"])
        self.assertTrue(build["with"]["load"])
        self.assertEqual(build["with"]["no-cache-filters"], "runtime")
        self.assertEqual(build["with"]["context"], "source")
        self.assertTrue(any(step.get("with", {}).get("ref") == "${{ needs.release.outputs.commit }}" for step in steps))

    def promotion_fixture(self, status):
        # Exercise the real shell entrypoint with stubbed registry operations.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            skopeo = root / "skopeo"
            skopeo.write_text('#!/bin/sh\ncase "$1" in\nlogin) cat >/dev/null;;\ninspect) printf "sha256:%064d\\n" 0;;\ncopy) printf "%s\\n" "$*" >> "$COPY_LOG";;\nesac\n')
            skopeo.chmod(0o755)
            python = root / "python3"
            python.write_text(f'#!/bin/sh\nexit {status}\n')
            python.chmod(0o755)
            env = {**os.environ, "PATH": f"{root}:/usr/bin:/bin", "GH_TOKEN": "test", "GITHUB_ACTOR": "test",
                   "GITHUB_REPOSITORY": "test/test", "CANDIDATE": "v1.8.2-rebuild-1-1-wolfi",
                   "ALIASES": "v1.8.2-wolfi", "QUAY_USERNAME": "", "DOCKERHUB_USERNAME": "",
                   "COPY_LOG": str(root / "copies"), "GITHUB_STEP_SUMMARY": str(root / "summary")}
            result = subprocess.run(["bash", "scripts/promote_container_refresh.sh"], cwd=ROOT, env=env, capture_output=True)
            if status:
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((root / "copies").exists())
            else:
                self.assertEqual(result.returncode, 0, result.stderr)
                copies = (root / "copies").read_text().splitlines()
                self.assertEqual(len(copies), 2)
                self.assertTrue(all("docker://ghcr.io/test/test@sha256:" + "0" * 64 in line for line in copies))
                summary = (root / "summary").read_text()
                self.assertIn("@sha256:" + "0" * 64, summary)
                self.assertIn("v1.8.2-rebuild-1-1-wolfi", summary)

    def test_promotion_failure_never_copies(self):
        self.promotion_fixture(1)

    def test_promotion_success_copies_candidate_and_alias(self):
        self.promotion_fixture(0)


if __name__ == "__main__":
    unittest.main()
