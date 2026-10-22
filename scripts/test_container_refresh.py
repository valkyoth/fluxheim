#!/usr/bin/env python3
"""Regression coverage for runtime-only refresh selection and publication."""

import json
import contextlib
import io
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import patch

import yaml

import container_refresh as refresh
import container_refresh_platforms as platforms
from smoke_container_refresh import check_php, engine_command, smoke


ROOT = Path(__file__).resolve().parents[1]


class RefreshTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.enterContext(contextlib.chdir(self.directory.name))
        for path in refresh.RELEASE_FILES.values():
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes((ROOT / path.relative_to("source")).read_bytes())

    def test_only_stable_published_versions(self):
        self.assertEqual(refresh.stable_tag({"tag_name": "v1.8.2"}), "v1.8.2")
        for tag in ["main", "v1.9.0-rc1", "v1.8.2\nextra", "--help", "v1.8.2-release"]:
            with self.subTest(tag=tag), self.assertRaises(ValueError):
                refresh.stable_tag({"tag_name": tag})
        for field in ["draft", "prerelease"]:
            with self.assertRaises(ValueError):
                refresh.stable_tag({"tag_name": "v1.8.2", field: True})

    def test_full_released_matrix_is_preserved(self):
        matrix = refresh.matrix()["include"]
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
        for entry in refresh.matrix()["include"]:
            _, names = refresh.tags("v1.8.2", **entry, revision="123-2")
            self.assertTrue(all(name.startswith("v1.8.2") for name in names))
            self.assertFalse(any(name.startswith(("sha-", "latest", "dev")) for name in names))

    def test_untrusted_tag_components_rejected(self):
        for revision in ["latest", "1-2\nfoo", "1;echo hi", ""]:
            with self.assertRaises(ValueError):
                refresh.tags("v1.8.2", "php", "wolfi", revision)

    def test_version_mismatch_fails_before_network_or_writes(self):
        with patch.object(refresh.subprocess, "check_output") as network:
            with self.assertRaisesRegex(ValueError, "Cargo version"):
                refresh.prepare("php", "wolfi", "v0.0.0")
            network.assert_not_called()

    def test_resolver_uses_latest_release_commit_not_workflow_sha(self):
        with contextlib.redirect_stdout(io.StringIO()) as output:
            commit = "a" * 40
            with patch.dict(os.environ, {"GITHUB_REPOSITORY": "valkyoth/fluxheim", "FLUXHEIM_RELEASE_ALLOWED_SIGNERS": "trusted",
                                         "GITHUB_SHA": "b" * 40}), \
                 patch("sys.argv", ["container_refresh.py", "resolve"]), \
                 patch.object(refresh.subprocess, "check_output", return_value=json.dumps({"tag_name": "v1.8.2"})) as capture, \
                 patch.object(refresh, "verified_release_commit", return_value=commit) as verify, \
                 patch.object(refresh.subprocess, "run") as run, \
                 patch.object(refresh, "matrix", return_value={"include": []}):
                refresh.main()
            self.assertIn("commit=" + commit, output.getvalue())
            self.assertIn("releases/latest", capture.call_args_list[0].args[0][-1])
            verify.assert_called_once_with("v1.8.2", "trusted")
            self.assertEqual(run.call_args_list[0].args[0][-1], "refs/tags/v1.8.2")
            self.assertEqual(run.call_args_list[1].args[0][-1], commit)

    def test_prepare_uses_release_features_and_resolved_base(self):
        version = refresh.tomllib.loads(refresh.release_text("manifest"))["package"]["version"]
        with patch.object(refresh.subprocess, "check_output", return_value="sha256:" + "a" * 64), patch.object(refresh, "output") as output:
            refresh.prepare("php", "wolfi", "v" + version)
        values = output.call_args.args[0]
        self.assertTrue(values["base"].endswith("@sha256:" + "a" * 64))
        self.assertEqual(values["config"], "packaging/container/php-managed.toml")
        self.assertIn("php-8.5-mysqli", values["packages"])
        self.assertIn("AS runtime", Path("source/containers/Containerfile.refresh").read_text())

    def test_all_24_release_combinations_prepare_with_fixed_paths(self):
        manifest = refresh.release_text("manifest")
        version = refresh.tomllib.loads(manifest)["package"]["version"]
        for entry in refresh.matrix()["include"]:
            with self.subTest(**entry), \
                 patch.object(refresh.subprocess, "check_output", return_value="sha256:" + "a" * 64), \
                 patch.object(refresh, "output") as output:
                refresh.prepare(**entry, version="v" + version)
                self.assertIn(output.call_args.args[0]["config"], refresh.CONFIGS)
                Path("source/containers/Containerfile.refresh").unlink()
        self.assertEqual(refresh.release_text("manifest"), manifest)

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

    def promotion_fixture(self, status, expected="sha256:" + "0" * 64, move_after_inspect=False):
        # Exercise the real shell entrypoint with stubbed registry operations.
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            skopeo = root / "skopeo"
            skopeo.write_text('#!/bin/sh\ncase "$1" in\nlogin) cat >/dev/null;;\ninspect) printf "sha256:%064d\\n" 0; '
                              'if [ "$MOVE_AFTER_INSPECT" = 1 ]; then printf substituted > "$REGISTRY_TAG"; fi;;\n'
                              'copy) if [ "$MOVE_AFTER_INSPECT" = 1 ]; then test -f "$REGISTRY_TAG" || exit 1; fi; '
                              'printf "%s\\n" "$*" >> "$COPY_LOG";;\nesac\n')
            skopeo.chmod(0o755)
            python = root / "python3"
            python.write_text(f'#!/bin/sh\nexit {status}\n')
            python.chmod(0o755)
            if expected is not None:
                (root / "tested-digest").mkdir()
                (root / "tested-digest/tested.digest").write_text(expected + "\n")
            env = {**os.environ, "PATH": f"{root}:/usr/bin:/bin", "GH_TOKEN": "test", "GITHUB_ACTOR": "test",
                   "GITHUB_REPOSITORY": "test/test", "CANDIDATE": "v1.8.2-rebuild-1-1-wolfi",
                   "ALIASES": "v1.8.2-wolfi", "QUAY_USERNAME": "", "DOCKERHUB_USERNAME": "",
                   "MOVE_AFTER_INSPECT": "1" if move_after_inspect else "0", "REGISTRY_TAG": str(root / "tag"),
                   "COPY_LOG": str(root / "copies"), "GITHUB_STEP_SUMMARY": str(root / "summary")}
            result = subprocess.run(["bash", str(ROOT / "scripts/promote_container_refresh.sh")], cwd=root, env=env, capture_output=True)
            if status or expected != "sha256:" + "0" * 64:
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

    def test_promotion_rejects_substituted_candidate(self):
        self.promotion_fixture(0, "sha256:" + "a" * 64)

    def test_promotion_uses_recorded_digest_even_if_tag_moves_after_check(self):
        self.promotion_fixture(0, move_after_inspect=True)

    def test_promotion_rejects_missing_or_malformed_evidence(self):
        for expected in [None, "", "--help", "sha256:bad", "sha256:" + "0" * 64 + "\ninjected"]:
            with self.subTest(expected=expected):
                self.promotion_fixture(0, expected)

    def test_signature_failure_stops_checkout_and_outputs(self):
        with patch.dict(os.environ, {"GITHUB_REPOSITORY": "valkyoth/fluxheim", "FLUXHEIM_RELEASE_ALLOWED_SIGNERS": "trusted"}), \
             patch("sys.argv", ["container_refresh.py", "resolve"]), \
             patch.object(refresh.subprocess, "check_output", return_value=json.dumps({"tag_name": "v1.8.2"})), \
             patch.object(refresh.subprocess, "run") as run, \
             patch.object(refresh, "verified_release_commit", side_effect=ValueError("bad signature")), \
             patch.object(refresh, "output") as output:
            with self.assertRaisesRegex(ValueError, "bad signature"):
                refresh.main()
            self.assertEqual(run.call_count, 1)  # fetch only, no worktree/build
            output.assert_not_called()

    def test_missing_trust_anchor_fails_before_fetch(self):
        with patch.dict(os.environ, {"GITHUB_REPOSITORY": "valkyoth/fluxheim", "FLUXHEIM_RELEASE_ALLOWED_SIGNERS": ""}), \
             patch("sys.argv", ["container_refresh.py", "resolve"]), \
             patch.object(refresh.subprocess, "check_output") as run:
            with self.assertRaisesRegex(ValueError, "allowed-signers"):
                refresh.main()
            run.assert_not_called()

    def test_release_file_paths_are_allowlisted_and_symlinks_rejected(self):
        for key in ["../Cargo.toml", "/etc/passwd", "source/Cargo.toml", "wolfi/../../outside"]:
            with self.assertRaises(ValueError):
                refresh.release_text(key)
        path = refresh.RELEASE_FILES["manifest"]
        path.unlink()
        path.symlink_to(ROOT / "Cargo.toml")
        with self.assertRaisesRegex(ValueError, "symlink"):
            refresh.release_text("manifest")

    def test_package_path_in_workflow_cannot_escape_checkout(self):
        path = refresh.RELEASE_FILES["workflow"]
        path.write_text(path.read_text().replace("packaging/container/php-wolfi-runtime-packages.txt", "../../outside"))
        version = refresh.tomllib.loads(refresh.release_text("manifest"))["package"]["version"]
        with patch.object(refresh.subprocess, "check_output") as network:
            with self.assertRaisesRegex(ValueError, "unreviewed"):
                refresh.prepare("php", "wolfi", "v" + version)
            network.assert_not_called()

    def test_generated_recipe_cannot_overwrite_a_symlink(self):
        outside = Path("outside")
        outside.write_text("untouched")
        Path("source/containers/Containerfile.refresh").symlink_to(outside.resolve())
        version = refresh.tomllib.loads(refresh.release_text("manifest"))["package"]["version"]
        with patch.object(refresh.subprocess, "check_output", return_value="sha256:" + "a" * 64):
            with self.assertRaises(FileExistsError):
                refresh.prepare("php", "wolfi", "v" + version)
        self.assertEqual(outside.read_text(), "untouched")

    def test_long_or_unicode_tag_revision_is_rejected(self):
        for revision in ["9" * 100000 + "-1", "1-" + "9" * 100000, "١-١"]:
            with self.assertRaises(ValueError):
                refresh.tags("v1.8.2", "full", "wolfi", revision)
        for tag in ["v١.٨.٢", "v" + "9" * 100000 + ".1.1"]:
            with self.assertRaises(ValueError):
                refresh.stable_tag({"tag_name": tag})

    def test_output_does_not_open_environment_paths(self):
        with patch.dict(os.environ, {"GITHUB_OUTPUT": "/untrusted/output"}), \
             contextlib.redirect_stdout(io.StringIO()) as output:
            refresh.output({"version": "v1.8.2"})
        self.assertEqual(output.getvalue(), "version=v1.8.2\n")
        with contextlib.redirect_stdout(io.StringIO()) as output:
            with self.assertRaises(ValueError):
                refresh.output({"version": "v1.8.2", "bad": "a\nb"})
        self.assertEqual(output.getvalue(), "")

    def test_container_executable_is_literal_including_cleanup(self):
        with patch("smoke_container_refresh.subprocess.run", return_value=SimpleNamespace(stdout="ok")) as run:
            for engine in ["docker", "podman"]:
                for command in [("run", "--rm", "fluxheim-refresh:test"), ("logs", "smoke"), ("rm", "-f", "smoke")]:
                    engine_command(engine, *command, check=False)
                    self.assertEqual(run.call_args.args[0], [engine, *command])
            run.reset_mock()
            for engine in ["/tmp/evil", "docker --help", "sh"]:
                with self.assertRaises(ValueError):
                    engine_command(engine, "rm", "-f", "smoke")
            run.assert_not_called()

    def test_image_cannot_inject_engine_options(self):
        with patch("smoke_container_refresh.engine_command") as run:
            for image in ["--privileged", "-v/tmp:/host", "image;evil", "image\n--help"]:
                with self.assertRaises(ValueError):
                    smoke(SimpleNamespace(version="v1.8.2", profile="full", variant="wolfi", image=image, engine="docker"))
            run.assert_not_called()

    def test_workflow_binds_same_attempt_digest_and_protected_signers(self):
        jobs = yaml.safe_load((ROOT / ".github/workflows/container-refresh.yml").read_text())["jobs"]
        self.assertEqual(jobs["release"]["environment"], "container-refresh-release")
        resolve = next(s for s in jobs["release"]["steps"] if s.get("id") == "release")
        self.assertEqual(resolve["env"]["FLUXHEIM_RELEASE_ALLOWED_SIGNERS"], "${{ secrets.FLUXHEIM_RELEASE_ALLOWED_SIGNERS }}")
        upload = next(s for s in jobs["build"]["steps"] if s.get("uses", "").startswith("actions/upload-artifact@"))
        download = next(s for s in jobs["promote"]["steps"] if s.get("uses", "").startswith("actions/download-artifact@"))
        self.assertEqual(upload["with"]["name"], download["with"]["name"])
        self.assertIn("github.run_attempt", upload["with"]["name"])
        self.assertEqual(upload["with"]["if-no-files-found"], "error")
        self.assertNotIn("run-id", download["with"])
        self.assertNotIn("github-token", download["with"])
        self.assertEqual(download["with"]["path"], "tested-digest")
        publish = next(s for s in jobs["build"]["steps"] if s.get("name") == "Publish tested candidate only")
        self.assertIn('--digestfile "$RUNNER_TEMP/tested.digest"', publish["run"])
        self.assertIn("docker-daemon:fluxheim-refresh:test", publish["run"])


class ReleaseSignatureTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.enterContext(contextlib.chdir(directory.name))
        # Use a private local Git configuration, independent of developer keys.
        self.enterContext(patch.dict(os.environ, {"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}))
        self.git("init", "-q")
        self.git("config", "user.name", "Refresh test")
        self.git("config", "user.email", "refresh@example.invalid")
        self.git("commit", "--allow-empty", "-qm", "fixture")
        self.commit = self.git("rev-parse", "HEAD")
        for key in ["trusted", "other"]:
            subprocess.run(["ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-f", key], check=True)
        self.signers = "refresh@example.invalid " + Path("trusted.pub").read_text()

    def git(self, *args):
        return subprocess.check_output(["git", *args], text=True, stderr=subprocess.PIPE).strip()

    def signed_tag(self, key="trusted", tag="v1.8.2"):
        self.git("-c", "gpg.format=ssh", "-c", f"user.signingkey={Path(key).resolve()}", "tag", "-s", "-m", "release", tag)

    def fetch(self, tag="v1.8.2"):
        self.git("fetch", "--no-tags", ".", "refs/tags/" + tag)

    def test_authorized_signed_tag_returns_exact_commit(self):
        self.signed_tag()
        self.fetch()
        self.assertEqual(refresh.verified_release_commit("v1.8.2", self.signers), self.commit)

    def test_lightweight_tag_is_rejected(self):
        self.git("tag", "v1.8.2")
        self.fetch()
        with self.assertRaisesRegex(ValueError, "annotated"):
            refresh.verified_release_commit("v1.8.2", self.signers)

    def test_unsigned_annotated_tag_is_rejected(self):
        self.git("tag", "-a", "-m", "unsigned", "v1.8.2")
        self.fetch()
        with self.assertRaisesRegex(ValueError, "SSH signature"):
            refresh.verified_release_commit("v1.8.2", self.signers)

    def test_unauthorized_signer_is_rejected(self):
        self.signed_tag("other")
        self.fetch()
        with self.assertRaises(subprocess.CalledProcessError):
            refresh.verified_release_commit("v1.8.2", self.signers)

    def test_signed_tag_renamed_to_another_release_is_rejected(self):
        self.signed_tag(tag="v1.8.1")
        self.git("update-ref", "refs/tags/v1.8.2", self.git("rev-parse", "v1.8.1"))
        self.fetch()
        with self.assertRaisesRegex(ValueError, "tag name"):
            refresh.verified_release_commit("v1.8.2", self.signers)

    def test_modified_signed_commit_is_rejected(self):
        self.signed_tag()
        self.git("commit", "--allow-empty", "-qm", "malicious replacement")
        modified = self.git("cat-file", "tag", "v1.8.2").replace(self.commit, self.git("rev-parse", "HEAD"), 1) + "\n"
        oid = subprocess.check_output(["git", "hash-object", "-w", "-t", "tag", "--stdin"], input=modified, text=True).strip()
        self.git("update-ref", "refs/tags/v1.8.2", oid)
        self.fetch()
        with self.assertRaises(subprocess.CalledProcessError):
            refresh.verified_release_commit("v1.8.2", self.signers)


if __name__ == "__main__":
    unittest.main()
