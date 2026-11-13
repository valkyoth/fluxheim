#!/usr/bin/env python3
"""Keep development coverage mandatory and costly qualification fail-closed."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

import yaml

import ci_qualification as policy


FULL = "needs.qualification-scope.outputs.full == 'true'"
BASE, HEAD = "a" * 40, "b" * 40


class QualificationTests(unittest.TestCase):
    def test_runtime_and_documentation_commits_use_development_gate(self):
        changes = Mock(return_value=["src/admin/security.rs", "crates/fluxheim-server/src/lib.rs", "docs/guides/cache.md"])
        self.assertFalse(policy.full_qualification("push", "refs/heads/main", {"before": BASE}, HEAD, changes))
        changes.assert_called_once_with(BASE, HEAD)

    def test_sensitive_release_inputs_trigger_full_gate(self):
        for path in ("Cargo.lock", "crates/fluxheim-config/Cargo.toml", "rust-toolchain.toml",
                     "build.rs", ".cargo/config.toml", "packaging/container/full.toml",
                     "containers/Containerfile.wolfi", "scripts/build_release_assets.ps1",
                     "scripts/reproducible_build_check.sh", "scripts/native_archive.py",
                     "scripts/portable_release_plan.py", "scripts/smoke_windows_archive_profiles.ps1",
                     "scripts/test_native_archives.py", "scripts/generate-sbom.sh",
                     ".github/workflows/ci.yml", "scripts/ci_qualification.py",
                     "scripts/create_release_archives.py"):
            with self.subTest(path=path):
                self.assertTrue(policy.release_paths_changed([path]))

    def test_archive_generator_and_gate_changes_force_full_on_push_and_pr(self):
        for path in ("scripts/create_release_archives.py", "scripts/ci_qualification.py",
                     ".github/workflows/ci.yml"):
            for name, event in (("push", {"before": BASE}),
                                ("pull_request", {"pull_request": {"base": {"sha": BASE}}})):
                with self.subTest(path=path, event=name):
                    self.assertTrue(policy.full_qualification(name, "", event, HEAD,
                                                             Mock(return_value=[path])))

    def test_tags_and_manual_runs_cannot_skip_full_qualification(self):
        changes = Mock(side_effect=AssertionError("must not inspect a diff"))
        for event, ref in (("push", "refs/tags/v1.9.0"), ("workflow_dispatch", "refs/heads/main")):
            self.assertTrue(policy.full_qualification(event, ref, {}, HEAD, changes))

    def test_pull_request_uses_base_to_checked_out_merge_commit(self):
        changes = Mock(return_value=["Cargo.toml"])
        self.assertTrue(policy.full_qualification("pull_request", "refs/pull/1/merge",
                                                {"pull_request": {"base": {"sha": BASE}}}, HEAD, changes))
        changes.assert_called_once_with(BASE, HEAD)

    def test_unknown_history_and_diff_errors_fail_to_full(self):
        for base in ("", "0" * 40, "--help", "x" * 40, None):
            self.assertTrue(policy.full_qualification("push", "refs/heads/main", {"before": base}, HEAD, Mock()))
        for error in (OSError(), subprocess.CalledProcessError(128, "git"), subprocess.TimeoutExpired("git", 60)):
            self.assertTrue(policy.full_qualification("push", "refs/heads/main", {"before": BASE}, HEAD, Mock(side_effect=error)))
        self.assertTrue(policy.full_qualification("unknown", "", {}, HEAD, Mock()))

    def test_diff_preserves_deleted_names_and_nul_boundaries(self):
        result = subprocess.CompletedProcess([], 0, stdout=b"Cargo.lock\0docs/a\nb.md\0")
        with patch.object(policy.subprocess, "run", return_value=result) as run:
            self.assertEqual(policy.git_changed_paths(BASE, HEAD), ["Cargo.lock", "docs/a\nb.md"])
        args, kwargs = run.call_args
        self.assertIn("--no-renames", args[0])
        self.assertIn("--no-ext-diff", args[0])
        self.assertIn("-z", args[0])
        self.assertNotIn("shell", kwargs)
        self.assertEqual(kwargs["timeout"], 60)

    def test_main_emits_only_boolean_outputs_and_malformed_events_fail_full(self):
        with tempfile.TemporaryDirectory() as directory:
            event, output = Path(directory) / "event.json", Path(directory) / "output"
            for content, expected in ((json.dumps({"before": BASE}), "false"), ("{bad", "true"), ("[]", "true")):
                event.write_text(content)
                output.write_text("")
                with patch.dict(os.environ, {"GITHUB_EVENT_PATH": str(event), "GITHUB_OUTPUT": str(output),
                                             "GITHUB_EVENT_NAME": "push", "GITHUB_REF": "refs/heads/main", "GITHUB_SHA": HEAD}), \
                        patch.object(policy, "git_changed_paths", return_value=["src/lib.rs"]):
                    policy.main()
                self.assertEqual(output.read_text(), f"full={expected}\n")


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.workflow = yaml.load((policy.ROOT / ".github/workflows/ci.yml").read_text(), Loader=yaml.BaseLoader)
        self.jobs = self.workflow["jobs"]

    def test_manual_full_run_and_complete_git_history(self):
        self.assertIn("workflow_dispatch", self.workflow["on"])
        scope = self.jobs["qualification-scope"]
        self.assertEqual(scope["steps"][0]["with"]["fetch-depth"], "0")
        self.assertEqual(scope["outputs"]["full"], "${{ steps.scope.outputs.full }}")
        self.assertEqual(scope["steps"][1]["run"], "python3 scripts/ci_qualification.py")

    def test_only_release_work_is_gated(self):
        self.assertEqual(self.jobs["linux-native-archives"]["if"], FULL)
        gated = {"Install SBOM tool", "Generate SBOM", "Verify reproducible release build",
                 "Build 1.0 core release matrix", "Build all macOS portable archives",
                 "Build and test Windows portable archives"}
        found = set()
        for name in ("checks", "macos-portable", "windows-x86_64-portable"):
            job = self.jobs[name]
            self.assertNotIn("if", job)
            self.assertEqual(job["needs"], "qualification-scope")
            for step in job["steps"]:
                if step.get("name") in gated:
                    found.add(step["name"])
                    self.assertEqual(step.get("if"), FULL)
                elif step.get("uses", "").startswith("actions/upload-artifact@"):
                    self.assertEqual(step.get("if"), FULL)
                else:
                    self.assertNotIn("if", step, step.get("name"))
        self.assertEqual(found, gated)
        for job in ("collectors", "acme-operation-scope", "container-refresh-policy"):
            self.assertNotIn("if", self.jobs[job])

    def test_slice_smoke_builds_required_profile_after_cache_smoke(self):
        steps = self.jobs["checks"]["steps"]
        smoke = next(step for step in steps if step.get("name") == "Run localhost smoke tests")
        lines = [line.strip() for line in smoke["run"].splitlines() if line.strip()]
        index = lines.index("python3 scripts/smoke_slice_upstreams.py target")
        self.assertEqual(lines[index - 1], "cargo build --locked --no-default-features --features profile-load-balancer,acme-client --bin fluxheim")
        self.assertLess(lines.index("sh scripts/smoke_proxy_cache.sh"), index - 1)


if __name__ == "__main__":
    unittest.main()
