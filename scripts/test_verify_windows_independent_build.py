#!/usr/bin/env python3
"""Regression tests for independent Windows release archive verification."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VERIFIER = ROOT / "scripts" / "verify_windows_independent_build.py"
PUBLICATION_GATE = ROOT / "scripts" / "verify_windows_release_publication.sh"
PROFILES = ("full", "wasm", "cache", "proxy", "load-balancer", "php", "config-tester")
COMMIT = "a" * 40
VERSION = "1.8.2"


class IndependentWindowsBuildTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory(prefix="fluxheim-windows-evidence-")
        root = Path(self.temporary.name)
        self.local = root / "local"
        self.independent = root / "independent"
        self.local.mkdir()
        self.independent.mkdir()
        self.fake_bin = root / "bin"
        self.fake_bin.mkdir()
        checksum_lines: list[str] = []
        for profile in PROFILES:
            name = f"fluxheim-{VERSION}-{profile}-x86_64-windows.zip"
            payload = f"deterministic-{profile}\n".encode()
            digest = hashlib.sha256(payload).hexdigest()
            checksum_lines.append(f"{digest}  {name}")
            (self.local / name).write_bytes(payload)
            (self.independent / name).write_bytes(payload)
        (self.local / "SHA256SUMS-x86_64-windows.txt").write_text(
            "\n".join(checksum_lines) + "\n", encoding="ascii"
        )
        (self.independent / "SHA256SUMS-independent-x86_64-windows.txt").write_text(
            "\n".join(checksum_lines) + "\n", encoding="ascii"
        )
        toolchain_manifest = {
            "schema": 1,
            "builder_mode": "fresh-disposable",
            "builder_id": "1" * 32,
            "rust_version": "1.98.1",
            "rust_target": "x86_64-pc-windows-msvc",
            "files": [{"path": "rustup/toolchains/rustc.exe", "sha256": "3" * 64}],
        }
        toolchain_manifest_path = (
            self.local / "toolchain-provisioning-x86_64-windows.json"
        )
        toolchain_manifest_path.write_text(
            json.dumps(toolchain_manifest), encoding="utf-8"
        )
        self.toolchain_manifest_hash = hashlib.sha256(
            toolchain_manifest_path.read_bytes()
        ).hexdigest()
        (self.local / "release-evidence-x86_64-windows.txt").write_text(
            f"version={VERSION}\n"
            f"tag=v{VERSION}\n"
            f"commit={COMMIT}\n"
            f"builder_id={'1' * 32}\n"
            "builder_provisioned_utc=2026-09-12T10:00:00+00:00\n"
            f"toolchain_manifest_sha256={self.toolchain_manifest_hash}\n"
            "builder_mode=fresh-disposable\n"
            "toolchain_read_only=true\n"
            "cargo_home_scope=per-run\n"
            "cargo_config_scope=trusted-cwd\n"
            "environment_scope=allowlist\n"
            "independent_windows_build_required=true\n"
            "archive_count=7\n"
            "reproducible=true\n",
            encoding="ascii",
        )
        (self.independent / "release-evidence-independent-x86_64-windows.txt").write_text(
            f"version={VERSION}\n"
            f"tag=v{VERSION}\n"
            f"commit={COMMIT}\n"
            "builder_domain=github-hosted-windows-2025\n"
            "repository=valkyoth/fluxheim\n"
            "workflow=.github/workflows/ci.yml\n"
            "workflow_run_id=1234\n"
            "archive_count=7\n",
            encoding="ascii",
        )
        fake_gh = self.fake_bin / "gh"
        fake_gh.write_text(
            "#!/usr/bin/env bash\n"
            "set -eu\n"
            f"commit=${{GH_FAKE_COMMIT:-{COMMIT}}}\n"
            "if [[ $1 == api && $* == *'/artifacts'* ]]; then\n"
            "  printf '123\\tfalse\\t%s\\n' \"$commit\"\n"
            "elif [[ $1 == api ]]; then\n"
            "  case \"$*\" in\n"
            "    *'.repository.full_name'*) echo valkyoth/fluxheim ;;\n"
            "    *'.head_sha'*) echo \"$commit\" ;;\n"
            f"    *'.head_branch'*) echo v{VERSION} ;;\n"
            "    *'.event'*) echo push ;;\n"
            "    *'.conclusion'*) echo success ;;\n"
            f"    *'.path'*) echo .github/workflows/ci.yml@v{VERSION} ;;\n"
            "    *) exit 2 ;;\n"
            "  esac\n"
            "elif [[ $1 == attestation && $2 == verify ]]; then\n"
            "  [[ ${GH_FAKE_ATTESTATION_FAILURE:-0} != 1 ]] || exit 1\n"
            "  [[ $* == *'--signer-workflow valkyoth/fluxheim/.github/workflows/ci.yml'* ]]\n"
            f"  [[ $* == *'--source-ref refs/tags/v{VERSION}'* ]]\n"
            f"  [[ $* == *'--source-digest {COMMIT}'* ]]\n"
            "  [[ $* == *'--deny-self-hosted-runners'* ]]\n"
            "else\n"
            "  exit 2\n"
            "fi\n",
            encoding="ascii",
        )
        fake_gh.chmod(0o755)

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def run_verifier(self) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                str(VERIFIER),
                "--expected-version",
                VERSION,
                "--expected-commit",
                COMMIT,
                str(self.local),
                str(self.independent),
            ],
            check=False,
            capture_output=True,
            text=True,
        )

    def run_publication_gate(self, **environment: str) -> subprocess.CompletedProcess[str]:
        process_environment = os.environ.copy()
        process_environment.update(environment)
        process_environment["PATH"] = f"{self.fake_bin}:{process_environment['PATH']}"
        return subprocess.run(
            [
                "bash",
                str(PUBLICATION_GATE),
                VERSION,
                COMMIT,
                "1234",
                str(self.local),
                str(self.independent),
                "valkyoth/fluxheim",
            ],
            check=False,
            capture_output=True,
            text=True,
            env=process_environment,
        )

    def test_accepts_identical_archives_from_two_builder_domains(self) -> None:
        result = self.run_verifier()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("independent Windows build verification: ok", result.stdout)

    def test_publication_gate_authenticates_workflow_and_attestations(self) -> None:
        result = self.run_publication_gate()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("authenticated Windows release publication gate: ok", result.stdout)

    def test_publication_gate_rejects_wrong_workflow_commit(self) -> None:
        result = self.run_publication_gate(GH_FAKE_COMMIT="b" * 40)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("workflow run does not match", result.stderr)

    def test_publication_gate_rejects_failed_attestation(self) -> None:
        result = self.run_publication_gate(GH_FAKE_ATTESTATION_FAILURE="1")
        self.assertNotEqual(result.returncode, 0)

    def test_rejects_independent_archive_tampering(self) -> None:
        archive = self.independent / f"fluxheim-{VERSION}-full-x86_64-windows.zip"
        archive.write_bytes(b"tampered\n")
        result = self.run_verifier()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("archive checksum mismatch", result.stderr)

    def test_rejects_archive_inventory_for_another_version(self) -> None:
        old_name = f"fluxheim-1.8.1-full-x86_64-windows.zip"
        current_name = f"fluxheim-{VERSION}-full-x86_64-windows.zip"
        for root in self.local, self.independent:
            (root / current_name).rename(root / old_name)
        for checksum_name, root in (
            ("SHA256SUMS-x86_64-windows.txt", self.local),
            ("SHA256SUMS-independent-x86_64-windows.txt", self.independent),
        ):
            checksum = root / checksum_name
            checksum.write_text(
                checksum.read_text(encoding="ascii").replace(current_name, old_name),
                encoding="ascii",
            )
        result = self.run_verifier()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("archive inventory does not match the intended release", result.stderr)

    def test_rejects_different_source_commits(self) -> None:
        evidence = self.independent / "release-evidence-independent-x86_64-windows.txt"
        evidence.write_text(
            f"version={VERSION}\n"
            f"tag=v{VERSION}\n"
            f"commit={'b' * 40}\n"
            "builder_domain=github-hosted-windows-2025\n"
            "archive_count=7\n",
            encoding="ascii",
        )
        result = self.run_verifier()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match the intended release commit", result.stderr)

    def test_rejects_wrong_expected_source_commit(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(VERIFIER),
                "--expected-version",
                VERSION,
                "--expected-commit",
                "b" * 40,
                str(self.local),
                str(self.independent),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match the intended release commit", result.stderr)

    def test_rejects_wrong_expected_release_version(self) -> None:
        result = subprocess.run(
            [
                sys.executable,
                str(VERIFIER),
                "--expected-version",
                "1.8.1",
                "--expected-commit",
                COMMIT,
                str(self.local),
                str(self.independent),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match the intended release version", result.stderr)

    def test_rejects_missing_toolchain_provenance(self) -> None:
        evidence = self.local / "release-evidence-x86_64-windows.txt"
        evidence.write_text(
            evidence.read_text(encoding="ascii").replace(
                f"toolchain_manifest_sha256={self.toolchain_manifest_hash}\n", ""
            ),
            encoding="ascii",
        )
        result = self.run_verifier()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("invalid toolchain manifest hash", result.stderr)

    def test_rejects_toolchain_manifest_tampering(self) -> None:
        manifest = self.local / "toolchain-provisioning-x86_64-windows.json"
        manifest.write_text("{}", encoding="utf-8")
        result = self.run_verifier()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("manifest hash does not match evidence", result.stderr)

    def test_rejects_symlinked_evidence_directory(self) -> None:
        link = self.local.parent / "local-link"
        link.symlink_to(self.local, target_is_directory=True)
        result = subprocess.run(
            [
                sys.executable,
                str(VERIFIER),
                "--expected-version",
                VERSION,
                "--expected-commit",
                COMMIT,
                str(link),
                str(self.independent),
            ],
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("evidence directory must not be a symlink", result.stderr)


if __name__ == "__main__":
    unittest.main()
