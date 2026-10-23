#!/usr/bin/env python3
"""Exercise the release validator against complete and understated Rust minima."""

from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class ReleaseMetadataTests(unittest.TestCase):
    def validate(self, cargo_rust, toolchain, rpm_rust):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixtures = {
                "Cargo.toml": (
                    '[package]\nversion = "1.8.3"\n'
                    f'rust-version = "{cargo_rust}"\nlicense = "EUPL-1.2"\n'
                ),
                "rust-toolchain.toml": f'[toolchain]\nchannel = "{toolchain}"\n',
                "Containerfile": f"ARG RUST_IMAGE=docker.io/library/rust:{toolchain}-bookworm\n",
                "LICENSE": "EUROPEAN UNION PUBLIC LICENCE v. 1.2\n",
                "CHANGELOG.md": "## 1.8.3 (unreleased)\n",
                "release-notes/RELEASE_NOTES_1.8.3.md": "# Fluxheim 1.8.3 Release Notes\n",
                "README.md": "v1.8.3\n",
                "docs/guides/build-and-podman.md": "v1.8.3\n",
                "packaging/rpm/fluxheim.spec": f"Version: 1.8.3\n%global rust_min_version {rpm_rust}\n",
                "Cargo.lock": "",
                "deny.toml": "",
                ".cargo/audit.toml": "",
            }
            for relative, content in fixtures.items():
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")
            return subprocess.run(
                ["sh", str(ROOT / "scripts/validate-release-metadata.sh")],
                cwd=root, capture_output=True, text=True, check=False,
            )

    def test_matching_patch_minimum_passes(self):
        result = self.validate("1.99.1", "1.99.1", "1.99.1")
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_understated_patch_minimum_fails(self):
        for rpm_rust in ("1.99", "1.99.0"):
            with self.subTest(rpm_rust=rpm_rust):
                result = self.validate("1.99.1", "1.99.1", rpm_rust)
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("RPM Rust minimum", result.stderr)

    def test_minor_only_cargo_minimum_passes(self):
        result = self.validate("1.99", "1.99.0", "1.99")
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
