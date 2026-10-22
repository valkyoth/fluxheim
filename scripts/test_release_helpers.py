#!/usr/bin/env python3
"""Exercise release orchestration without building or contacting remote hosts."""

from pathlib import Path
import subprocess
import tempfile
import unittest


SCRIPTS = Path(__file__).resolve().parent
HELPER = SCRIPTS / "release_helper.sh"


def remote_block(marker):
    source = HELPER.read_text()
    return source.split(f"<<'{marker}'\n", 1)[1].split(f"\n{marker}\n", 1)[0]


class ReleaseHelpers(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        self.env = {
            "HOME": str(self.root),
            "PATH": str(self.bin),
            "FLUXHEIM_AARCH64_LINUX_HOST": "arm-builder",
            "FLUXHEIM_LINUX_SSH_KEY": str(self.root / "key"),
            "FLUXHEIM_WINDOWS_X64_HOST": "windows-builder",
            "FLUXHEIM_WINDOWS_SSH_KEY": str(self.root / "key"),
            "FLUXHEIM_MACOS_HOST": "macosbuilder",
            "FLUXHEIM_RELEASE_OUTPUT_DIR": str(self.root / "output"),
            "FLUXHEIM_RELEASE_PREFLIGHT_ONLY": "1",
            "SSH_LOG": str(self.root / "ssh.log"),
        }
        (self.root / "key").touch()
        for name in (
            "cargo", "curl", "git", "podman", "python3", "rustc", "rustup",
            "scp", "sha256sum", "ssh", "tar", "unzip", "cc", "pkg-config",
            "cmp", "file", "shasum", "xcode-select",
        ):
            self.tool(name, "exit 0")
        for name in ("dirname", "mkdir", "chmod", "mktemp", "rm", "cat"):
            (self.bin / name).symlink_to(f"/usr/bin/{name}")
        self.tool("uname", "printf 'Linux aarch64\\n'")
        self.tool("ssh", 'printf "%s\\n" "$@" >> "$SSH_LOG"\n/bin/cat >/dev/null\nexit "${SSH_EXIT:-0}"')

    def tool(self, name, body):
        path = self.bin / name
        path.write_text("#!/bin/sh\n" + body + "\n")
        path.chmod(0o700)

    def run_shell(self, source, *args):
        return subprocess.run(
            ["/bin/bash", "-s", "--", *args], input=source, env=self.env,
            text=True, capture_output=True, check=False,
        )

    def run_helper(self):
        return subprocess.run(
            ["/bin/bash", str(HELPER), "1.99.1", "1.8.3"], env=self.env,
            text=True, capture_output=True, check=False,
        )

    def test_preflight_uses_macos_alias_and_separate_ssh_config(self):
        config = self.root / "ssh config"
        config.touch()
        self.env["FLUXHEIM_MACOS_SSH_CONFIG"] = str(config)
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stderr)
        log = (self.root / "ssh.log").read_text()
        self.assertIn(f"-F\n{config}\n", log)
        self.assertIn("macosbuilder\nbash -s --", log)
        self.assertIn("ProgramFiles 'FluxheimRustTrusted'", log)
        self.assertFalse((self.root / "output").exists())

    def test_preflight_failure_stops_before_output_creation(self):
        self.env["SSH_EXIT"] = "41"
        result = self.run_helper()
        self.assertEqual(result.returncode, 41)
        self.assertIn("remote builder preflight", result.stderr)
        self.assertFalse((self.root / "output").exists())

    def test_existing_output_is_not_deleted(self):
        output = self.root / "output/fluxheim-1.8.3-release-assets"
        output.mkdir(parents=True)
        artifact = output / "already-built.tar.gz"
        artifact.write_bytes(b"preserve me")
        self.env["FLUXHEIM_RELEASE_PREFLIGHT_ONLY"] = "0"
        result = self.run_helper()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("output already exists", result.stderr)
        self.assertEqual(artifact.read_bytes(), b"preserve me")

    def test_macos_import_does_not_contact_mac(self):
        self.env["FLUXHEIM_MACOS_HOST"] = ""
        self.env["FLUXHEIM_MACOS_ASSET_DIR"] = str(self.root)
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("macosbuilder", (self.root / "ssh.log").read_text())

    def test_rejects_option_in_macos_destination(self):
        self.env["FLUXHEIM_MACOS_HOST"] = "-oProxyCommand=bad"
        self.assertNotEqual(self.run_helper().returncode, 0)
        self.assertFalse((self.root / "ssh.log").exists())

    def test_missing_explicit_ssh_config_is_not_silently_ignored(self):
        self.env["FLUXHEIM_MACOS_SSH_CONFIG"] = str(self.root / "missing")
        self.assertIn("config is not readable", self.run_helper().stderr)

    def test_arm_missing_rust_is_actionable(self):
        (self.bin / "cargo").unlink()
        result = self.run_shell(remote_block("PREFLIGHT_LINUX"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ARM builder missing cargo", result.stderr)

    def test_arm_finds_rust_in_nonlogin_cargo_path(self):
        cargo = self.root / ".cargo/bin"
        cargo.mkdir(parents=True)
        (self.bin / "cargo").rename(cargo / "cargo")
        result = self.run_shell(remote_block("PREFLIGHT_LINUX"))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_mac_requires_signer_allowlist(self):
        self.tool("uname", "printf 'Darwin arm64\\n'")
        result = self.run_shell(remote_block("PREFLIGHT_MACOS"))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("allowedSignersFile", result.stderr)

    def test_mac_accepts_provisioned_signer_allowlist(self):
        self.tool("uname", "printf 'Darwin arm64\\n'")
        (self.root / "signers").touch()
        self.tool("git", 'printf "%s/signers\\n" "$HOME"')
        result = self.run_shell(remote_block("PREFLIGHT_MACOS"))
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_remote_mac_runs_helper_with_exact_commit_and_repo(self):
        job = self.root / ".fhr/job.test01"
        job.mkdir(parents=True)
        (job / "release_helper_macos.sh").write_text(
            'printf "%s\\n" "$1" "$2" "$FLUXHEIM_EXPECTED_RELEASE_COMMIT" '
            '"$FLUXHEIM_REPO_URL" "$FLUXHEIM_RELEASE_OUTPUT_DIR"\n'
        )
        (self.bin / "bash").symlink_to("/bin/bash")
        result = self.run_shell(
            remote_block("REMOTE_MACOS"), ".fhr/job.test01", "1.99.1", "1.8.3",
            "a" * 40, "https://example.invalid/repo.git",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), [
            "1.99.1", "1.8.3", "a" * 40, "https://example.invalid/repo.git", str(job),
        ])

    def test_mac_transport_quotes_remote_arguments(self):
        (self.bin / "bash").symlink_to("/bin/bash")
        self.tool("ssh", 'for last do :; done\n/bin/bash -c "$last"')
        function = HELPER.read_text().split("macos_bash() {", 1)[1].split("\n}", 1)[0]
        argument = f"repo with spaces; touch {self.root}/injected"
        result = self.run_shell(
            'MACOS_SSH=(); MACOS_HOST=macosbuilder\nmacos_bash() {' + function +
            '\n}\nmacos_bash "$1" <<\'TEST\'\nprintf "%s\\n" "$1"\nTEST\n', argument,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.strip(), argument)
        self.assertFalse((self.root / "injected").exists())

    def test_macos_helper_rejects_different_commit_before_building(self):
        self.tool("uname", 'case "$1" in -s) echo Darwin;; -m) echo arm64;; esac')
        self.tool("git", 'case "$1" in clone) /bin/mkdir -p "$7";; rev-parse) echo wrong;; *) exit 90;; esac')
        self.env["FLUXHEIM_EXPECTED_RELEASE_COMMIT"] = "a" * 40
        result = subprocess.run(
            ["/bin/bash", str(SCRIPTS / "release_helper_macos.sh"), "1.99.1", "1.8.3"],
            env=self.env, text=True, capture_output=True, check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("does not match the release coordinator commit", result.stderr)

    def test_macos_helper_does_not_bypass_tag_signature_verification(self):
        self.tool("uname", 'case "$1" in -s) echo Darwin;; -m) echo arm64;; esac')
        self.tool("git", 'case "$1" in clone) /bin/mkdir -p "$7";; rev-parse) echo matching;; tag) exit 1;; *) exit 90;; esac')
        self.env["FLUXHEIM_EXPECTED_RELEASE_COMMIT"] = "matching"
        result = subprocess.run(
            ["/bin/bash", str(SCRIPTS / "release_helper_macos.sh"), "1.99.1", "1.8.3"],
            env=self.env, text=True, capture_output=True, check=False,
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("signed tag verification failed", result.stderr)


if __name__ == "__main__":
    unittest.main()
