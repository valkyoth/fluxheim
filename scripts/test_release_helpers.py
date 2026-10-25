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
    def test_php_smoke_diagnostics_do_not_replace_original_failure(self):
        source = (SCRIPTS / 'smoke_windows_public_php.ps1').read_text()
        cleanup = source.rsplit('} finally {', 1)[1]
        self.assertIn('Write-Error -ErrorAction Continue', cleanup)
        self.assertIn('Write-Error "Windows public PHP smoke artifacts kept in $runRoot" -ErrorAction Continue', cleanup)

    def test_php_smoke_uses_archived_checksum_pinned_fixture(self):
        source = (SCRIPTS / 'smoke_windows_public_php.ps1').read_text()
        self.assertIn('https://downloads.php.net/~windows/releases/archives/php-8.4.25-nts-Win32-vs17-x64.zip', source)
        self.assertIn('43a8f67ed2e5223fafb21293c85976361808855405278cef2cf3037c3ae2529c', source)
        self.assertLess(source.index('if ($actualPhpHash -ne $phpSha256)'),
                        source.index('Expand-Archive -LiteralPath $phpArchivePath'))

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

    def test_windows_preflight_uses_explicit_port_and_strict_host_key(self):
        self.env["FLUXHEIM_WINDOWS_SSH_PORT"] = "2223"
        self.env["FLUXHEIM_WINDOWS_X64_HOST"] = "127.0.0.1"
        result = self.run_helper()
        self.assertEqual(result.returncode, 0, result.stderr)
        log = (self.root / "ssh.log").read_text()
        self.assertIn("Port=2223", log)
        self.assertIn("StrictHostKeyChecking=yes", log)
        self.assertIn("fluxheim-build@127.0.0.1", log)

    def test_windows_invalid_ports_fail_before_connecting(self):
        for port in ("0", "65536", "-p22", "22;id", "022", "1 2", "123456789012345"):
            with self.subTest(port=port):
                self.env["FLUXHEIM_WINDOWS_SSH_PORT"] = port
                self.assertNotEqual(self.run_helper().returncode, 0)
                self.assertFalse((self.root / "ssh.log").exists())

    def test_windows_upload_build_download_share_transport_options(self):
        source = HELPER.read_text()
        self.assertEqual(source.count('ssh "${WINDOWS_SSH[@]}"'), 2)
        self.assertEqual(source.count('scp "${WINDOWS_SSH[@]}"'), 2)

    def test_live_windows_smokes_keep_guest_and_forwarded_ports_separate(self):
        for name in ("smoke_windows_public_profiles.sh", "smoke_windows_public_php.sh"):
            with self.subTest(script=name):
                source = (SCRIPTS / name).read_text()
                self.assertIn('-o "Port=$SSH_PORT"', source)
                self.assertIn('-HttpPort $LISTEN_HTTP_PORT -HttpsPort $LISTEN_HTTPS_PORT', source)
                self.assertIn('"$PUBLIC_NAME:$HTTPS_PORT:$PUBLIC_ADDRESS"', source)
                for port in ("0", "65536", "022", "22;id"):
                    env = dict(self.env, FLUXHEIM_WINDOWS_SSH_PORT=port)
                    args = ["127.0.0.1", str(self.root / "key"), "unused.zip"]
                    if "profiles" in name:
                        args += ["unused.zip"] * 3
                    args += ["fluxheim-qemu.test"]
                    result = subprocess.run(["/bin/bash", str(SCRIPTS / name), *args], env=env,
                                            capture_output=True, text=True)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("ports must be", result.stderr)
                self.assertFalse((self.root / "ssh.log").exists())

    def test_windows_bootstrap_port_and_admin_user(self):
        for name in ("sed", "sleep"):
            (self.bin / name).symlink_to(f"/usr/bin/{name}")
        (self.root / "sign.pub").write_text("ssh-ed25519 AAAA test\n")
        self.tool("git", f'''case "$*" in
            'config --get user.signingkey') echo "{self.root}/sign.pub";;
            'config --get user.email') echo test@example.invalid;;
            'rev-parse --show-toplevel') echo "{SCRIPTS.parent}";;
            *) echo aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa;;
        esac''')
        self.tool("ssh-keygen", "echo 'ssh-ed25519 AAAA test'")
        self.tool("scp", 'printf "SCP\\n%s\\n" "$*" >> "$SSH_LOG"')
        self.tool("ssh", 'printf "SSH\\n%s\\n" "$*" >> "$SSH_LOG"\ncase "$*" in *"exit 0") exit 1;; esac')
        self.env.update(FLUXHEIM_WINDOWS_ADMIN_USER="fluxheim", FLUXHEIM_WINDOWS_SSH_PORT="2223")
        result = subprocess.run(["/bin/bash", str(SCRIPTS / "bootstrap_windows_release_builder.sh"),
                                 "127.0.0.1", str(self.root / "key"), "10.0.2.2/32"],
                                cwd=SCRIPTS.parent, env=self.env, text=True, capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        commands = (self.root / "ssh.log").read_text().splitlines()
        for command in commands:
            if command in ("SSH", "SCP"):
                continue
            self.assertIn("Port=2223", command)
            self.assertIn("StrictHostKeyChecking=yes", command)
        self.assertIn("fluxheim@127.0.0.1", "\n".join(commands))
        self.assertIn("C:\\Users\\fluxheim\\FluxheimBootstrap", "\n".join(commands))

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
