#!/usr/bin/env python3
"""Regression tests for the live smoke's native/Podman command boundary."""
from pathlib import Path, PureWindowsPath
import unittest
from unittest.mock import patch

from smoke_request_correlation import run, server_command, validate_container_image


class CommandTests(unittest.TestCase):
    def test_only_tested_runtime_image_is_selected(self):
        image = "registry.opensuse.org/opensuse/tumbleweed:latest"
        self.assertEqual(validate_container_image(image), image)
        self.assertIsNone(validate_container_image(None))

    def test_other_well_formed_images_are_rejected(self):
        for image in ("localhost/fluxheim:smoke", "localhost:5000/team/image:build_1",
                      "ghcr.io/valkyoth/fluxheim@sha256:" + "a" * 64,
                      "registry.opensuse.org/opensuse/tumbleweed:other"):
            with self.subTest(image=image), self.assertRaises(ValueError):
                validate_container_image(image)

    def test_option_and_shell_metacharacters_are_rejected(self):
        for image in (
            "", "--privileged", "--entrypoint=/bin/sh", "-v/host:/host",
            "image latest", "image\nnext", "image;id", "$(id)", "image`id`",
            "image|id", "image&next", "image'", 'image"', "image\x00",
            "im\u00e1ge", "a" * 257,
        ):
            with self.subTest(image=image), self.assertRaises(ValueError):
                validate_container_image(image)

    def test_invalid_image_fails_before_fixture_or_process_setup(self):
        with patch("smoke_request_correlation.ThreadingHTTPServer") as server:
            with self.assertRaises(ValueError):
                run(Path("unused"), "--privileged")
            server.assert_not_called()

    def test_native_paths_remain_separate_arguments(self):
        binary, config, root = map(Path, ("/test space/fluxheim", "/test space/config.toml", "/test space"))
        self.assertEqual(server_command(binary, config, root),
                         [str(binary), "--config", str(config)])

    def test_podman_options_end_before_image(self):
        with patch("os.getuid", return_value=1000, create=True), patch("os.getgid", return_value=1000, create=True):
            command = server_command(Path("/binary"), Path("/fixture/config.toml"), Path("/fixture"), "registry.opensuse.org/opensuse/tumbleweed:latest")
        boundary = command.index("--")
        self.assertEqual(command[boundary + 1:], ["registry.opensuse.org/opensuse/tumbleweed:latest", "--config", "/fixture/config.toml"])
        self.assertEqual(command[:2], ["podman", "run"])
        self.assertIn("--pull=never", command[:boundary])
        self.assertIn("/binary:/fluxheim:ro,Z", command[:boundary])

    def test_container_paths_are_posix_even_with_windows_path_objects(self):
        with patch("os.getuid", return_value=1000, create=True), patch("os.getgid", return_value=1000, create=True):
            command = server_command(PureWindowsPath("/binary"), PureWindowsPath("/fixture/config.toml"),
                                     PureWindowsPath("/fixture"), "registry.opensuse.org/opensuse/tumbleweed:latest")
        self.assertEqual(command[-1], "/fixture/config.toml")
        self.assertEqual(command[command.index("--workdir") + 1], "/fixture")
        self.assertIn("/fixture:/fixture:Z", command)
        self.assertIn("/binary:/fluxheim:ro,Z", command)

    def test_native_windows_paths_are_not_rewritten(self):
        binary, config, root = map(PureWindowsPath, ("C:/test space/fluxheim.exe", "C:/test space/config.toml", "C:/test space"))
        self.assertEqual(server_command(binary, config, root), [str(binary), "--config", str(config)])

    def test_command_builder_also_rejects_invalid_image(self):
        with self.assertRaises(ValueError):
            server_command(Path("/binary"), Path("/config"), Path("/fixture"), "--privileged")


if __name__ == "__main__":
    unittest.main()
