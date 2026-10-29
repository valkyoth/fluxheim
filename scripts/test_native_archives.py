#!/usr/bin/env python3
"""Negative archive fixtures must fail before executing their payloads."""
import io
import os
from pathlib import Path
import stat
import struct
import tarfile
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import native_archive as archive
from smoke_native_archives import CAPABILITIES, matches_identity
from portable_release_plan import PROFILES
from smoke_native_collector import acknowledged


class Archives(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.tar = self.root / "fixture.tar.gz"
        self.zip = self.root / "fixture.zip"
        self.bundle = "fluxheim-test"

    def pair(self, content=b"fixture", zip_content=None, name="fluxheim-test/fluxheim"):
        with tarfile.open(self.tar, "w:gz") as target:
            info = tarfile.TarInfo(name)
            info.size = len(content)
            target.addfile(info, io.BytesIO(content))
        with zipfile.ZipFile(self.zip, "w") as target:
            target.writestr(name, content if zip_content is None else zip_content)

    def test_equivalent_payload_extracts(self):
        self.pair()
        result = archive.extract_pair(self.tar, self.zip, self.bundle, self.root / "extracted")
        self.assertEqual(result, self.root / "extracted" / "payload")
        self.assertEqual((result / "fluxheim").read_bytes(), b"fixture")

    def test_bundle_name_does_not_select_execution_directory(self):
        self.bundle = "fluxheim-1.9.0-full-test"
        self.pair(name=self.bundle + "/fluxheim")
        result = archive.extract_pair(self.tar, self.zip, self.bundle, self.root / "extracted")
        self.assertEqual(result, self.root / "extracted" / "payload")
        self.assertFalse((self.root / "extracted" / self.bundle).exists())

    def test_root_cannot_be_a_regular_file(self):
        self.pair(name=self.bundle)
        for path in (self.tar, self.zip):
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "root"):
                archive.inventory(path, self.bundle)

    def test_executable_names_are_literal_and_checked_before_access(self):
        for name in ("../fluxheim", "/fluxheim", "fluxheim --version", "cmd.exe", "Fluxheim.exe", "fluxheim:stream"):
            with self.subTest(name=name), patch.object(archive, "architecture") as inspect:
                with self.assertRaisesRegex(ValueError, "unexpected"):
                    archive.executable(self.root / "missing", name, "x86_64-linux")
                inspect.assert_not_called()

    def test_executable_rejects_directory_and_hard_link(self):
        binary = self.root / "fluxheim"
        binary.mkdir()
        with self.assertRaisesRegex(ValueError, "regular file"):
            archive.executable(self.root, "fluxheim", "x86_64-linux")
        binary.rmdir()
        binary.write_bytes(b"fixture")
        os.link(binary, self.root / "alias")
        with self.assertRaisesRegex(ValueError, "single-link"):
            archive.executable(self.root, "fluxheim", "x86_64-linux")

    def test_all_allowed_executables_are_architecture_checked(self):
        for name in archive.EXECUTABLES:
            (self.root / name).write_bytes(b"fixture")
            with self.subTest(name=name), patch.object(archive, "architecture", return_value="x86_64-linux") as inspect:
                self.assertEqual(archive.executable(self.root, name, "x86_64-linux"), self.root / name)
                inspect.assert_called_once_with(self.root / name)
            with patch.object(archive, "architecture", return_value="aarch64-linux"):
                with self.assertRaisesRegex(ValueError, "architecture mismatch"):
                    archive.executable(self.root, name, "x86_64-linux")

    def test_identity_comparison_never_interprets_commit_as_regex(self):
        commit = "a" * 40
        identity = "fluxheim 1.9.0 (qualification-gaaaaaaaa)"
        self.assertTrue(matches_identity(identity, "1.9.0", commit))
        for bad in (".*", "a" * 8 + "." * 32, "b" * 40, "a" * 41, "A" * 40):
            with self.subTest(commit=bad):
                self.assertFalse(matches_identity(identity, "1.9.0", bad))
        for bad in ("fluxheim 1.8.3 (qualification-gaaaaaaaa)",
                    "fluxheim 1.9.0 (qualification-gaaaaaaaa-dirty)",
                    "fluxheim 1.9.0 (qualification-gaaaaaaaaa)"):
            with self.subTest(identity=bad):
                self.assertFalse(matches_identity(bad, "1.9.0", commit))

    def test_changed_payload_rejected(self):
        self.pair(zip_content=b"changed")
        with self.assertRaisesRegex(ValueError, "mismatch"):
            archive.extract_pair(self.tar, self.zip, self.bundle, self.root / "extracted")
        self.assertFalse((self.root / "extracted").exists())

    def test_unsafe_names(self):
        for name in ("/fluxheim-test/a", "fluxheim-test/../outside", "fluxheim-test/./a",
                     "fluxheim-test//a", "fluxheim-test/a\\b", "fluxheim-test/a:stream",
                     "fluxheim-test/NUL.txt", "fluxheim-test/COM1", "fluxheim-test/a.",
                     "fluxheim-test/a ", "other/a", "fluxheim-test/a\x00", "fluxheim-test/a\n"):
            with self.subTest(name=name), self.assertRaises(ValueError):
                archive.member_path(name, self.bundle)

    def test_tar_special_members_rejected(self):
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.FIFOTYPE, tarfile.CHRTYPE):
            with tarfile.open(self.tar, "w:gz") as target:
                info = tarfile.TarInfo("fluxheim-test/link")
                info.type, info.linkname = kind, "../outside"
                target.addfile(info)
            with self.subTest(kind=kind), self.assertRaises(ValueError):
                archive.inventory(self.tar, self.bundle)

    def test_zip_symlink_rejected(self):
        with zipfile.ZipFile(self.zip, "w") as target:
            info = zipfile.ZipInfo("fluxheim-test/link")
            info.external_attr = (stat.S_IFLNK | 0o777) << 16
            target.writestr(info, "../outside")
        with self.assertRaises(ValueError):
            archive.inventory(self.zip, self.bundle)

    def test_case_alias_rejected(self):
        with zipfile.ZipFile(self.zip, "w") as target:
            target.writestr("fluxheim-test/File", "a")
            target.writestr("fluxheim-test/file", "b")
        with self.assertRaisesRegex(ValueError, "aliased"):
            archive.inventory(self.zip, self.bundle)

    def test_resource_limits(self):
        self.pair()
        for limit in ("MAX_FILES", "MAX_FILE", "MAX_TOTAL"):
            for path in (self.zip, self.tar):
                with self.subTest(limit=limit, path=path), patch.object(archive, limit, 0):
                    with self.assertRaises(ValueError):
                        archive.inventory(path, self.bundle)

    def test_existing_destination_rejected(self):
        self.pair()
        with self.assertRaises(FileExistsError):
            archive.extract_pair(self.tar, self.zip, self.bundle, self.root)

    def test_empty_and_truncated_members(self):
        with zipfile.ZipFile(self.zip, "w"):
            pass
        with self.assertRaises(ValueError):
            archive.inventory(self.zip, self.bundle)
        for content, size in ((b"a", 2), (b"aa", 1), (b"", -1)):
            with self.subTest(content=content, size=size), self.assertRaises(ValueError):
                archive.digest(io.BytesIO(content), size)

    def test_extraction_rechecks_payload(self):
        self.pair()
        expected = archive.inventory(self.tar, self.bundle)
        self.pair(zip_content=b"changed")
        with patch.object(archive, "inventory", return_value=expected):
            with self.assertRaisesRegex(ValueError, "changed"):
                archive.extract_pair(self.tar, self.zip, self.bundle, self.root / "extract")

    def test_file_directory_collision_does_not_escape(self):
        for path, opener in ((self.zip, zipfile.ZipFile),):
            with opener(path, "w") as target:
                target.writestr("fluxheim-test/a", "a")
                target.writestr("fluxheim-test/a/b", "b")
        expected = archive.inventory(self.zip, self.bundle)
        with patch.object(archive, "inventory", return_value=expected), self.assertRaises(FileExistsError):
            archive.extract_pair(self.tar, self.zip, self.bundle, self.root / "extract")

    def test_executable_architectures(self):
        binary = self.root / "binary"
        for machine, label in ((62, "x86_64-linux"), (183, "aarch64-linux")):
            header = bytearray(64)
            header[:6] = b"\x7fELF\x02\x01"
            struct.pack_into("<H", header, 18, machine)
            binary.write_bytes(header)
            self.assertEqual(archive.architecture(binary), label)
        header[:4] = b"\xcf\xfa\xed\xfe"
        struct.pack_into("<I", header, 4, 0x100000C)
        binary.write_bytes(header)
        self.assertEqual(archive.architecture(binary), "aarch64-macos")
        header = bytearray(90)
        header[:2] = b"MZ"
        struct.pack_into("<I", header, 60, 64)
        header[64:70], header[88:90] = b"PE\0\0\x64\x86", b"\x0b\x02"
        binary.write_bytes(header)
        self.assertEqual(archive.architecture(binary), "x86_64-windows")
        struct.pack_into("<I", header, 60, 0xFFFFFFFF)
        binary.write_bytes(header)
        with self.assertRaises(ValueError):
            archive.architecture(binary)

    def test_profiles_all_accounted_for(self):
        self.assertEqual(set(CAPABILITIES) | {"config-tester"}, set(PROFILES))
        self.assertEqual({p for p, c in CAPABILITIES.items() if "metrics" in c}, {"full", "wasm"})

    def test_controller_acknowledgement(self):
        with patch("sys.stdin", io.StringIO("stopped\n")):
            acknowledged("stopped")
        for text in ("", "anything\n", "started\n", "x" * 1000):
            with self.subTest(text=text), patch("sys.stdin", io.StringIO(text)):
                with self.assertRaises(RuntimeError):
                    acknowledged("stopped")


if __name__ == "__main__":
    unittest.main()
