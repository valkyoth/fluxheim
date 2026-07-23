#!/usr/bin/env python3
"""Create portable tar.gz and zip archives from one staged release directory."""

from __future__ import annotations

import argparse
import gzip
import hashlib
import os
import re
import stat
import tarfile
import zipfile
from pathlib import Path
from typing import BinaryIO


SAFE_NAME = re.compile(r"^[0-9A-Za-z][0-9A-Za-z._+-]*$")
ROOT = Path(__file__).resolve().parents[1]
DIST = (ROOT / "dist").resolve()


def admitted_bundle(name: str) -> Path:
    if not SAFE_NAME.fullmatch(name):
        raise ValueError(f"unsafe release bundle name: {name}")
    bundle = (DIST / name).resolve()
    if bundle.parent != DIST or not bundle.is_dir() or bundle.is_symlink():
        raise ValueError(f"release bundle is not a regular staged directory: {name}")
    return bundle


def archive_members(bundle: Path) -> list[Path]:
    members = [bundle]
    members.extend(sorted(bundle.rglob("*")))
    for member in members:
        if member.is_symlink():
            raise ValueError(f"release bundle contains a symlink: {member}")
        if not member.is_dir() and not member.is_file():
            raise ValueError(f"release bundle contains a special file: {member}")
    return members


def normalized_mode(path: Path) -> int:
    if path.is_dir():
        return 0o755
    if path.suffix.lower() == ".exe" or os.access(path, os.X_OK):
        return 0o755
    return 0o644


def create_tar(bundle: Path, members: list[Path], output: Path) -> None:
    with output.open("wb") as destination:
        with gzip.GzipFile(
            filename="", mode="wb", fileobj=destination, mtime=0
        ) as compressed:
            with tarfile.open(
                fileobj=compressed, mode="w", format=tarfile.PAX_FORMAT
            ) as archive:
                for member in members:
                    relative = member.relative_to(DIST)
                    info = archive.gettarinfo(member, arcname=relative.as_posix())
                    info.uid = 0
                    info.gid = 0
                    info.uname = "root"
                    info.gname = "root"
                    info.mode = normalized_mode(member)
                    info.mtime = 0
                    info.pax_headers = {}
                    if member.is_file():
                        with member.open("rb") as source:
                            archive.addfile(info, source)
                    else:
                        archive.addfile(info)


def create_zip(bundle: Path, members: list[Path], output: Path) -> None:
    del bundle
    with zipfile.ZipFile(
        output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9
    ) as archive:
        for member in members:
            relative = member.relative_to(DIST).as_posix()
            is_directory = member.is_dir()
            name = f"{relative}/" if is_directory else relative
            info = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            info.create_system = 3
            mode = normalized_mode(member)
            file_type = stat.S_IFDIR if is_directory else stat.S_IFREG
            info.external_attr = (file_type | mode) << 16
            info.compress_type = zipfile.ZIP_DEFLATED
            if is_directory:
                archive.writestr(info, b"")
            else:
                with member.open("rb") as source:
                    archive.writestr(info, source.read())


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest()


def stream_sha256(source: BinaryIO) -> str:
    digest = hashlib.sha256()
    while chunk := source.read(1024 * 1024):
        digest.update(chunk)
    return digest.hexdigest()


def verify_equivalent(tar_path: Path, zip_path: Path) -> None:
    tar_payloads: dict[str, str | None] = {}
    with tarfile.open(tar_path, "r:gz") as archive:
        for member in archive.getmembers():
            if member.isdir():
                tar_payloads[member.name.rstrip("/")] = None
            elif member.isfile():
                source = archive.extractfile(member)
                if source is None:
                    raise ValueError(f"tar member could not be read: {member.name}")
                with source:
                    tar_payloads[member.name] = stream_sha256(source)
            else:
                raise ValueError(f"tar contains unsupported member: {member.name}")

    zip_payloads: dict[str, str | None] = {}
    with zipfile.ZipFile(zip_path, "r") as archive:
        for member in archive.infolist():
            name = member.filename.rstrip("/")
            if member.is_dir():
                zip_payloads[name] = None
            else:
                with archive.open(member, "r") as source:
                    zip_payloads[name] = stream_sha256(source)

    if tar_payloads != zip_payloads:
        raise ValueError("tar.gz and zip release payloads differ")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("bundle", help="staged directory name below dist/")
    args = parser.parse_args()

    bundle = admitted_bundle(args.bundle)
    members = archive_members(bundle)
    tar_output = DIST / f"{args.bundle}.tar.gz"
    zip_output = DIST / f"{args.bundle}.zip"
    create_tar(bundle, members, tar_output)
    create_zip(bundle, members, zip_output)
    verify_equivalent(tar_output, zip_output)

    for output in (tar_output, zip_output):
        print(f"{sha256(output)}  {output.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
