"""Bounded archive inspection for native qualification, not a package installer."""
import hashlib
import os
from pathlib import Path
import re
import stat
import struct
import tarfile
import zipfile

MAX_FILES = 4096
MAX_FILE = 512 * 1024 * 1024
MAX_TOTAL = 2 * 1024 * 1024 * 1024
RESERVED = re.compile(r"(?:con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\..*)?", re.I)


def member_path(name, bundle):
    parts = name.rstrip("/").split("/")
    if (not parts or parts[0] != bundle or len(name) > 1024
            or any(not p or p in (".", "..") or p[-1:] in (".", " ")
                   or RESERVED.fullmatch(p) or any(ord(c) < 32 or c in '\\:<>"|?*' for c in p)
                   for p in parts)):
        raise ValueError("unsafe archive member")
    return Path(*parts)


def digest(stream, size):
    if not 0 <= size <= MAX_FILE:
        raise ValueError("archive member exceeds limit")
    value = hashlib.sha256()
    remaining = size
    while remaining:
        block = stream.read(min(1024 * 1024, remaining))
        if not block:
            raise ValueError("truncated archive member")
        value.update(block)
        remaining -= len(block)
    if stream.read(1):
        raise ValueError("archive member size mismatch")
    return value.hexdigest()


def inventory(archive, bundle):
    result, seen, total = {}, set(), 0
    is_zip = archive.suffix == ".zip"
    with (zipfile.ZipFile(archive) if is_zip else tarfile.open(archive, "r:gz")) as source:
        entries = source.infolist() if is_zip else source
        for number, entry in enumerate(entries, 1):
            if number > MAX_FILES:
                raise ValueError("too many archive members")
            name = entry.filename if is_zip else entry.name
            relative = member_path(name, bundle)
            key = relative.as_posix()
            if key.casefold() in seen:
                raise ValueError("duplicate or case-aliased archive member")
            seen.add(key.casefold())
            if is_zip:
                mode = entry.external_attr >> 16
                directory = entry.is_dir()
                if stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR) or entry.flag_bits & 1:
                    raise ValueError("linked, special or encrypted archive member")
                size = entry.file_size
            else:
                directory = entry.isdir()
                if not directory and not entry.isfile():
                    raise ValueError("linked or special archive member")
                size = entry.size
            if directory:
                continue
            total += size
            if total > MAX_TOTAL:
                raise ValueError("archive exceeds total size limit")
            with (source.open(entry) if is_zip else source.extractfile(entry)) as stream:
                result[key] = (size, digest(stream, size))
    if not result:
        raise ValueError("empty archive")
    return result


def extract_pair(tar_path, zip_path, bundle, destination):
    """Re-read and hash every extracted file; never preserve links or permissions."""
    expected = inventory(tar_path, bundle)
    if inventory(zip_path, bundle) != expected:
        raise ValueError("tar/ZIP payload mismatch")
    destination.mkdir(mode=0o700)  # Must be a fresh, caller-owned private directory.
    with zipfile.ZipFile(zip_path) as source:
        seen = set()
        for entry in source.infolist():
            relative = member_path(entry.filename, bundle)
            if entry.is_dir():
                continue
            key = relative.as_posix()
            if key not in expected or key in seen or entry.file_size != expected[key][0]:
                raise ValueError("ZIP changed during verification")
            seen.add(key)
            target = destination / relative
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            value = hashlib.sha256()
            remaining = entry.file_size
            with source.open(entry) as src, target.open("xb") as dst:
                while remaining:
                    block = src.read(min(1024 * 1024, remaining))
                    if not block:
                        raise ValueError("truncated ZIP member")
                    remaining -= len(block)
                    value.update(block)
                    dst.write(block)
                if src.read(1) or value.hexdigest() != expected[key][1]:
                    raise ValueError("ZIP changed during extraction")
            target.chmod(0o600)
        if seen != set(expected):
            raise ValueError("ZIP lost members during verification")
    return destination / bundle


def architecture(binary):
    with binary.open("rb") as source:
        header = source.read(64)
        if len(header) < 64:
            raise ValueError("truncated executable")
        if header[:4] == b"\x7fELF" and header[4:6] == b"\x02\x01":
            return {62: "x86_64-linux", 183: "aarch64-linux"}.get(struct.unpack_from("<H", header, 18)[0])
        if header[:4] == b"\xcf\xfa\xed\xfe":
            return "aarch64-macos" if struct.unpack_from("<I", header, 4)[0] == 0x100000C else None
        if header[:2] == b"MZ":
            offset = struct.unpack_from("<I", header, 60)[0]
            if not 64 <= offset <= 1024 * 1024:
                raise ValueError("invalid PE header offset")
            source.seek(offset)
            pe = source.read(26)
            if len(pe) == 26 and pe[:6] == b"PE\0\0\x64\x86" and pe[24:] == b"\x0b\x02":
                return "x86_64-windows"
    raise ValueError("unsupported executable architecture")


def executable(bundle, name, label):
    binary = bundle / name
    if architecture(binary) != label:
        raise ValueError("archive executable architecture mismatch")
    if os.name != "nt":
        binary.chmod(0o700)
    return binary
