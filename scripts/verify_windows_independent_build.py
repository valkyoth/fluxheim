#!/usr/bin/env python3
"""Compare disposable-builder Windows archives with GitHub's independent build."""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import re
from pathlib import Path


CHECKSUM_RE = re.compile(r"^([0-9a-f]{64})  (fluxheim-[0-9A-Za-z.-]+-x86_64-windows[.]zip)$")
EVIDENCE_RE = re.compile(r"^([a-z][a-z0-9_]+)=([^\r\n]+)$")
VERSION_RE = re.compile(r"^[0-9]+[.][0-9]+[.][0-9]+(?:-[0-9A-Za-z.-]+)?$")
COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
PROFILES = ("full", "wasm", "cache", "proxy", "load-balancer", "php", "config-tester")


def fail(message: str) -> None:
    raise SystemExit(f"independent Windows build verification: {message}")


def parse_evidence(path: Path) -> dict[str, str]:
    if not path.is_file() or path.is_symlink():
        fail(f"evidence file is missing or unsafe: {path}")
    result: dict[str, str] = {}
    for line in path.read_text(encoding="ascii").splitlines():
        match = EVIDENCE_RE.fullmatch(line)
        if match is None or match.group(1) in result:
            fail(f"invalid evidence line in {path.name}")
        result[match.group(1)] = match.group(2)
    return result


def parse_checksums(path: Path) -> dict[str, str]:
    if not path.is_file() or path.is_symlink():
        fail(f"checksum file is missing or unsafe: {path}")
    result: dict[str, str] = {}
    for line in path.read_text(encoding="ascii").splitlines():
        match = CHECKSUM_RE.fullmatch(line)
        if match is None or match.group(2) in result:
            fail(f"invalid checksum line in {path.name}")
        result[match.group(2)] = match.group(1)
    if len(result) != 7:
        fail(f"expected seven checksums in {path.name}, found {len(result)}")
    return result


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_archives(root: Path, expected: dict[str, str]) -> None:
    archives = {
        path.name: path
        for path in root.glob("fluxheim-*-x86_64-windows.zip")
        if path.is_file() and not path.is_symlink()
    }
    if set(archives) != set(expected):
        fail(f"archive inventory does not match checksums in {root}")
    for name, expected_hash in expected.items():
        actual_hash = sha256(archives[name])
        if actual_hash != expected_hash:
            fail(f"archive checksum mismatch in {root}: {name}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--expected-commit", required=True)
    parser.add_argument("disposable_builder_directory", type=Path)
    parser.add_argument("independent_ci_directory", type=Path)
    args = parser.parse_args()
    if VERSION_RE.fullmatch(args.expected_version) is None:
        fail("expected version is invalid")
    if COMMIT_RE.fullmatch(args.expected_commit) is None:
        fail("expected commit is invalid")
    expected_tag = f"v{args.expected_version}"
    expected_names = {
        f"fluxheim-{args.expected_version}-{profile}-x86_64-windows.zip"
        for profile in PROFILES
    }

    for root in (args.disposable_builder_directory, args.independent_ci_directory):
        if root.is_symlink():
            fail(f"evidence directory must not be a symlink: {root}")
    local_root = args.disposable_builder_directory.resolve(strict=True)
    independent_root = args.independent_ci_directory.resolve(strict=True)
    local_evidence = parse_evidence(local_root / "release-evidence-x86_64-windows.txt")
    independent_evidence = parse_evidence(
        independent_root / "release-evidence-independent-x86_64-windows.txt"
    )
    for key, expected in (
        ("builder_mode", "fresh-disposable"),
        ("toolchain_read_only", "true"),
        ("cargo_home_scope", "per-run"),
        ("cargo_config_scope", "trusted-cwd"),
        ("environment_scope", "allowlist"),
        ("independent_windows_build_required", "true"),
    ):
        if local_evidence.get(key) != expected:
            fail(f"disposable-builder evidence does not assert {key}={expected}")
    if local_evidence.get("archive_count") != "7" or local_evidence.get("reproducible") != "true":
        fail("disposable-builder evidence does not assert seven reproducible archives")
    if independent_evidence.get("archive_count") != "7":
        fail("independent evidence does not assert seven archives")
    for evidence_name, evidence in (
        ("disposable-builder", local_evidence),
        ("independent", independent_evidence),
    ):
        if evidence.get("version") != args.expected_version or evidence.get("tag") != expected_tag:
            fail(f"{evidence_name} evidence does not match the intended release version")
    if not re.fullmatch(r"[0-9a-f]{32}", local_evidence.get("builder_id", "")):
        fail("disposable-builder evidence has an invalid builder identity")
    if not re.fullmatch(
        r"[0-9a-f]{64}", local_evidence.get("toolchain_manifest_sha256", "")
    ):
        fail("disposable-builder evidence has an invalid toolchain manifest hash")
    toolchain_manifest_path = (
        local_root / "toolchain-provisioning-x86_64-windows.json"
    )
    if not toolchain_manifest_path.is_file() or toolchain_manifest_path.is_symlink():
        fail("disposable-builder toolchain manifest is missing or unsafe")
    if sha256(toolchain_manifest_path) != local_evidence["toolchain_manifest_sha256"]:
        fail("disposable-builder toolchain manifest hash does not match evidence")
    try:
        toolchain_manifest = json.loads(toolchain_manifest_path.read_text(encoding="utf-8-sig"))
    except (UnicodeError, json.JSONDecodeError):
        fail("disposable-builder toolchain manifest is invalid JSON")
    if (
        toolchain_manifest.get("schema") != 1
        or toolchain_manifest.get("builder_mode") != "fresh-disposable"
        or toolchain_manifest.get("builder_id") != local_evidence["builder_id"]
        or toolchain_manifest.get("rust_target") != "x86_64-pc-windows-msvc"
        or not toolchain_manifest.get("files")
    ):
        fail("disposable-builder toolchain manifest does not match release evidence")
    try:
        provisioned = datetime.datetime.fromisoformat(
            local_evidence.get("builder_provisioned_utc", "").replace("Z", "+00:00")
        )
    except ValueError:
        fail("disposable-builder evidence has an invalid provisioning timestamp")
    if provisioned.tzinfo is None:
        fail("disposable-builder provisioning timestamp has no timezone")
    if independent_evidence.get("builder_domain") != "github-hosted-windows-2025":
        fail("independent evidence has an unexpected builder domain")
    local_commit = local_evidence.get("commit", "")
    independent_commit = independent_evidence.get("commit", "")
    if COMMIT_RE.fullmatch(local_commit) is None or COMMIT_RE.fullmatch(independent_commit) is None:
        fail("builder evidence has an invalid commit identity")
    if local_commit != args.expected_commit or independent_commit != args.expected_commit:
        fail("builder evidence does not match the intended release commit")
    if local_commit != independent_commit:
        fail("builder domains did not build the same commit")

    local_checksums = parse_checksums(local_root / "SHA256SUMS-x86_64-windows.txt")
    independent_checksums = parse_checksums(
        independent_root / "SHA256SUMS-independent-x86_64-windows.txt"
    )
    if set(local_checksums) != expected_names or set(independent_checksums) != expected_names:
        fail("archive inventory does not match the intended release")
    verify_archives(local_root, local_checksums)
    verify_archives(independent_root, independent_checksums)
    if local_checksums != independent_checksums:
        fail("independent builder domains produced different Windows archives")

    print("independent Windows build verification: ok")


if __name__ == "__main__":
    main()
