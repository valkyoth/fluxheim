#!/usr/bin/env python3
"""Validate the shared Linux, macOS, and Windows portable archive matrix."""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

from portable_release_plan import PLATFORMS, PROFILES, release_plan


ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "scripts" / "build_release_assets.sh"
CI_WORKFLOW = ROOT / ".github" / "workflows" / "ci.yml"


def package_version() -> str:
    cargo = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    return cargo["package"]["version"]


def expect_plan_rejection(version: str, kind: str, target: str) -> None:
    try:
        release_plan(version, kind, target)
    except ValueError:
        return
    raise ValueError(f"unsafe or mismatched target was accepted: {kind}/{target}")


def validate_platform(
    version: str, kind: str, target: str, label: str, suffix: str
) -> None:
    rows = release_plan(version, kind, target)
    if len(rows) != len(PROFILES):
        raise ValueError(f"{kind} plan has {len(rows)} profiles, expected {len(PROFILES)}")

    seen = set()
    for name, features, binaries in rows:
        match = re.fullmatch(
            rf"fluxheim-{re.escape(version)}-(.+)-{re.escape(label)}", name
        )
        if match is None:
            raise ValueError(f"{kind} plan has unexpected archive name: {name}")
        profile = match.group(1)
        if profile not in PROFILES or profile in seen:
            raise ValueError(f"{kind} plan has unknown or duplicate profile: {profile}")
        seen.add(profile)
        if features != PROFILES[profile]:
            raise ValueError(
                f"{kind} {profile} features differ: {features!r}"
            )
        expected_binaries = (
            f"fluxheim-config-tester{suffix}"
            if profile == "config-tester"
            else f"fluxheim{suffix},fluxheim-acme{suffix}"
        )
        if binaries != expected_binaries:
            raise ValueError(
                f"{kind} {profile} binaries differ: {binaries!r}"
            )

    for profile in PROFILES:
        selected = release_plan(version, kind, target, profile)
        if len(selected) != 1 or f"-{profile}-" not in selected[0][0]:
            raise ValueError(f"{kind} --profile {profile} is not isolated")


def main() -> int:
    builder = BUILDER.read_text(encoding="utf-8")
    if "scripts/portable_release_plan.py" not in builder:
        raise ValueError("release builder does not consume the shared Python plan")

    workflow = CI_WORKFLOW.read_text(encoding="utf-8")
    if "runs-on: macos-15" not in workflow:
        raise ValueError("macOS portable gate is missing its Apple Silicon runner")
    if "aarch64-apple-darwin" not in workflow:
        raise ValueError("macOS portable gate does not verify its Apple Silicon target")
    if "macos-15-intel" in workflow or "x86_64-apple-darwin" in workflow:
        raise ValueError("macOS portable gate still advertises unsupported Intel macOS")
    if 'scripts/build_release_assets.sh "${version}" --kind macos\n' not in workflow:
        raise ValueError("macOS portable gate must build the complete profile matrix")
    if "sh scripts/smoke_macos_native_parity.sh" not in workflow:
        raise ValueError("macOS portable gate must run the native live parity smoke")
    if "wasm-aarch64-macos/fluxheim" not in workflow:
        raise ValueError("macOS portable gate must smoke the staged Wasm archive binary")

    version = package_version()
    for platform in PLATFORMS:
        validate_platform(version, *platform)
    expect_plan_rejection(version, "windows", "x86_64-unknown-linux-gnu")
    expect_plan_rejection(version, "macos", "x86_64-apple-darwin")
    expect_plan_rejection(version, "macos-dev", "x86_64-apple-darwin")
    expect_plan_rejection(version, "linux", "../../escape")
    print("portable release plan: ok")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, ValueError) as error:
        print(f"portable release plan: {error}", file=sys.stderr)
        raise SystemExit(1) from error
