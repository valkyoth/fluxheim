#!/usr/bin/env python3
"""Validate the shared Linux, macOS, and Windows portable archive matrix."""

from __future__ import annotations

import re
import subprocess
import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
BUILDER = ROOT / "scripts" / "build_release_assets.sh"
PROFILES = {
    "full": "profile-full,acme-client,metrics,metrics-otlp,otel-tracing,otel-otlp",
    "wasm": "profile-wasm,acme-client,metrics,metrics-otlp,otel-tracing,otel-otlp",
    "cache": "profile-cache-edge,acme-client",
    "proxy": "profile-proxy-edge,acme-client",
    "load-balancer": "profile-load-balancer-edge,acme-client",
    "php": "profile-web-server,php-fpm,acme-client",
    "config-tester": "profile-development",
}
PLATFORMS = (
    ("linux", "x86_64-unknown-linux-gnu", "x86_64-linux", ""),
    ("macos", "aarch64-apple-darwin", "aarch64-macos", ""),
    ("windows", "x86_64-pc-windows-msvc", "x86_64-windows", ".exe"),
)


def package_version() -> str:
    cargo = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    return cargo["package"]["version"]


def release_plan(
    version: str, kind: str, target: str, profile: str = "all"
) -> list[tuple[str, str, str]]:
    result = subprocess.run(
        (
            str(BUILDER),
            version,
            "--kind",
            kind,
            "--target",
            target,
            "--profile",
            profile,
            "--plan",
        ),
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    rows = []
    for line in result.stdout.splitlines():
        parts = line.split("|")
        if len(parts) != 3:
            raise ValueError(f"malformed release plan row: {line!r}")
        rows.append((parts[0], parts[1], parts[2]))
    return rows


def expect_plan_rejection(version: str, kind: str, target: str) -> None:
    result = subprocess.run(
        (
            str(BUILDER),
            version,
            "--kind",
            kind,
            "--target",
            target,
            "--plan",
        ),
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if result.returncode == 0:
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
    version = package_version()
    for platform in PLATFORMS:
        validate_platform(version, *platform)
    expect_plan_rejection(version, "windows", "x86_64-unknown-linux-gnu")
    expect_plan_rejection(version, "linux", "../../escape")
    print("portable release plan: ok")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, subprocess.CalledProcessError, ValueError) as error:
        print(f"portable release plan: {error}", file=sys.stderr)
        raise SystemExit(1) from error
