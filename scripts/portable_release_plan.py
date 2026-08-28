#!/usr/bin/env python3
"""Build the portable release archive plan without requiring a shell."""

from __future__ import annotations

import argparse
import re
import sys


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
TARGET_LABELS = {
    "x86_64-unknown-linux-gnu": "x86_64-linux",
    "x86_64-unknown-linux-musl": "x86_64-linux",
    "aarch64-unknown-linux-gnu": "aarch64-linux",
    "aarch64-unknown-linux-musl": "aarch64-linux",
    "aarch64-apple-darwin": "aarch64-macos",
    "x86_64-pc-windows-msvc": "x86_64-windows",
    "aarch64-pc-windows-msvc": "aarch64-windows",
}


def _validate_inputs(version: str, kind: str, target: str, profile: str) -> None:
    if not re.fullmatch(r"[0-9A-Za-z][0-9A-Za-z._+-]*", version) or ".." in version:
        raise ValueError(f"unsafe release version: {version}")
    if not re.fullmatch(r"[0-9A-Za-z_-]+", target):
        raise ValueError(f"unsafe Rust target: {target}")
    if kind not in {"linux", "macos", "windows", "macos-dev"}:
        raise ValueError(f"unsupported release kind: {kind}")
    if profile != "all" and profile not in PROFILES:
        raise ValueError(f"unsupported release profile: {profile}")
    if kind == "linux" and "-linux-" not in target:
        raise ValueError(f"--kind linux requires a Linux target, got {target}")
    if kind in {"macos", "macos-dev"} and target != "aarch64-apple-darwin":
        raise ValueError(
            f"--kind {kind} supports only aarch64-apple-darwin, got {target}"
        )
    if kind == "windows" and not target.endswith("-windows-msvc"):
        raise ValueError(f"--kind windows requires a Windows MSVC target, got {target}")
    if kind == "macos-dev" and profile != "all":
        raise ValueError("--profile is not supported with --kind macos-dev")


def release_plan(
    version: str, kind: str, target: str, profile: str = "all"
) -> list[tuple[str, str, str]]:
    _validate_inputs(version, kind, target, profile)
    label = TARGET_LABELS.get(target, target)
    suffix = ".exe" if target.endswith("-windows-msvc") else ""
    if kind == "macos-dev":
        return [
            (
                f"fluxheim-{version}-dev-{label}",
                "profile-development",
                f"fluxheim{suffix},fluxheim-acme{suffix},fluxheim-config-tester{suffix}",
            )
        ]

    selected = PROFILES if profile == "all" else {profile: PROFILES[profile]}
    rows = []
    for name, features in selected.items():
        binaries = (
            f"fluxheim-config-tester{suffix}"
            if name == "config-tester"
            else f"fluxheim{suffix},fluxheim-acme{suffix}"
        )
        rows.append((f"fluxheim-{version}-{name}-{label}", features, binaries))
    return rows


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("version")
    parser.add_argument("--kind", required=True)
    parser.add_argument("--target", required=True)
    parser.add_argument("--profile", default="all")
    args = parser.parse_args()
    for row in release_plan(args.version, args.kind, args.target, args.profile):
        print("|".join(row))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as error:
        print(f"portable release plan: {error}", file=sys.stderr)
        raise SystemExit(2) from error
