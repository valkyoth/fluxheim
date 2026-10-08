#!/usr/bin/env python3
"""Commit 1's source/scope gate; never enables protocol code in Fluxheim."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROBE = ROOT / "tools/http3-source-probe"
REQUIREMENTS = dict(zip(
    "source-lock semantic-baseline configuration artifact-features shared-streaming "
    "crypto-boundary quic-tls udp-lifecycle admission address-policy control-qpack "
    "priority-policy request-adaptation response-adaptation static-routing origin-bridges "
    "security-policy stateful-parity observability reload discovery-drain packaging "
    "linux-live macos-live windows-live interop-impairment operator-contract release-qualification".split(),
    [1, 2, 3, 3, 4, 4, 5, 6, 7, 7, 8, 8, 9, 10, 11, 12, 13, 14, 15, 16, 16, 17, 18, 19, 20, 21, 22, 23],
    strict=True,
))
EXCLUDED = set("origin-http3 zero-rtt active-migration preferred-address multipath "
               "quic-datagram connect-udp masque webtransport extended-connect server-push "
               "dynamic-qpack brynja-backend windows-arm64 macos-intel".split())
FEATURES = {"profile-full", "http3", "php-fpm", "acme-client", "metrics", "metrics-otlp", "otel-tracing", "otel-otlp"}
PLATFORMS = {"x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu", "aarch64-apple-darwin", "x86_64-pc-windows-msvc"}


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def validate_scope(data: dict, acceptance: bool = False) -> None:
    require(data["schema"] == 1 and data["checkpoint"] == 1, "unsupported source-lock schema/checkpoint")
    for key in ("baseline", "release_baseline"):
        require(re.fullmatch(r"[0-9a-f]{40}", data[key]) is not None, "invalid baseline")
    rows = data["requirements"]
    require(len(rows) == len(REQUIREMENTS), "missing or duplicate requirement")
    require({row["id"] for row in rows} == set(REQUIREMENTS), "unclassified requirement")
    for row in rows:
        require(row["owner"] == REQUIREMENTS[row["id"]], "requirement ownership changed")
        require(bool(row["contract"].strip()), "empty requirement contract")
        require(row["standard"] in {"local", "RFC8999", "RFC9000", "RFC9001", "RFC9002", "RFC9114", "RFC9204", "RFC9218"}, "unknown standard")
    for key, expected in (("excluded", EXCLUDED), ("artifact_features", FEATURES), ("platforms", PLATFORMS)):
        require(set(data[key]) == expected and len(data[key]) == len(expected), f"{key} scope drift")
    require(data["proposed_address_policy"] == "reconnect-required", "address proposal changed")
    require(data["address_policy"] in {"pending-approval", "reconnect-required"}, "unknown address policy")
    if acceptance:
        require(data["address_policy"] != "pending-approval", "address-policy approval is still required")


def dependency_names(table: dict) -> set[str]:
    names = set()
    for key, value in table.items():
        if key in {"dependencies", "dev-dependencies", "build-dependencies"}:
            for name, spec in value.items():
                names.add(spec.get("package", name) if isinstance(spec, dict) else name)
        elif isinstance(value, dict):
            names.update(dependency_names(value))
    return names


def validate_sources(data: dict, manifest: dict, lock_bytes: bytes, production_names: set[str]) -> None:
    require(hashlib.sha256(lock_bytes).hexdigest() == data["probe_lock_sha256"], "probe transitive lock drift")
    lock = tomllib.loads(lock_bytes.decode())
    packages = lock["package"]
    for name, version in data["pins"].items():
        matches = [p for p in packages if p["name"] == name]
        require(len(matches) == 1 and matches[0]["version"] == version, f"pin drift: {name}")
    for p in packages:
        if p["name"] == "fluxheim-http3-source-probe":
            continue
        require(p.get("source") == "registry+https://github.com/rust-lang/crates.io-index", "non-registry probe source")
        require(re.fullmatch(r"[0-9a-f]{64}", p.get("checksum", "")) is not None, "missing source checksum")
        require(not p["name"].startswith("brynja"), "Brynja is future-only")
    require(manifest.get("workspace") == {}, "probe must remain an isolated workspace")
    require(manifest["package"]["publish"] is False, "probe must not be publishable")
    require(manifest["package"]["rust-version"] == data["rust"], "probe Rust drift")
    for name, spec in manifest["dependencies"].items():
        version = spec if isinstance(spec, str) else spec["version"]
        require(version == "=" + data["pins"][name], f"unpinned direct probe dependency: {name}")
    require(manifest["features"] == {
        "default": ["ring"],
        "ring": ["quinn/rustls-ring", "rustls/ring", "rcgen/ring"],
        "aws-lc": ["quinn/rustls-aws-lc-rs", "rustls/aws_lc_rs", "rcgen/aws_lc_rs"],
    }, "probe provider feature drift")
    for name in ("quinn", "h3", "h3-quinn", "rustls", "rcgen", "tokio"):
        require(manifest["dependencies"][name].get("default-features") is False, f"implicit defaults: {name}")
    require(manifest["dependencies"]["quinn"]["features"] == ["runtime-tokio"], "forbidden QUIC feature")
    require(not manifest["dependencies"]["h3-quinn"].get("features"), "forbidden H3 extension")
    require(not any(n.startswith(("quinn", "h3", "brynja")) for n in production_names), "probe dependencies entered production graph")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--acceptance", action="store_true", help="also require resolved scope approval; pentest/CI remain external gates")
    args = parser.parse_args()
    data = json.loads((ROOT / "docs/http3-source-lock.json").read_text())
    validate_scope(data, args.acceptance)
    manifests = [ROOT / "Cargo.toml", *sorted((ROOT / "crates").glob("*/Cargo.toml"))]
    owners = {}
    production_names = {p["name"] for p in tomllib.loads((ROOT / "Cargo.lock").read_text())["package"]}
    for path in manifests:
        table = tomllib.loads(path.read_text())
        names = dependency_names(table)
        production_names.update(names)
        crypto = sorted(names & {"rustls", "ring", "aws-lc-rs"})
        if crypto:
            owners[path.relative_to(ROOT).as_posix()] = crypto
    require(owners == data["existing_crypto_owners"], "existing crypto-owner allowlist drift")
    require(tomllib.loads((ROOT / "rust-toolchain.toml").read_text())["toolchain"]["channel"] == data["rust"], "toolchain drift")
    manifest = tomllib.loads((PROBE / "Cargo.toml").read_text())
    validate_sources(data, manifest, (PROBE / "Cargo.lock").read_bytes(), production_names)
    print(f"HTTP/3 source lock: ok; address policy={data['address_policy']}; no runtime admission")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, KeyError, TypeError, OSError) as error:
        print(f"HTTP/3 source lock: {error}", file=sys.stderr)
        raise SystemExit(1)
