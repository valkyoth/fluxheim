#!/usr/bin/env python3
"""Validate the explicit Wasm distribution boundary."""

from __future__ import annotations

import sys
import tomllib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ValueError(message)


def contains(path: str, text: str) -> bool:
    return text in (ROOT / path).read_text(encoding="utf-8")


def main() -> int:
    cargo = tomllib.loads((ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    features = cargo["features"]
    full = set(features["profile-full"])
    wasm = set(features["profile-wasm"])

    require(
        full.isdisjoint({"wasm", "wasm-proxy-abi", "wasm-wasi"}),
        "profile-full must remain Wasm-free",
    )
    require(
        wasm == {"profile-full", "wasm-proxy-abi", "wasm-wasi"},
        "profile-wasm must be profile-full plus both reviewed Wasm surfaces",
    )
    require(
        contains(".github/workflows/images.yml", "name: wasm")
        and contains(
            ".github/workflows/images.yml",
            "features: profile-wasm,acme-client,metrics,metrics-otlp,otel-tracing,otel-otlp",
        ),
        "container image matrix must publish the Wasm profile",
    )
    require(
        contains(
            "scripts/build_release_assets.sh",
            "bundle_runtime_profile wasm profile-wasm,acme-client,metrics,metrics-otlp,otel-tracing,otel-otlp",
        ),
        "release builder must package the Wasm profile",
    )
    require(
        contains(
            "scripts/smoke_wasm_all.sh", "scripts/smoke_wasm_release_asset.sh"
        ),
        "complete Wasm smoke must execute the packaged release binary",
    )
    require(
        contains(
            "docs/build-and-podman.md",
            "/srv/infra/fluxheim/plugins:/etc/fluxheim/plugins:ro,Z",
        ),
        "container documentation must include the read-only plugin mount",
    )
    require(
        contains(
            "scripts/smoke_wasm_container.sh",
            "$TMP_DIR/plugins:/etc/fluxheim/plugins:ro,Z",
        )
        and contains(
            "scripts/smoke_wasm_container.sh",
            "Wasm container read-only plugin mount smoke: ok",
        ),
        "Wasm image must have a live read-only plugin-mount smoke",
    )
    require(
        contains(
            "docs/wasm-extensibility.md",
            "### Container Plugin Trust Models",
        )
        and contains(
            "docs/wasm-extensibility.md",
            "A `:ro` bind mount is read-only from inside the container",
        )
        and contains(
            "docs/wasm-extensibility.md",
            "High-assurance deployments should build a derivative image",
        )
        and contains(
            "docs/wasm-extensibility.md",
            "Do not bake private keys, admin tokens, ACME EAB keys",
        ),
        "Wasm container docs must preserve the host-mount threat model",
    )
    print("Wasm release profile: ok")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except ValueError as error:
        print(f"Wasm release profile: {error}", file=sys.stderr)
        raise SystemExit(1) from error
