#!/usr/bin/env sh
set -eu

mode="${1:-check}"

case "$mode" in
    check | release)
        ;;
    *)
        echo "usage: scripts/stable_release_gate.sh [check|release]" >&2
        exit 2
        ;;
esac

echo "stable release gate: metadata"
scripts/validate-release-metadata.sh
perl scripts/check-doc-links.pl

echo "stable release gate: formatting"
cargo fmt --all --check

echo "stable release gate: lint"
cargo clippy --all-targets -- -D warnings

echo "stable release gate: tests"
cargo test

echo "stable release gate: 1.0 core matrix ($mode)"
scripts/validate-1-0-core.sh "$mode"

echo "stable release gate: 1.0 core smoke"
scripts/smoke_1_0_core.sh

echo "stable release gate: dependency and license policy"
cargo deny check
cargo audit

if [ "${FLUXHEIM_GATE_TLS_BACKENDS:-0}" = "1" ]; then
    echo "stable release gate: TLS backend matrix ($mode)"
    scripts/validate-tls-backends.sh "$mode"
else
    echo "stable release gate: skipping TLS backend matrix; set FLUXHEIM_GATE_TLS_BACKENDS=1 to enable"
fi

if [ "${FLUXHEIM_GATE_TLS_SCAN:-0}" = "1" ]; then
    echo "stable release gate: local TLS scan"
    scripts/tls_scan_local.sh
else
    echo "stable release gate: skipping local TLS scan; set FLUXHEIM_GATE_TLS_SCAN=1 to enable"
fi

if [ "${FLUXHEIM_GATE_LOAD:-0}" = "1" ]; then
    echo "stable release gate: 1.0 local load smoke"
    scripts/load_smoke_1_0.sh
else
    echo "stable release gate: skipping local load smoke; set FLUXHEIM_GATE_LOAD=1 to enable"
fi

if [ "${FLUXHEIM_GATE_FRAMING:-0}" = "1" ]; then
    echo "stable release gate: request framing smoke"
    scripts/smoke_request_framing.sh
else
    echo "stable release gate: skipping request framing smoke; set FLUXHEIM_GATE_FRAMING=1 to enable"
fi

if [ "${FLUXHEIM_GATE_FUZZ_CHECK:-0}" = "1" ]; then
    echo "stable release gate: fuzz target compile check"
    scripts/validate-fuzz-targets.sh
else
    echo "stable release gate: skipping fuzz target compile check; set FLUXHEIM_GATE_FUZZ_CHECK=1 to enable"
fi

if [ "${FLUXHEIM_GATE_PODMAN:-0}" = "1" ]; then
    echo "stable release gate: Podman smoke"
    scripts/podman_smoke.sh
    if [ "${FLUXHEIM_GATE_PODMAN_VARIANTS:-0}" = "1" ]; then
        scripts/podman_smoke_variants.sh
    fi
else
    echo "stable release gate: skipping Podman smoke; set FLUXHEIM_GATE_PODMAN=1 to enable"
fi

echo "stable release gate: ok"
