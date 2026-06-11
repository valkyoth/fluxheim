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

if [ "$mode" = "release" ]; then
    echo "stable release gate: compatible crate freshness"
    scripts/check_latest_crates.sh
else
    echo "stable release gate: skipping crate freshness check in check mode"
fi

echo "stable release gate: formatting"
cargo fmt --all --check

echo "stable release gate: lint"
cargo clippy --all-targets -- -D warnings

echo "stable release gate: tests"
cargo test

if [ "${FLUXHEIM_GATE_OWASP_RUN:-0}" = "1" ]; then
    echo "stable release gate: OWASP Top 10 2025 baseline (run)"
    scripts/validate-owasp-top10-2025.sh run
else
    echo "stable release gate: OWASP Top 10 2025 baseline (check)"
    scripts/validate-owasp-top10-2025.sh check
fi

echo "stable release gate: 1.0 core matrix ($mode)"
scripts/validate-1-0-core.sh "$mode"

echo "stable release gate: 1.0 representative fixtures"
scripts/validate-1-0-fixtures.sh

echo "stable release gate: 1.0 core smoke"
FLUXHEIM_SMOKE_SKIP_CORE_MATRIX=1 scripts/smoke_1_0_core.sh

echo "stable release gate: 1.2 cache smoke"
scripts/smoke_proxy_cache.sh

echo "stable release gate: 1.2 storage-bin cache smoke"
scripts/smoke_storage_bin_cache.sh

echo "stable release gate: 1.2 local cache encryption smoke"
scripts/smoke_cache_encryption_local.sh

echo "stable release gate: 1.2 peer-fill cache smoke"
scripts/smoke_peer_fill_cache.sh

echo "stable release gate: 1.2 observability smoke"
scripts/smoke_observability_local.sh

echo "stable release gate: dependency and license policy"
cargo deny check
cargo audit

echo "stable release gate: SBOM"
scripts/generate-sbom.sh

echo "stable release gate: reproducible release build"
scripts/reproducible_build_check.sh

if [ "${FLUXHEIM_GATE_TLS_BACKENDS:-0}" = "1" ]; then
    echo "stable release gate: TLS backend matrix ($mode)"
    scripts/validate-tls-backends.sh "$mode"
else
    echo "stable release gate: skipping TLS backend matrix; set FLUXHEIM_GATE_TLS_BACKENDS=1 to enable"
fi

if [ "${FLUXHEIM_GATE_FIPS_OPENSSL:-0}" = "1" ]; then
    echo "stable release gate: OpenSSL FIPS-capable validation ($mode)"
    scripts/validate-fips-openssl.sh "$mode"
else
    echo "stable release gate: skipping OpenSSL FIPS-capable validation; set FLUXHEIM_GATE_FIPS_OPENSSL=1 to enable"
fi

if [ "${FLUXHEIM_GATE_FIPS_RUSTLS:-0}" = "1" ]; then
    echo "stable release gate: rustls/AWS-LC FIPS-capable validation ($mode)"
    scripts/validate-fips-rustls.sh "$mode"
else
    echo "stable release gate: skipping rustls/AWS-LC FIPS-capable validation; set FLUXHEIM_GATE_FIPS_RUSTLS=1 to enable"
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
