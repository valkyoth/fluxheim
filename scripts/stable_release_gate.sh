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

echo "stable release gate: modularity policy"
scripts/validate-modularity-policy.sh check

echo "stable release gate: instant-acme patch provenance"
scripts/validate-instant-acme-patch.sh

echo "stable release gate: ACME mount-boundary test plan"
scripts/validate-acme-mount-boundary-plan.sh

if [ "$mode" = "release" ]; then
    echo "stable release gate: runtime baseline"
    scripts/capture-runtime-baseline.sh release
else
    echo "stable release gate: runtime baseline dependency surface"
    scripts/capture-runtime-baseline.sh check
fi

echo "stable release gate: Pingora dependency policy"
scripts/validate-pingora-dependency-policy.sh check

echo "stable release gate: native web TLS build proof"
scripts/validate-native-web-tls.sh "$mode"

echo "stable release gate: native runtime cutover evidence"
scripts/validate-native-runtime-cutover.sh

echo "stable release gate: Pingora HTTP/error boundary policy"
scripts/validate-pingora-boundary-policy.sh check

echo "stable release gate: runtime parity fixture inventory"
scripts/validate-runtime-fixtures.sh check

echo "stable release gate: Wasm example parity plan"
scripts/validate-wasm-example-plan.sh

if [ "$mode" = "release" ]; then
    echo "stable release gate: compatible crate freshness"
    scripts/check_latest_crates.sh
else
    echo "stable release gate: skipping crate freshness check in check mode"
fi

echo "stable release gate: formatting"
cargo fmt --all --check

echo "stable release gate: lint"
cargo clippy --workspace --all-targets -- -D warnings

echo "stable release gate: tests"
cargo test --workspace

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

echo "stable release gate: native HTTP/1 listener/proxy smoke"
scripts/smoke_native_http1_proxy.sh

echo "stable release gate: admin listener smoke"
scripts/smoke_admin_listener.sh

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

if [ "${FLUXHEIM_GATE_SMOKE_IMAGES:-0}" = "1" ]; then
    echo "stable release gate: smoke dependency image check"
    scripts/check_smoke_images.sh
else
    echo "stable release gate: skipping smoke dependency image check; set FLUXHEIM_GATE_SMOKE_IMAGES=1 to enable"
fi

if [ "${FLUXHEIM_GATE_OPENBAO:-0}" = "1" ]; then
    echo "stable release gate: OpenBao cache encryption smoke"
    scripts/smoke_openbao_cache_encryption.sh
else
    echo "stable release gate: skipping OpenBao cache encryption smoke; set FLUXHEIM_GATE_OPENBAO=1 to enable"
fi

if [ "${FLUXHEIM_GATE_DB_HEALTH:-0}" = "1" ]; then
    echo "stable release gate: database health-check smokes"
    scripts/smoke_redis_health_check.sh
    scripts/smoke_mysql_health_check.sh
    scripts/smoke_postgres_health_check.sh
else
    echo "stable release gate: skipping database health-check smokes; set FLUXHEIM_GATE_DB_HEALTH=1 to enable"
fi

if [ "${FLUXHEIM_GATE_WORDPRESS:-0}" = "1" ]; then
    echo "stable release gate: WordPress live smokes"
    scripts/smoke_wordpress_php_fpm.sh both
    scripts/smoke_wordpress_proxy_tls.sh
else
    echo "stable release gate: skipping WordPress live smokes; set FLUXHEIM_GATE_WORDPRESS=1 to enable"
fi

if [ "${FLUXHEIM_GATE_WASM:-0}" = "1" ]; then
    echo "stable release gate: complete Wasm smoke"
    scripts/smoke_wasm_all.sh
else
    echo "stable release gate: skipping Wasm sandbox smoke; set FLUXHEIM_GATE_WASM=1 to enable"
fi

if [ "${FLUXHEIM_GATE_WASM_CONTAINER:-0}" = "1" ]; then
    echo "stable release gate: Wasm container plugin-mount smoke"
    scripts/smoke_wasm_container.sh
else
    echo "stable release gate: skipping Wasm container smoke; set FLUXHEIM_GATE_WASM_CONTAINER=1 to enable"
fi

if [ "${FLUXHEIM_GATE_PHP_WOLFI:-0}" = "1" ]; then
    echo "stable release gate: PHP Wolfi image smoke"
    scripts/smoke_fluxheim_php_wolfi.sh
else
    echo "stable release gate: skipping PHP Wolfi image smoke; set FLUXHEIM_GATE_PHP_WOLFI=1 to enable"
fi

if [ "${FLUXHEIM_GATE_RPM_BUILD:-0}" = "1" ]; then
    echo "stable release gate: RPM build smoke"
    scripts/build_fluxheim_rpm.py latest native --target "${FLUXHEIM_GATE_RPM_TARGET:-fedora-44}"
else
    echo "stable release gate: skipping RPM build smoke; set FLUXHEIM_GATE_RPM_BUILD=1 to enable"
fi

if [ "${FLUXHEIM_GATE_PRIVACY:-0}" = "1" ]; then
    echo "stable release gate: privacy-mode smoke"
    scripts/smoke_privacy_mode.sh
else
    echo "stable release gate: skipping privacy-mode smoke; set FLUXHEIM_GATE_PRIVACY=1 to enable"
fi

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

if [ "${FLUXHEIM_GATE_FIPS_IMAGES:-0}" = "1" ]; then
    echo "stable release gate: FIPS backend image evidence"
    scripts/smoke_fips_backend_images.sh all
else
    echo "stable release gate: skipping FIPS backend image evidence; set FLUXHEIM_GATE_FIPS_IMAGES=1 to enable"
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

if [ "${FLUXHEIM_GATE_LOAD_BALANCER_CONTAINER:-0}" = "1" ]; then
    echo "stable release gate: load-balancer container runtime smoke"
    scripts/smoke_load_balancer_container.sh
else
    echo "stable release gate: skipping load-balancer container runtime smoke; set FLUXHEIM_GATE_LOAD_BALANCER_CONTAINER=1 to enable"
fi

if [ "${FLUXHEIM_GATE_UDP:-0}" = "1" ]; then
    echo "stable release gate: UDP beta smoke"
    scripts/smoke_udp_proxy.sh
else
    echo "stable release gate: skipping UDP beta smoke; set FLUXHEIM_GATE_UDP=1 to enable"
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

if [ "${FLUXHEIM_GATE_ACME_MOUNT_BOUNDARY:-0}" = "1" ]; then
    echo "stable release gate: isolated ACME mount-boundary smoke"
    scripts/smoke_acme_mount_boundary.sh
else
    echo "stable release gate: skipping isolated ACME mount-boundary smoke; set FLUXHEIM_GATE_ACME_MOUNT_BOUNDARY=1 to enable"
fi

if [ "$mode" = "release" ] && [ "${FLUXHEIM_SKIP_IMAGE_GATE:-0}" != "1" ]; then
    echo "stable release gate: required Podman image smoke"
    scripts/podman_smoke.sh
    FLUXHEIM_CONTAINER_VARIANTS="${FLUXHEIM_GATE_IMAGE_VARIANTS:-debian alpine}" \
        scripts/podman_smoke_variants.sh
elif [ "$mode" = "release" ]; then
    echo "stable release gate: skipping required image smoke because FLUXHEIM_SKIP_IMAGE_GATE=1" >&2
elif [ "${FLUXHEIM_GATE_PODMAN:-0}" = "1" ]; then
    echo "stable release gate: optional Podman smoke"
    scripts/podman_smoke.sh
    if [ "${FLUXHEIM_GATE_PODMAN_VARIANTS:-0}" = "1" ]; then
        scripts/podman_smoke_variants.sh
    fi
else
    echo "stable release gate: skipping Podman smoke; set FLUXHEIM_GATE_PODMAN=1 to enable"
fi

echo "stable release gate: ok"
