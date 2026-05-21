#!/usr/bin/env sh
set -eu

mode="${1:-check}"

case "$mode" in
    check)
        cargo_action="check"
        cargo_run_release=""
        ;;
    release)
        cargo_action="build --release"
        cargo_run_release="--release"
        ;;
    *)
        echo "usage: scripts/validate-fips-openssl.sh [check|release]" >&2
        exit 2
        ;;
esac

features="profile-fips-openssl"
require_provider="${FLUXHEIM_REQUIRE_FIPS_PROVIDER:-0}"
work_dir="target/fips-openssl-validation"
runtime_config="$work_dir/config.toml"

scripts/validate-features.sh "$features"

echo "fips openssl: cargo $cargo_action --no-default-features --features $features"
cargo $cargo_action --no-default-features --features "$features" --bin fluxheim --bin fluxheim-config-tester

echo "fips openssl: OpenSSL provider list"
if command -v openssl >/dev/null 2>&1; then
    if ! openssl list -providers -provider fips -provider base; then
        echo "fips openssl: openssl provider list failed; continuing unless FLUXHEIM_REQUIRE_FIPS_PROVIDER=1"
    fi
else
    echo "fips openssl: openssl command not found; continuing unless FLUXHEIM_REQUIRE_FIPS_PROVIDER=1"
fi

echo "fips openssl: fluxheim crypto diagnostics"
crypto_output="$(
    cargo run -q $cargo_run_release --no-default-features --features "$features" --bin fluxheim -- crypto
)"
printf '%s\n' "$crypto_output"

case "$crypto_output" in
    *"openssl_fips_provider: available"*)
        provider_available=1
        ;;
    *)
        provider_available=0
        ;;
esac

if [ "$provider_available" != "1" ]; then
    if [ "$require_provider" = "1" ]; then
        echo "fips openssl: OpenSSL FIPS provider is required but not available" >&2
        exit 1
    fi
    echo "fips openssl: provider unavailable; verified fail-closed diagnostics only"
    exit 0
fi

echo "fips openssl: config fixture"
cargo run -q $cargo_run_release --no-default-features --features "$features" --bin fluxheim-config-tester -- \
    --config examples/fips-openssl.toml \
    --profile fips-openssl \
    --no-runtime-paths \
    --crypto

mkdir -p "$work_dir"
cat >"$runtime_config" <<EOF
[server]
listen = ["127.0.0.1:0"]

[server.process]
pid_file = "$PWD/$work_dir/fluxheim.pid"
upgrade_sock = "$PWD/$work_dir/fluxheim-upgrade.sock"
certificate_reload_sock = "$PWD/$work_dir/fluxheim-cert-reload.sock"

[tls]
enabled = true
backend = "openssl"
curve_preferences = ["CurveP256", "CurveP384"]
cipher_suites = ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"]

[tls.fips]
required = true
EOF

echo "fips openssl: runtime validation with provider"
cargo run -q $cargo_run_release --no-default-features --features "$features" --bin fluxheim-config-tester -- \
    --config "$runtime_config" \
    --profile fips-openssl

echo "fips openssl: ok"
