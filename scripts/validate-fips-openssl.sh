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
case "$mode" in
    release)
        require_provider="${FLUXHEIM_REQUIRE_FIPS_PROVIDER:-1}"
        ;;
    *)
        require_provider="${FLUXHEIM_REQUIRE_FIPS_PROVIDER:-0}"
        ;;
esac
work_dir="target/fips-openssl-validation"
runtime_config="$work_dir/config.toml"
backend_mismatch_config="$work_dir/backend-mismatch.toml"
non_fips_policy_config="$work_dir/non-fips-policy.toml"
repo_root="$(pwd -P)"

case "$repo_root" in
    *\"*|*\\*)
        echo "fips openssl: repository path contains characters unsafe for generated TOML" >&2
        exit 2
        ;;
esac

scripts/validate-features.sh "$features"

echo "fips openssl: cargo $cargo_action --no-default-features --features $features"
cargo $cargo_action --no-default-features --features "$features" --bin fluxheim --bin fluxheim-config-tester

install -d -m 0700 "$work_dir"

cat >"$backend_mismatch_config" <<EOF
[tls]
enabled = true
backend = "rustls"
curve_preferences = ["CurveP256", "CurveP384"]
cipher_suites = ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"]

[tls.fips]
required = true
EOF

cat >"$non_fips_policy_config" <<EOF
[tls]
enabled = true
backend = "openssl"
curve_preferences = ["X25519", "CurveP256"]
cipher_suites = ["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"]

[tls.fips]
required = true
EOF

echo "fips openssl: fail-closed backend mismatch fixture"
if cargo run -q $cargo_run_release --no-default-features --features "$features" --bin fluxheim-config-tester -- \
    --config "$backend_mismatch_config" \
    --profile fips-openssl \
    --no-runtime-paths >/dev/null 2>&1; then
    echo "fips openssl: backend mismatch fixture unexpectedly passed" >&2
    exit 1
fi

echo "fips openssl: fail-closed non-FIPS TLS policy fixture"
if cargo run -q $cargo_run_release --no-default-features --features "$features" --bin fluxheim-config-tester -- \
    --config "$non_fips_policy_config" \
    --profile fips-openssl \
    --no-runtime-paths >/dev/null 2>&1; then
    echo "fips openssl: non-FIPS TLS policy fixture unexpectedly passed" >&2
    exit 1
fi

echo "fips openssl: ISO/IEC 19790 config alias fixture"
cargo run -q $cargo_run_release --no-default-features --features "$features" --bin fluxheim-config-tester -- \
    --config examples/iso19790-openssl.toml \
    --profile iso19790-openssl \
    --no-runtime-paths

echo "fips openssl: OpenSSL provider list"
if command -v openssl >/dev/null 2>&1; then
    if ! openssl list -providers -provider fips -provider base; then
        echo "fips openssl: openssl provider list failed; provider availability will be enforced by mode"
    fi
else
    echo "fips openssl: openssl command not found; provider availability will be enforced by mode"
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
        echo "fips openssl: set FLUXHEIM_REQUIRE_FIPS_PROVIDER=0 only for explicit stub-only validation environments" >&2
        exit 1
    fi
    echo "fips openssl: provider unavailable; stub-only validation allowed by FLUXHEIM_REQUIRE_FIPS_PROVIDER=0"
    exit 0
fi

echo "fips openssl: config fixture"
cargo run -q $cargo_run_release --no-default-features --features "$features" --bin fluxheim-config-tester -- \
    --config examples/fips-openssl.toml \
    --profile fips-openssl \
    --no-runtime-paths \
    --crypto

cat >"$runtime_config" <<EOF
[server]
listen = ["127.0.0.1:0"]

[server.process]
pid_file = "$repo_root/$work_dir/fluxheim.pid"
upgrade_sock = "$repo_root/$work_dir/fluxheim-upgrade.sock"
certificate_reload_sock = "$repo_root/$work_dir/fluxheim-cert-reload.sock"

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
