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
        echo "usage: scripts/validate-fips-rustls.sh [check|release]" >&2
        exit 2
        ;;
esac

features="profile-fips-rustls"
iso_features="profile-iso19790-rustls"
work_dir="target/fips-rustls-validation"
backend_mismatch_config="$work_dir/backend-mismatch.toml"
non_fips_policy_config="$work_dir/non-fips-policy.toml"
admin_config="$work_dir/admin-internal-crypto.toml"
acme_config="$work_dir/acme-internal-crypto.toml"
cache_config="$work_dir/cache-internal-crypto.toml"
openbao_remote_config="$work_dir/openbao-remote-internal-crypto.toml"
repo_root="$(pwd -P)"

case "$repo_root" in
    *\"*|*\\*)
        echo "fips rustls: repository path contains characters unsafe for generated TOML" >&2
        exit 2
        ;;
esac

scripts/validate-features.sh "$features"
scripts/validate-features.sh "$iso_features"

if ! command -v go >/dev/null 2>&1; then
    echo "fips rustls: Go is required by aws-lc-fips-sys; install Go before running this validation" >&2
    exit 2
fi

if [ "$mode" = "release" ] && [ "${FLUXHEIM_ALLOW_EXPERIMENTAL_AWS_LC_FIPS_TOOLCHAIN:-0}" != "1" ]; then
    if [ -z "${CC:-}" ]; then
        default_cc_macros="$(cc -dM -E - </dev/null 2>/dev/null || true)"
        default_clang_major="$(printf '%s\n' "$default_cc_macros" | sed -n 's/^#define __clang_major__ \([0-9][0-9]*\).*/\1/p' | head -1)"
        default_gcc_major="$(printf '%s\n' "$default_cc_macros" | sed -n 's/^#define __GNUC__ \([0-9][0-9]*\).*/\1/p' | head -1)"
        if { [ -n "$default_clang_major" ] && [ "$default_clang_major" -ge 19 ]; } \
            || { [ -z "$default_clang_major" ] && [ -n "$default_gcc_major" ] && [ "$default_gcc_major" -ge 14 ]; }
        then
            for version in 13 12 11; do
                if command -v "gcc-$version" >/dev/null 2>&1 \
                    && command -v "g++-$version" >/dev/null 2>&1
                then
                    CC="gcc-$version"
                    CXX="g++-$version"
                    export CC CXX
                    echo "fips rustls: selected supported compiler pair CC=$CC CXX=$CXX"
                    break
                fi
            done
        fi
    fi

    cc_bin="${CC:-cc}"
    cc_line="$($cc_bin --version 2>/dev/null | sed -n '1p' || true)"
    cc_macros="$($cc_bin -dM -E - </dev/null 2>/dev/null || true)"
    clang_major="$(printf '%s\n' "$cc_macros" | sed -n 's/^#define __clang_major__ \([0-9][0-9]*\).*/\1/p' | head -1)"
    gcc_major="$(printf '%s\n' "$cc_macros" | sed -n 's/^#define __GNUC__ \([0-9][0-9]*\).*/\1/p' | head -1)"

    if [ -n "$clang_major" ] && [ "$clang_major" -ge 19 ]; then
        echo "fips rustls: release-mode aws-lc-fips-sys builds can fail on newer Clang toolchains ($cc_line)" >&2
        echo "fips rustls: generate release evidence on an AWS-LC-supported FIPS builder, or set FLUXHEIM_ALLOW_EXPERIMENTAL_AWS_LC_FIPS_TOOLCHAIN=1 to try this toolchain anyway" >&2
        exit 2
    fi

    if [ -z "$clang_major" ] && [ -n "$gcc_major" ] && [ "$gcc_major" -ge 14 ]; then
        echo "fips rustls: release-mode aws-lc-fips-sys builds are known to fail on newer GCC toolchains ($cc_line)" >&2
        echo "fips rustls: generate release evidence on an AWS-LC-supported FIPS builder, or set FLUXHEIM_ALLOW_EXPERIMENTAL_AWS_LC_FIPS_TOOLCHAIN=1 to try this toolchain anyway" >&2
        exit 2
    fi
fi

echo "fips rustls: cargo $cargo_action --no-default-features --features $features"
cargo $cargo_action --no-default-features --features "$features" --bin fluxheim --bin fluxheim-config-tester
echo "fips rustls: cargo $cargo_action --no-default-features --features $iso_features"
cargo $cargo_action --no-default-features --features "$iso_features" --bin fluxheim --bin fluxheim-config-tester

install -d -m 0700 "$work_dir"

cat >"$backend_mismatch_config" <<EOF
[tls]
enabled = true
backend = "openssl"
curve_preferences = ["CurveP256", "CurveP384"]
cipher_suites = ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"]

[tls.fips]
required = true
EOF

cat >"$non_fips_policy_config" <<EOF
[tls]
enabled = true
backend = "rustls"
curve_preferences = ["X25519", "CurveP256"]
cipher_suites = ["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"]

[tls.fips]
required = true
EOF

cat >"$admin_config" <<EOF
[admin]
enabled = true
token_env = "FLUXHEIM_ADMIN_TOKEN"
snapshot_store = "$repo_root/$work_dir/admin-snapshots"

[tls]
enabled = true
backend = "rustls"
curve_preferences = ["CurveP256", "CurveP384"]
cipher_suites = ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"]

[tls.fips]
required = true
EOF

cat >"$acme_config" <<EOF
[tls]
enabled = true
backend = "rustls"
curve_preferences = ["CurveP256", "CurveP384"]
cipher_suites = ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"]

[tls.fips]
required = true

[tls.acme]
enabled = true
storage = "$repo_root/$work_dir/acme"
contact_email = "admin@example.test"
EOF

cat >"$cache_config" <<EOF
[tls]
enabled = true
backend = "rustls"
curve_preferences = ["CurveP256", "CurveP384"]
cipher_suites = ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"]

[tls.fips]
required = true

[cache]
enabled = true

[cache.disk]
enabled = true
path = "$repo_root/$work_dir/cache"

[cache.disk.encryption]
enabled = true
provider = "local"
key_credential = "fluxheim-cache-key"
EOF

cat >"$openbao_remote_config" <<EOF
[tls]
enabled = true
backend = "rustls"
curve_preferences = ["CurveP256", "CurveP384"]
cipher_suites = ["TLS_AES_256_GCM_SHA384", "TLS_AES_128_GCM_SHA256"]

[tls.fips]
required = true

[cache]
enabled = true

[cache.disk]
enabled = true
path = "$repo_root/$work_dir/openbao-cache"

[cache.disk.encryption]
enabled = true
provider = "openbao-transit"

[cache.disk.encryption.openbao]
address = "https://openbao.internal.example"
mount = "transit"
key_name = "fluxheim-cache"
token_credential = "openbao-token"
EOF

echo "fips rustls: fail-closed backend mismatch fixture"
if cargo run -q $cargo_run_release --no-default-features --features "$features" --bin fluxheim-config-tester -- \
    --config "$backend_mismatch_config" \
    --profile fips-rustls \
    --no-runtime-paths >/dev/null 2>&1; then
    echo "fips rustls: backend mismatch fixture unexpectedly passed" >&2
    exit 1
fi

echo "fips rustls: fail-closed non-FIPS TLS policy fixture"
if cargo run -q $cargo_run_release --no-default-features --features "$features" --bin fluxheim-config-tester -- \
    --config "$non_fips_policy_config" \
    --profile fips-rustls \
    --no-runtime-paths >/dev/null 2>&1; then
    echo "fips rustls: non-FIPS TLS policy fixture unexpectedly passed" >&2
    exit 1
fi

echo "fips rustls: provider-backed admin auth fixture"
cargo run -q $cargo_run_release --no-default-features --features "$features" --bin fluxheim-config-tester -- \
    --config "$admin_config" \
    --profile fips-rustls \
    --no-runtime-paths >/dev/null

echo "fips rustls: fail-closed managed ACME internal-crypto fixture"
if acme_output="$(cargo run -q $cargo_run_release --no-default-features --features "$features" --bin fluxheim-config-tester -- \
    --config "$acme_config" \
    --profile fips-rustls \
    --no-runtime-paths 2>&1)"; then
    echo "fips rustls: managed ACME internal-crypto fixture unexpectedly passed" >&2
    exit 1
fi
case "$acme_output" in
    *"account key generation, JWS account signing, EAB handling, outbound ACME HTTPS transport"*) ;;
    *)
        echo "fips rustls: managed ACME fixture failed for the wrong reason" >&2
        printf '%s\n' "$acme_output" >&2
        exit 1
        ;;
esac

echo "fips rustls: fail-closed local cache-encryption fixture"
if cargo run -q $cargo_run_release --no-default-features --features "$features" --bin fluxheim-config-tester -- \
    --config "$cache_config" \
    --profile fips-rustls \
    --no-runtime-paths >/dev/null 2>&1; then
    echo "fips rustls: local cache-encryption fixture unexpectedly passed" >&2
    exit 1
fi

echo "fips rustls: fail-closed remote OpenBao internal-crypto fixture"
if cargo run -q $cargo_run_release --no-default-features --features "$features" --bin fluxheim-config-tester -- \
    --config "$openbao_remote_config" \
    --profile fips-rustls \
    --no-runtime-paths >/dev/null 2>&1; then
    echo "fips rustls: remote OpenBao internal-crypto fixture unexpectedly passed" >&2
    exit 1
fi

echo "fips rustls: FIPS config fixture"
cargo run -q $cargo_run_release --no-default-features --features "$features" --bin fluxheim-config-tester -- \
    --config examples/fips-rustls.toml \
    --profile fips-rustls \
    --no-runtime-paths \
    --crypto

echo "fips rustls: ISO/IEC 19790 config alias fixture"
cargo run -q $cargo_run_release --no-default-features --features "$iso_features" --bin fluxheim-config-tester -- \
    --config examples/iso19790-rustls.toml \
    --profile iso19790-rustls \
    --no-runtime-paths \
    --crypto

echo "fips rustls: ok"
