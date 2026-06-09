#!/usr/bin/env sh
set -eu

expect_cargo_check_failure() {
    features="$1"
    expected="$2"
    set +e
    output="$(CARGO_BUILD_JOBS=1 cargo check --features "$features" 2>&1 >/dev/null)"
    status="$?"
    set -e
    if [ "$status" -eq 0 ]; then
        echo "cargo check unexpectedly succeeded for features: $features" >&2
        exit 1
    fi
    case "$output" in
        *"$expected"*) ;;
        *)
            echo "cargo check failed for features '$features' but did not include expected message:" >&2
            echo "$expected" >&2
            echo "$output" >&2
            exit 1
            ;;
    esac
}

expect_cargo_check_failure_no_defaults() {
    features="$1"
    expected="$2"
    set +e
    output="$(CARGO_BUILD_JOBS=1 cargo check --no-default-features --features "$features" 2>&1 >/dev/null)"
    status="$?"
    set -e
    if [ "$status" -eq 0 ]; then
        echo "cargo check unexpectedly succeeded for no-default features: $features" >&2
        exit 1
    fi
    case "$output" in
        *"$expected"*) ;;
        *)
            echo "cargo check failed for no-default features '$features' but did not include expected message:" >&2
            echo "$expected" >&2
            echo "$output" >&2
            exit 1
            ;;
    esac
}

expect_feature_validation_failure() {
    features="$1"
    expected="$2"
    set +e
    output="$(scripts/validate-features.sh "$features" 2>&1 >/dev/null)"
    status="$?"
    set -e
    if [ "$status" -eq 0 ]; then
        echo "feature validation unexpectedly succeeded for features: $features" >&2
        exit 1
    fi
    case "$output" in
        *"$expected"*) ;;
        *)
            echo "feature validation failed for '$features' but did not include expected message:" >&2
            echo "$expected" >&2
            echo "$output" >&2
            exit 1
            ;;
    esac
}

CHECKS_TMP_DIR="${TMPDIR:-/tmp}/fluxheim-checks-$$"
export CHECKS_TMP_DIR
mkdir -p \
    "$CHECKS_TMP_DIR/configs" \
    "$CHECKS_TMP_DIR/etc/fluxheim" \
    "$CHECKS_TMP_DIR/run/fluxheim" \
    "$CHECKS_TMP_DIR/srv/fluxheim" \
    "$CHECKS_TMP_DIR/srv/sites" \
    "$CHECKS_TMP_DIR/var/cache/fluxheim" \
    "$CHECKS_TMP_DIR/var/lib/fluxheim/acme" \
    "$CHECKS_TMP_DIR/var/log/fluxheim"
trap 'rm -rf "$CHECKS_TMP_DIR"' EXIT HUP INT TERM

local_config_copy() {
    source="$1"
    target="$CHECKS_TMP_DIR/configs/$source"
    mkdir -p "$(dirname "$target")"
    if [ -d "$source" ]; then
        mkdir -p "$target"
        cp -R "$source"/. "$target"/
    else
        cp "$source" "$target"
    fi
    find "$target" -type f -name '*.toml' -exec perl -0pi -e '
        s#/etc/fluxheim#$ENV{CHECKS_TMP_DIR}/etc/fluxheim#g;
        s#/run/fluxheim#$ENV{CHECKS_TMP_DIR}/run/fluxheim#g;
        s#/srv/fluxheim#$ENV{CHECKS_TMP_DIR}/srv/fluxheim#g;
        s#/srv/sites#$ENV{CHECKS_TMP_DIR}/srv/sites#g;
        s#/var/cache/fluxheim#$ENV{CHECKS_TMP_DIR}/var/cache/fluxheim#g;
        s#/var/lib/fluxheim#$ENV{CHECKS_TMP_DIR}/var/lib/fluxheim#g;
        s#/var/log/fluxheim#$ENV{CHECKS_TMP_DIR}/var/log/fluxheim#g;
    ' {} +
    printf '%s\n' "$target"
}

config_tester() {
    config="$(local_config_copy "$1")"
    profile="${2:-development}"
    cargo run --quiet --no-default-features --features profile-development --bin fluxheim-config-tester -- \
        --config "$config" \
        --profile "$profile" \
        --no-runtime-paths >/dev/null
}

cargo fmt --all --check
scripts/validate-release-metadata.sh
perl scripts/check-doc-links.pl
cargo clippy --all-targets -- -D warnings
cargo clippy --no-default-features --features tls-rustls --all-targets -- -D warnings
cargo clippy --no-default-features --features profile-full --all-targets -- -D warnings
cargo clippy --no-default-features --features profile-web-server --all-targets -- -D warnings
cargo clippy --no-default-features --features profile-web-server,php-fpm --all-targets -- -D warnings
cargo clippy --no-default-features --features profile-cache-edge --all-targets -- -D warnings
cargo clippy --no-default-features --features profile-proxy-edge --all-targets -- -D warnings
cargo clippy --no-default-features --features profile-load-balancer-edge --all-targets -- -D warnings
cargo clippy --no-default-features --features profile-fips-openssl --all-targets -- -D warnings
cargo clippy --no-default-features --features profile-iso19790-openssl --all-targets -- -D warnings
cargo clippy --no-default-features --features profile-fips-rustls --all-targets -- -D warnings
cargo clippy --no-default-features --features profile-iso19790-rustls --all-targets -- -D warnings
cargo test
scripts/validate-owasp-top10-2025.sh check
# Incubator profile permutations are build coverage. Check test cfgs without
# linking every feature-specific test binary; the default feature set still runs
# with `cargo test` above.
cargo check --tests --no-default-features --features proxy,load-balancer
cargo check --tests --no-default-features --features proxy,cache
cargo check --tests --no-default-features --features cache
cargo check --tests --no-default-features --features web
cargo check --tests --no-default-features --features profile-core
cargo check --no-default-features --features profile-observability,acme-client
scripts/validate-1-0-core.sh check
cargo check --no-default-features --features profile-static-site
cargo check --no-default-features --features profile-reverse-proxy
cargo check --no-default-features --features profile-cache-server
cargo check --no-default-features --features profile-load-balancer
cargo check --no-default-features --features profile-full
cargo check --no-default-features --features profile-development
cargo check --no-default-features --features profile-web-server
cargo check --no-default-features --features profile-web-server,php-fpm
cargo check --no-default-features --features profile-cache-edge
cargo check --no-default-features --features profile-proxy-edge
cargo check --no-default-features --features profile-load-balancer-edge
cargo check --no-default-features --features profile-observability
cargo check --no-default-features --features profile-privacy
cargo check --no-default-features --features profile-fips-openssl
cargo check --no-default-features --features profile-iso19790-openssl
cargo check --no-default-features --features profile-fips-rustls
cargo check --no-default-features --features profile-iso19790-rustls
cargo check --no-default-features --features profile-full,acme-client,metrics,metrics-otlp,otel-tracing,otel-otlp
cargo check --no-default-features --features profile-cache-edge,acme-client
cargo check --no-default-features --features profile-proxy-edge,acme-client
cargo check --no-default-features --features profile-load-balancer-edge,acme-client
expect_cargo_check_failure "privacy-mode" "privacy-mode cannot be combined with the cache feature"
expect_cargo_check_failure_no_defaults "profile-privacy,metrics" "privacy-mode cannot be combined with metrics"
expect_feature_validation_failure "profile-privacy,metrics" "privacy-mode cannot be combined with metrics"
expect_feature_validation_failure "profile-privacy,metrics-otlp" "privacy-mode cannot be combined with metrics-otlp"
expect_feature_validation_failure "profile-privacy,otel-tracing" "privacy-mode cannot be combined with otel-tracing"
expect_feature_validation_failure "profile-privacy,otel-otlp" "privacy-mode cannot be combined with otel-otlp"
expect_feature_validation_failure "profile-core,tls-openssl" "select only one Fluxheim TLS backend feature"
expect_feature_validation_failure "tls-rustls,tls-openssl" "select only one Fluxheim TLS backend feature"
expect_feature_validation_failure "tls-rustls,tls-rustls-fips" "select only one Fluxheim TLS backend feature"
cargo check --tests --no-default-features --features proxy,metrics
cargo check --tests --no-default-features --features proxy,metrics-otlp
cargo check --tests --no-default-features --features proxy,otel-tracing
cargo check --tests --no-default-features --features proxy,otel-otlp
cargo check --tests --no-default-features --features proxy,tls-rustls,acme
cargo check --tests --no-default-features --features proxy,tls-rustls,acme-client
cargo check --tests --no-default-features --features proxy,web,tls-rustls,privacy-mode
cargo check --no-default-features --features proxy,tls
cargo check --no-default-features --features proxy,tls-rustls
scripts/validate-fips-openssl.sh check
scripts/validate-fips-rustls.sh check
python3 -m py_compile scripts/prepare-server.py scripts/build_fluxheim_rpm.py
scripts/validate-tls-backends.sh check
config_tester examples/fluxheim.toml
config_tester examples/admin.toml
config_tester examples/vhosts.toml
config_tester examples/acme-http-01.toml
config_tester examples/acme-actalis.toml
config_tester examples/cache-storage-bin.toml
config_tester examples/cache-encryption-local.toml
config_tester examples/cache-encryption-openbao.toml
config_tester examples/cache-peer-fill.toml
config_tester examples/load-balancer-enterprise.toml load-balancer
config_tester examples/load-balancer-exec-health.toml load-balancer
config_tester examples/php-fpm.toml web-php
config_tester examples/tls-modern.toml
config_tester examples/tls-intermediate.toml
config_tester examples/privacy.toml
config_tester examples/container/fluxheim.toml
config_tester packaging/container/fluxheim.toml
config_tester packaging/container/cache.toml cache
config_tester packaging/container/proxy.toml proxy
config_tester packaging/container/load-balancer.toml load-balancer
config_tester packaging/container/php.toml web-php
config_tester packaging/default/fluxheim.toml
config_tester examples/conf.d
config_tester examples/gateway-1-0
cargo deny check
cargo audit
