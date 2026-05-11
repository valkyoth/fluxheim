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

cargo fmt --all --check
scripts/validate-release-metadata.sh
perl scripts/check-doc-links.pl
cargo clippy --all-targets -- -D warnings
cargo test
cargo test --no-default-features --features proxy,load-balancer
cargo test --no-default-features --features proxy,cache
cargo test --no-default-features --features cache
cargo test --no-default-features --features web
cargo test --no-default-features --features profile-core
cargo check --no-default-features --features profile-core,acme-client
scripts/validate-1-0-core.sh check
cargo check --no-default-features --features profile-static-site
cargo check --no-default-features --features profile-reverse-proxy
cargo check --no-default-features --features profile-cache-server
cargo check --no-default-features --features profile-load-balancer
cargo check --no-default-features --features profile-observability
cargo check --no-default-features --features profile-privacy
expect_cargo_check_failure "privacy-mode" "privacy-mode cannot be combined with the cache feature"
expect_cargo_check_failure_no_defaults "profile-privacy,metrics" "privacy-mode cannot be combined with metrics"
expect_feature_validation_failure "profile-privacy,metrics" "privacy-mode cannot be combined with metrics"
expect_feature_validation_failure "profile-privacy,otel-tracing" "privacy-mode cannot be combined with otel-tracing"
expect_feature_validation_failure "profile-core,tls-openssl" "select only one Fluxheim TLS backend feature"
expect_feature_validation_failure "tls-rustls,tls-openssl" "select only one Fluxheim TLS backend feature"
cargo test --no-default-features --features proxy,metrics
cargo test --no-default-features --features proxy,otel-tracing
cargo test --no-default-features --features proxy,tls-rustls,acme
cargo test --no-default-features --features proxy,tls-rustls,acme-client
cargo test --no-default-features --features proxy,web,tls-rustls,privacy-mode
cargo check --no-default-features --features proxy,tls
cargo check --no-default-features --features proxy,tls-rustls
python3 -m py_compile scripts/prepare-server.py scripts/build_fluxheim_rpm.py
scripts/validate-tls-backends.sh check
cargo run --quiet -- --check-config --config examples/fluxheim.toml >/dev/null
cargo run --quiet -- --check-config --config examples/admin.toml >/dev/null
cargo run --quiet -- --check-config --config examples/vhosts.toml >/dev/null
cargo run --quiet -- --check-config --config examples/acme-http-01.toml >/dev/null
cargo run --quiet -- --check-config --config examples/acme-actalis.toml >/dev/null
cargo run --quiet -- --check-config --config examples/tls-modern.toml >/dev/null
cargo run --quiet -- --check-config --config examples/tls-intermediate.toml >/dev/null
cargo run --quiet -- --check-config --config examples/privacy.toml >/dev/null
cargo run --quiet -- --check-config --config examples/container/fluxheim.toml >/dev/null
cargo run --quiet -- --check-config --config packaging/container/fluxheim.toml >/dev/null
cargo run --quiet -- --check-config --config packaging/default/fluxheim.toml >/dev/null
cargo run --quiet -- --check-config --config examples/conf.d >/dev/null
cargo run --quiet -- --check-config --config examples/gateway-1-0 >/dev/null
cargo run --quiet --no-default-features --features profile-privacy -- --check-config --config examples/privacy.toml >/dev/null
cargo deny check
cargo audit
