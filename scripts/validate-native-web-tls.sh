#!/usr/bin/env sh
set -eu

mode="${1:-check}"

case "$mode" in
    check)
        cargo_action="check"
        ;;
    release)
        cargo_action="build --release"
        ;;
    *)
        echo "usage: scripts/validate-native-web-tls.sh [check|release]" >&2
        exit 2
        ;;
esac

run_native_web_tls() {
    backend="$1"
    features="web,$backend"
    scripts/validate-features.sh "$features"
    echo "native web TLS: cargo $cargo_action --locked --no-default-features --features $features --lib"
    cargo $cargo_action --locked --no-default-features --features "$features" --lib
}

run_native_web_tls tls-rustls
run_native_web_tls tls-openssl
