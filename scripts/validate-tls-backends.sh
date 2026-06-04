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
        echo "usage: scripts/validate-tls-backends.sh [check|release]" >&2
        exit 2
        ;;
esac

run_tls_backend() {
    backend="$1"
    features="proxy,$backend"
    scripts/validate-features.sh "$features"
    echo "tls backend: $cargo_action --no-default-features --features $features"
    cargo $cargo_action --no-default-features --features "$features"
}

run_tls_backend tls-rustls
run_tls_backend tls-openssl
