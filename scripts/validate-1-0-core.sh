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
        echo "usage: scripts/validate-1-0-core.sh [check|release]" >&2
        exit 2
        ;;
esac

run_default() {
    echo "1.0 core: $cargo_action default"
    cargo $cargo_action
}

run_features() {
    features="$1"
    scripts/validate-features.sh "$features"
    echo "1.0 core: $cargo_action --no-default-features --features $features"
    cargo $cargo_action --no-default-features --features "$features"
}

run_default
run_features profile-core
run_features profile-static-site
run_features profile-reverse-proxy
run_features profile-cache-server
run_features profile-privacy

# Reduced forms promised by the 1.0 versioning plan.
run_features web
run_features proxy
