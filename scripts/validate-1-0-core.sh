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

echo "1.0 core: systemd sandbox policy"
grep -q '^NoNewPrivileges=true$' packaging/systemd/fluxheim.service
grep -q '^ProtectSystem=strict$' packaging/systemd/fluxheim.service
grep -q '^CapabilityBoundingSet=CAP_NET_BIND_SERVICE$' packaging/systemd/fluxheim.service
grep -q '^AmbientCapabilities=CAP_NET_BIND_SERVICE$' packaging/systemd/fluxheim.service
grep -q '^RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX$' packaging/systemd/fluxheim.service
grep -q '^RestrictNamespaces=true$' packaging/systemd/fluxheim.service
grep -q '^SystemCallFilter=@system-service @network-io$' packaging/systemd/fluxheim.service

echo "1.0 core: native/container port defaults"
grep -q '^listen = \["0.0.0.0:80"\]$' packaging/default/fluxheim.toml
grep -q '^listen = \["0.0.0.0:8080"\]$' packaging/container/fluxheim.toml
grep -q '^ARG FLUXHEIM_CONFIG=packaging/container/fluxheim.toml$' Containerfile
grep -q '^ARG FLUXHEIM_CONFIG=packaging/container/fluxheim.toml$' containers/Containerfile.wolfi
