#!/usr/bin/env sh
# Qualify both packaged Wolfi profiles against a local CA, never production ACME.
set -eu
cd "$(dirname "$0")/.."
runtime="${FLUXHEIM_CONTAINER_RUNTIME:-podman}"
case "$runtime" in podman|docker) ;; *) echo 'Expected podman or docker' >&2; exit 2 ;; esac
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
trap 'exit 130' INT
trap 'exit 143' HUP TERM
if [ "$runtime" = podman ]; then
    set -- --ignorefile .dockerignore
else
    set --
fi
"$runtime" build "$@" --iidfile "$tmp/full" \
    --build-arg FLUXHEIM_FEATURES=profile-full,acme-client,metrics,metrics-otlp,otel-tracing,otel-otlp \
    -f containers/Containerfile.wolfi .
packages=$(tr '\n' ' ' < packaging/container/php-wolfi-runtime-packages.txt)
"$runtime" build "$@" --iidfile "$tmp/php" \
    --build-arg FLUXHEIM_FEATURES=profile-web-server,php-fpm,acme-client \
    --build-arg FLUXHEIM_CONFIG=packaging/container/php-managed.toml \
    --build-arg FLUXHEIM_RUNTIME_PACKAGES="$packages" \
    -f containers/Containerfile.wolfi .
python3 scripts/smoke_acme_scope.py --runtime "$runtime" \
    --full-image "$(cat "$tmp/full")" --php-image "$(cat "$tmp/php")"
