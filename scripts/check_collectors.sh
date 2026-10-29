#!/usr/bin/env sh
# Build the production container, then require both real collector stacks.
set -eu
cd "$(dirname "$0")/.."
runtime="${FLUXHEIM_CONTAINER_RUNTIME:-podman}"
case "$runtime" in podman|docker) ;; *) echo 'Expected podman or docker' >&2; exit 2 ;; esac
output="${1:?usage: sh scripts/check_collectors.sh OUTPUT_DIRECTORY}"
prometheus=$(python3 -c 'import json; print(json.load(open("examples/observability/images.json"))["prometheus"]["image"])')
"$runtime" run --rm --network none --entrypoint /bin/promtool \
    --volume "$PWD/examples/observability:/proof:ro,Z" --workdir /proof \
    "$prometheus" test rules alerts-test.yml
tmp=$(mktemp -d)
trap 'rm -rf -- "$tmp"' EXIT
trap 'exit 130' INT
trap 'exit 143' HUP TERM
"$runtime" build --iidfile "$tmp/image" \
    --build-arg FLUXHEIM_FEATURES=profile-observability,php-fpm \
    --build-arg FLUXHEIM_RUNTIME_PACKAGES=php8.4-fpm \
    -f containers/Containerfile.debian .
sh scripts/smoke_observability_local.sh --required-collectors \
    --runtime "$runtime" --image "$(cat "$tmp/image")" --output "$output"
