#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
image="${FLUXHEIM_UPGRADE_CONTAINER_IMAGE:-fluxheim:upgrade-smoke}"

if [ -z "${FLUXHEIM_UPGRADE_CONTAINER_IMAGE:-}" ]; then
    podman build \
        --build-arg FLUXHEIM_FEATURES=profile-static-site \
        --build-arg FLUXHEIM_CONFIG=packaging/container/fluxheim.toml \
        -t "$image" \
        -f containers/Containerfile.wolfi \
        .
fi

python3 "$ROOT_DIR/scripts/smoke_podman_blue_green.py" "$image"
