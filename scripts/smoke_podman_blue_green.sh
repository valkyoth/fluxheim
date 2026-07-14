#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SMOKE_TMP_ROOT=$(sh "$ROOT_DIR/scripts/secure-smoke-tmp-root.sh")
tmp="$SMOKE_TMP_ROOT/fluxheim-podman-upgrade-smoke-$$"
image="${FLUXHEIM_UPGRADE_CONTAINER_IMAGE:-fluxheim:upgrade-smoke}"

cleanup() {
    rm -rf "$tmp"
}
trap cleanup EXIT INT TERM
mkdir -p "$tmp"

if [ -z "${FLUXHEIM_UPGRADE_CONTAINER_IMAGE:-}" ]; then
    podman build \
        --build-arg FLUXHEIM_FEATURES=profile-static-site \
        --build-arg FLUXHEIM_CONFIG=packaging/container/fluxheim.toml \
        -t "$image" \
        -f containers/Containerfile.wolfi \
        .
fi

python3 "$ROOT_DIR/scripts/smoke_podman_blue_green.py" "$image" "$tmp"
