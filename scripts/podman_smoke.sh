#!/usr/bin/env sh
set -eu

IMAGE="${FLUXHEIM_IMAGE:-fluxheim:dev}"
CONTAINERFILE="${FLUXHEIM_CONTAINERFILE:-Containerfile}"
FEATURES="${FLUXHEIM_FEATURES:-default}"
CONFIG="${FLUXHEIM_CONFIG:-}"
RUNTIME_UID="${FLUXHEIM_RUNTIME_UID:-65532}"
RUNTIME_GID="${FLUXHEIM_RUNTIME_GID:-65532}"
EXPECTED_UID="${FLUXHEIM_EXPECTED_UID:-$RUNTIME_UID}"

if [ -z "${CONTAINER_HOST:-}" ] && [ -n "${XDG_RUNTIME_DIR:-}" ] && [ -S "$XDG_RUNTIME_DIR/podman/podman.sock" ]; then
    CONTAINER_HOST="unix://$XDG_RUNTIME_DIR/podman/podman.sock"
    export CONTAINER_HOST
fi

if [ "$FEATURES" != "default" ]; then
    scripts/validate-features.sh "$FEATURES"
fi

if [ -z "$CONFIG" ]; then
    case ",$FEATURES," in
        *,profile-privacy,*|*,privacy-mode,*)
            CONFIG="examples/privacy.toml"
            ;;
        *)
            CONFIG="packaging/container/fluxheim.toml"
            ;;
    esac
fi

echo "podman smoke: image=$IMAGE features=$FEATURES config=$CONFIG uid=$RUNTIME_UID gid=$RUNTIME_GID"
if [ -n "${CONTAINER_HOST:-}" ]; then
    echo "podman smoke: CONTAINER_HOST=$CONTAINER_HOST"
fi

podman build \
    --build-arg "FLUXHEIM_FEATURES=$FEATURES" \
    --build-arg "FLUXHEIM_CONFIG=$CONFIG" \
    --build-arg "FLUXHEIM_RUNTIME_UID=$RUNTIME_UID" \
    --build-arg "FLUXHEIM_RUNTIME_GID=$RUNTIME_GID" \
    -t "$IMAGE" \
    -f "$CONTAINERFILE" \
    .

podman run --rm "$IMAGE" --check-config --config /etc/fluxheim/fluxheim.toml >/dev/null

USER_LINE="$(podman run --rm --entrypoint /bin/sh "$IMAGE" -c id)"
case "$USER_LINE" in
    *"uid=$EXPECTED_UID"* )
        ;;
    * )
        echo "podman smoke: expected runtime uid=$EXPECTED_UID, got: $USER_LINE" >&2
        exit 1
        ;;
esac

echo "podman smoke: ok"
