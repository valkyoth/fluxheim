#!/usr/bin/env sh
set -eu

IMAGE="${FLUXHEIM_IMAGE:-fluxheim:dev}"
CONTAINERFILE="${FLUXHEIM_CONTAINERFILE:-Containerfile}"
FEATURES="${FLUXHEIM_FEATURES:-default}"

if [ -z "${CONTAINER_HOST:-}" ] && [ -n "${XDG_RUNTIME_DIR:-}" ] && [ -S "$XDG_RUNTIME_DIR/podman/podman.sock" ]; then
    CONTAINER_HOST="unix://$XDG_RUNTIME_DIR/podman/podman.sock"
    export CONTAINER_HOST
fi

echo "podman smoke: image=$IMAGE features=$FEATURES"
if [ -n "${CONTAINER_HOST:-}" ]; then
    echo "podman smoke: CONTAINER_HOST=$CONTAINER_HOST"
fi

podman build \
    --build-arg "FLUXHEIM_FEATURES=$FEATURES" \
    -t "$IMAGE" \
    -f "$CONTAINERFILE" \
    .

podman run --rm "$IMAGE" --check-config --config /etc/fluxheim/fluxheim.toml >/dev/null

USER_LINE="$(podman run --rm --entrypoint /usr/bin/id "$IMAGE")"
case "$USER_LINE" in
    *"uid=65532"* )
        ;;
    * )
        echo "podman smoke: expected runtime uid=65532, got: $USER_LINE" >&2
        exit 1
        ;;
esac

echo "podman smoke: ok"
