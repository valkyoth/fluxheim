#!/usr/bin/env sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

if [ "$(uname -s)" != "Linux" ]; then
    echo "ACME mount-boundary smoke requires Linux" >&2
    exit 1
fi

runtime=${FLUXHEIM_ACME_MOUNT_TEST_RUNTIME:-}
if [ -z "$runtime" ]; then
    if command -v podman >/dev/null 2>&1; then
        runtime=podman
    elif command -v docker >/dev/null 2>&1; then
        runtime=docker
    else
        echo "ACME mount-boundary smoke requires Podman or Docker" >&2
        exit 1
    fi
fi
case "$runtime" in
    podman | docker) ;;
    *)
        echo "unsupported ACME mount-boundary container runtime: $runtime" >&2
        exit 1
        ;;
esac

test_name=acme_directory::tests::owned_directory_reconciliation_rejects_bind_mount
build_output=$(cargo test --locked -p fluxheim-acme --features acme-client \
    --no-run --message-format=json)
test_binary=$(printf '%s\n' "$build_output" \
    | sed -n 's/.*"executable":"\([^"]*\/fluxheim_acme-[^"]*\)".*/\1/p' \
    | tail -n 1)
if [ -z "$test_binary" ] || [ ! -x "$test_binary" ]; then
    echo "ACME mount-boundary smoke could not locate the compiled test binary" >&2
    exit 1
fi

image=${FLUXHEIM_ACME_MOUNT_TEST_IMAGE:-docker.io/library/debian:13.3-slim@sha256:1d3c811171a08a5adaa4a163fbafd96b61b87aa871bbc7aa15431ac275d3d430}
"$runtime" run --rm --privileged --user 0:0 \
    --entrypoint /fluxheim-acme-test \
    -v "$test_binary:/fluxheim-acme-test:ro,Z" \
    "$image" \
    --exact "$test_name" --ignored --nocapture

echo "ACME mount-boundary smoke passed"
