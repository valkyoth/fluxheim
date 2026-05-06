#!/usr/bin/env sh
set -eu

VARIANTS="${FLUXHEIM_CONTAINER_VARIANTS:-debian alpine wolfi suse-micro}"
FEATURES="${FLUXHEIM_FEATURES:-default}"

for variant in $VARIANTS; do
    case "$variant" in
        debian|alpine|wolfi|suse-micro)
            ;;
        *)
            echo "unknown container variant: $variant" >&2
            exit 2
            ;;
    esac

    FLUXHEIM_IMAGE="fluxheim:${variant}-smoke" \
    FLUXHEIM_CONTAINERFILE="containers/Containerfile.${variant}" \
    FLUXHEIM_FEATURES="$FEATURES" \
        scripts/podman_smoke.sh
done

echo "podman variant smokes: ok"
