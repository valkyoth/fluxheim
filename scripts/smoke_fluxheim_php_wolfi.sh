#!/usr/bin/env sh
set -eu

FLUXHEIM_PHP_IMAGE_VARIANTS="${FLUXHEIM_PHP_IMAGE_VARIANTS:-wolfi}" \
FLUXHEIM_PHP_SMOKE_PORT="${FLUXHEIM_WOLFI_PHP_SMOKE_PORT:-18182}" \
    exec scripts/smoke_fluxheim_php_images.sh
