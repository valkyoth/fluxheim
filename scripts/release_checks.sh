#!/usr/bin/env sh
set -eu

scripts/checks.sh
sh scripts/smoke_static_local.sh
sh scripts/smoke_load_balancer.sh

if [ "${FLUXHEIM_RELEASE_PODMAN:-0}" = "1" ]; then
    scripts/podman_smoke.sh
else
    echo "release checks: skipping Podman smoke; set FLUXHEIM_RELEASE_PODMAN=1 to enable"
fi
