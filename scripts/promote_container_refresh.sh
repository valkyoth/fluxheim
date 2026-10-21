#!/usr/bin/env bash
set -euo pipefail

printf '%s' "$GH_TOKEN" | skopeo login --username "$GITHUB_ACTOR" --password-stdin ghcr.io
registries=("ghcr.io/${GITHUB_REPOSITORY}")
if [[ -n "${QUAY_USERNAME:-}" && -n "${QUAY_TOKEN:-}" ]]; then
    printf '%s' "$QUAY_TOKEN" | skopeo login --username "$QUAY_USERNAME" --password-stdin quay.io
    registries+=("quay.io/${QUAY_NAMESPACE}/${QUAY_REPOSITORY}")
fi
if [[ -n "${DOCKERHUB_USERNAME:-}" && -n "${DOCKERHUB_TOKEN:-}" ]]; then
    printf '%s' "$DOCKERHUB_TOKEN" | skopeo login --username "$DOCKERHUB_USERNAME" --password-stdin docker.io
    registries+=("docker.io/${GITHUB_REPOSITORY_OWNER}/fluxheim")
fi

# Pin the already-tested candidate before copying it anywhere else.
digest="$(skopeo inspect --format '{{.Digest}}' "docker://ghcr.io/${GITHUB_REPOSITORY}:${CANDIDATE}")"
[[ "$digest" =~ ^sha256:[0-9a-f]{64}$ ]] || exit 1
source="docker://ghcr.io/${GITHUB_REPOSITORY}@${digest}"
read -r -a aliases <<< "$ALIASES"

# Refresh currently matches the release workflow's linux/amd64 default. Refuse
# to replace an existing multi-platform alias with a single-platform image.
for registry in "${registries[@]}"; do
    for alias in "${aliases[@]}"; do
        python3 scripts/container_refresh_platforms.py "docker://${registry}:${alias}"
    done
done

for registry in "${registries[@]}"; do
    for tag in "$CANDIDATE" "${aliases[@]}"; do
        skopeo copy --all --preserve-digests "$source" "docker://${registry}:${tag}"
        printf '%s@%s (%s)\n' "$registry" "$digest" "$tag" >> "$GITHUB_STEP_SUMMARY"
    done
done
