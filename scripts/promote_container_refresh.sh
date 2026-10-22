#!/usr/bin/env bash
set -euo pipefail

# This file is downloaded by exact artifact name from this workflow attempt.
# Never derive the expected digest from the mutable registry candidate tag.
expected="$(cat tested-digest/tested.digest)"
[[ "$expected" =~ ^sha256:[0-9a-f]{64}$ ]] || { echo 'invalid tested digest' >&2; exit 1; }

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

# Reject substitution and address every copy by the recorded immutable digest,
# including if the registry tag changes again after this comparison.
digest="$(skopeo inspect --format '{{.Digest}}' "docker://ghcr.io/${GITHUB_REPOSITORY}:${CANDIDATE}")"
[[ "$digest" == "$expected" ]] || { echo 'candidate substitution detected' >&2; exit 1; }
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
