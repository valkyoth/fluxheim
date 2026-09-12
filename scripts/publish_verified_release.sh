#!/usr/bin/env bash
set -euo pipefail

usage() {
    echo "usage: $0 VERSION COMMIT WORKFLOW_RUN_ID DISPOSABLE_DIR INDEPENDENT_DIR [REPOSITORY]" >&2
    exit 2
}

VERSION="${1:-}"
COMMIT="${2:-}"
RUN_ID="${3:-}"
DISPOSABLE_DIR="${4:-}"
INDEPENDENT_DIR="${5:-}"
REPOSITORY="${6:-valkyoth/fluxheim}"

[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.-]+)?$ ]] || usage
[[ "$COMMIT" =~ ^[0-9a-f]{40}$ ]] || usage
[[ "$RUN_ID" =~ ^[1-9][0-9]*$ ]] || usage
[[ "$REPOSITORY" =~ ^[0-9A-Za-z_.-]+/[0-9A-Za-z_.-]+$ ]] || usage
[[ -d "$DISPOSABLE_DIR" && ! -L "$DISPOSABLE_DIR" ]] || usage
[[ -d "$INDEPENDENT_DIR" && ! -L "$INDEPENDENT_DIR" ]] || usage

for command in gh; do
    command -v "$command" >/dev/null 2>&1 || {
        echo "missing command: $command" >&2
        exit 2
    }
done

SCRIPT_DIR="$(cd -- "$(dirname -- "$0")" && pwd -P)"
DISPOSABLE_DIR="$(cd -- "$DISPOSABLE_DIR" && pwd -P)"
INDEPENDENT_DIR="$(cd -- "$INDEPENDENT_DIR" && pwd -P)"
TAG="v$VERSION"
PROFILES=(full wasm cache proxy load-balancer php config-tester)
ARCHIVES=()

for profile in "${PROFILES[@]}"; do
    archive="$DISPOSABLE_DIR/fluxheim-$VERSION-$profile-x86_64-windows.zip"
    [[ -f "$archive" && ! -L "$archive" ]] || {
        echo "verified Windows archive is missing or unsafe: $archive" >&2
        exit 1
    }
    ARCHIVES+=("$archive")
done

# No GitHub release mutation is permitted before the authenticated independent
# build gate has accepted every archive.
"$SCRIPT_DIR/verify_windows_release_publication.sh" \
    "$VERSION" "$COMMIT" "$RUN_ID" \
    "$DISPOSABLE_DIR" "$INDEPENDENT_DIR" "$REPOSITORY"

REMOTE_COMMIT="$(gh api "repos/$REPOSITORY/commits/$TAG" --jq '.sha')"
if [[ "$REMOTE_COMMIT" != "$COMMIT" ]]; then
    echo 'remote release tag does not resolve to the verified commit' >&2
    exit 1
fi

RELEASE_STATE="$(gh release view "$TAG" --repo "$REPOSITORY" \
    --json tagName,isDraft,isImmutable \
    --jq '[.tagName, (.isDraft | tostring), (.isImmutable | tostring)] | @tsv')"
if [[ "$RELEASE_STATE" != "$TAG"$'\ttrue\tfalse' ]]; then
    echo 'verified archives may only be staged on the matching mutable draft release' >&2
    exit 1
fi

EXISTING_ASSETS="$(gh release view "$TAG" --repo "$REPOSITORY" \
    --json assets --jq '.assets[].name')"
for archive in "${ARCHIVES[@]}"; do
    name="${archive##*/}"
    if grep -Fx "$name" <<<"$EXISTING_ASSETS" >/dev/null; then
        echo "refusing to replace existing release asset: $name" >&2
        exit 1
    fi
done

gh release upload "$TAG" "${ARCHIVES[@]}" --repo "$REPOSITORY"
echo "verified Windows release archives staged on draft $TAG"
