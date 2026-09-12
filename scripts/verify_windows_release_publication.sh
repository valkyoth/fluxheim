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

for command in gh python3; do
    command -v "$command" >/dev/null 2>&1 || { echo "missing command: $command" >&2; exit 2; }
done

TAG="v$VERSION"
RUN_API="repos/$REPOSITORY/actions/runs/$RUN_ID"
ACTUAL_REPOSITORY="$(gh api "$RUN_API" --jq '.repository.full_name')"
ACTUAL_COMMIT="$(gh api "$RUN_API" --jq '.head_sha')"
ACTUAL_REF="$(gh api "$RUN_API" --jq '.head_branch')"
ACTUAL_EVENT="$(gh api "$RUN_API" --jq '.event')"
ACTUAL_CONCLUSION="$(gh api "$RUN_API" --jq '.conclusion')"
ACTUAL_WORKFLOW="$(gh api "$RUN_API" --jq '.path')"
if [[ "$ACTUAL_REPOSITORY" != "$REPOSITORY" || "$ACTUAL_COMMIT" != "$COMMIT" ||
      "$ACTUAL_REF" != "$TAG" || "$ACTUAL_EVENT" != push ||
      "$ACTUAL_CONCLUSION" != success ||
      ( "$ACTUAL_WORKFLOW" != .github/workflows/ci.yml &&
        "$ACTUAL_WORKFLOW" != ".github/workflows/ci.yml@$TAG" &&
        "$ACTUAL_WORKFLOW" != ".github/workflows/ci.yml@refs/tags/$TAG" ) ]]; then
    echo 'independent Windows workflow run does not match the intended release' >&2
    exit 1
fi

INDEPENDENT_EVIDENCE="$INDEPENDENT_DIR/release-evidence-independent-x86_64-windows.txt"
for assertion in \
    "version=$VERSION" \
    "tag=$TAG" \
    "commit=$COMMIT" \
    "repository=$REPOSITORY" \
    'workflow=.github/workflows/ci.yml' \
    "workflow_run_id=$RUN_ID"; do
    grep -Fx "$assertion" "$INDEPENDENT_EVIDENCE" >/dev/null || {
        echo "independent Windows evidence is missing authenticated identity: $assertion" >&2
        exit 1
    }
done

ARTIFACT_NAME="fluxheim-windows-independent-$COMMIT"
ARTIFACT_ROWS="$(gh api --paginate "repos/$REPOSITORY/actions/runs/$RUN_ID/artifacts" \
    --jq ".artifacts[] | select(.name == \"$ARTIFACT_NAME\") | [.id, .expired, .workflow_run.head_sha] | @tsv")"
if [[ "$(printf '%s\n' "$ARTIFACT_ROWS" | sed '/^$/d' | wc -l)" -ne 1 ||
      "$ARTIFACT_ROWS" != *$'\tfalse\t'"$COMMIT" ]]; then
    echo 'independent Windows workflow artifact identity is missing, expired, or ambiguous' >&2
    exit 1
fi

PROFILES=(full wasm cache proxy load-balancer php config-tester)
for profile in "${PROFILES[@]}"; do
    archive="$INDEPENDENT_DIR/fluxheim-$VERSION-$profile-x86_64-windows.zip"
    [[ -f "$archive" && ! -L "$archive" ]] || {
        echo "independent Windows archive is missing or unsafe: $archive" >&2
        exit 1
    }
    gh attestation verify "$archive" \
        --repo "$REPOSITORY" \
        --signer-workflow "$REPOSITORY/.github/workflows/ci.yml" \
        --source-ref "refs/tags/$TAG" \
        --source-digest "$COMMIT" \
        --deny-self-hosted-runners >/dev/null
done

python3 "$(dirname "$0")/verify_windows_independent_build.py" \
    --expected-version "$VERSION" \
    --expected-commit "$COMMIT" \
    "$DISPOSABLE_DIR" "$INDEPENDENT_DIR"

echo 'authenticated Windows release publication gate: ok'
