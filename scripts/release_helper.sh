#!/usr/bin/env bash

# Build and aggregate exact-tag Fluxheim release evidence on Linux.

set -euo pipefail
umask 077

REPO_URL="${FLUXHEIM_REPO_URL:-https://github.com/valkyoth/fluxheim.git}"
REPO_SLUG="${FLUXHEIM_REPO_SLUG:-valkyoth/fluxheim}"
LINUX_USER="${FLUXHEIM_LINUX_BUILD_USER:-ubuntu}"
WINDOWS_USER="${FLUXHEIM_WINDOWS_BUILD_USER:-fluxheim-build}"
SSH_CONFIG="${FLUXHEIM_RELEASE_SSH_CONFIG:-/dev/null}"
PROFILES=(full wasm cache proxy php load-balancer config-tester)

LINUX_HOST="${FLUXHEIM_AARCH64_LINUX_HOST:-}"
LINUX_SSH_KEY="${FLUXHEIM_LINUX_SSH_KEY:-}"
WINDOWS_HOST="${FLUXHEIM_WINDOWS_X64_HOST:-}"
WINDOWS_SSH_KEY="${FLUXHEIM_WINDOWS_SSH_KEY:-}"
RUST_VERSION="${1:-}"
RELEASE_VERSION="${2:-}"

[[ -n "$LINUX_HOST" ]] || read -r -p "Enter Linux aarch64 builder host: " LINUX_HOST
[[ -n "$LINUX_SSH_KEY" ]] || read -r -p "Enter Linux aarch64 SSH key path: " LINUX_SSH_KEY
[[ -n "$WINDOWS_HOST" ]] || read -r -p "Enter Windows x86_64 builder host, or leave blank to import: " WINDOWS_HOST
if [[ -n "$WINDOWS_HOST" && -z "$WINDOWS_SSH_KEY" ]]; then
    read -r -p "Enter Windows x86_64 SSH key path: " WINDOWS_SSH_KEY
fi
[[ -n "$RUST_VERSION" ]] || read -r -p "Enter Rust version (e.g., 1.98.1): " RUST_VERSION
[[ -n "$RELEASE_VERSION" ]] || read -r -p "Enter release version (e.g., 1.8.2): " RELEASE_VERSION

case "$RUST_VERSION" in "" | *[!0-9A-Za-z._+-]*) echo "error: unsafe Rust version" >&2; exit 2;; esac
case "$RELEASE_VERSION" in "" | .* | *..* | *[!0-9A-Za-z._+-]*) echo "error: unsafe release version" >&2; exit 2;; esac
for host in "$LINUX_HOST" "$WINDOWS_HOST"; do
    case "$host" in "") ;; *[!0-9A-Za-z:._-]*) echo "error: unsafe builder host: $host" >&2; exit 2;; esac
done
for user in "$LINUX_USER" "$WINDOWS_USER"; do
    case "$user" in "" | *[!0-9A-Za-z._-]*) echo "error: unsafe builder user: $user" >&2; exit 2;; esac
done
for command in cargo curl git podman python3 rustc rustup scp sha256sum ssh tar unzip; do
    command -v "$command" >/dev/null 2>&1 || { echo "error: missing command: $command" >&2; exit 2; }
done
[[ -f "$LINUX_SSH_KEY" ]] || { echo "error: Linux SSH key missing: $LINUX_SSH_KEY" >&2; exit 2; }
[[ -r "$SSH_CONFIG" ]] || { echo "error: SSH client config is not readable: $SSH_CONFIG" >&2; exit 2; }
if [[ -n "$WINDOWS_HOST" && ! -f "$WINDOWS_SSH_KEY" ]]; then
    echo "error: Windows SSH key missing: $WINDOWS_SSH_KEY" >&2
    exit 2
fi

TAG="v${RELEASE_VERSION}"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/fluxheim-release.XXXXXX")"
REPO_DIR="$WORK_DIR/source"
OUTPUT_BASE="${FLUXHEIM_RELEASE_OUTPUT_DIR:-$PWD}"
OUTPUT_DIR="$OUTPUT_BASE/fluxheim-${RELEASE_VERSION}-release-assets"
INPUT_DIR="${FLUXHEIM_RELEASE_INPUT_DIR:-$OUTPUT_BASE/release-inputs/$RELEASE_VERSION}"
REPORT="$OUTPUT_DIR/release-report.md"
cleanup() { rm -rf "$WORK_DIR"; }
trap cleanup EXIT INT TERM

echo "--- Checking out and verifying exact tag $TAG ---"
git clone --branch "$TAG" --depth 1 "$REPO_URL" "$REPO_DIR"
cd "$REPO_DIR"
COMMIT_HASH="$(git rev-parse HEAD)"
[[ "$COMMIT_HASH" == "$(git rev-parse "${TAG}^{commit}")" ]] || { echo "error: tag checkout mismatch" >&2; exit 1; }
git tag -v "$TAG" >"$WORK_DIR/tag-verification.txt" 2>&1 || {
    cat "$WORK_DIR/tag-verification.txt" >&2
    echo "error: signed tag verification failed" >&2
    exit 1
}
TAG_SIGNATURE="$(sed -n '/Good .*signature/p' "$WORK_DIR/tag-verification.txt" | sed -n '1p')"
[[ -n "$TAG_SIGNATURE" ]] || TAG_SIGNATURE="signed tag verification passed"

rustup toolchain install "$RUST_VERSION" --profile minimal
rustup override set "$RUST_VERSION"
[[ "$(rustc -vV | sed -n 's/^host: //p')" == "x86_64-unknown-linux-gnu" ]] || {
    echo "error: release helper requires native x86_64 GNU/Linux" >&2
    exit 1
}

rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"/{source,evidence,macos} "$OUTPUT_DIR"/linux/{x86_64,aarch64} \
    "$OUTPUT_DIR/windows/x86_64"

echo "--- Downloading GitHub source archives ---"
curl --fail --location --retry 4 --retry-all-errors \
    "https://github.com/${REPO_SLUG}/archive/refs/tags/${TAG}.tar.gz" \
    --output "$OUTPUT_DIR/source/fluxheim-${RELEASE_VERSION}.tar.gz"
curl --fail --location --retry 4 --retry-all-errors \
    "https://github.com/${REPO_SLUG}/archive/refs/tags/${TAG}.zip" \
    --output "$OUTPUT_DIR/source/fluxheim-${RELEASE_VERSION}.zip"
tar -tzf "$OUTPUT_DIR/source/fluxheim-${RELEASE_VERSION}.tar.gz" >/dev/null
unzip -tq "$OUTPUT_DIR/source/fluxheim-${RELEASE_VERSION}.zip" >/dev/null
(
    cd "$OUTPUT_DIR/source"
    sha256sum "fluxheim-${RELEASE_VERSION}.tar.gz" "fluxheim-${RELEASE_VERSION}.zip" > SHA256SUMS-source.txt
    sha256sum -c SHA256SUMS-source.txt
)

echo "--- Building Linux x86_64 archives ---"
scripts/validate_portable_release_plan.py
LOCAL_REPRO_HASH="$(scripts/reproducible_build_check.sh | tail -n 1 | awk '{print $1}')"
[[ "$LOCAL_REPRO_HASH" =~ ^[0-9a-f]{64}$ ]] || { echo "error: invalid local reproducible hash" >&2; exit 1; }
rm -rf dist
scripts/build_release_assets.sh "$RELEASE_VERSION" --kind linux
for profile in "${PROFILES[@]}"; do
    archive="fluxheim-${RELEASE_VERSION}-${profile}-x86_64-linux.tar.gz"
    tar -tzf "dist/$archive" >/dev/null
    cp "dist/$archive" "$OUTPUT_DIR/linux/x86_64/"
done
(
    cd "$OUTPUT_DIR/linux/x86_64"
    sha256sum fluxheim-*-x86_64-linux.tar.gz > SHA256SUMS-x86_64-linux.txt
    sha256sum -c SHA256SUMS-x86_64-linux.txt
)
printf '%s\n' "$LOCAL_REPRO_HASH" > "$OUTPUT_DIR/linux/x86_64/REPRODUCIBLE-BUILD-SHA256-x86_64-linux.txt"

echo "--- Building Linux aarch64 archives on $LINUX_HOST ---"
ssh -F "$SSH_CONFIG" -i "$LINUX_SSH_KEY" "$LINUX_USER@$LINUX_HOST" bash -s -- \
    "$RELEASE_VERSION" "$RUST_VERSION" "$COMMIT_HASH" "$REPO_URL" <<'REMOTE_LINUX'
set -euo pipefail
umask 077
version="$1"; rust_version="$2"; expected_commit="$3"; repo_url="$4"
case "$version$rust_version$expected_commit" in *[!0-9A-Za-z._+-]*) exit 2;; esac
[[ "$(uname -m)" == "aarch64" ]] || { echo "not an aarch64 host" >&2; exit 1; }
for command in cargo git python3 rustc rustup sha256sum tar; do command -v "$command" >/dev/null; done
tag="v${version}"; root="$HOME/fluxheim-release-${version}"; source="$root/source"; output="$root/output"
rm -rf "$root"; mkdir -p "$root"
git clone --branch "$tag" --depth 1 "$repo_url" "$source"
cd "$source"
[[ "$(git rev-parse HEAD)" == "$expected_commit" ]]
[[ "$(git rev-parse "${tag}^{commit}")" == "$expected_commit" ]]
rustup toolchain install "$rust_version" --profile minimal
rustup override set "$rust_version"
[[ "$(rustc -vV | sed -n 's/^host: //p')" == "aarch64-unknown-linux-gnu" ]]
repro="$(scripts/reproducible_build_check.sh | tail -n 1 | awk '{print $1}')"
[[ "$repro" =~ ^[0-9a-f]{64}$ ]]
scripts/build_release_assets.sh "$version" --kind linux
mkdir -p "$output"; cp dist/fluxheim-"$version"-*-aarch64-linux.tar.gz "$output/"
[[ "$(find "$output" -maxdepth 1 -name '*.tar.gz' -type f | wc -l)" -eq 7 ]]
cd "$output"
for archive in ./*.tar.gz; do tar -tzf "$archive" >/dev/null; done
sha256sum fluxheim-*-aarch64-linux.tar.gz > SHA256SUMS-aarch64-linux.txt
sha256sum -c SHA256SUMS-aarch64-linux.txt
printf '%s\n' "$repro" > REPRODUCIBLE-BUILD-SHA256-aarch64-linux.txt
printf 'version=%s\ncommit=%s\narchitecture=aarch64\narchive_count=7\nreproducible=true\n' \
    "$version" "$expected_commit" > release-evidence-aarch64-linux.txt
REMOTE_LINUX
scp -F "$SSH_CONFIG" -i "$LINUX_SSH_KEY" "$LINUX_USER@$LINUX_HOST:fluxheim-release-${RELEASE_VERSION}/output/*" \
    "$OUTPUT_DIR/linux/aarch64/"
(
    cd "$OUTPUT_DIR/linux/aarch64"
    [[ "$(find . -maxdepth 1 -name '*.tar.gz' -type f | wc -l)" -eq 7 ]]
    sha256sum -c SHA256SUMS-aarch64-linux.txt
    grep -Fx "commit=$COMMIT_HASH" release-evidence-aarch64-linux.txt >/dev/null
)

import_evidence() {
    local source="$1" destination="$2" checksum_file="$3" expected_count="$4" pattern="$5"
    [[ -d "$source" ]] || { echo "error: evidence directory missing: $source" >&2; exit 1; }
    cp "$source"/* "$destination/"
    (
        cd "$destination"
        [[ "$(find . -maxdepth 1 -name "$pattern" -type f | wc -l)" -eq "$expected_count" ]]
        sha256sum -c "$checksum_file"
    )
}

normalize_windows_text_evidence() {
    local directory="$1" name path
    for name in \
        SHA256SUMS-x86_64-windows.txt \
        REPRODUCIBLE-BUILD-SHA256-x86_64-windows.txt \
        release-evidence-x86_64-windows.txt \
        tag-verification.txt; do
        path="$directory/$name"
        [[ -f "$path" ]] || { echo "error: Windows evidence file missing: $path" >&2; exit 1; }
        sed -i 's/\r$//' "$path"
    done
}

if [[ -n "$WINDOWS_HOST" ]]; then
    echo "--- Building Windows x86_64 archives on $WINDOWS_HOST ---"
    scp -F "$SSH_CONFIG" -i "$WINDOWS_SSH_KEY" scripts/run_windows_release_builder.ps1 \
        scripts/windows_release_tag_policy.ps1 "$WINDOWS_USER@$WINDOWS_HOST:"
    ssh -F "$SSH_CONFIG" -i "$WINDOWS_SSH_KEY" "$WINDOWS_USER@$WINDOWS_HOST" pwsh.exe -NoProfile \
        -NonInteractive -ExecutionPolicy Bypass -File run_windows_release_builder.ps1 \
        -Version "$RELEASE_VERSION" -RustVersion "$RUST_VERSION" -Architecture x86_64 \
        -ExpectedCommit "$COMMIT_HASH"
    scp -F "$SSH_CONFIG" -i "$WINDOWS_SSH_KEY" \
        "$WINDOWS_USER@$WINDOWS_HOST:/C:/FluxheimBuild/output/$RELEASE_VERSION/x86_64/*" \
        "$OUTPUT_DIR/windows/x86_64/"
else
    import_evidence "$INPUT_DIR/windows/x86_64" "$OUTPUT_DIR/windows/x86_64" \
        SHA256SUMS-x86_64-windows.txt 7 '*.zip'
fi
normalize_windows_text_evidence "$OUTPUT_DIR/windows/x86_64"
(
    cd "$OUTPUT_DIR/windows/x86_64"
    [[ "$(find . -maxdepth 1 -name '*.zip' -type f | wc -l)" -eq 7 ]]
    sha256sum -c SHA256SUMS-x86_64-windows.txt
    grep -Fx "commit=$COMMIT_HASH" release-evidence-x86_64-windows.txt >/dev/null
    grep -Fx 'archive_count=7' release-evidence-x86_64-windows.txt >/dev/null
    grep -Fx 'reproducible=true' release-evidence-x86_64-windows.txt >/dev/null
    grep -Fx 'reproducibility_scope=default-release-binary' release-evidence-x86_64-windows.txt >/dev/null
)

MACOS_INPUT="${FLUXHEIM_MACOS_ASSET_DIR:-$INPUT_DIR/macos}"
if [[ ! -d "$MACOS_INPUT" ]]; then
    default_macos="$OUTPUT_BASE/fluxheim-${RELEASE_VERSION}-macos-assets"
    read -r -p "Enter macOS asset directory [$default_macos]: " MACOS_INPUT
    MACOS_INPUT="${MACOS_INPUT:-$default_macos}"
fi
import_evidence "$MACOS_INPUT" "$OUTPUT_DIR/macos" SHA256SUMS-aarch64-macos.txt 7 '*.tar.gz'
grep -F -- "- Commit: \`$COMMIT_HASH\`" "$OUTPUT_DIR/macos/release-report-macos.md" >/dev/null || {
    echo "error: macOS evidence is not for commit $COMMIT_HASH" >&2; exit 1;
}

echo "--- Generating SBOM evidence ---"
FLUXHEIM_SBOM_DIR="$OUTPUT_DIR/evidence" scripts/generate-sbom.sh
(
    cd "$OUTPUT_DIR/evidence"
    sha256sum fluxheim.spdx.json fluxheim.cyclonedx.json > SHA256SUMS-sbom.txt
)
cp "$WORK_DIR/tag-verification.txt" "$OUTPUT_DIR/evidence/"

echo "--- Pulling release images and recording immutable digests ---"
CONTAINER_DIGESTS="$OUTPUT_DIR/evidence/container-digests.txt"
: > "$CONTAINER_DIGESTS"
for profile in full wasm cache proxy load-balancer php; do
    profile_tag=""; [[ "$profile" == full ]] || profile_tag="${profile}-"
    bases=(wolfi alpine suse-micro debian)
    [[ "$profile" == php ]] && bases=(wolfi alpine suse-bci debian)
    for base in "${bases[@]}"; do
        image="ghcr.io/valkyoth/fluxheim:${TAG}-${profile_tag}${base}"
        echo "  Pulling $image" >&2
        podman pull "$image" >/dev/null
        digest="$(podman image inspect --format '{{.Digest}}' "$image")"
        [[ "$digest" == sha256:* ]] || { echo "error: no digest for $image" >&2; exit 1; }
        printf '%s@%s\n' "$image" "$digest" >> "$CONTAINER_DIGESTS"
    done
done

markdown_checksums() {
    while IFS= read -r line; do printf '    - `%s`\n' "$line"; done < "$1"
}

markdown_profile_checksums() {
    local checksum_file="$1" suffix="$2" extension="$3" profile line
    for profile in "${PROFILES[@]}"; do
        line="$(grep -E "  fluxheim-${RELEASE_VERSION}-${profile}-${suffix}[.]${extension}$" "$checksum_file")"
        [[ -n "$line" ]] || { echo "error: missing checksum for $profile $suffix" >&2; exit 1; }
        printf '    - `%s`\n' "$line"
    done
}

container_group() {
    local profile="$1" label="$2" base display image
    printf '%s\n' "- $label Build Container digests:"
    for pair in 'wolfi:Wolfi' 'alpine:Alpine' 'suse-micro:SUSE Micro' 'debian:Debian'; do
        base="${pair%%:*}"; display="${pair#*:}"
        [[ "$profile" == php && "$base" == suse-micro ]] && { base=suse-bci; display='SUSE BCI'; }
        image="ghcr.io/valkyoth/fluxheim:${TAG}-"
        [[ "$profile" != full ]] && image+="${profile}-"
        image+="$base"
        printf '  - %s: `%s`\n' "$display" "$(grep -F "$image@" "$CONTAINER_DIGESTS")"
    done
}

{
    echo '## Checksums And Signatures'
    echo
    echo "- Commit: \`$COMMIT_HASH\`"
    echo '- Local gate: GitHub CI green before tag; local release metadata checks passed'
    echo '- CodeQL/code scanning: no open release-blocking alerts before tag'
    echo '- Source archive checksums:'
    markdown_checksums "$OUTPUT_DIR/source/SHA256SUMS-source.txt"
    echo '- Binary Checksums (SHA-256):'
    echo '  - Linux (x86_64):'
    markdown_profile_checksums "$OUTPUT_DIR/linux/x86_64/SHA256SUMS-x86_64-linux.txt" x86_64-linux tar.gz
    echo '  - Linux (aarch64):'
    markdown_profile_checksums "$OUTPUT_DIR/linux/aarch64/SHA256SUMS-aarch64-linux.txt" aarch64-linux tar.gz
    echo '  - macOS (Apple Silicon / aarch64):'
    markdown_profile_checksums "$OUTPUT_DIR/macos/SHA256SUMS-aarch64-macos.txt" aarch64-macos tar.gz
    echo '  - Windows (x86_64):'
    markdown_profile_checksums "$OUTPUT_DIR/windows/x86_64/SHA256SUMS-x86_64-windows.txt" x86_64-windows zip
    echo '- SBOM checksums:'
    markdown_checksums "$OUTPUT_DIR/evidence/SHA256SUMS-sbom.txt"
    echo '- Reproducible build:'
    echo "  - \`$LOCAL_REPRO_HASH\`  Linux x86_64"
    echo "  - \`$(cat "$OUTPUT_DIR/linux/aarch64/REPRODUCIBLE-BUILD-SHA256-aarch64-linux.txt")\`  Linux aarch64"
    echo "  - \`$(cat "$OUTPUT_DIR/macos/REPRODUCIBLE-BUILD-SHA256-aarch64-macos.txt")\`  macOS (Apple Silicon / aarch64)"
    echo "  - \`$(cat "$OUTPUT_DIR/windows/x86_64/REPRODUCIBLE-BUILD-SHA256-x86_64-windows.txt")\`  Windows x86_64"
    container_group full Full
    container_group wasm Wasm
    container_group cache Cache
    container_group proxy Proxy
    container_group php PHP
    container_group load-balancer 'Load Balancer'
    echo '- Tag signature:'
    echo "  - \`$TAG_SIGNATURE\`"
} | tee "$REPORT"

echo
echo "Fluxheim release aggregation: ok"
echo "Output: $OUTPUT_DIR"
echo "Report: $REPORT"
