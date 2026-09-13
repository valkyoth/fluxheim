#!/usr/bin/env bash

# Build and verify Fluxheim Apple Silicon release assets for Linux aggregation.

set -euo pipefail

REPO_URL="${FLUXHEIM_REPO_URL:-https://github.com/valkyoth/fluxheim.git}"
OUTPUT_BASE="${FLUXHEIM_RELEASE_OUTPUT_DIR:-$PWD}"
RUST_VERSION="${1:-}"
RELEASE_VERSION="${2:-}"

[[ -n "$RUST_VERSION" ]] || read -r -p "Enter Rust version (e.g., 1.98.1): " RUST_VERSION
[[ -n "$RELEASE_VERSION" ]] || read -r -p "Enter release version (e.g., 1.8.2): " RELEASE_VERSION
case "$RUST_VERSION" in "" | *[!0-9A-Za-z._+-]*) echo "error: unsafe Rust version" >&2; exit 2;; esac
case "$RELEASE_VERSION" in "" | .* | *..* | *[!0-9A-Za-z._+-]*) echo "error: unsafe release version" >&2; exit 2;; esac
for command in cargo cmp file git python3 rustc rustup shasum tar unzip; do
    command -v "$command" >/dev/null 2>&1 || { echo "error: missing command: $command" >&2; exit 2; }
done
if [[ "$(uname -s)" != Darwin || "$(uname -m)" != arm64 ]]; then
    echo 'error: this helper requires an Apple Silicon Mac' >&2
    exit 2
fi

TAG="v${RELEASE_VERSION}"
WORK_PARENT="${HOME}/.fhr"
mkdir -p "$WORK_PARENT"
chmod 700 "$WORK_PARENT"
WORK_DIR="$(mktemp -d "${WORK_PARENT}/r.XXXXXX")"
REPO_DIR="$WORK_DIR/f"
OUTPUT_DIR="$OUTPUT_BASE/fluxheim-${RELEASE_VERSION}-macos-assets"
export FLUXHEIM_SMOKE_TMP_ROOT="$WORK_DIR/s"
mkdir -p "$FLUXHEIM_SMOKE_TMP_ROOT"
chmod 700 "$FLUXHEIM_SMOKE_TMP_ROOT"
cleanup() { rm -rf "$WORK_DIR"; }
trap cleanup EXIT INT TERM

rustup toolchain install "$RUST_VERSION" --profile minimal
git clone --branch "$TAG" --depth 1 "$REPO_URL" "$REPO_DIR"
cd "$REPO_DIR"
TAG_COMMIT="$(git rev-parse "${TAG}^{commit}")"
[[ "$(git rev-parse HEAD)" == "$TAG_COMMIT" ]] || { echo 'error: tag checkout mismatch' >&2; exit 1; }
git tag -v "$TAG" > "$WORK_DIR/tag-verification.txt" 2>&1 || {
    cat "$WORK_DIR/tag-verification.txt" >&2
    echo 'error: signed tag verification failed' >&2
    exit 1
}
TAG_SIGNATURE_LINE="$(sed -n '/Good .*signature/p' "$WORK_DIR/tag-verification.txt" | sed -n '1p')"

rustup override set "$RUST_VERSION"
HOST_TARGET="$(rustc -vV | sed -n 's/^host: //p')"
[[ "$HOST_TARGET" == aarch64-apple-darwin ]] || { echo "error: unexpected Rust host: $HOST_TARGET" >&2; exit 1; }

echo '--- Running native macOS parity smoke ---'
sh scripts/smoke_macos_native_parity.sh

echo '--- Checking reproducible macOS build ---'
export SOURCE_DATE_EPOCH="$(git log -1 --format=%ct)"
CARGO_TARGET_DIR="$WORK_DIR/reproducible-a" cargo build --release --locked
CARGO_TARGET_DIR="$WORK_DIR/reproducible-b" cargo build --release --locked
cmp "$WORK_DIR/reproducible-a/release/fluxheim" "$WORK_DIR/reproducible-b/release/fluxheim"
REPRO_HASH="$(shasum -a 256 "$WORK_DIR/reproducible-a/release/fluxheim" | awk '{print $1}')"

echo '--- Building all macOS release profiles ---'
rm -rf dist "target/${HOST_TARGET}"
scripts/build_release_assets.sh "$RELEASE_VERSION" --kind macos
WASM_BIN="$REPO_DIR/dist/fluxheim-${RELEASE_VERSION}-wasm-aarch64-macos/fluxheim"
FLUXHEIM_BIN="$WASM_BIN" sh scripts/smoke_wasm_policy_examples_binary.sh

profiles=(full wasm cache proxy load-balancer php config-tester)
for profile in "${profiles[@]}"; do
    bundle="fluxheim-${RELEASE_VERSION}-${profile}-aarch64-macos"
    tar -tzf "dist/${bundle}.tar.gz" >/dev/null
    unzip -tq "dist/${bundle}.zip" >/dev/null
    binaries=(fluxheim fluxheim-acme)
    [[ "$profile" == config-tester ]] && binaries=(fluxheim-config-tester)
    for binary in "${binaries[@]}"; do
        path="dist/${bundle}/${binary}"
        file "$path" | grep -q 'Mach-O 64-bit executable arm64'
        "$path" --version | grep -q "fluxheim ${RELEASE_VERSION}"
    done
done

rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"
for profile in "${profiles[@]}"; do
    cp "dist/fluxheim-${RELEASE_VERSION}-${profile}-aarch64-macos.tar.gz" "$OUTPUT_DIR/"
done
(
    cd "$OUTPUT_DIR"
    shasum -a 256 fluxheim-"${RELEASE_VERSION}"-*-aarch64-macos.tar.gz > SHA256SUMS-aarch64-macos.txt
    shasum -a 256 -c SHA256SUMS-aarch64-macos.txt
)
cp "$WORK_DIR/tag-verification.txt" "$OUTPUT_DIR/"
printf '%s\n' "$REPRO_HASH" > "$OUTPUT_DIR/REPRODUCIBLE-BUILD-SHA256-aarch64-macos.txt"

cat > "$OUTPUT_DIR/release-report-macos.md" <<EOF
## macOS Apple Silicon Release Evidence

- Tag: \`${TAG}\`
- Commit: \`${TAG_COMMIT}\`
- Rust: \`$(rustc --version)\`
- Target: \`${HOST_TARGET}\`
- Native parity smoke: passed
- Packaged Wasm policy smoke: passed
- Archive validation: tar.gz and zip payloads passed for all seven profiles
- Publication set: seven tar.gz archives; zip is validation-only until signed packaging is available
- Native binary validation: all staged executables are Mach-O arm64 and report Fluxheim ${RELEASE_VERSION}
- Reproducible build SHA-256: \`${REPRO_HASH}\`
- Tag signature: \`${TAG_SIGNATURE_LINE}\`

### Binary Archive Checksums

\`\`\`text
$(cat "$OUTPUT_DIR/SHA256SUMS-aarch64-macos.txt")
\`\`\`
EOF

echo "macOS release assets: ok"
echo "Output: $OUTPUT_DIR"
echo "Report: $OUTPUT_DIR/release-report-macos.md"
