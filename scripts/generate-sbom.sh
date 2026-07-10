#!/usr/bin/env sh
set -eu

output_dir="${FLUXHEIM_SBOM_DIR:-target/release-evidence}"
mkdir -p "$output_dir"

if ! cargo sbom --version >/dev/null 2>&1; then
    echo "cargo-sbom is required; install with: cargo install --locked cargo-sbom" >&2
    exit 1
fi

spdx_output="$output_dir/fluxheim.spdx.json"
cyclonedx_output="$output_dir/fluxheim.cyclonedx.json"
base_images_output="$output_dir/fluxheim-base-images.txt"

cargo sbom --output-format spdx_json_2_3 > "$spdx_output"
cargo sbom --output-format cyclone_dx_json_1_4 > "$cyclonedx_output"

{
    for file in Containerfile containers/Containerfile.*; do
        sed -n -E "s#^ARG (RUST|RUNTIME)_IMAGE=#$file \\1_IMAGE=#p" "$file"
    done
} > "$base_images_output"

test -s "$spdx_output"
test -s "$cyclonedx_output"
grep -q '"spdxVersion"[[:space:]]*:[[:space:]]*"SPDX-2.3"' "$spdx_output"
grep -q '"bomFormat"[[:space:]]*:[[:space:]]*"CycloneDX"' "$cyclonedx_output"
test -s "$base_images_output"
if grep -Ev '^[^ ]+ (RUST|RUNTIME)_IMAGE=.+@sha256:[0-9a-f]{64}$' "$base_images_output" >/dev/null; then
    echo "SBOM evidence contains an unpinned container base image" >&2
    exit 1
fi

sha256sum "$spdx_output" "$cyclonedx_output" "$base_images_output"
