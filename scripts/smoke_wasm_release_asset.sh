#!/usr/bin/env sh
set -eu

root="$(git rev-parse --show-toplevel)"
cd "$root"

version="$(
    sed -n '/^\[package\]$/,/^\[/s/^version = "\([^"]*\)"/\1/p' Cargo.toml |
        sed -n '1p'
)"
case "$version" in
    *[!0-9A-Za-z._+-]* | "")
        echo "Wasm release smoke found an unsafe package version" >&2
        exit 2
        ;;
esac

target="$(rustc -vV | sed -n 's/^host: //p')"
case "$target" in
    x86_64-unknown-linux-gnu | x86_64-unknown-linux-musl)
        label="x86_64-linux"
        ;;
    aarch64-unknown-linux-gnu | aarch64-unknown-linux-musl)
        label="aarch64-linux"
        ;;
    *)
        echo "Wasm release smoke currently requires a Linux host target" >&2
        exit 2
        ;;
esac

scripts/build_release_assets.sh "$version" --kind linux --profile wasm

archive="dist/fluxheim-${version}-wasm-${label}.tar.gz"
test -f "$archive"
test -f "dist/fluxheim-${version}-wasm-${label}.zip"

tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/fluxheim-wasm-release.XXXXXX")"
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM
tar -xzf "$archive" -C "$tmp_dir"

FLUXHEIM_BIN="$tmp_dir/fluxheim-${version}-wasm-${label}/fluxheim" \
    scripts/smoke_wasm_policy_examples_binary.sh

echo "Wasm release archive smoke passed"
