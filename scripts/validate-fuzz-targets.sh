#!/usr/bin/env sh
set -eu

cargo check --manifest-path fuzz/Cargo.toml --bin host_normalization
cargo check --manifest-path fuzz/Cargo.toml --bin cache_headers

echo "fuzz targets: ok"
