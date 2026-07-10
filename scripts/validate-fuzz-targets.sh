#!/usr/bin/env sh
set -eu

cargo check --manifest-path fuzz/Cargo.toml --bins

echo "fuzz targets: ok"
