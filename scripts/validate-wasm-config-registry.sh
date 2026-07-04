#!/usr/bin/env sh
set -eu

cargo test --locked -p fluxheim-config wasm
cargo test --locked -p fluxheim-config --features wasm wasm
cargo test --locked --features wasm status_endpoint_reports_wasm_registry_summary

echo "wasm config registry: ok"
