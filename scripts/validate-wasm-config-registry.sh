#!/usr/bin/env sh
set -eu

cargo test --locked -p fluxheim-config wasm
cargo test --locked -p fluxheim-config --features wasm wasm
cargo test --locked --features wasm status_endpoint_reports_wasm_registry_summary
cargo run --quiet --locked --no-default-features --features profile-development,wasm \
    --bin fluxheim-config-tester -- \
    --config tests/fixtures/wasm-config/accepted-registry.toml \
    --profile development \
    --no-runtime-paths >/dev/null

if cargo run --quiet --locked --no-default-features --features profile-development,wasm \
    --bin fluxheim-config-tester -- \
    --config tests/fixtures/wasm-config/rejected-fail-open-access.toml \
    --profile development \
    --no-runtime-paths >/dev/null 2>&1
then
    echo "wasm config registry: unsafe fail-open fixture was accepted" >&2
    exit 1
fi

echo "wasm config registry: ok"
