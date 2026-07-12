#!/usr/bin/env sh
set -eu

cargo test --locked -p fluxheim-server --features wasm \
    native_wasm_irules_policy_example_allows_public_and_denies_admin
cargo test --locked -p fluxheim-server --features wasm \
    native_wasm_access_decision_fails_closed_on_trap

echo "wasm policy examples smoke: ok"
