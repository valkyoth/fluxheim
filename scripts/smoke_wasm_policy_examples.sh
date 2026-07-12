#!/usr/bin/env sh
set -eu

cargo test --locked -p fluxheim-server --features wasm \
    native_wasm_irules_policy_example_allows_public_and_denies_admin
cargo test --locked -p fluxheim-server --features wasm \
    native_wasm_access_decision_fails_closed_on_trap
cargo test --locked -p fluxheim-server --features wasm \
    native_wasm_openresty_header_policy_example_uses_bounded_host_calls
cargo test --locked -p fluxheim-server --features wasm \
    native_wasm_forbidden_header_mutation_fails_closed
cargo test --locked -p fluxheim-server \
    --features "wasm,load-balancer,traffic-mirror" \
    native_wasm_route_decision

echo "wasm policy examples smoke: ok"
