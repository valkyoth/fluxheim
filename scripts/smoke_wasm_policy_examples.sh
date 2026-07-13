#!/usr/bin/env sh
set -eu

family="${1:-all}"

case "$family" in
    all | irules | openresty | haproxy-spoe | vcl)
        ;;
    *)
        echo "usage: scripts/smoke_wasm_policy_examples.sh [all|irules|openresty|haproxy-spoe|vcl]" >&2
        exit 2
        ;;
esac

if [ "$family" = "all" ] || [ "$family" = "irules" ]; then
    cargo test --locked -p fluxheim-server --features wasm \
        native_wasm_irules_policy_example_allows_public_and_denies_admin
    cargo test --locked -p fluxheim-server --features wasm \
        native_wasm_access_decision_fails_closed_on_trap
fi

if [ "$family" = "all" ] || [ "$family" = "openresty" ]; then
    cargo test --locked -p fluxheim-server --features wasm \
        native_wasm_openresty_header_policy_example_uses_bounded_host_calls
    cargo test --locked -p fluxheim-server --features wasm \
        native_wasm_forbidden_header_mutation_fails_closed
fi

if [ "$family" = "all" ] || [ "$family" = "haproxy-spoe" ]; then
    cargo test --locked -p fluxheim-server \
        --features "wasm,load-balancer,traffic-mirror" \
        native_wasm_route_decision
fi

if [ "$family" = "all" ] || [ "$family" = "vcl" ]; then
    cargo test --locked -p fluxheim-server --features wasm native_wasm_cache_
fi

echo "wasm policy examples smoke ($family): ok"
