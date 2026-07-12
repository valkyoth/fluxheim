#!/usr/bin/env sh
set -eu

plan="docs/versioning-plan.md"
examples="docs/wasm-policy-example-parity.md"

for file in "$plan" "$examples"; do
    if [ ! -f "$file" ]; then
        echo "wasm example plan: missing $file" >&2
        exit 1
    fi
done

for file in \
    examples/wasm/irules-access-policy.wat \
    examples/wasm/irules-access-policy.toml \
    examples/wasm/openresty-header-policy.wat \
    examples/wasm/openresty-header-policy.toml \
    examples/wasm/haproxy-spoe-routing-policy.wat \
    examples/wasm/haproxy-spoe-routing-policy.toml \
    examples/wasm/cache-lookup-policy.wat \
    examples/wasm/cache-store-policy.wat \
    examples/wasm/cache-policy.toml \
    scripts/build_wasm_policy_examples.sh \
    scripts/smoke_wasm_all.sh \
    scripts/smoke_wasm_policy_examples.sh
do
    if [ ! -f "$file" ]; then
        echo "wasm example plan: missing $file" >&2
        exit 1
    fi
done

for term in \
    "F5 iRules" \
    "nginx Lua/OpenResty" \
    "HAProxy Lua/SPOE" \
    "VCL-Like Cache Policy"
do
    if ! grep -q "$term" "$examples"; then
        echo "wasm example plan: $examples does not document $term" >&2
        exit 1
    fi
done

for version in 1.7.1 1.7.2 1.7.3 1.7.4 1.7.8 1.7.9; do
    if ! grep -q "v$version" "$plan"; then
        echo "wasm example plan: $plan does not assign v$version work" >&2
        exit 1
    fi
done

if ! grep -q "scripts/test_starter.py" "$examples"; then
    echo "wasm example plan: examples doc must require test_starter coverage" >&2
    exit 1
fi

if ! python3 scripts/test_starter.py --run wasm --dry-run \
    | grep -q "scripts/smoke_wasm_all.sh"
then
    echo "wasm example plan: test starter does not run the complete Wasm smoke" >&2
    exit 1
fi

if ! grep -q "scripts/smoke_wasm_all.sh" scripts/stable_release_gate.sh; then
    echo "wasm example plan: stable release gate does not run the complete Wasm smoke" >&2
    exit 1
fi

if ! grep -q "capability parity, not syntax" "$examples"; then
    echo "wasm example plan: examples doc must state capability parity, not syntax compatibility" >&2
    exit 1
fi

echo "wasm example plan: ok"
