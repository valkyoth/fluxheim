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

for version in 1.7.2 1.7.3 1.7.4 1.7.5 1.7.9 1.7.10; do
    if ! grep -q "v$version" "$plan"; then
        echo "wasm example plan: $plan does not assign v$version work" >&2
        exit 1
    fi
done

if ! grep -q "scripts/test_starter.py" "$examples"; then
    echo "wasm example plan: examples doc must require test_starter coverage" >&2
    exit 1
fi

if ! grep -q "capability parity, not syntax" "$examples"; then
    echo "wasm example plan: examples doc must state capability parity, not syntax compatibility" >&2
    exit 1
fi

echo "wasm example plan: ok"
