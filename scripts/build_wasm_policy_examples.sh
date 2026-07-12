#!/usr/bin/env sh
set -eu

output="target/wasm-policy-examples"

cargo run --locked -p fluxheim-wasm --example build_policy_examples --quiet

for name in \
    irules-access-policy \
    openresty-header-policy \
    haproxy-spoe-routing-policy \
    cache-lookup-policy \
    cache-store-policy
do
    test -s "$output/$name.wasm"
    grep -q "  $name.wasm$" "$output/SHA256SUMS"
done

(cd "$output" && sha256sum -c SHA256SUMS)

echo "wasm policy example build: ok"
