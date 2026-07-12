#!/usr/bin/env sh
set -eu

scripts/build_wasm_policy_examples.sh
scripts/validate-wasm-config-registry.sh
scripts/smoke_wasm_sandbox.sh
scripts/smoke_wasm_policy_examples.sh
scripts/smoke_wasm_policy_examples_binary.sh

echo "wasm complete smoke: ok"
