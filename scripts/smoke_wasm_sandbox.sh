#!/usr/bin/env sh
set -eu

cargo run --locked -p fluxheim-wasm --features runtime --example wasm_sandbox_smoke --quiet
