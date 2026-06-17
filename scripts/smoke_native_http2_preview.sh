#!/usr/bin/env sh
set -eu

cargo test --locked -p fluxheim-server native_http2
cargo test --locked -p fluxheim-server server_plan_exposes_native_http2_preview_gate

echo "native HTTP/2 preview smoke passed"
