#!/usr/bin/env sh
set -eu

echo "1.0 fixtures: validate representative gateway config set"
cargo run -- --validate-config --config examples/gateway-1-0
echo "1.0 fixtures: ok"
