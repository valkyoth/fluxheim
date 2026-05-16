#!/usr/bin/env sh
set -eu

echo "1.0 fixtures: validate representative gateway config set"
# Gateway fixtures use placeholder /srv roots and upstreams. Keep this as a
# static config check; deployment preflight uses --validate-config.
cargo run --quiet -- --check-config --config examples/gateway-1-0 >/dev/null
echo "1.0 fixtures: ok"
