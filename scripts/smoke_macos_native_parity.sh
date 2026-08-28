#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT_DIR"

if [ "$(uname -s)" != "Darwin" ] \
    && [ "${FLUXHEIM_MACOS_PARITY_ALLOW_NON_DARWIN:-0}" != "1" ]; then
    echo "macOS native parity smoke requires a Darwin host" >&2
    exit 2
fi

for command in cargo curl openssl python3; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "macOS native parity smoke requires $command" >&2
        exit 2
    fi
done

echo "macOS parity: static, proxy, and TLS"
FLUXHEIM_SMOKE_SKIP_CORE_MATRIX=1 sh scripts/smoke_1_0_core.sh

echo "macOS parity: verified upstream TLS"
sh scripts/smoke_upstream_tls_local.sh

echo "macOS parity: admin listener and local operations socket"
sh scripts/smoke_admin_listener.sh

echo "macOS parity: local static serving and cache"
sh scripts/smoke_static_local.sh

echo "macOS parity: load balancer"
sh scripts/smoke_load_balancer.sh

echo "macOS parity: proxy memory and disk cache"
sh scripts/smoke_proxy_cache.sh

echo "macOS parity: local metrics and exporter health"
FLUXHEIM_OBSERVABILITY_START_PROMETHEUS=0 \
FLUXHEIM_OBSERVABILITY_START_JAEGER=0 \
FLUXHEIM_PROMETHEUS_REQUIRED=0 \
FLUXHEIM_PROMETHEUS_REQUIRE_FLUXHEIM=0 \
FLUXHEIM_PROMETHEUS_REQUIRE_OTLP=0 \
FLUXHEIM_PROMETHEUS_REQUIRE_OTLP_FLUXHEIM=0 \
FLUXHEIM_JAEGER_REQUIRE_TRACE=0 \
    sh scripts/smoke_observability_local.sh

echo "macOS native static/proxy/TLS/cache/admin/load-balancer/observability parity: ok"
