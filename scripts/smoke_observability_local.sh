#!/usr/bin/env sh
set -eu

tmp="$(mktemp -d "${TMPDIR:-/tmp}/fluxheim-observability-smoke.XXXXXX")"
config="$tmp/fluxheim.toml"
body="$tmp/body.txt"
cache_body="$tmp/cache-body.txt"
metrics_body="$tmp/metrics.txt"
prometheus_body="$tmp/prometheus.json"
prometheus_flags="$tmp/prometheus-flags.json"
jaeger_body="$tmp/jaeger.json"
trace_id="4bf92f3577b34da6a3ce929d0e0e4736"
span_id="00f067aa0ba902b7"
traceparent="00-$trace_id-$span_id-01"
prometheus_name="fluxheim-observability-prometheus-$$"
jaeger_name="fluxheim-observability-jaeger-$$"
prometheus_image="${FLUXHEIM_PROMETHEUS_IMAGE:-docker.io/prom/prometheus:latest}"
jaeger_image="${FLUXHEIM_JAEGER_IMAGE:-docker.io/jaegertracing/all-in-one:latest}"
prometheus_started=0
jaeger_started=0

ports=$(python3 - <<'PY'
import socket

sockets = []
try:
    for _ in range(7):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("127.0.0.1", 0))
        sockets.append(sock)
    print(" ".join(str(sock.getsockname()[1]) for sock in sockets))
finally:
    for sock in sockets:
        sock.close()
PY
)

set -- $ports
fluxheim_port="${FLUXHEIM_OBSERVABILITY_PORT:-$1}"
metrics_port="${FLUXHEIM_OBSERVABILITY_METRICS_PORT:-$2}"
upstream_port="${FLUXHEIM_OBSERVABILITY_UPSTREAM_PORT:-$3}"
prometheus_port="${FLUXHEIM_PROMETHEUS_PORT:-$4}"
jaeger_query_port="${FLUXHEIM_JAEGER_QUERY_PORT:-$5}"
jaeger_otlp_http_port="${FLUXHEIM_JAEGER_OTLP_HTTP_PORT:-$6}"
jaeger_otlp_grpc_port="${FLUXHEIM_JAEGER_OTLP_GRPC_PORT:-$7}"

if [ -n "${FLUXHEIM_PROMETHEUS_URL+x}" ]; then
    auto_prometheus=0
    prometheus_url="$FLUXHEIM_PROMETHEUS_URL"
else
    auto_prometheus="${FLUXHEIM_OBSERVABILITY_START_PROMETHEUS:-1}"
    prometheus_url="http://127.0.0.1:$prometheus_port"
fi

if [ -n "${FLUXHEIM_JAEGER_URL+x}" ]; then
    auto_jaeger=0
    jaeger_url="$FLUXHEIM_JAEGER_URL"
else
    auto_jaeger="${FLUXHEIM_OBSERVABILITY_START_JAEGER:-1}"
    jaeger_url="http://127.0.0.1:$jaeger_query_port"
fi

otlp_trace_endpoint="${FLUXHEIM_OTLP_TRACE_ENDPOINT:-http://127.0.0.1:$jaeger_otlp_http_port/v1/traces}"
otlp_metrics_endpoint="${FLUXHEIM_OTLP_METRICS_ENDPOINT:-http://127.0.0.1:$prometheus_port/api/v1/otlp/v1/metrics}"
require_prometheus="${FLUXHEIM_PROMETHEUS_REQUIRED:-$auto_prometheus}"
require_fluxheim_scrape="${FLUXHEIM_PROMETHEUS_REQUIRE_FLUXHEIM:-$auto_prometheus}"
require_prometheus_otlp="${FLUXHEIM_PROMETHEUS_REQUIRE_OTLP:-$auto_prometheus}"
require_prometheus_otlp_fluxheim="${FLUXHEIM_PROMETHEUS_REQUIRE_OTLP_FLUXHEIM:-$auto_prometheus}"
require_jaeger_trace="${FLUXHEIM_JAEGER_REQUIRE_TRACE:-0}"

cleanup() {
    if [ -n "${server_pid:-}" ]; then
        kill "$server_pid" 2>/dev/null || true
        sleep 0.2
        if kill -0 "$server_pid" 2>/dev/null; then
            kill -9 "$server_pid" 2>/dev/null || true
        fi
        wait "$server_pid" 2>/dev/null || true
    fi
    if [ -n "${upstream_pid:-}" ]; then
        kill "$upstream_pid" 2>/dev/null || true
        sleep 0.2
        if kill -0 "$upstream_pid" 2>/dev/null; then
            kill -9 "$upstream_pid" 2>/dev/null || true
        fi
        wait "$upstream_pid" 2>/dev/null || true
    fi
    if [ "$prometheus_started" = "1" ]; then
        podman rm -f "$prometheus_name" >/dev/null 2>&1 || true
    fi
    if [ "$jaeger_started" = "1" ]; then
        podman rm -f "$jaeger_name" >/dev/null 2>&1 || true
    fi
    rm -rf "$tmp"
}

trap cleanup EXIT INT TERM

mkdir -p "$tmp/cache"
mkdir -p "$tmp/run"

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "observability smoke failed: missing required command: $1" >&2
        exit 1
    fi
}

wait_http() {
    url="$1"
    for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
        if curl -fsS "$url" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.2
    done
    return 1
}

if [ "$auto_prometheus" = "1" ]; then
    require_command podman
    cat > "$tmp/prometheus.yml" <<EOF
global:
  scrape_interval: 1s
scrape_configs:
  - job_name: fluxheim
    static_configs:
      - targets: ["127.0.0.1:$metrics_port"]
EOF
    podman rm -f "$prometheus_name" >/dev/null 2>&1 || true
    podman run -d \
        --name "$prometheus_name" \
        --network host \
        --security-opt no-new-privileges \
        -v "$tmp/prometheus.yml:/etc/prometheus/prometheus.yml:ro,Z" \
        "$prometheus_image" \
        --config.file=/etc/prometheus/prometheus.yml \
        --storage.tsdb.path=/tmp/prometheus \
        --web.listen-address="127.0.0.1:$prometheus_port" \
        --web.enable-otlp-receiver >/dev/null
    prometheus_started=1
    if ! wait_http "$prometheus_url/-/ready"; then
        echo "observability smoke failed: timed out waiting for disposable Prometheus" >&2
        podman logs "$prometheus_name" >&2 || true
        exit 1
    fi
fi

if [ "$auto_jaeger" = "1" ]; then
    require_command podman
    podman rm -f "$jaeger_name" >/dev/null 2>&1 || true
    podman run -d \
        --name "$jaeger_name" \
        --network host \
        --security-opt no-new-privileges \
        -e COLLECTOR_OTLP_ENABLED=true \
        "$jaeger_image" \
        --query.http-server.host-port="127.0.0.1:$jaeger_query_port" \
        --collector.otlp.http.host-port="127.0.0.1:$jaeger_otlp_http_port" \
        --collector.otlp.grpc.host-port="127.0.0.1:$jaeger_otlp_grpc_port" >/dev/null
    jaeger_started=1
    if ! wait_http "$jaeger_url/api/services"; then
        echo "observability smoke failed: timed out waiting for disposable Jaeger" >&2
        podman logs "$jaeger_name" >&2 || true
        exit 1
    fi
fi

python3 - "$upstream_port" >"$tmp/upstream.log" 2>&1 <<'PY' &
import http.server
import socketserver
import sys

port = int(sys.argv[1])

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/cached.css":
            body = b"body { color: #123456; }\n"
            self.send_response(200)
            self.send_header("content-type", "text/css")
            self.send_header("content-length", str(len(body)))
            self.send_header("cache-control", "public, max-age=120")
            self.send_header("etag", '"observability-cache-v1"')
            self.end_headers()
            self.wfile.write(body)
            return

        traceparent = self.headers.get("traceparent", "")
        body = f"traceparent={traceparent}\n".encode("utf-8")
        self.send_response(200)
        self.send_header("content-type", "text/plain")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        return

class ReuseTCPServer(socketserver.TCPServer):
    allow_reuse_address = True

with ReuseTCPServer(("127.0.0.1", port), Handler) as server:
    server.serve_forever()
PY
upstream_pid="$!"

cat > "$config" <<EOF
[server]
listen = ["127.0.0.1:$fluxheim_port"]
trusted_proxies = ["127.0.0.1/32"]

[server.process]
pid_file = "$tmp/run/fluxheim.pid"
upgrade_sock = "$tmp/run/fluxheim-upgrade.sock"
certificate_reload_sock = "$tmp/run/fluxheim-cert-reload.sock"

[logging]
level = "warn"
format = "text"

[logging.access]
enabled = true
include_host = true
include_path = true
request_id = true

[metrics]
enabled = true
listen = "127.0.0.1:$metrics_port"
require_loopback = true

[metrics.otlp]
enabled = true
endpoint = "$otlp_metrics_endpoint"
service_name = "fluxheim-smoke"
interval_secs = 1
timeout_secs = 2

[tracing]
enabled = true
mode = "propagate_only"
traceparent = true
log_trace_id = true

[tracing.otlp]
enabled = true
endpoint = "$otlp_trace_endpoint"
service_name = "fluxheim-smoke"
queue_size = 64
timeout_secs = 2

[tls]
enabled = false
backend = "rustls"

[cache]
enabled = false
max_object_bytes = "256KiB"

[cache.memory]
enabled = false
max_size_bytes = "1MiB"

[cache_purger]
enabled = true
interval_secs = 1
limit = 8
batches = 1

[proxy]
upstreams = ["127.0.0.1:$upstream_port"]
upstream_tls = false

[[vhosts]]
name = "observability.test"
hosts = ["observability.test"]

[vhosts.cache]
enabled = true
max_object_bytes = "256KiB"

[vhosts.cache.memory]
enabled = true
max_size_bytes = "1MiB"

[vhosts.cache.lock]
enabled = true
wait_timeout_secs = 11

[vhosts.proxy]
upstreams = ["127.0.0.1:$upstream_port"]
upstream_tls = false

[[vhosts.routes]]
name = "observability-cache"
path_exact = "/cached.css"

[vhosts.routes.cache]
enabled = true
max_object_bytes = "256KiB"

[vhosts.routes.cache.memory]
enabled = true
max_size_bytes = "1MiB"

[vhosts.routes.cache.disk]
enabled = true
path = "$tmp/cache"
max_size_bytes = "1MiB"

[vhosts.routes.cache.lock]
enabled = true
wait_timeout_secs = 17

[vhosts.routes.proxy]
upstreams = ["127.0.0.1:$upstream_port"]
upstream_tls = false
EOF

cargo build --quiet --no-default-features --features profile-observability
target/debug/fluxheim --config "$config" >"$tmp/fluxheim.log" 2>&1 &
server_pid="$!"

if ! wait_http "http://127.0.0.1:$upstream_port/"; then
    echo "observability smoke failed: timed out waiting for upstream test server" >&2
    cat "$tmp/upstream.log" >&2 || true
    exit 1
fi

if ! wait_http "http://127.0.0.1:$fluxheim_port/"; then
    echo "observability smoke failed: timed out waiting for Fluxheim listener" >&2
    cat "$tmp/fluxheim.log" >&2 || true
    exit 1
fi

if ! wait_http "http://127.0.0.1:$metrics_port/metrics"; then
    echo "observability smoke failed: timed out waiting for metrics listener" >&2
    cat "$tmp/fluxheim.log" >&2 || true
    exit 1
fi

curl -fsS \
    -H "Host: observability.test" \
    -H "traceparent: $traceparent" \
    "http://127.0.0.1:$fluxheim_port/" >"$body"

if ! grep -q "traceparent=00-$trace_id-" "$body"; then
    echo "observability smoke failed: upstream did not receive propagated traceparent" >&2
    cat "$body" >&2
    exit 1
fi

if grep -q "$span_id" "$body"; then
    echo "observability smoke failed: upstream received the inbound span id without regeneration" >&2
    cat "$body" >&2
    exit 1
fi

curl -fsS \
    -H "Host: observability.test" \
    "http://127.0.0.1:$fluxheim_port/cached.css" >"$cache_body"

if ! grep -q "body { color: #123456; }" "$cache_body"; then
    echo "observability smoke failed: cache route response body mismatch" >&2
    cat "$cache_body" >&2
    exit 1
fi

curl -fsS \
    -H "Host: observability.test" \
    "http://127.0.0.1:$fluxheim_port/cached.css" >"$cache_body"

for _ in 1 2 3 4 5 6 7; do
    curl -fsS "http://127.0.0.1:$metrics_port/metrics" >"$metrics_body"
    if grep -q 'fluxheim_cache_memory_entries 1' "$metrics_body"; then
        break
    fi
    sleep 1
done

if curl -fsS "http://127.0.0.1:$metrics_port/metrics" >"$metrics_body" \
    && grep -q "fluxheim_" "$metrics_body"; then
    :
elif curl -fsS "http://127.0.0.1:$metrics_port/" >"$metrics_body" \
    && grep -q "fluxheim_" "$metrics_body"; then
    :
else
    echo "observability smoke failed: metrics listener did not return Fluxheim metrics on /metrics or /" >&2
    head -n 40 "$metrics_body" >&2 || true
    exit 1
fi

if ! grep -q "fluxheim_proxy_requests_total" "$metrics_body"; then
    echo "observability smoke failed: metrics endpoint missed fluxheim_proxy_requests_total" >&2
    head -n 40 "$metrics_body" >&2 || true
    exit 1
fi

if ! grep -q 'vhost="observability.test"' "$metrics_body"; then
    echo "observability smoke failed: metrics endpoint missed observability.test vhost label" >&2
    exit 1
fi

if ! grep -q 'fluxheim_cache_configured_routes 1' "$metrics_body"; then
    echo "observability smoke failed: metrics endpoint missed configured cache route gauge" >&2
    grep 'fluxheim_cache_' "$metrics_body" >&2 || true
    exit 1
fi

if ! grep -q 'fluxheim_cache_enabled_vhosts 1' "$metrics_body"; then
    echo "observability smoke failed: metrics endpoint missed enabled cache vhost gauge" >&2
    grep 'fluxheim_cache_' "$metrics_body" >&2 || true
    exit 1
fi

if ! grep -q 'fluxheim_cache_enabled_routes 1' "$metrics_body"; then
    echo "observability smoke failed: metrics endpoint missed enabled cache route gauge" >&2
    grep 'fluxheim_cache_' "$metrics_body" >&2 || true
    exit 1
fi

if ! grep -q 'fluxheim_cache_lock_enabled_policies 2' "$metrics_body"; then
    echo "observability smoke failed: metrics endpoint missed cache lock policy gauge" >&2
    grep 'fluxheim_cache_' "$metrics_body" >&2 || true
    exit 1
fi

if ! grep -q 'fluxheim_cache_lock_wait_timeout_max_seconds 17' "$metrics_body"; then
    echo "observability smoke failed: metrics endpoint missed cache lock timeout gauge" >&2
    grep 'fluxheim_cache_' "$metrics_body" >&2 || true
    exit 1
fi

if ! grep -q 'fluxheim_cache_memory_entries 1' "$metrics_body"; then
    echo "observability smoke failed: metrics endpoint missed runtime memory cache entry gauge" >&2
    grep 'fluxheim_cache_memory_' "$metrics_body" >&2 || true
    exit 1
fi

if ! grep -Eq 'fluxheim_cache_memory_weighted_size_bytes [1-9][0-9]*' "$metrics_body"; then
    echo "observability smoke failed: metrics endpoint missed runtime memory cache size gauge" >&2
    grep 'fluxheim_cache_memory_' "$metrics_body" >&2 || true
    exit 1
fi

if ! grep -q 'fluxheim_cache_memory_max_size_bytes 2097152' "$metrics_body"; then
    echo "observability smoke failed: metrics endpoint missed runtime memory cache budget gauge" >&2
    grep 'fluxheim_cache_memory_' "$metrics_body" >&2 || true
    exit 1
fi

if ! grep -q 'fluxheim_cache_disk_entries 1' "$metrics_body"; then
    echo "observability smoke failed: metrics endpoint missed runtime disk cache entry gauge" >&2
    grep 'fluxheim_cache_disk_' "$metrics_body" >&2 || true
    exit 1
fi

if ! grep -Eq 'fluxheim_cache_disk_size_bytes [1-9][0-9]*' "$metrics_body"; then
    echo "observability smoke failed: metrics endpoint missed runtime disk cache size gauge" >&2
    grep 'fluxheim_cache_disk_' "$metrics_body" >&2 || true
    exit 1
fi

if ! grep -q 'fluxheim_cache_disk_max_size_bytes 1048576' "$metrics_body"; then
    echo "observability smoke failed: metrics endpoint missed runtime disk cache budget gauge" >&2
    grep 'fluxheim_cache_disk_' "$metrics_body" >&2 || true
    exit 1
fi

if ! grep -q 'fluxheim_cache_operation_duration_seconds_bucket' "$metrics_body"; then
    echo "observability smoke failed: metrics endpoint missed cache operation duration histogram" >&2
    grep 'fluxheim_cache_operation_duration' "$metrics_body" >&2 || true
    exit 1
fi

if ! grep -q 'phase="miss"' "$metrics_body"; then
    echo "observability smoke failed: cache operation metrics missed cache miss phase" >&2
    grep 'fluxheim_cache_operation_duration' "$metrics_body" >&2 || true
    exit 1
fi

if ! grep -q 'phase="hit"' "$metrics_body"; then
    echo "observability smoke failed: cache operation metrics missed cache hit phase" >&2
    grep 'fluxheim_cache_operation_duration' "$metrics_body" >&2 || true
    exit 1
fi

if ! grep -q 'operation="lookup"' "$metrics_body"; then
    echo "observability smoke failed: cache operation metrics missed lookup operation" >&2
    grep 'fluxheim_cache_operation_duration' "$metrics_body" >&2 || true
    exit 1
fi

for _ in 1 2 3 4 5 6 7 8 9 10; do
    curl -fsS "http://127.0.0.1:$metrics_port/metrics" >"$metrics_body"
    if grep -q 'fluxheim_cache_purger_runs_total{outcome=' "$metrics_body"; then
        break
    fi
    sleep 0.5
done
if ! grep -q 'fluxheim_cache_purger_runs_total{outcome=' "$metrics_body"; then
    echo "observability smoke failed: metrics endpoint missed cache purger outcome metric" >&2
    head -n 80 "$metrics_body" >&2 || true
    exit 1
fi
if ! grep -q 'fluxheim_cache_purger_duration_seconds_bucket{outcome=' "$metrics_body"; then
    echo "observability smoke failed: metrics endpoint missed cache purger duration histogram" >&2
    grep 'fluxheim_cache_purger_' "$metrics_body" >&2 || true
    exit 1
fi

for _ in 1 2 3 4 5 6 7 8 9 10; do
    curl -fsS "http://127.0.0.1:$metrics_port/metrics" >"$metrics_body"
    if grep -q 'fluxheim_metrics_otlp_exports_total{outcome=' "$metrics_body"; then
        break
    fi
    sleep 0.5
done
if ! grep -q 'fluxheim_metrics_otlp_exports_total{outcome=' "$metrics_body"; then
    echo "observability smoke failed: metrics endpoint missed OTLP exporter health metric" >&2
    head -n 100 "$metrics_body" >&2 || true
    exit 1
fi

if curl -fsS "$prometheus_url/-/ready" >/dev/null 2>&1; then
    curl -fsS "$prometheus_url/api/v1/status/flags" >"$prometheus_flags"
    if grep -q '"web.enable-otlp-receiver":"true"' "$prometheus_flags"; then
        echo "observability smoke: prometheus OTLP metrics receiver enabled"
    elif [ "$require_prometheus_otlp" = "1" ]; then
        echo "observability smoke failed: Prometheus API is reachable but OTLP metrics receiver is disabled" >&2
        cat "$prometheus_flags" >&2
        exit 1
    else
        echo "observability smoke: prometheus api ok; OTLP metrics receiver disabled"
    fi

    encoded_query="fluxheim_proxy_requests_total"
    curl -fsS "$prometheus_url/api/v1/query?query=$encoded_query" >"$prometheus_body"
    if grep -q '"status":"success"' "$prometheus_body" \
        && grep -q 'fluxheim_proxy_requests_total' "$prometheus_body"; then
        echo "observability smoke: prometheus api ok and fluxheim metrics are present"
    elif [ "$require_fluxheim_scrape" = "1" ]; then
        echo "observability smoke failed: Prometheus API is reachable but has no Fluxheim scrape result" >&2
        cat "$prometheus_body" >&2
        exit 1
    else
        echo "observability smoke: prometheus api ok; Fluxheim scrape not present yet"
    fi

    for _ in 1 2 3 4 5 6 7 8 9 10; do
        curl -fsS "$prometheus_url/api/v1/query?query=$encoded_query" >"$prometheus_body"
        if grep -q '"status":"success"' "$prometheus_body" \
            && grep -q 'fluxheim_proxy_requests_total' "$prometheus_body"; then
            echo "observability smoke: prometheus OTLP metrics receiver has Fluxheim series"
            break
        fi
        sleep 1
    done
    if ! grep -q 'fluxheim_proxy_requests_total' "$prometheus_body"; then
        if [ "$require_prometheus_otlp_fluxheim" = "1" ]; then
            echo "observability smoke failed: Prometheus OTLP receiver did not ingest Fluxheim metrics" >&2
            cat "$prometheus_body" >&2
            exit 1
        fi
        echo "observability smoke: Prometheus OTLP metrics ingestion not observed yet"
    fi
elif [ "$require_prometheus" = "1" ]; then
    echo "observability smoke failed: Prometheus is required but $prometheus_url is not ready" >&2
    exit 1
else
    echo "observability smoke: Prometheus API not ready at $prometheus_url; skipped external API check"
fi

if curl -fsS "$jaeger_url/api/services" >/dev/null 2>&1; then
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        if curl -fsS "$jaeger_url/api/traces?service=fluxheim-smoke&limit=20" >"$jaeger_body" \
            && grep -q "$trace_id" "$jaeger_body"; then
            echo "observability smoke: Jaeger API ok and received Fluxheim OTLP trace"
            echo "observability smoke: ok"
            exit 0
        fi
        sleep 0.5
    done
    if [ "$require_jaeger_trace" = "1" ]; then
        echo "observability smoke failed: Jaeger API is reachable but no Fluxheim trace was found" >&2
        cat "$jaeger_body" >&2 || true
        exit 1
    fi
    echo "observability smoke: Jaeger API ok; Fluxheim trace not present yet"
elif [ "$require_jaeger_trace" = "1" ]; then
    echo "observability smoke failed: Jaeger is required but $jaeger_url is not ready" >&2
    exit 1
else
    echo "observability smoke: Jaeger API not ready at $jaeger_url; skipped trace export check"
fi

echo "observability smoke: ok"
