#!/usr/bin/env sh
set -eu

fluxheim_port="${FLUXHEIM_OBSERVABILITY_PORT:-18180}"
metrics_port="${FLUXHEIM_OBSERVABILITY_METRICS_PORT:-19191}"
upstream_port="${FLUXHEIM_OBSERVABILITY_UPSTREAM_PORT:-18181}"
prometheus_url="${FLUXHEIM_PROMETHEUS_URL:-http://127.0.0.1:9090}"
jaeger_url="${FLUXHEIM_JAEGER_URL:-http://127.0.0.1:16686}"
otlp_trace_endpoint="${FLUXHEIM_OTLP_TRACE_ENDPOINT:-http://127.0.0.1:4318/v1/traces}"
otlp_metrics_endpoint="${FLUXHEIM_OTLP_METRICS_ENDPOINT:-http://127.0.0.1:9090/api/v1/otlp/v1/metrics}"
require_prometheus="${FLUXHEIM_PROMETHEUS_REQUIRED:-0}"
require_fluxheim_scrape="${FLUXHEIM_PROMETHEUS_REQUIRE_FLUXHEIM:-0}"
require_prometheus_otlp="${FLUXHEIM_PROMETHEUS_REQUIRE_OTLP:-0}"
require_prometheus_otlp_fluxheim="${FLUXHEIM_PROMETHEUS_REQUIRE_OTLP_FLUXHEIM:-0}"
require_jaeger_trace="${FLUXHEIM_JAEGER_REQUIRE_TRACE:-0}"
tmp="$(mktemp -d "${TMPDIR:-/tmp}/fluxheim-observability-smoke.XXXXXX")"
config="$tmp/fluxheim.toml"
body="$tmp/body.txt"
metrics_body="$tmp/metrics.txt"
prometheus_body="$tmp/prometheus.json"
prometheus_flags="$tmp/prometheus-flags.json"
jaeger_body="$tmp/jaeger.json"
trace_id="4bf92f3577b34da6a3ce929d0e0e4736"
span_id="00f067aa0ba902b7"
traceparent="00-$trace_id-$span_id-01"

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
    rm -rf "$tmp"
}

trap cleanup EXIT INT TERM

mkdir -p "$tmp"

python3 - "$upstream_port" >"$tmp/upstream.log" 2>&1 <<'PY' &
import http.server
import socketserver
import sys

port = int(sys.argv[1])

class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
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

[vhosts.proxy]
upstreams = ["127.0.0.1:$upstream_port"]
upstream_tls = false
EOF

cargo build --quiet --no-default-features --features profile-observability
target/debug/fluxheim --config "$config" >"$tmp/fluxheim.log" 2>&1 &
server_pid="$!"

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

for _ in 1 2 3 4 5; do
    curl -fsS "http://127.0.0.1:$metrics_port/metrics" >"$metrics_body"
    if grep -q 'fluxheim_cache_purger_runs_total{outcome="skipped"}' "$metrics_body"; then
        break
    fi
    sleep 0.2
done
if ! grep -q 'fluxheim_cache_purger_runs_total{outcome="skipped"}' "$metrics_body"; then
    echo "observability smoke failed: metrics endpoint missed cache purger outcome metric" >&2
    head -n 80 "$metrics_body" >&2 || true
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
