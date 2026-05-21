#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/fluxheim-peer-fill-smoke.XXXXXX")
KEEP_LOGS=${FLUXHEIM_SMOKE_KEEP_LOGS:-0}
CURL_MAX_TIME=${FLUXHEIM_SMOKE_CURL_MAX_TIME:-5}

ports=$(python3 - <<'PY'
import socket

sockets = []
try:
    for _ in range(5):
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
NODE_A_PORT=$1
NODE_B_PORT=$2
ORIGIN_PORT=$3
METRICS_PORT=$4
NODE_C_PORT=$5

ORIGIN_PID=
NODE_A_PID=
NODE_B_PID=
NODE_C_PID=

cleanup() {
    status=$?

    for pid in "$NODE_A_PID" "$NODE_B_PID" "$NODE_C_PID" "$ORIGIN_PID"; do
        if [ -n "$pid" ]; then
            kill "$pid" 2>/dev/null || true
        fi
    done

    sleep 0.2

    for pid in "$NODE_A_PID" "$NODE_B_PID" "$NODE_C_PID" "$ORIGIN_PID"; do
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill -9 "$pid" 2>/dev/null || true
        fi
    done

    for pid in "$NODE_A_PID" "$NODE_B_PID" "$NODE_C_PID" "$ORIGIN_PID"; do
        if [ -n "$pid" ]; then
            wait "$pid" 2>/dev/null || true
        fi
    done

    if [ "$KEEP_LOGS" = "1" ] || [ "$status" -ne 0 ]; then
        echo "peer-fill cache smoke artifacts kept in $TMP_DIR" >&2
    else
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT INT TERM

mkdir -p "$TMP_DIR/node-a-cache" "$TMP_DIR/node-b-cache" "$TMP_DIR/node-c-cache" "$TMP_DIR/run"

cat > "$TMP_DIR/origin.py" <<'PY'
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

BODY = b"peer-fill-body"
VARY_DE_BODY = b"peer-fill-vary-de"
VARY_EN_BODY = b"peer-fill-vary-en"
COUNTS = {}
COUNTS_LOCK = threading.Lock()


def record_path(path):
    with COUNTS_LOCK:
        COUNTS[path] = COUNTS.get(path, 0) + 1


def path_count(path):
    with COUNTS_LOCK:
        return COUNTS.get(path, 0)


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/__count":
            path = parse_qs(parsed.query).get("path", [""])[0]
            body = str(path_count(path)).encode("ascii")
            self.send_response(200)
            self.send_header("content-type", "text/plain")
            self.send_header("content-length", str(len(body)))
            self.send_header("cache-control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return

        if parsed.path == "/uncached.webp":
            record_path(parsed.path)
            body = b"uncached-origin-body"
            self.send_response(200)
            self.send_header("content-type", "image/webp")
            self.send_header("content-length", str(len(body)))
            self.send_header("cache-control", "public, max-age=120")
            self.send_header("etag", '"peer-fill-uncached-origin"')
            self.end_headers()
            self.wfile.write(body)
            return

        if parsed.path == "/vary.webp":
            record_path(parsed.path)
            language = self.headers.get("accept-language", "")
            body = VARY_DE_BODY if "de" in language.lower() else VARY_EN_BODY
            self.send_response(200)
            self.send_header("content-type", "image/webp")
            self.send_header("content-length", str(len(body)))
            self.send_header("cache-control", "public, max-age=120")
            self.send_header("vary", "Accept-Language")
            self.send_header("etag", '"peer-fill-vary"')
            self.end_headers()
            self.wfile.write(body)
            return

        if parsed.path != "/asset.webp":
            self.send_response(404)
            self.send_header("content-length", "0")
            self.end_headers()
            return

        record_path(parsed.path)
        self.send_response(200)
        self.send_header("content-type", "image/webp")
        self.send_header("content-length", str(len(BODY)))
        self.send_header("cache-control", "public, max-age=120")
        self.send_header("etag", '"peer-fill-smoke-v1"')
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, *_args):
        pass


server = ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), Handler)
server.serve_forever()
PY

write_config() {
    node_name=$1
    listen_port=$2
    cache_dir=$3
    metrics_block=$4
    peer_fill_block=$5

    cat > "$TMP_DIR/${node_name}.toml" <<EOF_CONFIG
[server]
listen = ["127.0.0.1:${listen_port}"]
default_vhost = "cache.test"

[server.process]
pid_file = "${TMP_DIR}/run/${node_name}.pid"
upgrade_sock = "${TMP_DIR}/run/${node_name}-upgrade.sock"
certificate_reload_sock = "${TMP_DIR}/run/${node_name}-cert-reload.sock"
threads = 1

[logging]
level = "warn"
format = "text"
target = "stderr"

[logging.access]
enabled = false

${metrics_block}

[[vhosts]]
name = "cache.test"
hosts = ["cache.test"]

[vhosts.proxy]
upstreams = ["127.0.0.1:${ORIGIN_PORT}"]
upstream_tls = false

[vhosts.cache]
enabled = true
status_header = "x-cache-status"
status_reason_header = "x-cache-reason"
content_types = ["image/webp"]
image_extensions = ["webp"]
max_object_bytes = "256KiB"

[vhosts.cache.memory]
enabled = true
max_size_bytes = "4MiB"

[vhosts.cache.disk]
enabled = true
path = "${cache_dir}"
max_size_bytes = "16MiB"

${peer_fill_block}
EOF_CONFIG
}

NODE_A_METRICS="
[metrics]
enabled = true
listen = \"127.0.0.1:${METRICS_PORT}\"
require_loopback = true
"

NODE_A_PEER_FILL="
[vhosts.cache.peer_fill]
enabled = true
connect_timeout_secs = 2
read_timeout_secs = 5
max_object_bytes = \"256KiB\"
max_concurrent_requests = 4
allow_insecure_http = true
fail_open = false

[[vhosts.cache.peer_fill.peers]]
name = \"node-b\"
base_url = \"http://127.0.0.1:${NODE_B_PORT}\"
"

NODE_C_PEER_FILL="
[vhosts.cache.peer_fill]
enabled = true
connect_timeout_secs = 2
read_timeout_secs = 5
max_object_bytes = \"256KiB\"
max_concurrent_requests = 4
allow_insecure_http = true
fail_open = true

[[vhosts.cache.peer_fill.peers]]
name = \"node-b\"
base_url = \"http://127.0.0.1:${NODE_B_PORT}\"
"

write_config "node-a" "$NODE_A_PORT" "$TMP_DIR/node-a-cache" "$NODE_A_METRICS" "$NODE_A_PEER_FILL"
write_config "node-b" "$NODE_B_PORT" "$TMP_DIR/node-b-cache" "" ""
write_config "node-c" "$NODE_C_PORT" "$TMP_DIR/node-c-cache" "" "$NODE_C_PEER_FILL"

cargo build --quiet --no-default-features --features profile-cache-edge,metrics

python3 "$TMP_DIR/origin.py" "$ORIGIN_PORT" >"$TMP_DIR/origin.log" 2>&1 &
ORIGIN_PID=$!

i=0
until curl -sSf --max-time "$CURL_MAX_TIME" "http://127.0.0.1:${ORIGIN_PORT}/__count?path=/asset.webp" >/dev/null 2>&1; do
    i=$((i + 1))
    if [ "$i" -gt 50 ]; then
        echo "timed out waiting for origin" >&2
        exit 1
    fi
    sleep 0.1
done

"$ROOT_DIR/target/debug/fluxheim" --config "$TMP_DIR/node-b.toml" >"$TMP_DIR/node-b.log" 2>&1 &
NODE_B_PID=$!

"$ROOT_DIR/target/debug/fluxheim" --config "$TMP_DIR/node-a.toml" >"$TMP_DIR/node-a.log" 2>&1 &
NODE_A_PID=$!

"$ROOT_DIR/target/debug/fluxheim" --config "$TMP_DIR/node-c.toml" >"$TMP_DIR/node-c.log" 2>&1 &
NODE_C_PID=$!

wait_for_port() {
    port=$1
    name=$2
    i=0
    until python3 - "$port" <<'PY'
import socket
import sys

try:
    with socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=0.2):
        pass
except OSError:
    raise SystemExit(1)
PY
    do
        i=$((i + 1))
        if [ "$i" -gt 50 ]; then
            echo "timed out waiting for $name" >&2
            exit 1
        fi
        sleep 0.1
    done
}

wait_for_port "$NODE_B_PORT" "node B"
wait_for_port "$NODE_A_PORT" "node A"
wait_for_port "$NODE_C_PORT" "node C"
wait_for_port "$METRICS_PORT" "node A metrics"

b_miss_headers=$(mktemp "$TMP_DIR/b-miss-headers.XXXXXX")
b_hit_headers=$(mktemp "$TMP_DIR/b-hit-headers.XXXXXX")
a_peer_headers=$(mktemp "$TMP_DIR/a-peer-headers.XXXXXX")
a_hit_headers=$(mktemp "$TMP_DIR/a-hit-headers.XXXXXX")
vary_b_headers=$(mktemp "$TMP_DIR/vary-b-headers.XXXXXX")
vary_a_peer_headers=$(mktemp "$TMP_DIR/vary-a-peer-headers.XXXXXX")
vary_a_hit_headers=$(mktemp "$TMP_DIR/vary-a-hit-headers.XXXXXX")
vary_a_fail_headers=$(mktemp "$TMP_DIR/vary-a-fail-headers.XXXXXX")
fail_closed_headers=$(mktemp "$TMP_DIR/fail-closed-headers.XXXXXX")
fail_open_headers=$(mktemp "$TMP_DIR/fail-open-headers.XXXXXX")
b_body=$(mktemp "$TMP_DIR/b-body.XXXXXX")
a_peer_body=$(mktemp "$TMP_DIR/a-peer-body.XXXXXX")
a_hit_body=$(mktemp "$TMP_DIR/a-hit-body.XXXXXX")
vary_b_body=$(mktemp "$TMP_DIR/vary-b-body.XXXXXX")
vary_a_peer_body=$(mktemp "$TMP_DIR/vary-a-peer-body.XXXXXX")
vary_a_hit_body=$(mktemp "$TMP_DIR/vary-a-hit-body.XXXXXX")
vary_a_fail_body=$(mktemp "$TMP_DIR/vary-a-fail-body.XXXXXX")
fail_closed_body=$(mktemp "$TMP_DIR/fail-closed-body.XXXXXX")
fail_open_body=$(mktemp "$TMP_DIR/fail-open-body.XXXXXX")
metrics_body=$(mktemp "$TMP_DIR/metrics.XXXXXX")

curl -sS --max-time "$CURL_MAX_TIME" -D "$b_miss_headers" -o "$b_body" \
    -H "Host: cache.test" "http://127.0.0.1:${NODE_B_PORT}/asset.webp"
grep -qi '^x-cache-status: MISS' "$b_miss_headers"

curl -sS --max-time "$CURL_MAX_TIME" -D "$b_hit_headers" -o /dev/null \
    -H "Host: cache.test" "http://127.0.0.1:${NODE_B_PORT}/asset.webp"
grep -qi '^x-cache-status: HIT' "$b_hit_headers"

origin_count=$(curl -sSf --max-time "$CURL_MAX_TIME" "http://127.0.0.1:${ORIGIN_PORT}/__count?path=/asset.webp")
if [ "$origin_count" != "1" ]; then
    echo "peer-fill cache smoke failed: expected one origin fetch after node B warm, got $origin_count" >&2
    exit 1
fi

sleep 1

curl -sS --max-time "$CURL_MAX_TIME" -D "$a_peer_headers" -o "$a_peer_body" \
    -H "Host: cache.test" "http://127.0.0.1:${NODE_A_PORT}/asset.webp"
grep -qi '^x-cache-status: PEER-HIT' "$a_peer_headers"
cmp "$b_body" "$a_peer_body" >/dev/null
peer_age=$(awk 'tolower($1) == "age:" {gsub("\r", "", $2); print $2; exit}' "$a_peer_headers")
if [ -z "$peer_age" ] || [ "$peer_age" -lt 1 ]; then
    echo "peer-fill cache smoke failed: expected peer-hit age >= 1, got ${peer_age:-missing}" >&2
    exit 1
fi

origin_count=$(curl -sSf --max-time "$CURL_MAX_TIME" "http://127.0.0.1:${ORIGIN_PORT}/__count?path=/asset.webp")
if [ "$origin_count" != "1" ]; then
    echo "peer-fill cache smoke failed: peer fill contacted origin; origin count is $origin_count" >&2
    exit 1
fi

curl -sS --max-time "$CURL_MAX_TIME" -D "$a_hit_headers" -o "$a_hit_body" \
    -H "Host: cache.test" "http://127.0.0.1:${NODE_A_PORT}/asset.webp"
grep -qi '^x-cache-status: HIT' "$a_hit_headers"
cmp "$b_body" "$a_hit_body" >/dev/null
local_age=$(awk 'tolower($1) == "age:" {gsub("\r", "", $2); print $2; exit}' "$a_hit_headers")
if [ -z "$local_age" ] || [ "$local_age" -lt "$peer_age" ]; then
    echo "peer-fill cache smoke failed: expected local hit age >= peer age $peer_age, got ${local_age:-missing}" >&2
    exit 1
fi

curl -sS --max-time "$CURL_MAX_TIME" -D "$vary_b_headers" -o "$vary_b_body" \
    -H "Host: cache.test" -H "Accept-Language: de" \
    "http://127.0.0.1:${NODE_B_PORT}/vary.webp"
grep -qi '^x-cache-status: MISS' "$vary_b_headers"
if ! grep -q '^peer-fill-vary-de$' "$vary_b_body"; then
    echo "peer-fill cache smoke failed: node B vary warm returned unexpected body" >&2
    exit 1
fi

curl -sS --max-time "$CURL_MAX_TIME" -D "$vary_a_peer_headers" -o "$vary_a_peer_body" \
    -H "Host: cache.test" -H "Accept-Language: de" \
    "http://127.0.0.1:${NODE_A_PORT}/vary.webp"
grep -qi '^x-cache-status: PEER-HIT' "$vary_a_peer_headers"
cmp "$vary_b_body" "$vary_a_peer_body" >/dev/null

curl -sS --max-time "$CURL_MAX_TIME" -D "$vary_a_hit_headers" -o "$vary_a_hit_body" \
    -H "Host: cache.test" -H "Accept-Language: de" \
    "http://127.0.0.1:${NODE_A_PORT}/vary.webp"
grep -qi '^x-cache-status: HIT' "$vary_a_hit_headers"
cmp "$vary_b_body" "$vary_a_hit_body" >/dev/null

vary_fail_status=$(curl -sS --max-time "$CURL_MAX_TIME" -w '%{http_code}' \
    -D "$vary_a_fail_headers" -o "$vary_a_fail_body" \
    -H "Host: cache.test" -H "Accept-Language: en" \
    "http://127.0.0.1:${NODE_A_PORT}/vary.webp")
if [ "$vary_fail_status" != "504" ]; then
    echo "peer-fill cache smoke failed: expected 504 for missing vary variant, got $vary_fail_status" >&2
    exit 1
fi
grep -qi '^x-cache-status: MISS' "$vary_a_fail_headers"

fail_closed_status=$(curl -sS --max-time "$CURL_MAX_TIME" -w '%{http_code}' \
    -D "$fail_closed_headers" -o "$fail_closed_body" \
    -H "Host: cache.test" "http://127.0.0.1:${NODE_A_PORT}/uncached.webp")
if [ "$fail_closed_status" != "504" ]; then
    echo "peer-fill cache smoke failed: expected fail-closed 504 for peer miss, got $fail_closed_status" >&2
    exit 1
fi
grep -qi '^x-cache-status: MISS' "$fail_closed_headers"
grep -qi '^x-cache-reason: peer-fill-miss' "$fail_closed_headers"

uncached_origin_count=$(curl -sSf --max-time "$CURL_MAX_TIME" "http://127.0.0.1:${ORIGIN_PORT}/__count?path=/uncached.webp")
if [ "$uncached_origin_count" != "0" ]; then
    echo "peer-fill cache smoke failed: fail-closed peer miss contacted origin $uncached_origin_count times" >&2
    exit 1
fi

fail_open_status=$(curl -sS --max-time "$CURL_MAX_TIME" -w '%{http_code}' \
    -D "$fail_open_headers" -o "$fail_open_body" \
    -H "Host: cache.test" "http://127.0.0.1:${NODE_C_PORT}/uncached.webp")
if [ "$fail_open_status" != "200" ]; then
    echo "peer-fill cache smoke failed: expected fail-open origin fallback 200, got $fail_open_status" >&2
    exit 1
fi
grep -qi '^x-cache-status: MISS' "$fail_open_headers"
if ! grep -q '^uncached-origin-body$' "$fail_open_body"; then
    echo "peer-fill cache smoke failed: fail-open fallback returned unexpected body" >&2
    exit 1
fi

uncached_origin_count=$(curl -sSf --max-time "$CURL_MAX_TIME" "http://127.0.0.1:${ORIGIN_PORT}/__count?path=/uncached.webp")
if [ "$uncached_origin_count" != "1" ]; then
    echo "peer-fill cache smoke failed: expected one origin fetch after fail-open fallback, got $uncached_origin_count" >&2
    exit 1
fi

vary_origin_count=$(curl -sSf --max-time "$CURL_MAX_TIME" "http://127.0.0.1:${ORIGIN_PORT}/__count?path=/vary.webp")
if [ "$vary_origin_count" != "1" ]; then
    echo "peer-fill cache smoke failed: expected one origin fetch for vary warm only, got $vary_origin_count" >&2
    exit 1
fi

curl -sSf --max-time "$CURL_MAX_TIME" "http://127.0.0.1:${METRICS_PORT}/metrics" > "$metrics_body"
grep -q 'fluxheim_cache_activity_total{event="peer_fill_hit",tier="policy"}' "$metrics_body"
grep -q 'fluxheim_cache_activity_total{event="peer_fill_fail_closed",tier="policy"}' "$metrics_body"

echo "peer-fill cache smoke passed"
