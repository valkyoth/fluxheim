#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/fluxheim-proxy-cache-smoke.XXXXXX")
KEEP_LOGS=${FLUXHEIM_SMOKE_KEEP_LOGS:-0}
CURL_MAX_TIME=${FLUXHEIM_SMOKE_CURL_MAX_TIME:-5}

ports=$(python3 - <<'PY'
import socket

sockets = []
try:
    for _ in range(2):
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
FLUXHEIM_PORT=$1
ORIGIN_PORT=$2

ORIGIN_PID=
FLUXHEIM_PID=

cleanup() {
    status=$?

    for pid in "$FLUXHEIM_PID" "$ORIGIN_PID"; do
        if [ -n "$pid" ]; then
            kill "$pid" 2>/dev/null || true
        fi
    done

    sleep 0.2

    for pid in "$FLUXHEIM_PID" "$ORIGIN_PID"; do
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill -9 "$pid" 2>/dev/null || true
        fi
    done

    for pid in "$FLUXHEIM_PID" "$ORIGIN_PID"; do
        if [ -n "$pid" ]; then
            wait "$pid" 2>/dev/null || true
        fi
    done

    if [ "$KEEP_LOGS" = "1" ] || [ "$status" -ne 0 ]; then
        echo "proxy cache smoke artifacts kept in $TMP_DIR" >&2
    else
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT INT TERM

mkdir -p "$TMP_DIR/run" "$TMP_DIR/cache"

cat > "$TMP_DIR/origin.py" <<'PY'
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BODY = b"0123456789abcdef"
ETAG = '"cache-smoke-v1"'
LAST_MODIFIED = "Sun, 10 May 2026 00:00:00 GMT"


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        if self.path != "/asset.png":
            self.send_response(404)
            self.send_header("content-length", "0")
            self.end_headers()
            return

        self.send_response(200)
        self.send_header("content-type", "image/png")
        self.send_header("content-length", str(len(BODY)))
        self.send_header("cache-control", "public, max-age=120")
        self.send_header("etag", ETAG)
        self.send_header("last-modified", LAST_MODIFIED)
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, _format, *args):
        return


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
PY

cat > "$TMP_DIR/fluxheim.toml" <<EOF
[server]
listen = ["127.0.0.1:$FLUXHEIM_PORT"]
default_vhost = "cache.test"
trusted_proxies = []

[server.process]
daemon = false
pid_file = "$TMP_DIR/run/fluxheim.pid"
upgrade_sock = "$TMP_DIR/run/fluxheim-upgrade.sock"

[server.limits]
max_request_header_bytes = "64KiB"
max_uri_bytes = "8KiB"
max_request_headers = 100
max_request_body_bytes = "1MiB"

[logging]
level = "warn"
format = "text"

[logging.access]
enabled = false
request_id = false

[headers.response]
enabled = true
unset = ["server", "x-powered-by"]

[proxy]
upstreams = ["127.0.0.1:$ORIGIN_PORT"]
upstream_tls = false

[tls]
enabled = false
backend = "rustls"

[cache]
enabled = true
status_header = "X-Cache-Status"
max_object_bytes = "1MiB"

[cache.memory]
enabled = true
max_size_bytes = "16MiB"

[cache.disk]
enabled = true
path = "$TMP_DIR/cache"
max_size_bytes = "32MiB"

[web]
index_files = ["index.html"]
deny_dotfiles = true

[[vhosts]]
name = "cache.test"
hosts = ["cache.test"]

[vhosts.cache]
enabled = true
status_header = "X-Cache-Status"
max_object_bytes = "1MiB"

[vhosts.cache.memory]
enabled = true
max_size_bytes = "16MiB"

[vhosts.cache.disk]
enabled = true
path = "$TMP_DIR/cache"
max_size_bytes = "32MiB"

[vhosts.proxy]
upstreams = ["127.0.0.1:$ORIGIN_PORT"]
upstream_tls = false
EOF

python3 "$TMP_DIR/origin.py" "$ORIGIN_PORT" &
ORIGIN_PID=$!

(cd "$ROOT_DIR" && cargo build --quiet)

stop_pid() {
    pid=$1
    if [ -z "$pid" ]; then
        return 0
    fi

    kill "$pid" 2>/dev/null || true
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        if ! kill -0 "$pid" 2>/dev/null; then
            wait "$pid" 2>/dev/null || true
            return 0
        fi
        sleep 0.2
    done

    kill -9 "$pid" 2>/dev/null || true
    wait "$pid" 2>/dev/null || true
}

start_fluxheim() {
    "$ROOT_DIR/target/debug/fluxheim" --config "$TMP_DIR/fluxheim.toml" &
    FLUXHEIM_PID=$!
}

stop_fluxheim() {
    if [ -n "$FLUXHEIM_PID" ]; then
        stop_pid "$FLUXHEIM_PID"
        FLUXHEIM_PID=
    fi
}

stop_origin() {
    if [ -n "$ORIGIN_PID" ]; then
        stop_pid "$ORIGIN_PID"
        ORIGIN_PID=
    fi
}

start_fluxheim

wait_http() {
    url=$1
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        status=$(
            curl -sS --max-time "$CURL_MAX_TIME" -o /dev/null -w '%{http_code}' \
                -H "Host: cache.test" \
                -H "Cache-Control: no-cache" \
                "$url" 2>/dev/null || true
        )
        if [ "$status" = "200" ]; then
            return 0
        fi
        sleep 0.2
    done
    echo "proxy cache smoke failed: timed out waiting for $url" >&2
    return 1
}

wait_http "http://127.0.0.1:$FLUXHEIM_PORT/asset.png"

first_headers="$TMP_DIR/first.headers"
second_headers="$TMP_DIR/second.headers"
conditional_headers="$TMP_DIR/conditional.headers"
range_headers="$TMP_DIR/range.headers"
restart_headers="$TMP_DIR/restart.headers"
body="$TMP_DIR/body.bin"
range_body="$TMP_DIR/range-body.bin"

curl -sS --max-time "$CURL_MAX_TIME" -D "$first_headers" -o "$body" -H "Host: cache.test" "http://127.0.0.1:$FLUXHEIM_PORT/asset.png"
if ! grep -qi '^x-cache-status: MISS' "$first_headers"; then
    echo "proxy cache smoke failed: first request was not a cache MISS" >&2
    cat "$first_headers" >&2
    exit 1
fi

curl -sS --max-time "$CURL_MAX_TIME" -D "$second_headers" -o "$body" -H "Host: cache.test" "http://127.0.0.1:$FLUXHEIM_PORT/asset.png"
if ! grep -qi '^x-cache-status: HIT' "$second_headers"; then
    echo "proxy cache smoke failed: second request was not a cache HIT" >&2
    cat "$second_headers" >&2
    exit 1
fi
if ! grep -qi '^age:' "$second_headers"; then
    echo "proxy cache smoke failed: cache HIT did not include Age header" >&2
    cat "$second_headers" >&2
    exit 1
fi

conditional_status=$(
    curl -sS --max-time "$CURL_MAX_TIME" -D "$conditional_headers" -o /dev/null -w '%{http_code}' \
        -H "Host: cache.test" \
        -H 'If-None-Match: "cache-smoke-v1"' \
        "http://127.0.0.1:$FLUXHEIM_PORT/asset.png"
)
if [ "$conditional_status" != "304" ]; then
    echo "proxy cache smoke failed: cached conditional returned $conditional_status instead of 304" >&2
    cat "$conditional_headers" >&2
    exit 1
fi

range_status=$(
    curl -sS --max-time "$CURL_MAX_TIME" -D "$range_headers" -o "$range_body" -w '%{http_code}' \
        -H "Host: cache.test" \
        -H "Range: bytes=0-3" \
        "http://127.0.0.1:$FLUXHEIM_PORT/asset.png"
)
if [ "$range_status" != "206" ]; then
    echo "proxy cache smoke failed: cached range returned $range_status instead of 206" >&2
    cat "$range_headers" >&2
    exit 1
fi
if ! grep -qi '^content-range: bytes 0-3/16' "$range_headers"; then
    echo "proxy cache smoke failed: cached range response missed expected Content-Range" >&2
    cat "$range_headers" >&2
    exit 1
fi
if [ "$(cat "$range_body")" != "0123" ]; then
    echo "proxy cache smoke failed: cached range body mismatch" >&2
    exit 1
fi

stop_fluxheim
stop_origin
start_fluxheim

restart_status=
for _ in 1 2 3 4 5 6 7 8 9 10; do
    restart_status=$(
        curl -sS --max-time "$CURL_MAX_TIME" -D "$restart_headers" -o "$body" -w '%{http_code}' \
            -H "Host: cache.test" \
            "http://127.0.0.1:$FLUXHEIM_PORT/asset.png" 2>/dev/null || true
    )
    if [ "$restart_status" = "200" ]; then
        break
    fi
    sleep 0.2
done
if [ "$restart_status" != "200" ]; then
    echo "proxy cache smoke failed: restarted Fluxheim returned $restart_status instead of 200 from disk cache" >&2
    cat "$restart_headers" >&2
    exit 1
fi
if ! grep -qi '^x-cache-status: HIT' "$restart_headers"; then
    echo "proxy cache smoke failed: restarted Fluxheim did not serve disk cache HIT" >&2
    cat "$restart_headers" >&2
    exit 1
fi
if ! grep -qi '^age:' "$restart_headers"; then
    echo "proxy cache smoke failed: restarted disk cache HIT did not include Age header" >&2
    cat "$restart_headers" >&2
    exit 1
fi

echo "proxy cache smoke: ok"
