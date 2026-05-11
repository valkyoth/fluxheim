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
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

BODY = b"0123456789abcdef"
VARY_BODIES = {
    "de": b"vary-de",
    "en": b"vary-en",
}
ETAG = '"cache-smoke-v1"'
REVALIDATE_ETAG = '"cache-smoke-revalidate"'
REFRESH_OLD_ETAG = '"cache-smoke-refresh-old"'
REFRESH_NEW_ETAG = '"cache-smoke-refresh-new"'
SWR_OLD_ETAG = '"cache-smoke-swr-old"'
SWR_NEW_ETAG = '"cache-smoke-swr-new"'
STALE_ERROR_ETAG = '"cache-smoke-stale-error"'
LOCKED_ETAG = '"cache-smoke-locked"'
LAST_MODIFIED = "Sun, 10 May 2026 00:00:00 GMT"
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

        if self.path == "/vary.png" or self.path == "/warm-vary.png":
            language = self.headers.get("accept-language", "")
            body = VARY_BODIES["de"] if "de" in language.lower() else VARY_BODIES["en"]
            self.send_response(200)
            self.send_header("content-type", "image/png")
            self.send_header("content-length", str(len(body)))
            self.send_header("cache-control", "public, max-age=120")
            self.send_header("vary", "Accept-Language")
            self.send_header("etag", '"cache-smoke-vary"')
            self.send_header("last-modified", LAST_MODIFIED)
            self.send_header("surrogate-key", "smoke:vary smoke:warm")
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path == "/revalidate.png":
            if self.headers.get("if-none-match") == REVALIDATE_ETAG:
                self.send_response(304)
                self.send_header("cache-control", "public, max-age=120")
                self.send_header("etag", REVALIDATE_ETAG)
                self.send_header("last-modified", LAST_MODIFIED)
                self.end_headers()
                return

            body = b"revalidated-body"
            self.send_response(200)
            self.send_header("content-type", "image/png")
            self.send_header("content-length", str(len(body)))
            self.send_header("cache-control", "public, max-age=1")
            self.send_header("etag", REVALIDATE_ETAG)
            self.send_header("last-modified", LAST_MODIFIED)
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path == "/refresh.png":
            if self.headers.get("if-none-match") == REFRESH_OLD_ETAG:
                body = b"refreshed-body"
                self.send_response(200)
                self.send_header("content-type", "image/png")
                self.send_header("content-length", str(len(body)))
                self.send_header("cache-control", "public, max-age=120")
                self.send_header("etag", REFRESH_NEW_ETAG)
                self.send_header("last-modified", LAST_MODIFIED)
                self.end_headers()
                self.wfile.write(body)
                return

            body = b"refresh-old-body"
            self.send_response(200)
            self.send_header("content-type", "image/png")
            self.send_header("content-length", str(len(body)))
            self.send_header("cache-control", "public, max-age=1")
            self.send_header("etag", REFRESH_OLD_ETAG)
            self.send_header("last-modified", LAST_MODIFIED)
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path == "/swr.png":
            if self.headers.get("if-none-match") == SWR_OLD_ETAG:
                time.sleep(0.8)
                body = b"swr-new-body"
                self.send_response(200)
                self.send_header("content-type", "image/png")
                self.send_header("content-length", str(len(body)))
                self.send_header("cache-control", "public, max-age=120")
                self.send_header("etag", SWR_NEW_ETAG)
                self.send_header("last-modified", LAST_MODIFIED)
                self.end_headers()
                self.wfile.write(body)
                return

            body = b"swr-old-body"
            self.send_response(200)
            self.send_header("content-type", "image/png")
            self.send_header("content-length", str(len(body)))
            self.send_header("cache-control", "public, max-age=1")
            self.send_header("etag", SWR_OLD_ETAG)
            self.send_header("last-modified", LAST_MODIFIED)
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path == "/locked.png":
            record_path(self.path)
            time.sleep(0.6)
            body = b"locked-body"
            self.send_response(200)
            self.send_header("content-type", "image/png")
            self.send_header("content-length", str(len(body)))
            self.send_header("cache-control", "public, max-age=120")
            self.send_header("etag", LOCKED_ETAG)
            self.send_header("last-modified", LAST_MODIFIED)
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path == "/stale-error.png":
            body = b"stale-error-body"
            self.send_response(200)
            self.send_header("content-type", "image/png")
            self.send_header("content-length", str(len(body)))
            self.send_header("cache-control", "public, max-age=1")
            self.send_header("etag", STALE_ERROR_ETAG)
            self.send_header("last-modified", LAST_MODIFIED)
            self.end_headers()
            self.wfile.write(body)
            return

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
status_reason_header = "X-Cache-Reason"
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
status_reason_header = "X-Cache-Reason"
stale_if_error_secs = 60
stale_if_error_on = ["connect", "http-status"]
stale_if_error_statuses = [502, 503, 504]
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

[[vhosts.routes]]
name = "swr"
path_exact = "/swr.png"

[vhosts.routes.proxy]
upstreams = ["127.0.0.1:$ORIGIN_PORT"]
upstream_tls = false

[vhosts.routes.cache]
enabled = true
status_header = "X-Cache-Status"
status_reason_header = "X-Cache-Reason"
stale_while_revalidate_secs = 60
stale_if_error_secs = 60
max_object_bytes = "1MiB"

[vhosts.routes.cache.memory]
enabled = true
max_size_bytes = "16MiB"

[vhosts.routes.cache.disk]
enabled = true
path = "$TMP_DIR/cache"
max_size_bytes = "32MiB"
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

"$ROOT_DIR/target/debug/fluxheim" --config "$TMP_DIR/fluxheim.toml" cache-key \
    --host cache.test \
    --path /asset.png \
    --expect-eligible \
    --expect-cache-lock-enabled \
    --expect-memory-tier-enabled \
    --expect-disk-tier-enabled \
    --expect-scope vhost \
    --expect-vhost cache.test \
    --expect-storage-tiers 2

first_headers="$TMP_DIR/first.headers"
second_headers="$TMP_DIR/second.headers"
bypass_headers="$TMP_DIR/bypass.headers"
pragma_bypass_headers="$TMP_DIR/pragma-bypass.headers"
conditional_headers="$TMP_DIR/conditional.headers"
range_headers="$TMP_DIR/range.headers"
if_range_match_headers="$TMP_DIR/if-range-match.headers"
if_range_mismatch_headers="$TMP_DIR/if-range-mismatch.headers"
revalidate_first_headers="$TMP_DIR/revalidate-first.headers"
revalidate_second_headers="$TMP_DIR/revalidate-second.headers"
revalidate_third_headers="$TMP_DIR/revalidate-third.headers"
refresh_first_headers="$TMP_DIR/refresh-first.headers"
refresh_second_headers="$TMP_DIR/refresh-second.headers"
refresh_third_headers="$TMP_DIR/refresh-third.headers"
swr_first_headers="$TMP_DIR/swr-first.headers"
swr_second_headers="$TMP_DIR/swr-second.headers"
swr_third_headers="$TMP_DIR/swr-third.headers"
stale_error_first_headers="$TMP_DIR/stale-error-first.headers"
stale_error_second_headers="$TMP_DIR/stale-error-second.headers"
restart_headers="$TMP_DIR/restart.headers"
body="$TMP_DIR/body.bin"
range_body="$TMP_DIR/range-body.bin"
if_range_match_body="$TMP_DIR/if-range-match-body.bin"
if_range_mismatch_body="$TMP_DIR/if-range-mismatch-body.bin"
revalidate_body="$TMP_DIR/revalidate-body.bin"
refresh_body="$TMP_DIR/refresh-body.bin"
swr_body="$TMP_DIR/swr-body.bin"
stale_error_body="$TMP_DIR/stale-error-body.bin"
vary_en_first_headers="$TMP_DIR/vary-en-first.headers"
vary_en_second_headers="$TMP_DIR/vary-en-second.headers"
vary_de_headers="$TMP_DIR/vary-de.headers"
vary_en_body="$TMP_DIR/vary-en.bin"
vary_de_body="$TMP_DIR/vary-de.bin"
warm_vary_headers="$TMP_DIR/warm-vary.headers"
warm_vary_body="$TMP_DIR/warm-vary.bin"

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

curl -sS --max-time "$CURL_MAX_TIME" -D "$bypass_headers" -o "$body" \
    -H "Host: cache.test" \
    -H "Cache-Control: no-cache" \
    "http://127.0.0.1:$FLUXHEIM_PORT/asset.png"
if ! grep -qi '^x-cache-status: BYPASS' "$bypass_headers"; then
    echo "proxy cache smoke failed: client refresh bypass did not expose BYPASS status" >&2
    cat "$bypass_headers" >&2
    exit 1
fi
if ! grep -qi '^x-cache-reason: request-refresh' "$bypass_headers"; then
    echo "proxy cache smoke failed: client refresh bypass did not expose bounded reason" >&2
    cat "$bypass_headers" >&2
    exit 1
fi

curl -sS --max-time "$CURL_MAX_TIME" -D "$pragma_bypass_headers" -o "$body" \
    -H "Host: cache.test" \
    -H "Pragma: no-cache" \
    "http://127.0.0.1:$FLUXHEIM_PORT/asset.png"
if ! grep -qi '^x-cache-status: BYPASS' "$pragma_bypass_headers"; then
    echo "proxy cache smoke failed: Pragma refresh bypass did not expose BYPASS status" >&2
    cat "$pragma_bypass_headers" >&2
    exit 1
fi
if ! grep -qi '^x-cache-reason: request-refresh' "$pragma_bypass_headers"; then
    echo "proxy cache smoke failed: Pragma refresh bypass did not expose bounded reason" >&2
    cat "$pragma_bypass_headers" >&2
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

if_range_match_status=$(
    curl -sS --max-time "$CURL_MAX_TIME" -D "$if_range_match_headers" -o "$if_range_match_body" -w '%{http_code}' \
        -H "Host: cache.test" \
        -H "Range: bytes=4-7" \
        -H 'If-Range: "cache-smoke-v1"' \
        "http://127.0.0.1:$FLUXHEIM_PORT/asset.png"
)
if [ "$if_range_match_status" != "206" ]; then
    echo "proxy cache smoke failed: cached If-Range match returned $if_range_match_status instead of 206" >&2
    cat "$if_range_match_headers" >&2
    exit 1
fi
if ! grep -qi '^content-range: bytes 4-7/16' "$if_range_match_headers"; then
    echo "proxy cache smoke failed: cached If-Range match missed expected Content-Range" >&2
    cat "$if_range_match_headers" >&2
    exit 1
fi
if [ "$(cat "$if_range_match_body")" != "4567" ]; then
    echo "proxy cache smoke failed: cached If-Range match body mismatch" >&2
    exit 1
fi

if_range_mismatch_status=$(
    curl -sS --max-time "$CURL_MAX_TIME" -D "$if_range_mismatch_headers" -o "$if_range_mismatch_body" -w '%{http_code}' \
        -H "Host: cache.test" \
        -H "Range: bytes=4-7" \
        -H 'If-Range: "cache-smoke-other"' \
        "http://127.0.0.1:$FLUXHEIM_PORT/asset.png"
)
if [ "$if_range_mismatch_status" != "200" ]; then
    echo "proxy cache smoke failed: cached If-Range mismatch returned $if_range_mismatch_status instead of 200" >&2
    cat "$if_range_mismatch_headers" >&2
    exit 1
fi
if grep -qi '^content-range:' "$if_range_mismatch_headers"; then
    echo "proxy cache smoke failed: cached If-Range mismatch unexpectedly included Content-Range" >&2
    cat "$if_range_mismatch_headers" >&2
    exit 1
fi
if [ "$(cat "$if_range_mismatch_body")" != "0123456789abcdef" ]; then
    echo "proxy cache smoke failed: cached If-Range mismatch body was not the full object" >&2
    exit 1
fi

curl -sS --max-time "$CURL_MAX_TIME" -D "$revalidate_first_headers" -o "$revalidate_body" \
    -H "Host: cache.test" \
    "http://127.0.0.1:$FLUXHEIM_PORT/revalidate.png"
if ! grep -qi '^x-cache-status: MISS' "$revalidate_first_headers"; then
    echo "proxy cache smoke failed: initial revalidation asset request was not a cache MISS" >&2
    cat "$revalidate_first_headers" >&2
    exit 1
fi
if [ "$(cat "$revalidate_body")" != "revalidated-body" ]; then
    echo "proxy cache smoke failed: initial revalidation asset body mismatch" >&2
    exit 1
fi

sleep 1.2

curl -sS --max-time "$CURL_MAX_TIME" -D "$revalidate_second_headers" -o "$revalidate_body" \
    -H "Host: cache.test" \
    "http://127.0.0.1:$FLUXHEIM_PORT/revalidate.png"
if ! grep -qi '^x-cache-status: REVALIDATED' "$revalidate_second_headers"; then
    echo "proxy cache smoke failed: stale asset did not revalidate from upstream 304" >&2
    cat "$revalidate_second_headers" >&2
    exit 1
fi
if [ "$(cat "$revalidate_body")" != "revalidated-body" ]; then
    echo "proxy cache smoke failed: revalidated asset body mismatch" >&2
    exit 1
fi

curl -sS --max-time "$CURL_MAX_TIME" -D "$revalidate_third_headers" -o "$revalidate_body" \
    -H "Host: cache.test" \
    "http://127.0.0.1:$FLUXHEIM_PORT/revalidate.png"
if ! grep -qi '^x-cache-status: HIT' "$revalidate_third_headers"; then
    echo "proxy cache smoke failed: revalidated metadata did not make asset fresh" >&2
    cat "$revalidate_third_headers" >&2
    exit 1
fi
if ! grep -qi '^age:' "$revalidate_third_headers"; then
    echo "proxy cache smoke failed: revalidated cache HIT did not include Age header" >&2
    cat "$revalidate_third_headers" >&2
    exit 1
fi

"$ROOT_DIR/target/debug/fluxheim" --config "$TMP_DIR/fluxheim.toml" cache-lookup \
    --host cache.test \
    --path /revalidate.png \
    --require-object \
    --expect-tier disk \
    --expect-status 200 \
    --expect-body-bytes 16 \
    --expect-fresh-ttl-secs 120 \
    --expect-header-name etag \
    --expect-freshness-state fresh

curl -sS --max-time "$CURL_MAX_TIME" -D "$refresh_first_headers" -o "$refresh_body" \
    -H "Host: cache.test" \
    "http://127.0.0.1:$FLUXHEIM_PORT/refresh.png"
if ! grep -qi '^x-cache-status: MISS' "$refresh_first_headers"; then
    echo "proxy cache smoke failed: initial refresh asset request was not a cache MISS" >&2
    cat "$refresh_first_headers" >&2
    exit 1
fi
if [ "$(cat "$refresh_body")" != "refresh-old-body" ]; then
    echo "proxy cache smoke failed: initial refresh asset body mismatch" >&2
    exit 1
fi

sleep 1.2

curl -sS --max-time "$CURL_MAX_TIME" -D "$refresh_second_headers" -o "$refresh_body" \
    -H "Host: cache.test" \
    "http://127.0.0.1:$FLUXHEIM_PORT/refresh.png"
if ! grep -qi '^x-cache-status: EXPIRED' "$refresh_second_headers"; then
    echo "proxy cache smoke failed: stale asset did not refresh from upstream 200" >&2
    cat "$refresh_second_headers" >&2
    exit 1
fi
if [ "$(cat "$refresh_body")" != "refreshed-body" ]; then
    echo "proxy cache smoke failed: refreshed asset body mismatch" >&2
    exit 1
fi

curl -sS --max-time "$CURL_MAX_TIME" -D "$refresh_third_headers" -o "$refresh_body" \
    -H "Host: cache.test" \
    "http://127.0.0.1:$FLUXHEIM_PORT/refresh.png"
if ! grep -qi '^x-cache-status: HIT' "$refresh_third_headers"; then
    echo "proxy cache smoke failed: refreshed metadata did not make asset fresh" >&2
    cat "$refresh_third_headers" >&2
    exit 1
fi
if [ "$(cat "$refresh_body")" != "refreshed-body" ]; then
    echo "proxy cache smoke failed: refreshed cache HIT body mismatch" >&2
    exit 1
fi

"$ROOT_DIR/target/debug/fluxheim" --config "$TMP_DIR/fluxheim.toml" cache-lookup \
    --host cache.test \
    --path /refresh.png \
    --require-object \
    --expect-tier disk \
    --expect-status 200 \
    --expect-body-bytes 14 \
    --expect-fresh-ttl-secs 120 \
    --expect-header-name etag \
    --expect-freshness-state fresh

curl -sS --max-time "$CURL_MAX_TIME" -D "$swr_first_headers" -o "$swr_body" \
    -H "Host: cache.test" \
    "http://127.0.0.1:$FLUXHEIM_PORT/swr.png"
if ! grep -qi '^x-cache-status: MISS' "$swr_first_headers"; then
    echo "proxy cache smoke failed: initial stale-while-revalidate request was not a cache MISS" >&2
    cat "$swr_first_headers" >&2
    exit 1
fi
if [ "$(cat "$swr_body")" != "swr-old-body" ]; then
    echo "proxy cache smoke failed: initial stale-while-revalidate body mismatch" >&2
    exit 1
fi

sleep 1.2

"$ROOT_DIR/target/debug/fluxheim" --config "$TMP_DIR/fluxheim.toml" cache-lookup \
    --host cache.test \
    --path /swr.png \
    --require-object \
    --expect-tier disk \
    --expect-status 200 \
    --expect-body-bytes 12 \
    --expect-header-name etag \
    --expect-serve-stale-while-revalidate \
    --expect-scope route \
    --expect-vhost cache.test \
    --expect-route swr \
    --expect-freshness-state stale

curl -sS --max-time "$CURL_MAX_TIME" -D "$swr_second_headers" -o "$swr_body" \
    -H "Host: cache.test" \
    "http://127.0.0.1:$FLUXHEIM_PORT/swr.png"
if ! grep -qi '^x-cache-status: STALE-UPDATING' "$swr_second_headers"; then
    echo "proxy cache smoke failed: stale-while-revalidate did not serve stale while updating" >&2
    cat "$swr_second_headers" >&2
    exit 1
fi
if [ "$(cat "$swr_body")" != "swr-old-body" ]; then
    echo "proxy cache smoke failed: stale-while-revalidate stale body mismatch" >&2
    exit 1
fi

sleep 1.2

curl -sS --max-time "$CURL_MAX_TIME" -D "$swr_third_headers" -o "$swr_body" \
    -H "Host: cache.test" \
    "http://127.0.0.1:$FLUXHEIM_PORT/swr.png"
if ! grep -qi '^x-cache-status: HIT' "$swr_third_headers"; then
    echo "proxy cache smoke failed: stale-while-revalidate background refresh did not make asset fresh" >&2
    cat "$swr_third_headers" >&2
    exit 1
fi
if [ "$(cat "$swr_body")" != "swr-new-body" ]; then
    echo "proxy cache smoke failed: stale-while-revalidate refreshed body mismatch" >&2
    exit 1
fi

"$ROOT_DIR/target/debug/fluxheim" --config "$TMP_DIR/fluxheim.toml" cache-lookup \
    --host cache.test \
    --path /swr.png \
    --require-object \
    --expect-tier disk \
    --expect-status 200 \
    --expect-body-bytes 12 \
    --expect-fresh-ttl-secs 120 \
    --expect-header-name etag \
    --expect-scope route \
    --expect-vhost cache.test \
    --expect-route swr \
    --expect-freshness-state fresh

python3 - "$FLUXHEIM_PORT" "$ORIGIN_PORT" <<'PY'
import http.client
import sys
import threading
from urllib.parse import quote

fluxheim_port = int(sys.argv[1])
origin_port = int(sys.argv[2])
results = []
lock = threading.Lock()


def fetch():
    conn = http.client.HTTPConnection("127.0.0.1", fluxheim_port, timeout=5)
    try:
        conn.request("GET", "/locked.png", headers={"Host": "cache.test"})
        response = conn.getresponse()
        body = response.read()
        status = response.status
        cache_status = response.getheader("x-cache-status")
    finally:
        conn.close()

    with lock:
        results.append((status, cache_status, body))


threads = [threading.Thread(target=fetch) for _ in range(8)]
for thread in threads:
    thread.start()
for thread in threads:
    thread.join()

if len(results) != len(threads):
    raise SystemExit(f"expected {len(threads)} collapsed responses, got {len(results)}")
if any(status != 200 for status, _cache_status, _body in results):
    raise SystemExit(f"cache lock request returned non-200 responses: {results!r}")
if any(body != b"locked-body" for _status, _cache_status, body in results):
    raise SystemExit(f"cache lock response body mismatch: {results!r}")
misses = sum(1 for _status, cache_status, _body in results if cache_status == "MISS")
hits = sum(1 for _status, cache_status, _body in results if cache_status == "HIT")
if misses != 1 or hits != len(threads) - 1:
    raise SystemExit(f"expected one MISS and {len(threads) - 1} HITs, got {results!r}")

conn = http.client.HTTPConnection("127.0.0.1", origin_port, timeout=5)
try:
    conn.request("GET", f"/__count?path={quote('/locked.png')}")
    response = conn.getresponse()
    count = int(response.read().decode("ascii"))
finally:
    conn.close()
if count != 1:
    raise SystemExit(f"expected collapsed cache lock to fetch origin once, got {count}")
PY

"$ROOT_DIR/target/debug/fluxheim" --config "$TMP_DIR/fluxheim.toml" cache-lookup \
    --host cache.test \
    --path /locked.png \
    --require-object \
    --expect-tier disk \
    --expect-status 200 \
    --expect-body-bytes 11 \
    --expect-header-name etag \
    --expect-cache-lock-enabled \
    --expect-memory-tier-enabled \
    --expect-disk-tier-enabled \
    --expect-storage-tiers 2 \
    --expect-vhost cache.test \
    --expect-freshness-state fresh

curl -sS --max-time "$CURL_MAX_TIME" -D "$vary_en_first_headers" -o "$vary_en_body" \
    -H "Host: cache.test" \
    -H "Accept-Language: en" \
    "http://127.0.0.1:$FLUXHEIM_PORT/vary.png"
if ! grep -qi '^x-cache-status: MISS' "$vary_en_first_headers"; then
    echo "proxy cache smoke failed: first Vary request was not a cache MISS" >&2
    cat "$vary_en_first_headers" >&2
    exit 1
fi
if [ "$(cat "$vary_en_body")" != "vary-en" ]; then
    echo "proxy cache smoke failed: first Vary body mismatch" >&2
    exit 1
fi

curl -sS --max-time "$CURL_MAX_TIME" -D "$vary_en_second_headers" -o "$vary_en_body" \
    -H "Host: cache.test" \
    -H "Accept-Language: en" \
    "http://127.0.0.1:$FLUXHEIM_PORT/vary.png"
if ! grep -qi '^x-cache-status: HIT' "$vary_en_second_headers"; then
    echo "proxy cache smoke failed: repeated Vary request was not a cache HIT" >&2
    cat "$vary_en_second_headers" >&2
    exit 1
fi
if [ "$(cat "$vary_en_body")" != "vary-en" ]; then
    echo "proxy cache smoke failed: repeated Vary body mismatch" >&2
    exit 1
fi

curl -sS --max-time "$CURL_MAX_TIME" -D "$vary_de_headers" -o "$vary_de_body" \
    -H "Host: cache.test" \
    -H "Accept-Language: de" \
    "http://127.0.0.1:$FLUXHEIM_PORT/vary.png"
if ! grep -qi '^x-cache-status: MISS' "$vary_de_headers"; then
    echo "proxy cache smoke failed: distinct Vary request was not a cache MISS" >&2
    cat "$vary_de_headers" >&2
    exit 1
fi
if [ "$(cat "$vary_de_body")" != "vary-de" ]; then
    echo "proxy cache smoke failed: distinct Vary body mismatch" >&2
    exit 1
fi

"$ROOT_DIR/target/debug/fluxheim" --config "$TMP_DIR/fluxheim.toml" cache-warm \
    --listen "127.0.0.1:$FLUXHEIM_PORT" \
    --host cache.test \
    --header "Accept-Language: de" \
    --path /warm-vary.png \
    --repeat 2 \
    --expect-cache-status-sequence MISS,HIT

"$ROOT_DIR/target/debug/fluxheim" --config "$TMP_DIR/fluxheim.toml" cache-lookup \
    --host cache.test \
    --header "Accept-Language: de" \
    --path /warm-vary.png \
    --require-object \
    --expect-tier disk \
    --expect-status 200 \
    --expect-body-bytes 7 \
    --expect-cache-tag smoke:warm \
    --expect-header-name etag \
    --expect-header-name vary \
    --expect-purge-indexed \
    --expect-freshness-state fresh

curl -sS --max-time "$CURL_MAX_TIME" -D "$warm_vary_headers" -o "$warm_vary_body" \
    -H "Host: cache.test" \
    -H "Accept-Language: de" \
    "http://127.0.0.1:$FLUXHEIM_PORT/warm-vary.png"
if ! grep -qi '^x-cache-status: HIT' "$warm_vary_headers"; then
    echo "proxy cache smoke failed: cache-warm did not preload negotiated Vary variant" >&2
    cat "$warm_vary_headers" >&2
    exit 1
fi
if [ "$(cat "$warm_vary_body")" != "vary-de" ]; then
    echo "proxy cache smoke failed: cache-warm negotiated Vary body mismatch" >&2
    exit 1
fi

curl -sS --max-time "$CURL_MAX_TIME" -D "$stale_error_first_headers" -o "$stale_error_body" \
    -H "Host: cache.test" \
    "http://127.0.0.1:$FLUXHEIM_PORT/stale-error.png"
if ! grep -qi '^x-cache-status: MISS' "$stale_error_first_headers"; then
    echo "proxy cache smoke failed: initial stale-if-error request was not a cache MISS" >&2
    cat "$stale_error_first_headers" >&2
    exit 1
fi
if [ "$(cat "$stale_error_body")" != "stale-error-body" ]; then
    echo "proxy cache smoke failed: initial stale-if-error body mismatch" >&2
    exit 1
fi

sleep 1.2
stop_origin

stale_error_status=$(
    curl -sS --max-time "$CURL_MAX_TIME" -D "$stale_error_second_headers" -o "$stale_error_body" -w '%{http_code}' \
        -H "Host: cache.test" \
        "http://127.0.0.1:$FLUXHEIM_PORT/stale-error.png"
)
if [ "$stale_error_status" != "200" ]; then
    echo "proxy cache smoke failed: stale-if-error returned $stale_error_status instead of 200" >&2
    cat "$stale_error_second_headers" >&2
    exit 1
fi
if ! grep -qi '^x-cache-status: STALE' "$stale_error_second_headers"; then
    echo "proxy cache smoke failed: stale-if-error did not serve a stale cache response" >&2
    cat "$stale_error_second_headers" >&2
    exit 1
fi
if [ "$(cat "$stale_error_body")" != "stale-error-body" ]; then
    echo "proxy cache smoke failed: stale-if-error body mismatch" >&2
    exit 1
fi

"$ROOT_DIR/target/debug/fluxheim" --config "$TMP_DIR/fluxheim.toml" cache-lookup \
    --host cache.test \
    --path /stale-error.png \
    --require-object \
    --expect-tier disk \
    --expect-status 200 \
    --expect-body-bytes 16 \
    --expect-header-name etag \
    --expect-serve-stale-if-error \
    --expect-freshness-state stale

stop_fluxheim
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
