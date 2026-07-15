#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SMOKE_TMP_ROOT=$(sh "$ROOT_DIR/scripts/secure-smoke-tmp-root.sh")
TMP_DIR=$(mktemp -d "$SMOKE_TMP_ROOT/fluxheim-proxy-cache-smoke.XXXXXX")
KEEP_LOGS=${FLUXHEIM_SMOKE_KEEP_LOGS:-0}
CURL_MAX_TIME=${FLUXHEIM_SMOKE_CURL_MAX_TIME:-5}
LAST_MODIFIED="Sun, 10 May 2026 00:00:00 GMT"
REVALIDATED_LAST_MODIFIED="Mon, 11 May 2026 00:00:00 GMT"

wait_for_cache_lookup() {
    cache_lookup_attempt=1
    while [ "$cache_lookup_attempt" -lt 20 ]; do
        if "$@" >/dev/null 2>&1; then
            return 0
        fi
        cache_lookup_attempt=$((cache_lookup_attempt + 1))
        sleep 0.1
    done
    "$@"
}

ports=$(python3 - <<'PY'
import socket

sockets = []
try:
    for _ in range(4):
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
ADMIN_PORT=$3
METRICS_PORT=$4

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

mkdir -p "$TMP_DIR/run" "$TMP_DIR/cache" "$TMP_DIR/snapshots"
chmod 0700 "$TMP_DIR/snapshots"

cat > "$TMP_DIR/origin.py" <<'PY'
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

BODY = b"0123456789abcdef"
PARTIAL_BODY = b"abcdefghijklmnopqrstuvwxyz0123456789"
SLICE_BODY = b"0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
VARY_BODIES = {
    "de": b"vary-de",
    "en": b"vary-en",
}
INPUT_WARM_BODY = b"input-warm-body"
ETAG = '"cache-smoke-v1"'
INPUT_WARM_ETAG = '"cache-smoke-input-warm"'
REVALIDATE_ETAG = '"cache-smoke-revalidate"'
REVALIDATE_LAST_MODIFIED_ETAG = '"cache-smoke-revalidate-last-modified"'
REFRESH_OLD_ETAG = '"cache-smoke-refresh-old"'
REFRESH_NEW_ETAG = '"cache-smoke-refresh-new"'
SWR_OLD_ETAG = '"cache-smoke-swr-old"'
SWR_NEW_ETAG = '"cache-smoke-swr-new"'
STALE_ERROR_ETAG = '"cache-smoke-stale-error"'
LOCKED_ETAG = '"cache-smoke-locked"'
LAST_MODIFIED = "Sun, 10 May 2026 00:00:00 GMT"
REVALIDATED_LAST_MODIFIED = "Mon, 11 May 2026 00:00:00 GMT"
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

    def do_HEAD(self):
        parsed = urlparse(self.path)
        if parsed.path != "/asset.png":
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

        if parsed.path == "/partial.bin":
            record_path(parsed.path)
            range_header = self.headers.get("range")
            if range_header == "bytes=4-11":
                body = PARTIAL_BODY[4:12]
                self.send_response(206)
                self.send_header("content-type", "image/png")
                self.send_header("content-length", str(len(body)))
                self.send_header("content-range", f"bytes 4-11/{len(PARTIAL_BODY)}")
                self.send_header("cache-control", "public, max-age=120")
                self.send_header("etag", '"cache-smoke-partial"')
                self.send_header("last-modified", LAST_MODIFIED)
                self.end_headers()
                self.wfile.write(body)
                return

            self.send_response(416)
            self.send_header("content-range", f"bytes */{len(PARTIAL_BODY)}")
            self.send_header("content-length", "0")
            self.end_headers()
            return

        if parsed.path == "/slice.bin":
            record_path(parsed.path)
            range_header = self.headers.get("range")
            if not range_header or not range_header.startswith("bytes=") or "," in range_header:
                self.send_response(200)
                self.send_header("content-type", "image/png")
                self.send_header("content-length", str(len(SLICE_BODY)))
                self.send_header("cache-control", "public, max-age=120")
                self.send_header("etag", '"cache-smoke-slice"')
                self.send_header("last-modified", LAST_MODIFIED)
                self.end_headers()
                self.wfile.write(SLICE_BODY)
                return
            start_text, end_text = range_header.removeprefix("bytes=").split("-", 1)
            if start_text == "":
                requested = int(end_text)
                start = max(0, len(SLICE_BODY) - requested)
                end = len(SLICE_BODY) - 1
            else:
                start = int(start_text)
                end = len(SLICE_BODY) - 1 if end_text == "" else int(end_text)
            if start >= len(SLICE_BODY) or end < start:
                self.send_response(416)
                self.send_header("content-range", f"bytes */{len(SLICE_BODY)}")
                self.send_header("content-length", "0")
                self.end_headers()
                return
            end = min(end, len(SLICE_BODY) - 1)
            body = SLICE_BODY[start:end + 1]
            self.send_response(206)
            self.send_header("content-type", "image/png")
            self.send_header("content-length", str(len(body)))
            self.send_header("content-range", f"bytes {start}-{end}/{len(SLICE_BODY)}")
            self.send_header("cache-control", "public, max-age=120")
            self.send_header("etag", '"cache-smoke-slice"')
            self.send_header("last-modified", LAST_MODIFIED)
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

        if self.path == "/input-warm.png":
            body = INPUT_WARM_BODY
            self.send_response(200)
            self.send_header("content-type", "image/png")
            self.send_header("content-length", str(len(body)))
            self.send_header("cache-control", "public, max-age=120")
            self.send_header("etag", INPUT_WARM_ETAG)
            self.send_header("last-modified", LAST_MODIFIED)
            self.send_header("surrogate-key", "smoke:input-warm")
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

        if self.path == "/revalidate-last-modified.png":
            if self.headers.get("if-none-match") == REVALIDATE_LAST_MODIFIED_ETAG:
                self.send_response(304)
                self.send_header("cache-control", "public, max-age=120")
                self.send_header("etag", REVALIDATE_LAST_MODIFIED_ETAG)
                self.send_header("last-modified", REVALIDATED_LAST_MODIFIED)
                self.end_headers()
                return

            body = b"revalidated-lm-body"
            self.send_response(200)
            self.send_header("content-type", "image/png")
            self.send_header("content-length", str(len(body)))
            self.send_header("cache-control", "public, max-age=1")
            self.send_header("etag", REVALIDATE_LAST_MODIFIED_ETAG)
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

        if self.path == "/missing.png":
            self.send_response(404)
            self.send_header("content-type", "image/png")
            self.send_header("content-length", "0")
            self.end_headers()
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
certificate_reload_sock = "$TMP_DIR/run/fluxheim-cert-reload.sock"

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

[admin]
enabled = true
listen = "127.0.0.1:$ADMIN_PORT"
require_loopback = true
token_env = "FLUXHEIM_ADMIN_TOKEN"
snapshot_store = "$TMP_DIR/snapshots"

[metrics]
enabled = true
listen = "127.0.0.1:$METRICS_PORT"
require_loopback = true

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
key_namespace = "cache-vhost-v1"
bypass_request_headers = ["authorization"]
bypass_request_header_values = { x-preview-mode = "1" }
bypass_cookie_names = ["sessionid"]
bypass_cookie_values = { preview = "1" }
bypass_query_params = ["preview"]
bypass_query_values = { mode = "private" }
status_ttls = { "404" = 60 }
stale_if_error_secs = 60
stale_if_error_on = ["connect", "http-status"]
stale_if_error_statuses = [502, 503, 504]
allow_client_cache_refresh = true
max_object_bytes = "1MiB"

[vhosts.cache.memory]
enabled = true
max_size_bytes = "16MiB"

[vhosts.cache.disk]
enabled = true
path = "$TMP_DIR/cache"
max_size_bytes = "32MiB"

[vhosts.cache.predictor]
enabled = true

[vhosts.proxy]
upstreams = ["127.0.0.1:$ORIGIN_PORT"]
upstream_tls = false

[[vhosts.routes]]
name = "partial-range"
path_exact = "/partial.bin"

[vhosts.routes.proxy]
upstreams = ["127.0.0.1:$ORIGIN_PORT"]
upstream_tls = false

[vhosts.routes.cache]
enabled = true
status_header = "X-Cache-Status"
status_reason_header = "X-Cache-Reason"
key_namespace = "cache-route-range-v1"
extensions = ["bin"]
content_types = ["image/png"]
max_object_bytes = "1MiB"

[vhosts.routes.cache.range]
enabled = true
max_bytes = "8KiB"

[vhosts.routes.cache.memory]
enabled = true
max_size_bytes = "16MiB"

[vhosts.routes.cache.disk]
enabled = true
path = "$TMP_DIR/cache"
max_size_bytes = "32MiB"

[[vhosts.routes]]
name = "slice-range"
path_exact = "/slice.bin"

[vhosts.routes.proxy]
upstreams = ["127.0.0.1:$ORIGIN_PORT"]
upstream_tls = false

[vhosts.routes.cache]
enabled = true
status_header = "X-Cache-Status"
status_reason_header = "X-Cache-Reason"
key_namespace = "cache-route-slice-v1"
extensions = ["bin"]
content_types = ["image/png"]
max_object_bytes = "1MiB"

[vhosts.routes.cache.range]
enabled = true
max_bytes = "64B"

[vhosts.routes.cache.range.slice]
enabled = true
size_bytes = "8B"
max_slices = 8
fill_missing = true

[vhosts.routes.cache.origin_protection]
enabled = true
max_concurrent_fills = 2

[vhosts.routes.cache.memory]
enabled = true
max_size_bytes = "16MiB"

[vhosts.routes.cache.disk]
enabled = true
path = "$TMP_DIR/cache"
max_size_bytes = "32MiB"

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
key_namespace = "cache-route-swr-v1"
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

[vhosts.routes.cache.predictor]
enabled = true
EOF

python3 "$TMP_DIR/origin.py" "$ORIGIN_PORT" &
ORIGIN_PID=$!

(cd "$ROOT_DIR" && cargo build --quiet --features metrics)

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
    FLUXHEIM_ADMIN_TOKEN=secret-token "$ROOT_DIR/target/debug/fluxheim" --config "$TMP_DIR/fluxheim.toml" &
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

admin_status_body="$TMP_DIR/admin-status.json"
admin_cache_status_body="$TMP_DIR/admin-cache-status.json"
admin_bulk_purge_body="$TMP_DIR/admin-bulk-purge.json"
admin_exact_purge_body="$TMP_DIR/admin-exact-purge.json"
admin_stale_dry_run_body="$TMP_DIR/admin-stale-dry-run.json"
admin_prefix_purge_body="$TMP_DIR/admin-prefix-purge.json"
admin_route_purge_body="$TMP_DIR/admin-route-purge.json"
admin_tag_purge_body="$TMP_DIR/admin-tag-purge.json"
admin_wildcard_purge_body="$TMP_DIR/admin-wildcard-purge.json"
metrics_body="$TMP_DIR/metrics.txt"

start_fluxheim

wait_http() {
    url=$1
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        status=$(
            curl -sS --max-time "$CURL_MAX_TIME" -o /dev/null -w '%{http_code}' \
                -H "Host: cache.test" \
                -H "Cache-Control: no-store" \
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

if ! curl -sS --max-time "$CURL_MAX_TIME" -o "$admin_status_body" \
    -H "Authorization: Bearer secret-token" \
    "http://127.0.0.1:$ADMIN_PORT/_fluxheim/status"; then
    echo "proxy cache smoke failed: admin endpoint did not become reachable" >&2
    cat "$TMP_DIR/fluxheim.log" >&2 || true
    exit 1
fi
if ! grep -q '"status":"ok"' "$admin_status_body"; then
    echo "proxy cache smoke failed: admin status endpoint did not return ok" >&2
    cat "$admin_status_body" >&2
    exit 1
fi

if ! curl -sS --max-time "$CURL_MAX_TIME" -o "$admin_cache_status_body" \
    -H "Authorization: Bearer secret-token" \
    "http://127.0.0.1:$ADMIN_PORT/_fluxheim/cache/status"; then
    echo "proxy cache smoke failed: admin cache-status endpoint did not become reachable" >&2
    cat "$TMP_DIR/fluxheim.log" >&2 || true
    exit 1
fi
if ! grep -q '"origin_protection_enabled_policies":1' "$admin_cache_status_body"; then
    echo "proxy cache smoke failed: admin status missed origin-protection policy count" >&2
    cat "$admin_cache_status_body" >&2
    exit 1
fi
if ! grep -q '"origin_protection_max_concurrent_fills":2' "$admin_cache_status_body"; then
    echo "proxy cache smoke failed: admin status missed origin-protection fill budget" >&2
    cat "$admin_cache_status_body" >&2
    exit 1
fi

if ! curl -sS --max-time "$CURL_MAX_TIME" -o "$metrics_body" \
    "http://127.0.0.1:$METRICS_PORT/metrics"; then
    echo "proxy cache smoke failed: metrics endpoint did not become reachable" >&2
    cat "$TMP_DIR/fluxheim.log" >&2 || true
    exit 1
fi
if ! grep -q '^fluxheim_cache_configured_routes ' "$metrics_body"; then
    echo "proxy cache smoke failed: metrics endpoint did not expose Fluxheim metrics" >&2
    head -n 40 "$metrics_body" >&2 || true
    exit 1
fi
if ! grep -q '^fluxheim_cache_origin_protection_enabled_policies 1$' "$metrics_body"; then
    echo "proxy cache smoke failed: metrics missed origin-protection policy count" >&2
    grep 'fluxheim_cache_origin_protection' "$metrics_body" >&2 || true
    exit 1
fi
if ! grep -q '^fluxheim_cache_origin_protection_max_concurrent_fills 2$' "$metrics_body"; then
    echo "proxy cache smoke failed: metrics missed origin-protection fill budget" >&2
    grep 'fluxheim_cache_origin_protection' "$metrics_body" >&2 || true
    exit 1
fi

"$ROOT_DIR/target/debug/fluxheim" --config "$TMP_DIR/fluxheim.toml" cache-key \
    --host cache.test \
    --path /asset.png \
    --expect-eligible \
    --expect-cache-lock-enabled \
    --expect-cache-lock-wait-timeout-secs 30 \
    --expect-cache-predictor-enabled \
    --expect-memory-tier-enabled \
    --expect-disk-tier-enabled \
    --expect-scope vhost \
    --expect-vhost cache.test \
    --expect-namespace fluxheim-image-v1 \
    --expect-key-namespace cache-vhost-v1 \
    --expect-user-tag cache.test \
    --expect-storage-tiers 2

"$ROOT_DIR/target/debug/fluxheim" --config "$TMP_DIR/fluxheim.toml" cache-key \
    --host cache.test \
    --method HEAD \
    --path /asset.png \
    --expect-ineligible \
    --expect-reason "method HEAD currently bypasses proxy cache storage" \
    --expect-cache-predictor-enabled \
    --expect-scope vhost \
    --expect-vhost cache.test

"$ROOT_DIR/target/debug/fluxheim" --config "$TMP_DIR/fluxheim.toml" cache-key \
    --host cache.test \
    --path /swr.png \
    --expect-eligible \
    --expect-cache-lock-enabled \
    --expect-cache-lock-wait-timeout-secs 30 \
    --expect-cache-predictor-enabled \
    --expect-scope route \
    --expect-vhost cache.test \
    --expect-route swr \
    --expect-namespace fluxheim-image-v1 \
    --expect-key-namespace cache-route-swr-v1 \
    --expect-user-tag cache.test:route:swr

"$ROOT_DIR/target/debug/fluxheim" --config "$TMP_DIR/fluxheim.toml" cache-key \
    --host cache.test \
    --path /slice.bin \
    --expect-eligible \
    --expect-origin-protection-enabled \
    --expect-origin-protection-max-concurrent-fills 2 \
    --expect-scope route \
    --expect-vhost cache.test \
    --expect-route slice-range \
    --expect-namespace fluxheim-image-v1 \
    --expect-key-namespace cache-route-slice-v1 \
    --expect-user-tag cache.test:route:slice-range

"$ROOT_DIR/target/debug/fluxheim" --config "$TMP_DIR/fluxheim.toml" cache-lookup \
    --host cache.test \
    --method HEAD \
    --path /asset.png \
    --expect-ineligible \
    --expect-reason "method HEAD currently bypasses proxy cache storage" \
    --expect-objects 0

first_headers="$TMP_DIR/first.headers"
second_headers="$TMP_DIR/second.headers"
head_first_headers="$TMP_DIR/head-first.headers"
head_second_headers="$TMP_DIR/head-second.headers"
post_head_get_headers="$TMP_DIR/post-head-get.headers"
refresh_headers="$TMP_DIR/refresh.headers"
pragma_refresh_headers="$TMP_DIR/pragma-refresh.headers"
max_age_refresh_headers="$TMP_DIR/max-age-refresh.headers"
no_store_bypass_headers="$TMP_DIR/no-store-bypass.headers"
header_bypass_headers="$TMP_DIR/header-bypass.headers"
header_value_bypass_headers="$TMP_DIR/header-value-bypass.headers"
cookie_name_bypass_headers="$TMP_DIR/cookie-name-bypass.headers"
cookie_value_bypass_headers="$TMP_DIR/cookie-value-bypass.headers"
query_param_bypass_headers="$TMP_DIR/query-param-bypass.headers"
query_value_bypass_headers="$TMP_DIR/query-value-bypass.headers"
post_configured_bypass_get_headers="$TMP_DIR/post-configured-bypass-get.headers"
conditional_headers="$TMP_DIR/conditional.headers"
conditional_mismatch_headers="$TMP_DIR/conditional-mismatch.headers"
modified_since_headers="$TMP_DIR/modified-since.headers"
modified_since_mismatch_headers="$TMP_DIR/modified-since-mismatch.headers"
range_headers="$TMP_DIR/range.headers"
partial_range_first_headers="$TMP_DIR/partial-range-first.headers"
partial_range_second_headers="$TMP_DIR/partial-range-second.headers"
slice_first_headers="$TMP_DIR/slice-first.headers"
slice_second_headers="$TMP_DIR/slice-second.headers"
slice_open_headers="$TMP_DIR/slice-open.headers"
slice_suffix_headers="$TMP_DIR/slice-suffix.headers"
slice_multi_headers="$TMP_DIR/slice-multi.headers"
slice_if_range_headers="$TMP_DIR/slice-if-range.headers"
if_range_match_headers="$TMP_DIR/if-range-match.headers"
if_range_mismatch_headers="$TMP_DIR/if-range-mismatch.headers"
if_range_date_match_headers="$TMP_DIR/if-range-date-match.headers"
if_range_date_mismatch_headers="$TMP_DIR/if-range-date-mismatch.headers"
revalidate_first_headers="$TMP_DIR/revalidate-first.headers"
revalidate_second_headers="$TMP_DIR/revalidate-second.headers"
revalidate_third_headers="$TMP_DIR/revalidate-third.headers"
revalidate_lm_first_headers="$TMP_DIR/revalidate-lm-first.headers"
revalidate_lm_second_headers="$TMP_DIR/revalidate-lm-second.headers"
revalidate_lm_third_headers="$TMP_DIR/revalidate-lm-third.headers"
refresh_first_headers="$TMP_DIR/refresh-first.headers"
refresh_second_headers="$TMP_DIR/refresh-second.headers"
refresh_third_headers="$TMP_DIR/refresh-third.headers"
swr_first_headers="$TMP_DIR/swr-first.headers"
swr_second_headers="$TMP_DIR/swr-second.headers"
swr_third_headers="$TMP_DIR/swr-third.headers"
stale_error_first_headers="$TMP_DIR/stale-error-first.headers"
stale_error_second_headers="$TMP_DIR/stale-error-second.headers"
restart_headers="$TMP_DIR/restart.headers"
post_prefix_purge_headers="$TMP_DIR/post-prefix-purge.headers"
post_tag_purge_headers="$TMP_DIR/post-tag-purge.headers"
post_wildcard_purge_headers="$TMP_DIR/post-wildcard-purge.headers"
post_exact_purge_headers="$TMP_DIR/post-exact-purge.headers"
post_route_purge_headers="$TMP_DIR/post-route-purge.headers"
body="$TMP_DIR/body.bin"
range_body="$TMP_DIR/range-body.bin"
partial_range_body="$TMP_DIR/partial-range-body.bin"
slice_body="$TMP_DIR/slice-body.bin"
slice_multi_body="$TMP_DIR/slice-multi-body.bin"
if_range_match_body="$TMP_DIR/if-range-match-body.bin"
if_range_mismatch_body="$TMP_DIR/if-range-mismatch-body.bin"
if_range_date_match_body="$TMP_DIR/if-range-date-match-body.bin"
if_range_date_mismatch_body="$TMP_DIR/if-range-date-mismatch-body.bin"
revalidate_body="$TMP_DIR/revalidate-body.bin"
revalidate_lm_body="$TMP_DIR/revalidate-lm-body.bin"
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
warm_input_file="$TMP_DIR/warm-input.txt"
warm_input_headers="$TMP_DIR/warm-input.headers"
warm_input_body="$TMP_DIR/warm-input.bin"
warm_missing_headers="$TMP_DIR/warm-missing.headers"
warm_missing_body="$TMP_DIR/warm-missing.bin"

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
if ! grep -qi "^last-modified: $LAST_MODIFIED" "$second_headers"; then
    echo "proxy cache smoke failed: cache HIT did not preserve Last-Modified header" >&2
    cat "$second_headers" >&2
    exit 1
fi

head_first_status=$(
    curl -sS --max-time "$CURL_MAX_TIME" -I -D "$head_first_headers" -o /dev/null -w '%{http_code}' \
        -H "Host: cache.test" \
        "http://127.0.0.1:$FLUXHEIM_PORT/asset.png"
)
if [ "$head_first_status" != "200" ]; then
    echo "proxy cache smoke failed: first HEAD request returned $head_first_status instead of 200" >&2
    cat "$head_first_headers" >&2
    exit 1
fi
if ! grep -qi '^x-cache-status: BYPASS' "$head_first_headers"; then
    echo "proxy cache smoke failed: first HEAD request was not a safe cache BYPASS" >&2
    cat "$head_first_headers" >&2
    exit 1
fi
if ! grep -qi '^x-cache-reason: method-head' "$head_first_headers"; then
    echo "proxy cache smoke failed: first HEAD request missed bounded bypass reason" >&2
    cat "$head_first_headers" >&2
    exit 1
fi
if ! grep -qi '^content-length: 16' "$head_first_headers"; then
    echo "proxy cache smoke failed: first HEAD request missed expected Content-Length" >&2
    cat "$head_first_headers" >&2
    exit 1
fi

head_second_status=$(
    curl -sS --max-time "$CURL_MAX_TIME" -I -D "$head_second_headers" -o /dev/null -w '%{http_code}' \
        -H "Host: cache.test" \
        "http://127.0.0.1:$FLUXHEIM_PORT/asset.png"
)
if [ "$head_second_status" != "200" ]; then
    echo "proxy cache smoke failed: second HEAD request returned $head_second_status instead of 200" >&2
    cat "$head_second_headers" >&2
    exit 1
fi
if ! grep -qi '^x-cache-status: BYPASS' "$head_second_headers"; then
    echo "proxy cache smoke failed: second HEAD request was not a safe cache BYPASS" >&2
    cat "$head_second_headers" >&2
    exit 1
fi
if ! grep -qi '^x-cache-reason: method-head' "$head_second_headers"; then
    echo "proxy cache smoke failed: second HEAD request missed bounded bypass reason" >&2
    cat "$head_second_headers" >&2
    exit 1
fi
if ! grep -qi '^content-length: 16' "$head_second_headers"; then
    echo "proxy cache smoke failed: cached HEAD request missed expected Content-Length" >&2
    cat "$head_second_headers" >&2
    exit 1
fi

curl -sS --max-time "$CURL_MAX_TIME" -D "$post_head_get_headers" -o "$body" \
    -H "Host: cache.test" \
    "http://127.0.0.1:$FLUXHEIM_PORT/asset.png"
if ! grep -qi '^x-cache-status: HIT' "$post_head_get_headers"; then
    echo "proxy cache smoke failed: HEAD requests poisoned the cached GET entry" >&2
    cat "$post_head_get_headers" >&2
    exit 1
fi
if [ "$(cat "$body")" != "0123456789abcdef" ]; then
    echo "proxy cache smoke failed: GET body changed after HEAD requests" >&2
    exit 1
fi

curl -sS --max-time "$CURL_MAX_TIME" -D "$refresh_headers" -o "$body" \
    -H "Host: cache.test" \
    -H "Cache-Control: no-cache" \
    "http://127.0.0.1:$FLUXHEIM_PORT/asset.png"
if ! grep -qi '^x-cache-status: REVALIDATE' "$refresh_headers"; then
    echo "proxy cache smoke failed: client refresh did not force cache revalidation" >&2
    cat "$refresh_headers" >&2
    exit 1
fi
if ! grep -qi '^x-cache-reason: request-refresh' "$refresh_headers"; then
    echo "proxy cache smoke failed: client refresh did not expose bounded reason" >&2
    cat "$refresh_headers" >&2
    exit 1
fi

curl -sS --max-time "$CURL_MAX_TIME" -D "$pragma_refresh_headers" -o "$body" \
    -H "Host: cache.test" \
    -H "Pragma: no-cache" \
    "http://127.0.0.1:$FLUXHEIM_PORT/asset.png"
if ! grep -qi '^x-cache-status: REVALIDATE' "$pragma_refresh_headers"; then
    echo "proxy cache smoke failed: Pragma refresh did not force cache revalidation" >&2
    cat "$pragma_refresh_headers" >&2
    exit 1
fi
if ! grep -qi '^x-cache-reason: request-refresh' "$pragma_refresh_headers"; then
    echo "proxy cache smoke failed: Pragma refresh did not expose bounded reason" >&2
    cat "$pragma_refresh_headers" >&2
    exit 1
fi

curl -sS --max-time "$CURL_MAX_TIME" -D "$max_age_refresh_headers" -o "$body" \
    -H "Host: cache.test" \
    -H "Cache-Control: max-age=0" \
    "http://127.0.0.1:$FLUXHEIM_PORT/asset.png"
if ! grep -qi '^x-cache-status: REVALIDATE' "$max_age_refresh_headers"; then
    echo "proxy cache smoke failed: Cache-Control max-age=0 did not force cache revalidation" >&2
    cat "$max_age_refresh_headers" >&2
    exit 1
fi
if ! grep -qi '^x-cache-reason: request-refresh' "$max_age_refresh_headers"; then
    echo "proxy cache smoke failed: Cache-Control max-age=0 did not expose bounded reason" >&2
    cat "$max_age_refresh_headers" >&2
    exit 1
fi

curl -sS --max-time "$CURL_MAX_TIME" -D "$no_store_bypass_headers" -o "$body" \
    -H "Host: cache.test" \
    -H "Cache-Control: no-store" \
    "http://127.0.0.1:$FLUXHEIM_PORT/asset.png"
if ! grep -qi '^x-cache-status: BYPASS' "$no_store_bypass_headers"; then
    echo "proxy cache smoke failed: no-store request did not expose BYPASS status" >&2
    cat "$no_store_bypass_headers" >&2
    exit 1
fi
if ! grep -qi '^x-cache-reason: request-no-store' "$no_store_bypass_headers"; then
    echo "proxy cache smoke failed: no-store request did not expose bounded reason" >&2
    cat "$no_store_bypass_headers" >&2
    exit 1
fi

curl -sS --max-time "$CURL_MAX_TIME" -D "$header_bypass_headers" -o "$body" \
    -H "Host: cache.test" \
    -H "Authorization: Bearer smoke" \
    "http://127.0.0.1:$FLUXHEIM_PORT/asset.png"
if ! grep -qi '^x-cache-status: BYPASS' "$header_bypass_headers"; then
    echo "proxy cache smoke failed: configured request-header bypass did not expose BYPASS status" >&2
    cat "$header_bypass_headers" >&2
    exit 1
fi
if ! grep -qi '^x-cache-reason: request-authorization' "$header_bypass_headers"; then
    echo "proxy cache smoke failed: Authorization bypass did not expose bounded reason" >&2
    cat "$header_bypass_headers" >&2
    exit 1
fi

curl -sS --max-time "$CURL_MAX_TIME" -D "$header_value_bypass_headers" -o "$body" \
    -H "Host: cache.test" \
    -H "X-Preview-Mode: 1" \
    "http://127.0.0.1:$FLUXHEIM_PORT/asset.png"
if ! grep -qi '^x-cache-status: BYPASS' "$header_value_bypass_headers"; then
    echo "proxy cache smoke failed: configured request-header-value bypass did not expose BYPASS status" >&2
    cat "$header_value_bypass_headers" >&2
    exit 1
fi
if ! grep -qi '^x-cache-reason: request-header-value' "$header_value_bypass_headers"; then
    echo "proxy cache smoke failed: configured request-header-value bypass did not expose bounded reason" >&2
    cat "$header_value_bypass_headers" >&2
    exit 1
fi

curl -sS --max-time "$CURL_MAX_TIME" -D "$cookie_name_bypass_headers" -o "$body" \
    -H "Host: cache.test" \
    -H "Cookie: theme=dark; sessionid=abc" \
    "http://127.0.0.1:$FLUXHEIM_PORT/asset.png"
if ! grep -qi '^x-cache-status: BYPASS' "$cookie_name_bypass_headers"; then
    echo "proxy cache smoke failed: configured cookie-name bypass did not expose BYPASS status" >&2
    cat "$cookie_name_bypass_headers" >&2
    exit 1
fi
if ! grep -qi '^x-cache-reason: request-cookie' "$cookie_name_bypass_headers"; then
    echo "proxy cache smoke failed: configured cookie-name bypass did not expose bounded reason" >&2
    cat "$cookie_name_bypass_headers" >&2
    exit 1
fi

curl -sS --max-time "$CURL_MAX_TIME" -D "$cookie_value_bypass_headers" -o "$body" \
    -H "Host: cache.test" \
    -H "Cookie: theme=dark; preview=1" \
    "http://127.0.0.1:$FLUXHEIM_PORT/asset.png"
if ! grep -qi '^x-cache-status: BYPASS' "$cookie_value_bypass_headers"; then
    echo "proxy cache smoke failed: configured cookie-value bypass did not expose BYPASS status" >&2
    cat "$cookie_value_bypass_headers" >&2
    exit 1
fi
if ! grep -qi '^x-cache-reason: request-cookie' "$cookie_value_bypass_headers"; then
    echo "proxy cache smoke failed: configured cookie-value bypass did not expose bounded reason" >&2
    cat "$cookie_value_bypass_headers" >&2
    exit 1
fi

curl -sS --max-time "$CURL_MAX_TIME" -D "$query_param_bypass_headers" -o "$body" \
    -H "Host: cache.test" \
    "http://127.0.0.1:$FLUXHEIM_PORT/asset.png?preview=1"
if ! grep -qi '^x-cache-status: BYPASS' "$query_param_bypass_headers"; then
    echo "proxy cache smoke failed: configured query-param bypass did not expose BYPASS status" >&2
    cat "$query_param_bypass_headers" >&2
    exit 1
fi
if ! grep -qi '^x-cache-reason: request-query' "$query_param_bypass_headers"; then
    echo "proxy cache smoke failed: configured query-param bypass did not expose bounded reason" >&2
    cat "$query_param_bypass_headers" >&2
    exit 1
fi

curl -sS --max-time "$CURL_MAX_TIME" -D "$query_value_bypass_headers" -o "$body" \
    -H "Host: cache.test" \
    "http://127.0.0.1:$FLUXHEIM_PORT/asset.png?mode=private"
if ! grep -qi '^x-cache-status: BYPASS' "$query_value_bypass_headers"; then
    echo "proxy cache smoke failed: configured query-value bypass did not expose BYPASS status" >&2
    cat "$query_value_bypass_headers" >&2
    exit 1
fi
if ! grep -qi '^x-cache-reason: request-query' "$query_value_bypass_headers"; then
    echo "proxy cache smoke failed: configured query-value bypass did not expose bounded reason" >&2
    cat "$query_value_bypass_headers" >&2
    exit 1
fi

curl -sS --max-time "$CURL_MAX_TIME" -D "$post_configured_bypass_get_headers" -o "$body" \
    -H "Host: cache.test" \
    "http://127.0.0.1:$FLUXHEIM_PORT/asset.png"
if ! grep -qi '^x-cache-status: HIT' "$post_configured_bypass_get_headers"; then
    echo "proxy cache smoke failed: configured bypass requests poisoned the cached GET entry" >&2
    cat "$post_configured_bypass_get_headers" >&2
    exit 1
fi

curl -sS --max-time "$CURL_MAX_TIME" -o "$metrics_body" \
    "http://127.0.0.1:$METRICS_PORT/metrics"
if ! grep -Eq 'fluxheim_cache_activity_total\{event="bypass",tier="policy"\} [1-9][0-9]*' "$metrics_body"; then
    echo "proxy cache smoke failed: metrics missed policy bypass activity counter" >&2
    grep 'fluxheim_cache_activity' "$metrics_body" >&2 || true
    exit 1
fi
if ! grep -Eq 'fluxheim_cache_activity_scope_total\{event="bypass",route="",scope="vhost",tier="policy",vhost="cache\.test"\} [1-9][0-9]*' "$metrics_body"; then
    echo "proxy cache smoke failed: metrics missed scoped policy bypass activity counter" >&2
    grep 'fluxheim_cache_activity_scope_total' "$metrics_body" >&2 || true
    exit 1
fi
if ! grep -Eq 'fluxheim_cache_activity_total\{event="revalidate",tier="policy"\} [1-9][0-9]*' "$metrics_body"; then
    echo "proxy cache smoke failed: metrics missed policy revalidate activity counter" >&2
    grep 'fluxheim_cache_activity' "$metrics_body" >&2 || true
    exit 1
fi
if ! grep -Eq 'fluxheim_cache_activity_scope_total\{event="revalidate",route="",scope="vhost",tier="policy",vhost="cache\.test"\} [1-9][0-9]*' "$metrics_body"; then
    echo "proxy cache smoke failed: metrics missed scoped policy revalidate activity counter" >&2
    grep 'fluxheim_cache_activity_scope_total' "$metrics_body" >&2 || true
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
if ! grep -qi '^x-cache-status: HIT' "$conditional_headers"; then
    echo "proxy cache smoke failed: cached conditional 304 was not served as a cache HIT" >&2
    cat "$conditional_headers" >&2
    exit 1
fi
if ! grep -qi "^last-modified: $LAST_MODIFIED" "$conditional_headers"; then
    echo "proxy cache smoke failed: cached conditional 304 did not preserve Last-Modified header" >&2
    cat "$conditional_headers" >&2
    exit 1
fi

conditional_mismatch_status=$(
    curl -sS --max-time "$CURL_MAX_TIME" -D "$conditional_mismatch_headers" -o "$body" -w '%{http_code}' \
        -H "Host: cache.test" \
        -H 'If-None-Match: "cache-smoke-other"' \
        "http://127.0.0.1:$FLUXHEIM_PORT/asset.png"
)
if [ "$conditional_mismatch_status" != "200" ]; then
    echo "proxy cache smoke failed: cached conditional mismatch returned $conditional_mismatch_status instead of 200" >&2
    cat "$conditional_mismatch_headers" >&2
    exit 1
fi
if ! grep -qi '^x-cache-status: HIT' "$conditional_mismatch_headers"; then
    echo "proxy cache smoke failed: cached conditional mismatch was not served as a cache HIT" >&2
    cat "$conditional_mismatch_headers" >&2
    exit 1
fi
if [ "$(cat "$body")" != "0123456789abcdef" ]; then
    echo "proxy cache smoke failed: cached conditional mismatch body mismatch" >&2
    exit 1
fi

modified_since_status=$(
    curl -sS --max-time "$CURL_MAX_TIME" -D "$modified_since_headers" -o /dev/null -w '%{http_code}' \
        -H "Host: cache.test" \
        -H "If-Modified-Since: Sun, 10 May 2026 00:00:00 GMT" \
        "http://127.0.0.1:$FLUXHEIM_PORT/asset.png"
)
if [ "$modified_since_status" != "304" ]; then
    echo "proxy cache smoke failed: cached If-Modified-Since returned $modified_since_status instead of 304" >&2
    cat "$modified_since_headers" >&2
    exit 1
fi
if ! grep -qi '^x-cache-status: HIT' "$modified_since_headers"; then
    echo "proxy cache smoke failed: cached If-Modified-Since 304 was not served as a cache HIT" >&2
    cat "$modified_since_headers" >&2
    exit 1
fi

modified_since_mismatch_status=$(
    curl -sS --max-time "$CURL_MAX_TIME" -D "$modified_since_mismatch_headers" -o "$body" -w '%{http_code}' \
        -H "Host: cache.test" \
        -H "If-Modified-Since: Sat, 09 May 2026 00:00:00 GMT" \
        "http://127.0.0.1:$FLUXHEIM_PORT/asset.png"
)
if [ "$modified_since_mismatch_status" != "200" ]; then
    echo "proxy cache smoke failed: cached If-Modified-Since mismatch returned $modified_since_mismatch_status instead of 200" >&2
    cat "$modified_since_mismatch_headers" >&2
    exit 1
fi
if ! grep -qi '^x-cache-status: HIT' "$modified_since_mismatch_headers"; then
    echo "proxy cache smoke failed: cached If-Modified-Since mismatch was not served as a cache HIT" >&2
    cat "$modified_since_mismatch_headers" >&2
    exit 1
fi
if [ "$(cat "$body")" != "0123456789abcdef" ]; then
    echo "proxy cache smoke failed: cached If-Modified-Since mismatch body mismatch" >&2
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
if ! grep -qi '^x-cache-status: HIT' "$range_headers"; then
    echo "proxy cache smoke failed: cached range was not served as a cache HIT" >&2
    cat "$range_headers" >&2
    exit 1
fi
if ! grep -qi '^content-range: bytes 0-3/16' "$range_headers"; then
    echo "proxy cache smoke failed: cached range response missed expected Content-Range" >&2
    cat "$range_headers" >&2
    exit 1
fi
if ! grep -qi "^last-modified: $LAST_MODIFIED" "$range_headers"; then
    echo "proxy cache smoke failed: cached range response did not preserve Last-Modified header" >&2
    cat "$range_headers" >&2
    exit 1
fi
if [ "$(cat "$range_body")" != "0123" ]; then
    echo "proxy cache smoke failed: cached range body mismatch" >&2
    exit 1
fi

partial_range_first_status=$(
    curl -sS --max-time "$CURL_MAX_TIME" -D "$partial_range_first_headers" -o "$partial_range_body" -w '%{http_code}' \
        -H "Host: cache.test" \
        -H "Range: bytes=4-11" \
        "http://127.0.0.1:$FLUXHEIM_PORT/partial.bin"
)
if [ "$partial_range_first_status" != "206" ]; then
    echo "proxy cache smoke failed: first bounded range returned $partial_range_first_status instead of 206" >&2
    cat "$partial_range_first_headers" >&2
    exit 1
fi
if ! grep -qi '^x-cache-status: BYPASS' "$partial_range_first_headers"; then
    echo "proxy cache smoke failed: first bounded range was not a cache BYPASS" >&2
    cat "$partial_range_first_headers" >&2
    exit 1
fi
if ! grep -qi '^x-cache-reason: range-miss' "$partial_range_first_headers"; then
    echo "proxy cache smoke failed: first bounded range missed range-miss reason" >&2
    cat "$partial_range_first_headers" >&2
    exit 1
fi
if ! grep -qi '^content-range: bytes 4-11/36' "$partial_range_first_headers"; then
    echo "proxy cache smoke failed: first bounded range missed expected Content-Range" >&2
    cat "$partial_range_first_headers" >&2
    exit 1
fi
if [ "$(cat "$partial_range_body")" != "efghijkl" ]; then
    echo "proxy cache smoke failed: first bounded range body mismatch" >&2
    exit 1
fi

partial_range_second_status=$(
    curl -sS --max-time "$CURL_MAX_TIME" -D "$partial_range_second_headers" -o "$partial_range_body" -w '%{http_code}' \
        -H "Host: cache.test" \
        -H "Range: bytes=4-11" \
        "http://127.0.0.1:$FLUXHEIM_PORT/partial.bin"
)
if [ "$partial_range_second_status" != "206" ]; then
    echo "proxy cache smoke failed: second bounded range returned $partial_range_second_status instead of 206" >&2
    cat "$partial_range_second_headers" >&2
    exit 1
fi
if ! grep -qi '^x-cache-status: BYPASS' "$partial_range_second_headers"; then
    echo "proxy cache smoke failed: second bounded range was not a cache BYPASS" >&2
    cat "$partial_range_second_headers" >&2
    exit 1
fi
if ! grep -qi '^x-cache-reason: range-miss' "$partial_range_second_headers"; then
    echo "proxy cache smoke failed: second bounded range missed range-miss reason" >&2
    cat "$partial_range_second_headers" >&2
    exit 1
fi
if ! grep -qi '^content-range: bytes 4-11/36' "$partial_range_second_headers"; then
    echo "proxy cache smoke failed: cached bounded range missed expected Content-Range" >&2
    cat "$partial_range_second_headers" >&2
    exit 1
fi
if [ "$(cat "$partial_range_body")" != "efghijkl" ]; then
    echo "proxy cache smoke failed: cached bounded range body mismatch" >&2
    exit 1
fi
partial_range_origin_count=$(
    curl -sS --max-time "$CURL_MAX_TIME" \
        "http://127.0.0.1:$ORIGIN_PORT/__count?path=/partial.bin"
)
if [ "$partial_range_origin_count" != "2" ]; then
    echo "proxy cache smoke failed: bounded range did not bypass repeated origin reads, count=$partial_range_origin_count" >&2
    exit 1
fi

slice_first_status=$(
    curl -sS --max-time "$CURL_MAX_TIME" -D "$slice_first_headers" -o "$slice_body" -w '%{http_code}' \
        -H "Host: cache.test" \
        -H "Range: bytes=4-21" \
        "http://127.0.0.1:$FLUXHEIM_PORT/slice.bin"
)
if [ "$slice_first_status" != "206" ]; then
    echo "proxy cache smoke failed: first slice range returned $slice_first_status instead of 206" >&2
    cat "$slice_first_headers" >&2
    exit 1
fi
if ! grep -qi '^x-cache-status: MISS' "$slice_first_headers"; then
    echo "proxy cache smoke failed: first slice range was not a cache MISS" >&2
    cat "$slice_first_headers" >&2
    exit 1
fi
if ! grep -qi '^x-cache-reason: slice-fill' "$slice_first_headers"; then
    echo "proxy cache smoke failed: first slice range missed slice-fill reason" >&2
    cat "$slice_first_headers" >&2
    exit 1
fi
if ! grep -qi '^content-range: bytes 4-21/62' "$slice_first_headers"; then
    echo "proxy cache smoke failed: first slice range missed expected Content-Range" >&2
    cat "$slice_first_headers" >&2
    exit 1
fi
if [ "$(cat "$slice_body")" != "456789abcdefghijkl" ]; then
    echo "proxy cache smoke failed: first slice range body mismatch" >&2
    exit 1
fi

slice_second_status=$(
    curl -sS --max-time "$CURL_MAX_TIME" -D "$slice_second_headers" -o "$slice_body" -w '%{http_code}' \
        -H "Host: cache.test" \
        -H "Range: bytes=4-21" \
        "http://127.0.0.1:$FLUXHEIM_PORT/slice.bin"
)
if [ "$slice_second_status" != "206" ]; then
    echo "proxy cache smoke failed: second slice range returned $slice_second_status instead of 206" >&2
    cat "$slice_second_headers" >&2
    exit 1
fi
if ! grep -qi '^x-cache-status: HIT' "$slice_second_headers"; then
    echo "proxy cache smoke failed: second slice range was not a cache HIT" >&2
    cat "$slice_second_headers" >&2
    exit 1
fi
if ! grep -qi '^x-cache-reason: slice' "$slice_second_headers"; then
    echo "proxy cache smoke failed: second slice range missed slice reason" >&2
    cat "$slice_second_headers" >&2
    exit 1
fi

slice_open_status=$(
    curl -sS --max-time "$CURL_MAX_TIME" -D "$slice_open_headers" -o "$slice_body" -w '%{http_code}' \
        -H "Host: cache.test" \
        -H "Range: bytes=58-" \
        "http://127.0.0.1:$FLUXHEIM_PORT/slice.bin"
)
if [ "$slice_open_status" != "206" ]; then
    echo "proxy cache smoke failed: open-ended slice range returned $slice_open_status instead of 206" >&2
    cat "$slice_open_headers" >&2
    exit 1
fi
if ! grep -qi '^content-range: bytes 58-61/62' "$slice_open_headers"; then
    echo "proxy cache smoke failed: open-ended slice range missed expected Content-Range" >&2
    cat "$slice_open_headers" >&2
    exit 1
fi
if [ "$(cat "$slice_body")" != "WXYZ" ]; then
    echo "proxy cache smoke failed: open-ended slice range body mismatch" >&2
    exit 1
fi

slice_suffix_status=$(
    curl -sS --max-time "$CURL_MAX_TIME" -D "$slice_suffix_headers" -o "$slice_body" -w '%{http_code}' \
        -H "Host: cache.test" \
        -H "Range: bytes=-5" \
        "http://127.0.0.1:$FLUXHEIM_PORT/slice.bin"
)
if [ "$slice_suffix_status" != "206" ]; then
    echo "proxy cache smoke failed: suffix slice range returned $slice_suffix_status instead of 206" >&2
    cat "$slice_suffix_headers" >&2
    exit 1
fi
if ! grep -qi '^content-range: bytes 57-61/62' "$slice_suffix_headers"; then
    echo "proxy cache smoke failed: suffix slice range missed expected Content-Range" >&2
    cat "$slice_suffix_headers" >&2
    exit 1
fi
if [ "$(cat "$slice_body")" != "VWXYZ" ]; then
    echo "proxy cache smoke failed: suffix slice range body mismatch" >&2
    exit 1
fi

slice_multi_status=$(
    curl -sS --max-time "$CURL_MAX_TIME" -D "$slice_multi_headers" -o "$slice_multi_body" -w '%{http_code}' \
        -H "Host: cache.test" \
        -H "Range: bytes=0-3,10-12" \
        "http://127.0.0.1:$FLUXHEIM_PORT/slice.bin"
)
if [ "$slice_multi_status" != "206" ]; then
    echo "proxy cache smoke failed: multi slice range returned $slice_multi_status instead of 206" >&2
    cat "$slice_multi_headers" >&2
    exit 1
fi
if ! grep -qi '^content-type: multipart/byteranges;' "$slice_multi_headers"; then
    echo "proxy cache smoke failed: multi slice range was not multipart/byteranges" >&2
    cat "$slice_multi_headers" >&2
    exit 1
fi
if ! grep -q 'Content-Range: bytes 0-3/62' "$slice_multi_body" \
    || ! grep -q 'Content-Range: bytes 10-12/62' "$slice_multi_body" \
    || ! grep -q '0123' "$slice_multi_body" \
    || ! grep -q 'abc' "$slice_multi_body"; then
    echo "proxy cache smoke failed: multi slice body missing expected parts" >&2
    cat "$slice_multi_body" >&2
    exit 1
fi

slice_if_range_status=$(
    curl -sS --max-time "$CURL_MAX_TIME" -D "$slice_if_range_headers" -o "$slice_body" -w '%{http_code}' \
        -H "Host: cache.test" \
        -H "Range: bytes=8-15" \
        -H 'If-Range: "cache-smoke-slice"' \
        "http://127.0.0.1:$FLUXHEIM_PORT/slice.bin"
)
if [ "$slice_if_range_status" != "206" ]; then
    echo "proxy cache smoke failed: slice If-Range match returned $slice_if_range_status instead of 206" >&2
    cat "$slice_if_range_headers" >&2
    exit 1
fi
if ! grep -qi '^x-cache-status: HIT' "$slice_if_range_headers"; then
    echo "proxy cache smoke failed: slice If-Range match was not served as a cache HIT" >&2
    cat "$slice_if_range_headers" >&2
    exit 1
fi
if ! grep -qi '^x-cache-reason: slice' "$slice_if_range_headers"; then
    echo "proxy cache smoke failed: slice If-Range match missed slice reason" >&2
    cat "$slice_if_range_headers" >&2
    exit 1
fi
if ! grep -qi '^content-range: bytes 8-15/62' "$slice_if_range_headers"; then
    echo "proxy cache smoke failed: slice If-Range match missed expected Content-Range" >&2
    cat "$slice_if_range_headers" >&2
    exit 1
fi
if [ "$(cat "$slice_body")" != "89abcdef" ]; then
    echo "proxy cache smoke failed: slice If-Range match body mismatch" >&2
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
if ! grep -qi '^x-cache-status: HIT' "$if_range_match_headers"; then
    echo "proxy cache smoke failed: cached If-Range match was not served as a cache HIT" >&2
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
if ! grep -qi '^x-cache-status: HIT' "$if_range_mismatch_headers"; then
    echo "proxy cache smoke failed: cached If-Range mismatch was not served as a cache HIT" >&2
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

if_range_date_match_status=$(
    curl -sS --max-time "$CURL_MAX_TIME" -D "$if_range_date_match_headers" -o "$if_range_date_match_body" -w '%{http_code}' \
        -H "Host: cache.test" \
        -H "Range: bytes=8-11" \
        -H "If-Range: Sun, 10 May 2026 00:00:00 GMT" \
        "http://127.0.0.1:$FLUXHEIM_PORT/asset.png"
)
if [ "$if_range_date_match_status" != "206" ]; then
    echo "proxy cache smoke failed: cached date If-Range match returned $if_range_date_match_status instead of 206" >&2
    cat "$if_range_date_match_headers" >&2
    exit 1
fi
if ! grep -qi '^x-cache-status: HIT' "$if_range_date_match_headers"; then
    echo "proxy cache smoke failed: cached date If-Range match was not served as a cache HIT" >&2
    cat "$if_range_date_match_headers" >&2
    exit 1
fi
if ! grep -qi '^content-range: bytes 8-11/16' "$if_range_date_match_headers"; then
    echo "proxy cache smoke failed: cached date If-Range match missed expected Content-Range" >&2
    cat "$if_range_date_match_headers" >&2
    exit 1
fi
if [ "$(cat "$if_range_date_match_body")" != "89ab" ]; then
    echo "proxy cache smoke failed: cached date If-Range match body mismatch" >&2
    exit 1
fi

if_range_date_mismatch_status=$(
    curl -sS --max-time "$CURL_MAX_TIME" -D "$if_range_date_mismatch_headers" -o "$if_range_date_mismatch_body" -w '%{http_code}' \
        -H "Host: cache.test" \
        -H "Range: bytes=8-11" \
        -H "If-Range: Sat, 09 May 2026 00:00:00 GMT" \
        "http://127.0.0.1:$FLUXHEIM_PORT/asset.png"
)
if [ "$if_range_date_mismatch_status" != "200" ]; then
    echo "proxy cache smoke failed: cached date If-Range mismatch returned $if_range_date_mismatch_status instead of 200" >&2
    cat "$if_range_date_mismatch_headers" >&2
    exit 1
fi
if ! grep -qi '^x-cache-status: HIT' "$if_range_date_mismatch_headers"; then
    echo "proxy cache smoke failed: cached date If-Range mismatch was not served as a cache HIT" >&2
    cat "$if_range_date_mismatch_headers" >&2
    exit 1
fi
if grep -qi '^content-range:' "$if_range_date_mismatch_headers"; then
    echo "proxy cache smoke failed: cached date If-Range mismatch unexpectedly included Content-Range" >&2
    cat "$if_range_date_mismatch_headers" >&2
    exit 1
fi
if [ "$(cat "$if_range_date_mismatch_body")" != "0123456789abcdef" ]; then
    echo "proxy cache smoke failed: cached date If-Range mismatch body was not the full object" >&2
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
if ! grep -qi "^last-modified: $LAST_MODIFIED" "$revalidate_third_headers"; then
    echo "proxy cache smoke failed: revalidated cache HIT did not preserve Last-Modified header" >&2
    cat "$revalidate_third_headers" >&2
    exit 1
fi

"$ROOT_DIR/target/debug/fluxheim" --config "$TMP_DIR/fluxheim.toml" cache-lookup \
    --host cache.test \
    --path /revalidate.png \
    --require-object \
    --expect-tier disk \
    --expect-cache-lock-wait-timeout-secs 30 \
    --expect-cache-predictor-enabled \
    --expect-namespace fluxheim-image-v1 \
    --expect-key-namespace cache-vhost-v1 \
    --expect-user-tag cache.test \
    --expect-status 200 \
    --expect-body-bytes 16 \
    --expect-fresh-ttl-secs 120 \
    --expect-header-name etag \
    --expect-header 'etag: "cache-smoke-revalidate"' \
    --expect-header-name last-modified \
    --expect-header "last-modified: $LAST_MODIFIED" \
    --expect-freshness-state fresh

curl -sS --max-time "$CURL_MAX_TIME" -D "$revalidate_lm_first_headers" -o "$revalidate_lm_body" \
    -H "Host: cache.test" \
    "http://127.0.0.1:$FLUXHEIM_PORT/revalidate-last-modified.png"
if ! grep -qi '^x-cache-status: MISS' "$revalidate_lm_first_headers"; then
    echo "proxy cache smoke failed: initial Last-Modified revalidation request was not a cache MISS" >&2
    cat "$revalidate_lm_first_headers" >&2
    exit 1
fi
if [ "$(cat "$revalidate_lm_body")" != "revalidated-lm-body" ]; then
    echo "proxy cache smoke failed: initial Last-Modified revalidation body mismatch" >&2
    exit 1
fi

sleep 1.2

curl -sS --max-time "$CURL_MAX_TIME" -D "$revalidate_lm_second_headers" -o "$revalidate_lm_body" \
    -H "Host: cache.test" \
    "http://127.0.0.1:$FLUXHEIM_PORT/revalidate-last-modified.png"
if ! grep -qi '^x-cache-status: REVALIDATED' "$revalidate_lm_second_headers"; then
    echo "proxy cache smoke failed: stale asset did not revalidate changed Last-Modified from upstream 304" >&2
    cat "$revalidate_lm_second_headers" >&2
    exit 1
fi
if [ "$(cat "$revalidate_lm_body")" != "revalidated-lm-body" ]; then
    echo "proxy cache smoke failed: revalidated Last-Modified asset body mismatch" >&2
    exit 1
fi

curl -sS --max-time "$CURL_MAX_TIME" -D "$revalidate_lm_third_headers" -o "$revalidate_lm_body" \
    -H "Host: cache.test" \
    "http://127.0.0.1:$FLUXHEIM_PORT/revalidate-last-modified.png"
if ! grep -qi '^x-cache-status: HIT' "$revalidate_lm_third_headers"; then
    echo "proxy cache smoke failed: changed Last-Modified revalidation did not leave asset fresh" >&2
    cat "$revalidate_lm_third_headers" >&2
    exit 1
fi
if ! grep -qi "^last-modified: $REVALIDATED_LAST_MODIFIED" "$revalidate_lm_third_headers"; then
    echo "proxy cache smoke failed: changed Last-Modified was not persisted after upstream 304" >&2
    cat "$revalidate_lm_third_headers" >&2
    exit 1
fi

"$ROOT_DIR/target/debug/fluxheim" --config "$TMP_DIR/fluxheim.toml" cache-lookup \
    --host cache.test \
    --path /revalidate-last-modified.png \
    --require-object \
    --expect-tier disk \
    --expect-cache-lock-wait-timeout-secs 30 \
    --expect-cache-predictor-enabled \
    --expect-namespace fluxheim-image-v1 \
    --expect-key-namespace cache-vhost-v1 \
    --expect-user-tag cache.test \
    --expect-status 200 \
    --expect-body-bytes 19 \
    --expect-fresh-ttl-secs 120 \
    --expect-header-name etag \
    --expect-header 'etag: "cache-smoke-revalidate-last-modified"' \
    --expect-header-name last-modified \
    --expect-header "last-modified: $REVALIDATED_LAST_MODIFIED" \
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
    --expect-header 'etag: "cache-smoke-refresh-new"' \
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
    --expect-cache-predictor-enabled \
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

wait_for_cache_lookup \
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
    --expect-cache-predictor-enabled \
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

printf 'cache.test /input-warm.png\n' > "$warm_input_file"
"$ROOT_DIR/target/debug/fluxheim" --config "$TMP_DIR/fluxheim.toml" cache-warm \
    --listen "127.0.0.1:$FLUXHEIM_PORT" \
    --input "$warm_input_file" \
    --dry-run

"$ROOT_DIR/target/debug/fluxheim" --config "$TMP_DIR/fluxheim.toml" cache-warm \
    --listen "127.0.0.1:$FLUXHEIM_PORT" \
    --input "$warm_input_file" \
    --repeat 2 \
    --expect-cache-status-sequence MISS,HIT

"$ROOT_DIR/target/debug/fluxheim" --config "$TMP_DIR/fluxheim.toml" cache-lookup \
    --host cache.test \
    --path /input-warm.png \
    --require-object \
    --expect-tier disk \
    --expect-status 200 \
    --expect-body-bytes 15 \
    --expect-cache-tag smoke:input-warm \
    --expect-header-name etag \
    --expect-purge-indexed \
    --expect-freshness-state fresh

curl -sS --max-time "$CURL_MAX_TIME" -D "$warm_input_headers" -o "$warm_input_body" \
    -H "Host: cache.test" \
    "http://127.0.0.1:$FLUXHEIM_PORT/input-warm.png"
if ! grep -qi '^x-cache-status: HIT' "$warm_input_headers"; then
    echo "proxy cache smoke failed: cache-warm input file did not preload target" >&2
    cat "$warm_input_headers" >&2
    exit 1
fi
if [ "$(cat "$warm_input_body")" != "input-warm-body" ]; then
    echo "proxy cache smoke failed: cache-warm input body mismatch" >&2
    exit 1
fi

"$ROOT_DIR/target/debug/fluxheim" --config "$TMP_DIR/fluxheim.toml" cache-warm \
    --listen "127.0.0.1:$FLUXHEIM_PORT" \
    --host cache.test \
    --path /missing.png \
    --allow-status 404 \
    --repeat 2 \
    --expect-cache-status-sequence MISS,HIT

"$ROOT_DIR/target/debug/fluxheim" --config "$TMP_DIR/fluxheim.toml" cache-lookup \
    --host cache.test \
    --path /missing.png \
    --require-object \
    --expect-tier disk \
    --expect-status 404 \
    --expect-body-bytes 0 \
    --expect-fresh-ttl-secs 60 \
    --expect-header-name content-type \
    --expect-purge-indexed \
    --expect-freshness-state fresh

warm_missing_status=$(
    curl -sS --max-time "$CURL_MAX_TIME" -D "$warm_missing_headers" -o "$warm_missing_body" -w '%{http_code}' \
        -H "Host: cache.test" \
        "http://127.0.0.1:$FLUXHEIM_PORT/missing.png"
)
if [ "$warm_missing_status" != "404" ]; then
    echo "proxy cache smoke failed: warmed negative-cache request returned $warm_missing_status instead of 404" >&2
    cat "$warm_missing_headers" >&2
    exit 1
fi
if ! grep -qi '^x-cache-status: HIT' "$warm_missing_headers"; then
    echo "proxy cache smoke failed: cache-warm did not preload configured 404 TTL" >&2
    cat "$warm_missing_headers" >&2
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

curl -sS --max-time "$CURL_MAX_TIME" -o "$metrics_body" \
    "http://127.0.0.1:$METRICS_PORT/metrics"
if ! grep -Eq 'fluxheim_cache_activity_total\{event="stale",tier="policy"\} [1-9][0-9]*' "$metrics_body"; then
    echo "proxy cache smoke failed: metrics missed policy stale activity counter" >&2
    grep 'fluxheim_cache_activity' "$metrics_body" >&2 || true
    exit 1
fi
if ! grep -Eq 'fluxheim_cache_activity_scope_total\{event="stale",route="",scope="vhost",tier="policy",vhost="cache\.test"\} [1-9][0-9]*' "$metrics_body"; then
    echo "proxy cache smoke failed: metrics missed scoped policy stale activity counter" >&2
    grep 'fluxheim_cache_activity_scope_total' "$metrics_body" >&2 || true
    exit 1
fi

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

if ! curl -sS --max-time "$CURL_MAX_TIME" -X POST -o "$admin_stale_dry_run_body" \
    -H "Authorization: Bearer secret-token" \
    "http://127.0.0.1:$ADMIN_PORT/_fluxheim/cache/purge-stale?vhost=cache.test&limit=16&dry_run=true"; then
    echo "proxy cache smoke failed: admin stale dry-run purge request failed" >&2
    cat "$admin_stale_dry_run_body" >&2 || true
    exit 1
fi
if ! grep -q '"dry_run":true' "$admin_stale_dry_run_body"; then
    echo "proxy cache smoke failed: admin stale dry-run purge did not report dry_run=true" >&2
    cat "$admin_stale_dry_run_body" >&2
    exit 1
fi
if ! grep -Eq '"would_purge":[1-9][0-9]*' "$admin_stale_dry_run_body"; then
    echo "proxy cache smoke failed: admin stale dry-run purge did not count stale object" >&2
    cat "$admin_stale_dry_run_body" >&2
    exit 1
fi
if ! grep -q '"purged":0' "$admin_stale_dry_run_body"; then
    echo "proxy cache smoke failed: admin stale dry-run purge removed objects" >&2
    cat "$admin_stale_dry_run_body" >&2
    exit 1
fi

if ! curl -sS --max-time "$CURL_MAX_TIME" -X POST -o "$admin_prefix_purge_body" \
    -H "Authorization: Bearer secret-token" \
    "http://127.0.0.1:$ADMIN_PORT/_fluxheim/cache/purge-prefix?vhost=cache.test&path_prefix=/warm-&limit=16"; then
    echo "proxy cache smoke failed: admin prefix purge request failed" >&2
    cat "$admin_prefix_purge_body" >&2 || true
    exit 1
fi
if ! grep -q '"status":"ok"' "$admin_prefix_purge_body"; then
    echo "proxy cache smoke failed: admin prefix purge did not return ok" >&2
    cat "$admin_prefix_purge_body" >&2
    exit 1
fi
if ! grep -q '"path_prefix":"/warm-"' "$admin_prefix_purge_body"; then
    echo "proxy cache smoke failed: admin prefix purge did not echo bounded prefix" >&2
    cat "$admin_prefix_purge_body" >&2
    exit 1
fi
if ! grep -Eq '"purged":[1-9][0-9]*' "$admin_prefix_purge_body"; then
    echo "proxy cache smoke failed: admin prefix purge did not remove warmed Vary object" >&2
    cat "$admin_prefix_purge_body" >&2
    exit 1
fi

"$ROOT_DIR/target/debug/fluxheim" --config "$TMP_DIR/fluxheim.toml" cache-lookup \
    --host cache.test \
    --header "Accept-Language: de" \
    --path /warm-vary.png \
    --expect-objects 0

post_prefix_purge_status=$(
    curl -sS --max-time "$CURL_MAX_TIME" -D "$post_prefix_purge_headers" -o "$body" -w '%{http_code}' \
        -H "Host: cache.test" \
        -H "Accept-Language: de" \
        "http://127.0.0.1:$FLUXHEIM_PORT/warm-vary.png" 2>/dev/null || true
)
if grep -qi '^x-cache-status: HIT' "$post_prefix_purge_headers"; then
    echo "proxy cache smoke failed: admin prefix purge left native memory cache HIT behind" >&2
    cat "$post_prefix_purge_headers" >&2
    exit 1
fi
if [ "$post_prefix_purge_status" = "200" ]; then
    echo "proxy cache smoke failed: admin prefix purge served warmed object while origin was stopped" >&2
    cat "$post_prefix_purge_headers" >&2
    exit 1
fi

if ! curl -sS --max-time "$CURL_MAX_TIME" -X POST -o "$admin_tag_purge_body" \
    -H "Authorization: Bearer secret-token" \
    "http://127.0.0.1:$ADMIN_PORT/_fluxheim/cache/purge-tag?vhost=cache.test&cache_tag=smoke:input-warm&limit=16"; then
    echo "proxy cache smoke failed: admin tag purge request failed" >&2
    cat "$admin_tag_purge_body" >&2 || true
    exit 1
fi
if ! grep -q '"status":"ok"' "$admin_tag_purge_body"; then
    echo "proxy cache smoke failed: admin tag purge did not return ok" >&2
    cat "$admin_tag_purge_body" >&2
    exit 1
fi
if ! grep -q '"cache_tag":"smoke:input-warm"' "$admin_tag_purge_body"; then
    echo "proxy cache smoke failed: admin tag purge did not echo bounded cache tag" >&2
    cat "$admin_tag_purge_body" >&2
    exit 1
fi
if ! grep -Eq '"purged":[1-9][0-9]*' "$admin_tag_purge_body"; then
    echo "proxy cache smoke failed: admin tag purge did not remove warmed object" >&2
    cat "$admin_tag_purge_body" >&2
    exit 1
fi

"$ROOT_DIR/target/debug/fluxheim" --config "$TMP_DIR/fluxheim.toml" cache-lookup \
    --host cache.test \
    --path /input-warm.png \
    --expect-objects 0

post_tag_purge_status=$(
    curl -sS --max-time "$CURL_MAX_TIME" -D "$post_tag_purge_headers" -o "$body" -w '%{http_code}' \
        -H "Host: cache.test" \
        "http://127.0.0.1:$FLUXHEIM_PORT/input-warm.png" 2>/dev/null || true
)
if grep -qi '^x-cache-status: HIT' "$post_tag_purge_headers"; then
    echo "proxy cache smoke failed: admin tag purge left native memory cache HIT behind" >&2
    cat "$post_tag_purge_headers" >&2
    exit 1
fi
if [ "$post_tag_purge_status" = "200" ]; then
    echo "proxy cache smoke failed: admin tag purge served tagged object while origin was stopped" >&2
    cat "$post_tag_purge_headers" >&2
    exit 1
fi

if ! curl -sS --max-time "$CURL_MAX_TIME" -X POST -o "$admin_wildcard_purge_body" \
    -H "Authorization: Bearer secret-token" \
    "http://127.0.0.1:$ADMIN_PORT/_fluxheim/cache/purge-wildcard?vhost=cache.test&pattern=/missing*.png&limit=16"; then
    echo "proxy cache smoke failed: admin wildcard purge request failed" >&2
    cat "$admin_wildcard_purge_body" >&2 || true
    exit 1
fi
if ! grep -q '"status":"ok"' "$admin_wildcard_purge_body"; then
    echo "proxy cache smoke failed: admin wildcard purge did not return ok" >&2
    cat "$admin_wildcard_purge_body" >&2
    exit 1
fi
if ! grep -q '"path_pattern":"/missing\*.png"' "$admin_wildcard_purge_body"; then
    echo "proxy cache smoke failed: admin wildcard purge did not echo bounded pattern" >&2
    cat "$admin_wildcard_purge_body" >&2
    exit 1
fi
if ! grep -Eq '"purged":[1-9][0-9]*' "$admin_wildcard_purge_body"; then
    echo "proxy cache smoke failed: admin wildcard purge did not remove warmed 404 object" >&2
    cat "$admin_wildcard_purge_body" >&2
    exit 1
fi

"$ROOT_DIR/target/debug/fluxheim" --config "$TMP_DIR/fluxheim.toml" cache-lookup \
    --host cache.test \
    --path /missing.png \
    --expect-objects 0

post_wildcard_purge_status=$(
    curl -sS --max-time "$CURL_MAX_TIME" -D "$post_wildcard_purge_headers" -o "$body" -w '%{http_code}' \
        -H "Host: cache.test" \
        "http://127.0.0.1:$FLUXHEIM_PORT/missing.png" 2>/dev/null || true
)
if grep -qi '^x-cache-status: HIT' "$post_wildcard_purge_headers"; then
    echo "proxy cache smoke failed: admin wildcard purge left native memory cache HIT behind" >&2
    cat "$post_wildcard_purge_headers" >&2
    exit 1
fi
if [ "$post_wildcard_purge_status" = "404" ]; then
    echo "proxy cache smoke failed: admin wildcard purge served cached missing object while origin was stopped" >&2
    cat "$post_wildcard_purge_headers" >&2
    exit 1
fi

if ! curl -sS --max-time "$CURL_MAX_TIME" -X POST -o "$admin_bulk_purge_body" \
    -H "Authorization: Bearer secret-token" \
    "http://127.0.0.1:$ADMIN_PORT/_fluxheim/cache/purge-bulk?host=cache.test&method=GET&path=/revalidate.png&path=/refresh.png"; then
    echo "proxy cache smoke failed: admin bulk purge request failed" >&2
    cat "$admin_bulk_purge_body" >&2 || true
    exit 1
fi
if ! grep -q '"status":"ok"' "$admin_bulk_purge_body"; then
    echo "proxy cache smoke failed: admin bulk purge did not return ok" >&2
    cat "$admin_bulk_purge_body" >&2
    exit 1
fi
if ! grep -q '"requested":2' "$admin_bulk_purge_body"; then
    echo "proxy cache smoke failed: admin bulk purge did not report two requested paths" >&2
    cat "$admin_bulk_purge_body" >&2
    exit 1
fi
if ! grep -Eq '"purged":([2-9]|[1-9][0-9]+)' "$admin_bulk_purge_body"; then
    echo "proxy cache smoke failed: admin bulk purge did not remove both objects" >&2
    cat "$admin_bulk_purge_body" >&2
    exit 1
fi

"$ROOT_DIR/target/debug/fluxheim" --config "$TMP_DIR/fluxheim.toml" cache-lookup \
    --host cache.test \
    --path /revalidate.png \
    --expect-objects 0
"$ROOT_DIR/target/debug/fluxheim" --config "$TMP_DIR/fluxheim.toml" cache-lookup \
    --host cache.test \
    --path /refresh.png \
    --expect-objects 0

if ! curl -sS --max-time "$CURL_MAX_TIME" -X POST -o "$admin_exact_purge_body" \
    -H "Authorization: Bearer secret-token" \
    "http://127.0.0.1:$ADMIN_PORT/_fluxheim/cache/purge?host=cache.test&method=GET&path=/asset.png"; then
    echo "proxy cache smoke failed: admin exact purge request failed" >&2
    cat "$admin_exact_purge_body" >&2 || true
    exit 1
fi
if ! grep -q '"status":"ok"' "$admin_exact_purge_body"; then
    echo "proxy cache smoke failed: admin exact purge did not return ok" >&2
    cat "$admin_exact_purge_body" >&2
    exit 1
fi
if ! grep -q '"path":"/asset.png"' "$admin_exact_purge_body"; then
    echo "proxy cache smoke failed: admin exact purge did not echo requested path" >&2
    cat "$admin_exact_purge_body" >&2
    exit 1
fi
if ! grep -q '"purged":true' "$admin_exact_purge_body"; then
    echo "proxy cache smoke failed: admin exact purge did not remove asset object" >&2
    cat "$admin_exact_purge_body" >&2
    exit 1
fi

"$ROOT_DIR/target/debug/fluxheim" --config "$TMP_DIR/fluxheim.toml" cache-lookup \
    --host cache.test \
    --path /asset.png \
    --expect-objects 0

post_exact_purge_status=$(
    curl -sS --max-time "$CURL_MAX_TIME" -D "$post_exact_purge_headers" -o "$body" -w '%{http_code}' \
        -H "Host: cache.test" \
        "http://127.0.0.1:$FLUXHEIM_PORT/asset.png" 2>/dev/null || true
)
if grep -qi '^x-cache-status: HIT' "$post_exact_purge_headers"; then
    echo "proxy cache smoke failed: admin exact purge left native memory cache HIT behind" >&2
    cat "$post_exact_purge_headers" >&2
    exit 1
fi
if [ "$post_exact_purge_status" = "200" ]; then
    echo "proxy cache smoke failed: admin exact purge served asset while origin was stopped" >&2
    cat "$post_exact_purge_headers" >&2
    exit 1
fi

if ! curl -sS --max-time "$CURL_MAX_TIME" -X POST -o "$admin_route_purge_body" \
    -H "Authorization: Bearer secret-token" \
    "http://127.0.0.1:$ADMIN_PORT/_fluxheim/cache/purge-index?vhost=cache.test&route=swr&limit=16"; then
    echo "proxy cache smoke failed: admin route purge request failed" >&2
    cat "$admin_route_purge_body" >&2 || true
    exit 1
fi
if ! grep -q '"status":"ok"' "$admin_route_purge_body"; then
    echo "proxy cache smoke failed: admin route purge did not return ok" >&2
    cat "$admin_route_purge_body" >&2
    exit 1
fi
if ! grep -q '"route":"swr"' "$admin_route_purge_body"; then
    echo "proxy cache smoke failed: admin route purge did not echo route scope" >&2
    cat "$admin_route_purge_body" >&2
    exit 1
fi
if ! grep -q '"scope":"route"' "$admin_route_purge_body"; then
    echo "proxy cache smoke failed: admin route purge did not report route scope" >&2
    cat "$admin_route_purge_body" >&2
    exit 1
fi
if ! grep -Eq '"purged":[1-9][0-9]*' "$admin_route_purge_body"; then
    echo "proxy cache smoke failed: admin route purge did not remove route object" >&2
    cat "$admin_route_purge_body" >&2
    exit 1
fi

"$ROOT_DIR/target/debug/fluxheim" --config "$TMP_DIR/fluxheim.toml" cache-lookup \
    --host cache.test \
    --path /swr.png \
    --expect-scope route \
    --expect-vhost cache.test \
    --expect-route swr \
    --expect-objects 0

post_route_purge_status=$(
    curl -sS --max-time "$CURL_MAX_TIME" -D "$post_route_purge_headers" -o "$body" -w '%{http_code}' \
        -H "Host: cache.test" \
        "http://127.0.0.1:$FLUXHEIM_PORT/swr.png" 2>/dev/null || true
)
if grep -Eiq '^x-cache-status: (HIT|STALE)' "$post_route_purge_headers"; then
    echo "proxy cache smoke failed: admin route purge left native memory route cache behind" >&2
    cat "$post_route_purge_headers" >&2
    exit 1
fi
if [ "$post_route_purge_status" = "200" ]; then
    echo "proxy cache smoke failed: admin route purge served route object while origin was stopped" >&2
    cat "$post_route_purge_headers" >&2
    exit 1
fi

curl -sS --max-time "$CURL_MAX_TIME" -o "$metrics_body" \
    "http://127.0.0.1:$METRICS_PORT/metrics"
if ! grep -Eq 'fluxheim_cache_purges_total\{mode="normal",operation="exact",route="",scope="vhost",vhost="cache\.test"\} 1' "$metrics_body"; then
    echo "proxy cache smoke failed: metrics missed exact purge counter" >&2
    grep 'fluxheim_cache_purges_total' "$metrics_body" >&2 || true
    exit 1
fi
if ! grep -Eq 'fluxheim_cache_purges_total\{mode="normal",operation="bulk",route="",scope="vhost",vhost="cache\.test"\} 1' "$metrics_body"; then
    echo "proxy cache smoke failed: metrics missed bulk purge counter" >&2
    grep 'fluxheim_cache_purges_total' "$metrics_body" >&2 || true
    exit 1
fi
if ! grep -Eq 'fluxheim_cache_purges_total\{mode="dry_run",operation="stale",route="",scope="vhost",vhost="cache\.test"\} 1' "$metrics_body"; then
    echo "proxy cache smoke failed: metrics missed stale dry-run purge counter" >&2
    grep 'fluxheim_cache_purges_total' "$metrics_body" >&2 || true
    exit 1
fi
if ! grep -Eq 'fluxheim_cache_purges_total\{mode="normal",operation="prefix",route="",scope="vhost",vhost="cache\.test"\} 1' "$metrics_body"; then
    echo "proxy cache smoke failed: metrics missed prefix purge counter" >&2
    grep 'fluxheim_cache_purges_total' "$metrics_body" >&2 || true
    exit 1
fi
if ! grep -Eq 'fluxheim_cache_purges_total\{mode="normal",operation="tag",route="",scope="vhost",vhost="cache\.test"\} 1' "$metrics_body"; then
    echo "proxy cache smoke failed: metrics missed tag purge counter" >&2
    grep 'fluxheim_cache_purges_total' "$metrics_body" >&2 || true
    exit 1
fi
if ! grep -Eq 'fluxheim_cache_purges_total\{mode="normal",operation="wildcard",route="",scope="vhost",vhost="cache\.test"\} 1' "$metrics_body"; then
    echo "proxy cache smoke failed: metrics missed wildcard purge counter" >&2
    grep 'fluxheim_cache_purges_total' "$metrics_body" >&2 || true
    exit 1
fi
if ! grep -Eq 'fluxheim_cache_purges_total\{mode="normal",operation="index",route="swr",scope="route",vhost="cache\.test"\} 1' "$metrics_body"; then
    echo "proxy cache smoke failed: metrics missed route index purge counter" >&2
    grep 'fluxheim_cache_purges_total' "$metrics_body" >&2 || true
    exit 1
fi
if ! grep -Eq 'fluxheim_cache_activity_total\{event="hit",tier="disk"\} [1-9][0-9]*' "$metrics_body"; then
    echo "proxy cache smoke failed: metrics missed disk hit activity counter" >&2
    grep 'fluxheim_cache_activity' "$metrics_body" >&2 || true
    exit 1
fi
if ! grep -Eq 'fluxheim_cache_activity_total\{event="purge",tier="disk"\} [1-9][0-9]*' "$metrics_body"; then
    echo "proxy cache smoke failed: metrics missed disk purge activity counter" >&2
    grep 'fluxheim_cache_activity' "$metrics_body" >&2 || true
    exit 1
fi
if ! grep -Eq 'fluxheim_cache_activity_scope_total\{event="hit",route="",scope="vhost",tier="disk",vhost="cache\.test"\} [1-9][0-9]*' "$metrics_body"; then
    echo "proxy cache smoke failed: metrics missed scoped vhost disk hit activity counter" >&2
    grep 'fluxheim_cache_activity_scope_total' "$metrics_body" >&2 || true
    exit 1
fi
if ! grep -Eq 'fluxheim_cache_activity_scope_total\{event="purge",route="swr",scope="route",tier="disk",vhost="cache\.test"\} [1-9][0-9]*' "$metrics_body"; then
    echo "proxy cache smoke failed: metrics missed scoped route disk purge activity counter" >&2
    grep 'fluxheim_cache_activity_scope_total' "$metrics_body" >&2 || true
    exit 1
fi

echo "proxy cache smoke: ok"
