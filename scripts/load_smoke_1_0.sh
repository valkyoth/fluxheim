#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/fluxheim-1-0-load-smoke.XXXXXX")
KEEP_LOGS=${FLUXHEIM_LOAD_KEEP_LOGS:-0}
BUILD_RELEASE=${FLUXHEIM_LOAD_BUILD:-1}
DURATION=${FLUXHEIM_LOAD_DURATION:-15s}
CONCURRENCY=${FLUXHEIM_LOAD_CONCURRENCY:-64}
TIMEOUT=${FLUXHEIM_LOAD_TIMEOUT:-5}

if ! command -v hey >/dev/null 2>&1; then
    echo "1.0 load smoke requires hey" >&2
    exit 1
fi

FLUXHEIM_PID=

cleanup() {
    status=$?

    if [ -n "$FLUXHEIM_PID" ]; then
        kill "$FLUXHEIM_PID" 2>/dev/null || true
        sleep 0.2
        if kill -0 "$FLUXHEIM_PID" 2>/dev/null; then
            kill -9 "$FLUXHEIM_PID" 2>/dev/null || true
        fi
        wait "$FLUXHEIM_PID" 2>/dev/null || true
    fi

    if [ "$KEEP_LOGS" = "1" ] || [ "$status" -ne 0 ]; then
        echo "1.0 load smoke artifacts kept in $TMP_DIR" >&2
    else
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT INT TERM

FLUXHEIM_PORT=$(python3 - <<'PY'
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
finally:
    sock.close()
PY
)

mkdir -p "$TMP_DIR/public"
mkdir -p "$TMP_DIR/run"
printf '%s\n' '<!doctype html><title>Fluxheim load smoke</title><h1>load-ok</h1>' > "$TMP_DIR/public/index.html"

cat > "$TMP_DIR/fluxheim.toml" <<EOF
[server]
listen = ["127.0.0.1:$FLUXHEIM_PORT"]
default_vhost = "static.test"
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

[headers.response]
enabled = true
x_content_type_options = "nosniff"
x_frame_options = "DENY"
referrer_policy = "no-referrer"
unset = ["server", "x-powered-by"]

[headers.response.set]
cache-control = "public, max-age=60"

[proxy]
upstreams = ["127.0.0.1:9"]
upstream_tls = false

[tls]
enabled = false
backend = "rustls"

[cache]
enabled = false

[web]
root = "$TMP_DIR/public"
index_files = ["index.html"]
deny_dotfiles = true
cache_control = "public, max-age=60"

[[vhosts]]
name = "static.test"
hosts = ["static.test"]

[vhosts.web]
root = "$TMP_DIR/public"
index_files = ["index.html"]
deny_dotfiles = true
cache_control = "public, max-age=60"
EOF

if [ "$BUILD_RELEASE" = "1" ]; then
    cargo build --quiet --release
fi

"$ROOT_DIR/target/release/fluxheim" --config "$TMP_DIR/fluxheim.toml" &
FLUXHEIM_PID=$!

status=""
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    status="$(curl -sS -o "$TMP_DIR/body.txt" -w '%{http_code}' -H "Host: static.test" "http://127.0.0.1:$FLUXHEIM_PORT/" 2>/dev/null || true)"
    if [ "$status" = "200" ]; then
        break
    fi
    sleep 0.2
done

if [ "$status" != "200" ]; then
    echo "1.0 load smoke failed: expected HTTP 200 before load, got ${status:-no response}" >&2
    exit 1
fi

hey \
    -z "$DURATION" \
    -c "$CONCURRENCY" \
    -t "$TIMEOUT" \
    -host static.test \
    "http://127.0.0.1:$FLUXHEIM_PORT/" > "$TMP_DIR/hey.txt"

if ! grep -q "Status code distribution:" "$TMP_DIR/hey.txt"; then
    echo "1.0 load smoke failed: hey output did not include status distribution" >&2
    cat "$TMP_DIR/hey.txt" >&2
    exit 1
fi

awk '
    /Status code distribution:/ { in_status = 1; next }
    in_status && /^[[:space:]]*\[[0-9][0-9][0-9]\]/ { print }
' "$TMP_DIR/hey.txt" > "$TMP_DIR/status-codes.txt"

if ! grep -q "\\[200\\]" "$TMP_DIR/status-codes.txt"; then
    echo "1.0 load smoke failed: hey did not record HTTP 200 responses" >&2
    cat "$TMP_DIR/hey.txt" >&2
    exit 1
fi

if grep -Eq "\\[[345][0-9][0-9]\\]" "$TMP_DIR/status-codes.txt"; then
    echo "1.0 load smoke failed: hey recorded non-2xx/redirect responses" >&2
    cat "$TMP_DIR/hey.txt" >&2
    exit 1
fi

status="$(curl -sS -o "$TMP_DIR/body-after.txt" -w '%{http_code}' -H "Host: static.test" "http://127.0.0.1:$FLUXHEIM_PORT/")"
if [ "$status" != "200" ]; then
    echo "1.0 load smoke failed: expected HTTP 200 after load, got $status" >&2
    exit 1
fi

echo "1.0 load smoke: ok"
