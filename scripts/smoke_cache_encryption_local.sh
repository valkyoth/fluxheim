#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/fluxheim-cache-encryption-local-smoke.XXXXXX")
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
        echo "local cache encryption smoke artifacts kept in $TMP_DIR" >&2
    else
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT INT TERM

if [ ! -x "$ROOT_DIR/target/debug/fluxheim" ]; then
    echo "target/debug/fluxheim is missing; run 'cargo build' first" >&2
    exit 1
fi

mkdir -p "$TMP_DIR/cache" "$TMP_DIR/run" "$TMP_DIR/secrets"
chmod 0700 "$TMP_DIR/secrets"
printf '%s\n' "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" \
    > "$TMP_DIR/secrets/fluxheim-cache-key"
chmod 0600 "$TMP_DIR/secrets/fluxheim-cache-key"

cat > "$TMP_DIR/origin.py" <<'PY'
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BODY = b"local-encrypted-cache-body"
COUNT = 0
COUNT_LOCK = threading.Lock()


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self):
        global COUNT
        if self.path == "/__count":
            with COUNT_LOCK:
                body = str(COUNT).encode("ascii")
            self.send_response(200)
            self.send_header("content-type", "text/plain")
            self.send_header("content-length", str(len(body)))
            self.send_header("cache-control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return

        if self.path != "/asset.webp":
            self.send_response(404)
            self.send_header("content-length", "0")
            self.end_headers()
            return

        with COUNT_LOCK:
            COUNT += 1
        self.send_response(200)
        self.send_header("content-type", "image/webp")
        self.send_header("content-length", str(len(BODY)))
        self.send_header("cache-control", "public, max-age=120")
        self.send_header("etag", '"local-encrypted-cache-smoke"')
        self.end_headers()
        self.wfile.write(BODY)

    def log_message(self, *_args):
        pass


server = ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), Handler)
server.serve_forever()
PY

cat > "$TMP_DIR/fluxheim.toml" <<EOF_CONFIG
[server]
listen = ["127.0.0.1:${FLUXHEIM_PORT}"]

[server.process]
pid_file = "${TMP_DIR}/run/fluxheim.pid"
upgrade_sock = "${TMP_DIR}/run/fluxheim-upgrade.sock"
threads = 1

[logging]
level = "warn"
format = "text"
target = "stderr"

[proxy]
upstreams = ["127.0.0.1:${ORIGIN_PORT}"]

[cache]
enabled = true
status_header = "x-cache-status"
content_types = ["image/webp"]
extensions = ["webp"]
max_object_bytes = "256KiB"

[cache.memory]
enabled = false

[cache.disk]
enabled = true
backend = "storage-bin"
path = "${TMP_DIR}/cache"
max_size_bytes = "8MiB"

[cache.disk.storage_bin]
bin_size_bytes = "1MiB"
preallocate = false
max_open_bins = 4

[cache.disk.encryption]
enabled = true
provider = "local"
algorithm = "aes-256-gcm"
key_id = "local-smoke-v1"
key_credential = "fluxheim-cache-key"
EOF_CONFIG

python3 "$TMP_DIR/origin.py" "$ORIGIN_PORT" >"$TMP_DIR/origin.log" 2>&1 &
ORIGIN_PID=$!

i=0
until curl -sSf --max-time "$CURL_MAX_TIME" "http://127.0.0.1:${ORIGIN_PORT}/__count" >/dev/null 2>&1; do
    i=$((i + 1))
    if [ "$i" -gt 50 ]; then
        echo "timed out waiting for origin" >&2
        exit 1
    fi
    sleep 0.1
done

CREDENTIALS_DIRECTORY="$TMP_DIR/secrets" \
    "$ROOT_DIR/target/debug/fluxheim" --config "$TMP_DIR/fluxheim.toml" --validate-config

CREDENTIALS_DIRECTORY="$TMP_DIR/secrets" \
    "$ROOT_DIR/target/debug/fluxheim" --config "$TMP_DIR/fluxheim.toml" >"$TMP_DIR/fluxheim.log" 2>&1 &
FLUXHEIM_PID=$!

i=0
until python3 - "$FLUXHEIM_PORT" <<'PY'
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
        echo "timed out waiting for fluxheim" >&2
        exit 1
    fi
    sleep 0.1
done

first_headers=$(mktemp "$TMP_DIR/first-headers.XXXXXX")
second_headers=$(mktemp "$TMP_DIR/second-headers.XXXXXX")
first_body=$(mktemp "$TMP_DIR/first-body.XXXXXX")
second_body=$(mktemp "$TMP_DIR/second-body.XXXXXX")

curl -sS --max-time "$CURL_MAX_TIME" -D "$first_headers" -o "$first_body" \
    "http://127.0.0.1:${FLUXHEIM_PORT}/asset.webp"
curl -sS --max-time "$CURL_MAX_TIME" -D "$second_headers" -o "$second_body" \
    "http://127.0.0.1:${FLUXHEIM_PORT}/asset.webp"

cmp "$first_body" "$second_body" >/dev/null
grep -qi '^x-cache-status: MISS' "$first_headers"
grep -qi '^x-cache-status: HIT' "$second_headers"

count=$(curl -sSf --max-time "$CURL_MAX_TIME" "http://127.0.0.1:${ORIGIN_PORT}/__count")
if [ "$count" != "1" ]; then
    echo "local cache encryption smoke failed: expected one origin fetch, got $count" >&2
    exit 1
fi

bin_file=$(find "$TMP_DIR/cache/bins" -type f -name '*.fhbin' | head -n 1)
if [ -z "$bin_file" ]; then
    echo "local cache encryption smoke failed: no storage-bin file found" >&2
    exit 1
fi

grep -aq 'FLUXHEIM-CACHE-ENC-v1' "$bin_file"
if grep -aq 'local-encrypted-cache-body' "$bin_file"; then
    echo "local cache encryption smoke failed: storage-bin file contains plaintext body" >&2
    exit 1
fi

echo "local cache encryption smoke passed"
