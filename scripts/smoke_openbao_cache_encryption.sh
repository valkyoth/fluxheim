#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP_ROOT="$ROOT_DIR/target/fluxheim-openbao-smoke"
mkdir -p "$TMP_ROOT"
TMP_DIR=$(mktemp -d "$TMP_ROOT/run.XXXXXX")
KEEP_LOGS=${FLUXHEIM_SMOKE_KEEP_LOGS:-0}
KEEP_OPENBAO=${FLUXHEIM_SMOKE_KEEP_OPENBAO:-0}
CURL_MAX_TIME=${FLUXHEIM_SMOKE_CURL_MAX_TIME:-5}
OPENBAO_IMAGE=${FLUXHEIM_OPENBAO_IMAGE:-quay.io/openbao/openbao:2.6}
OPENBAO_TOKEN=${FLUXHEIM_OPENBAO_DEV_TOKEN:-fluxheim-dev-token}
OPENBAO_KEY=${FLUXHEIM_OPENBAO_TRANSIT_KEY:-fluxheim-cache}
OPENBAO_NAME="fluxheim-openbao-smoke-$$"

ports=$(python3 - <<'PY'
import socket

sockets = []
try:
    for _ in range(3):
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
OPENBAO_PORT=$3

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

    if [ "$KEEP_OPENBAO" != "1" ]; then
        podman rm -f "$OPENBAO_NAME" >/dev/null 2>&1 || true
    fi

    if [ "$KEEP_LOGS" = "1" ] || [ "$status" -ne 0 ]; then
        echo "OpenBao cache encryption smoke artifacts kept in $TMP_DIR" >&2
        if [ "$KEEP_OPENBAO" = "1" ]; then
            echo "OpenBao smoke container kept as $OPENBAO_NAME" >&2
        fi
    else
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT INT TERM

if [ -n "${FLUXHEIM_BIN:-}" ]; then
    fluxheim_bin="$FLUXHEIM_BIN"
else
    "$ROOT_DIR/scripts/validate-features.sh" profile-cache-server
    (
        cd "$ROOT_DIR"
        cargo build --quiet --no-default-features --features profile-cache-server
    )
    fluxheim_bin="$ROOT_DIR/${CARGO_TARGET_DIR:-target}/debug/fluxheim"
fi

mkdir -p "$TMP_DIR/cache" "$TMP_DIR/run" "$TMP_DIR/secrets"
chmod 0700 "$TMP_DIR/secrets"
printf '%s\n' "$OPENBAO_TOKEN" > "$TMP_DIR/secrets/openbao-token"
chmod 0600 "$TMP_DIR/secrets/openbao-token"

podman run -d \
    --name "$OPENBAO_NAME" \
    --security-opt no-new-privileges \
    -p "127.0.0.1:${OPENBAO_PORT}:8200" \
    -e "BAO_DEV_ROOT_TOKEN_ID=${OPENBAO_TOKEN}" \
    -e "BAO_DEV_LISTEN_ADDRESS=0.0.0.0:8200" \
    "$OPENBAO_IMAGE" \
    server -dev >"$TMP_DIR/openbao.container"

i=0
until podman exec "$OPENBAO_NAME" bao status -address=http://127.0.0.1:8200 >/dev/null 2>&1; do
    i=$((i + 1))
    if [ "$i" -gt 80 ]; then
        echo "timed out waiting for OpenBao" >&2
        podman logs "$OPENBAO_NAME" >&2 || true
        exit 1
    fi
    sleep 0.25
done

podman exec \
    -e BAO_ADDR=http://127.0.0.1:8200 \
    -e "BAO_TOKEN=${OPENBAO_TOKEN}" \
    "$OPENBAO_NAME" \
    bao secrets enable transit >/dev/null
podman exec \
    -e BAO_ADDR=http://127.0.0.1:8200 \
    -e "BAO_TOKEN=${OPENBAO_TOKEN}" \
    "$OPENBAO_NAME" \
    bao write -f "transit/keys/${OPENBAO_KEY}" >/dev/null

cat > "$TMP_DIR/origin.py" <<'PY'
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BODY = b"openbao-secret-cache-body"
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
        self.send_header("etag", '"openbao-cache-smoke"')
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
certificate_reload_sock = "${TMP_DIR}/run/fluxheim-cert-reload.sock"
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
backend = "filesystem"
path = "${TMP_DIR}/cache"
max_size_bytes = "8MiB"

[cache.disk.encryption]
enabled = true
provider = "openbao-transit"
key_id = "openbao-dev-v1"

[cache.disk.encryption.openbao]
address = "http://127.0.0.1:${OPENBAO_PORT}"
mount = "transit"
key_name = "${OPENBAO_KEY}"
token_credential = "openbao-token"
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
    "$fluxheim_bin" --config "$TMP_DIR/fluxheim.toml" --validate-config

CREDENTIALS_DIRECTORY="$TMP_DIR/secrets" \
    "$fluxheim_bin" --config "$TMP_DIR/fluxheim.toml" >"$TMP_DIR/fluxheim.log" 2>&1 &
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
    echo "OpenBao cache encryption smoke failed: expected one origin fetch, got $count" >&2
    exit 1
fi

object_file=$(find "$TMP_DIR/cache" -type f -name '*.fhc' | head -n 1)
if [ -z "$object_file" ]; then
    echo "OpenBao cache encryption smoke failed: no filesystem cache object found" >&2
    exit 1
fi

grep -aq 'vault:v' "$object_file"
if grep -aq 'openbao-secret-cache-body' "$object_file"; then
    echo "OpenBao cache encryption smoke failed: cache object contains plaintext body" >&2
    exit 1
fi

echo "OpenBao cache encryption smoke passed"
