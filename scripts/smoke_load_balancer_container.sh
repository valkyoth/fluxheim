#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP_ROOT="$ROOT_DIR/target/fluxheim-lb-container-smoke"
mkdir -p "$TMP_ROOT"
TMP_DIR=$(mktemp -d "$TMP_ROOT/run.XXXXXX")
KEEP_LOGS=${FLUXHEIM_SMOKE_KEEP_LOGS:-0}
CURL_MAX_TIME=${FLUXHEIM_SMOKE_CURL_MAX_TIME:-5}
IMAGE=${FLUXHEIM_LB_CONTAINER_SMOKE_IMAGE:-fluxheim:load-balancer-smoke}
CONTAINERFILE=${FLUXHEIM_LB_CONTAINER_SMOKE_CONTAINERFILE:-containers/Containerfile.wolfi}
FEATURES=${FLUXHEIM_LB_CONTAINER_SMOKE_FEATURES:-profile-load-balancer-edge,acme-client}
CONFIG=${FLUXHEIM_LB_CONTAINER_SMOKE_CONFIG:-packaging/container/load-balancer.toml}
CONTAINER_NAME="fluxheim-lb-container-smoke-$$"

if [ -z "${CONTAINER_HOST:-}" ] && [ -n "${XDG_RUNTIME_DIR:-}" ] && [ -S "$XDG_RUNTIME_DIR/podman/podman.sock" ]; then
    CONTAINER_HOST="unix://$XDG_RUNTIME_DIR/podman/podman.sock"
    export CONTAINER_HOST
fi

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "required command not found: $1" >&2
        exit 1
    fi
}

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
ORIGIN_ONE_PORT=$2
ORIGIN_TWO_PORT=$3

ORIGIN_ONE_PID=
ORIGIN_TWO_PID=

cleanup() {
    status=$?

    podman rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true

    for pid in "$ORIGIN_ONE_PID" "$ORIGIN_TWO_PID"; do
        if [ -n "$pid" ]; then
            kill "$pid" 2>/dev/null || true
        fi
    done

    sleep 0.2

    for pid in "$ORIGIN_ONE_PID" "$ORIGIN_TWO_PID"; do
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill -9 "$pid" 2>/dev/null || true
        fi
    done

    for pid in "$ORIGIN_ONE_PID" "$ORIGIN_TWO_PID"; do
        if [ -n "$pid" ]; then
            wait "$pid" 2>/dev/null || true
        fi
    done

    if [ "$KEEP_LOGS" = "1" ] || [ "$status" -ne 0 ]; then
        echo "load-balancer container smoke artifacts kept in $TMP_DIR" >&2
    else
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT INT TERM

wait_http() {
    url=$1
    tries=0
    while [ "$tries" -lt 100 ]; do
        if curl -fsS --max-time "$CURL_MAX_TIME" "$url" >/dev/null 2>&1; then
            return 0
        fi
        tries=$((tries + 1))
        sleep 0.1
    done

    echo "timed out waiting for $url" >&2
    return 1
}

require_command curl
require_command podman
require_command python3

cat > "$TMP_DIR/origin.py" <<'PY'
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    label = "origin"

    def do_GET(self):
        body = f"{self.label}\n".encode("ascii")
        self.send_response(200)
        self.send_header("content-type", "text/plain; charset=ascii")
        self.send_header("content-length", str(len(body)))
        self.send_header("x-origin", self.label)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *args):
        return


if __name__ == "__main__":
    host = sys.argv[1]
    port = int(sys.argv[2])
    Handler.label = sys.argv[3]
    ThreadingHTTPServer((host, port), Handler).serve_forever()
PY

cat > "$TMP_DIR/fluxheim.toml" <<EOF
[server]
listen = ["127.0.0.1:$FLUXHEIM_PORT"]
default_vhost = "smoke"
trusted_proxies = []

[server.process]
daemon = false
pid_file = "/run/fluxheim/fluxheim-lb-container-smoke.pid"
upgrade_sock = "/run/fluxheim/fluxheim-lb-container-smoke-upgrade.sock"
certificate_reload_sock = "/run/fluxheim/fluxheim-lb-container-smoke-cert.sock"
grace_period_seconds = 1
graceful_shutdown_timeout_seconds = 2

[logging]
level = "info"
format = "json"
target = "stderr"

[tls]
enabled = false
backend = "rustls"

[[vhosts]]
name = "smoke"
hosts = ["127.0.0.1", "localhost"]

[vhosts.proxy]
upstreams = ["127.0.0.1:$ORIGIN_ONE_PORT", "127.0.0.1:$ORIGIN_TWO_PORT"]
upstream_aliases = ["origin-one", "origin-two"]
upstream_tls = false

[vhosts.proxy.load_balance]
selection = "round-robin"
all_down_status = 503
max_iterations = 128

[vhosts.proxy.load_balance.health_check]
enabled = true
protocol = "http"
method = "GET"
path = "/"
host = "127.0.0.1"
interval_secs = 1
consecutive_success = 1
consecutive_failure = 1
parallel = true
connect_timeout_secs = 1
read_timeout_secs = 1

[[vhosts.routes]]
name = "sticky"
path_prefix = "/sticky/"

[vhosts.routes.proxy]
upstreams = ["127.0.0.1:$ORIGIN_ONE_PORT", "127.0.0.1:$ORIGIN_TWO_PORT"]
upstream_aliases = ["origin-one", "origin-two"]
upstream_tls = false

[vhosts.routes.proxy.load_balance]
selection = "round-robin"
all_down_status = 503
max_iterations = 128

[vhosts.routes.proxy.load_balance.persistence]
enabled = true
mode = "header"
header = "x-sticky-session"
ttl_secs = 60
table_max_entries = 16
EOF

chmod 755 "$TMP_DIR"
chmod 644 "$TMP_DIR/fluxheim.toml"

python3 "$TMP_DIR/origin.py" 127.0.0.1 "$ORIGIN_ONE_PORT" origin-one >"$TMP_DIR/origin-one.log" 2>&1 &
ORIGIN_ONE_PID=$!
python3 "$TMP_DIR/origin.py" 127.0.0.1 "$ORIGIN_TWO_PORT" origin-two >"$TMP_DIR/origin-two.log" 2>&1 &
ORIGIN_TWO_PID=$!

wait_http "http://127.0.0.1:$ORIGIN_ONE_PORT/"
wait_http "http://127.0.0.1:$ORIGIN_TWO_PORT/"

"$ROOT_DIR/scripts/validate-features.sh" "$FEATURES"

echo "load-balancer container smoke: image=$IMAGE features=$FEATURES config=$CONFIG"
(
    cd "$ROOT_DIR"
    podman build \
        --build-arg "FLUXHEIM_FEATURES=$FEATURES" \
        --build-arg "FLUXHEIM_CONFIG=$CONFIG" \
        -t "$IMAGE" \
        -f "$CONTAINERFILE" \
        .
)

podman rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
podman run -d \
    --name "$CONTAINER_NAME" \
    --network host \
    -v "$TMP_DIR/fluxheim.toml:/etc/fluxheim/fluxheim.toml:ro,Z" \
    "$IMAGE" \
    --config /etc/fluxheim/fluxheim.toml \
    > "$TMP_DIR/container.id"

wait_http "http://127.0.0.1:$FLUXHEIM_PORT/smoke"

RESPONSES="$TMP_DIR/responses.txt"
: > "$RESPONSES"
for _ in 1 2 3 4 5 6; do
    curl -fsS --max-time "$CURL_MAX_TIME" "http://127.0.0.1:$FLUXHEIM_PORT/smoke" >> "$RESPONSES"
done

if ! grep -q '^origin-one$' "$RESPONSES"; then
    echo "origin-one was not selected by the containerized load balancer" >&2
    podman logs "$CONTAINER_NAME" >&2 || true
    cat "$RESPONSES" >&2
    exit 1
fi

if ! grep -q '^origin-two$' "$RESPONSES"; then
    echo "origin-two was not selected by the containerized load balancer" >&2
    podman logs "$CONTAINER_NAME" >&2 || true
    cat "$RESPONSES" >&2
    exit 1
fi

STICKY_RESPONSES="$TMP_DIR/sticky-responses.txt"
: > "$STICKY_RESPONSES"
for _ in 1 2; do
    curl -fsS --max-time "$CURL_MAX_TIME" \
        -H "x-sticky-session: container-smoke-session" \
        "http://127.0.0.1:$FLUXHEIM_PORT/sticky/session" >> "$STICKY_RESPONSES"
done

if [ "$(sort -u "$STICKY_RESPONSES" | wc -l)" -ne 1 ]; then
    echo "containerized header persistence did not keep the same session pinned" >&2
    podman logs "$CONTAINER_NAME" >&2 || true
    cat "$STICKY_RESPONSES" >&2
    exit 1
fi

(
    cd "$ROOT_DIR"
    cargo tree --locked --no-default-features --features profile-load-balancer-edge \
        > "$TMP_DIR/load-balancer-edge-cargo-tree.txt"
    cargo tree --locked -p fluxheim-load-balancer \
        > "$TMP_DIR/fluxheim-load-balancer-cargo-tree.txt"
)
if grep -E 'pingora-load-balancing|pingora-ketama' "$TMP_DIR/load-balancer-edge-cargo-tree.txt" >/dev/null; then
    echo "load-balancer-edge dependency tree still compiles Pingora load-balancing crates" >&2
    cat "$TMP_DIR/load-balancer-edge-cargo-tree.txt" >&2
    exit 1
fi
if grep -E 'pingora[-_a-z]* v[0-9]' "$TMP_DIR/fluxheim-load-balancer-cargo-tree.txt" >/dev/null; then
    echo "fluxheim-load-balancer crate dependency tree still compiles Pingora crates" >&2
    cat "$TMP_DIR/fluxheim-load-balancer-cargo-tree.txt" >&2
    exit 1
fi

echo "load-balancer container smoke passed"
