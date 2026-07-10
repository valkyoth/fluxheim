#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP_ROOT="$ROOT_DIR/target/fluxheim-redis-health-smoke"
mkdir -p "$TMP_ROOT"
TMP_DIR=$(mktemp -d "$TMP_ROOT/run.XXXXXX")
KEEP_LOGS=${FLUXHEIM_SMOKE_KEEP_LOGS:-0}
KEEP_REDIS=${FLUXHEIM_SMOKE_KEEP_REDIS:-0}
REDIS_IMAGE=${FLUXHEIM_REDIS_IMAGE:-docker.io/valkey/valkey:9.1-alpine}
REDIS_NAME="fluxheim-redis-health-smoke-$$"
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
FLUXHEIM_PORT=$1
ADMIN_PORT=$2
METRICS_PORT=$3
REDIS_PORT=$4
REDIS_BAD_PORT=$5

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

    if [ "$KEEP_REDIS" != "1" ]; then
        podman rm -f "$REDIS_NAME" >/dev/null 2>&1 || true
    fi

    if [ "$KEEP_LOGS" = "1" ] || [ "$status" -ne 0 ]; then
        echo "Redis health-check smoke artifacts kept in $TMP_DIR" >&2
        if [ "$KEEP_REDIS" = "1" ]; then
            echo "Redis health-check smoke container kept as $REDIS_NAME" >&2
        fi
    else
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT INT TERM

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "required command not found: $1" >&2
        exit 1
    fi
}

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

redis_info() {
    section=$1
    python3 - "$REDIS_PORT" "$section" <<'PY'
import socket
import sys

port = int(sys.argv[1])
section = sys.argv[2].encode("ascii")
request = (
    b"*2\r\n$4\r\nINFO\r\n$"
    + str(len(section)).encode("ascii")
    + b"\r\n"
    + section
    + b"\r\n"
)

with socket.create_connection(("127.0.0.1", port), timeout=2.0) as sock:
    sock.settimeout(2.0)
    sock.sendall(request)
    data = b""
    while b"\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise SystemExit("Redis closed connection before INFO response")
        data += chunk
    line, rest = data.split(b"\r\n", 1)
    if line.startswith(b"-"):
        raise SystemExit(line.decode("utf-8", "replace"))
    if not line.startswith(b"$"):
        raise SystemExit(f"unexpected Redis INFO response: {line!r}")
    length = int(line[1:])
    while len(rest) < length + 2:
        chunk = sock.recv(4096)
        if not chunk:
            raise SystemExit("Redis closed connection during INFO response")
        rest += chunk
    sys.stdout.write(rest[:length].decode("utf-8", "replace"))
PY
}

redis_ping_calls() {
    redis_info commandstats \
        | awk -F'[=,]' '/^cmdstat_ping:/ {print $2; found=1} END {if (!found) print 0}'
}

wait_log_contains() {
    pattern=$1
    tries=0
    while [ "$tries" -lt 80 ]; do
        if grep -F -q "$pattern" "$TMP_DIR/fluxheim.log"; then
            return 0
        fi
        tries=$((tries + 1))
        sleep 0.25
    done

    echo "timed out waiting for Fluxheim log pattern: $pattern" >&2
    cat "$TMP_DIR/fluxheim.log" >&2
    return 1
}

wait_redis_ping_observed() {
    initial=$1
    tries=0
    while [ "$tries" -lt 80 ]; do
        current=$(redis_ping_calls)
        if [ "$current" -gt "$initial" ]; then
            printf '%s\n' "$current"
            return 0
        fi
        tries=$((tries + 1))
        sleep 0.25
    done

    echo "timed out waiting for Redis PING command stats to increase" >&2
    redis_info commandstats >&2 || true
    return 1
}

require_command cargo
require_command curl
require_command podman
require_command python3

"$ROOT_DIR/scripts/validate-features.sh" proxy,load-balancer,metrics
(
    cd "$ROOT_DIR"
    cargo build --quiet --no-default-features --features proxy,load-balancer,metrics
)

podman run -d \
    --name "$REDIS_NAME" \
    --security-opt no-new-privileges \
    -p "127.0.0.1:${REDIS_PORT}:6379" \
    "$REDIS_IMAGE" \
    valkey-server --save "" --appendonly no --protected-mode no >"$TMP_DIR/redis.container"

i=0
until redis_info server >/dev/null 2>&1; do
    i=$((i + 1))
    if [ "$i" -gt 80 ]; then
        echo "timed out waiting for Redis/Valkey" >&2
        podman logs "$REDIS_NAME" >&2 || true
        exit 1
    fi
    sleep 0.25
done

initial_ping_calls=$(redis_ping_calls)

cat > "$TMP_DIR/fluxheim.toml" <<EOF_CONFIG
[server]
listen = ["127.0.0.1:${FLUXHEIM_PORT}"]
default_vhost = "redis-health"

[server.process]
pid_file = "${TMP_DIR}/fluxheim.pid"
upgrade_sock = "${TMP_DIR}/fluxheim-upgrade.sock"
certificate_reload_sock = "${TMP_DIR}/fluxheim-cert-reload.sock"
threads = 1
grace_period_seconds = 1
graceful_shutdown_timeout_seconds = 2

[admin]
enabled = true
listen = "127.0.0.1:${ADMIN_PORT}"
token_env = "FLUXHEIM_ADMIN_TOKEN"
snapshot_store = "${TMP_DIR}/admin-snapshots"

[admin.health]
unauthenticated = true

[metrics]
enabled = true
listen = "127.0.0.1:${METRICS_PORT}"
require_loopback = true

[logging]
level = "warn"
format = "text"
target = "stderr"

[[vhosts]]
name = "redis-health"
hosts = ["127.0.0.1"]

[vhosts.proxy]
upstreams = ["127.0.0.1:${REDIS_PORT}", "127.0.0.1:${REDIS_BAD_PORT}"]
upstream_aliases = ["redis-main", "redis-down"]
connect_timeout_secs = 1
read_timeout_secs = 1
send_timeout_secs = 1

[vhosts.proxy.load_balance]
selection = "least-connections"
max_iterations = 32
all_down_status = 503

[vhosts.proxy.load_balance.health_check]
enabled = true
protocol = "redis"
interval_secs = 1
consecutive_success = 1
consecutive_failure = 1
connect_timeout_secs = 1
read_timeout_secs = 1
EOF_CONFIG

export FLUXHEIM_ADMIN_TOKEN="redis-health-smoke-token"
"$ROOT_DIR/target/debug/fluxheim" --config "$TMP_DIR/fluxheim.toml" >"$TMP_DIR/fluxheim.log" 2>&1 &
FLUXHEIM_PID=$!

wait_http "http://127.0.0.1:$ADMIN_PORT/_fluxheim/health"
wait_http "http://127.0.0.1:$METRICS_PORT/metrics"
observed_ping_calls=$(wait_redis_ping_observed "$initial_ping_calls")

podman rm -f "$REDIS_NAME" >/dev/null 2>&1 || true
KEEP_REDIS=0
wait_log_contains "127.0.0.1:${REDIS_PORT} via redis becomes unhealthy"

echo "redis health-check smoke passed (PING calls: ${initial_ping_calls}->${observed_ping_calls})"
