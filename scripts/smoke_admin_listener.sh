#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SMOKE_TMP_ROOT=$(sh "$ROOT_DIR/scripts/secure-smoke-tmp-root.sh" short)
TMP_DIR=$(mktemp -d "$SMOKE_TMP_ROOT/a.XXXXXX")
KEEP_LOGS=${FLUXHEIM_SMOKE_KEEP_LOGS:-0}

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
ADMIN_PORT=$2
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
        echo "admin listener smoke artifacts kept in $TMP_DIR" >&2
    else
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT INT TERM

mkdir -p "$TMP_DIR/public" "$TMP_DIR/run" "$TMP_DIR/admin-snapshots"
chmod 0700 "$TMP_DIR/admin-snapshots"
printf '%s\n' "fluxheim-admin-smoke-token" > "$TMP_DIR/admin-token"
printf '%s' "0123456789abcdef0123456789abcdef" > "$TMP_DIR/snapshot-integrity.key"
chmod 0600 "$TMP_DIR/snapshot-integrity.key"
printf '%s\n' '<!doctype html><title>admin smoke</title><h1>admin smoke ok</h1>' \
    > "$TMP_DIR/public/index.html"

cat > "$TMP_DIR/fluxheim.toml" <<EOF
[server]
listen = ["127.0.0.1:$FLUXHEIM_PORT"]
default_vhost = "admin-smoke.test"
trusted_proxies = []

[server.process]
daemon = false
pid_file = "$TMP_DIR/run/pid"
upgrade_sock = "$TMP_DIR/run/up.sock"
certificate_reload_sock = "$TMP_DIR/run/reload.sock"
grace_period_seconds = 1
graceful_shutdown_timeout_seconds = 2

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
token_file = "$TMP_DIR/admin-token"
snapshot_store = "$TMP_DIR/admin-snapshots"
snapshot_integrity_key_file = "$TMP_DIR/snapshot-integrity.key"

[admin.ops_socket]
enabled = true
path = "$TMP_DIR/run/ops.sock"
mode = "0600"
require_bearer_token = false

[admin.health]
unauthenticated = true

[proxy]
upstreams = ["127.0.0.1:9"]
upstream_tls = false

[[vhosts]]
name = "admin-smoke.test"
hosts = ["admin-smoke.test", "127.0.0.1"]

[vhosts.web]
root = "$TMP_DIR/public"
index_files = ["index.html"]
deny_dotfiles = true
EOF

(
    cd "$ROOT_DIR"
    cargo build --quiet --no-default-features --features proxy,web
)

"$ROOT_DIR/target/debug/fluxheim" --config "$TMP_DIR/fluxheim.toml" \
    >"$TMP_DIR/fluxheim.log" 2>&1 &
FLUXHEIM_PID=$!

wait_http() {
    url=$1
    for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15; do
        if curl -fsS "$url" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.2
    done

    echo "timed out waiting for $url" >&2
    cat "$TMP_DIR/fluxheim.log" >&2 || true
    return 1
}

wait_http "http://127.0.0.1:$FLUXHEIM_PORT/"
wait_http "http://127.0.0.1:$ADMIN_PORT/_fluxheim/health"

curl -fsS "http://127.0.0.1:$FLUXHEIM_PORT/" > "$TMP_DIR/root-body.txt"
if ! grep -q "admin smoke ok" "$TMP_DIR/root-body.txt"; then
    echo "admin listener smoke failed: root vhost response body mismatch" >&2
    cat "$TMP_DIR/root-body.txt" >&2
    exit 1
fi

health_status=$(curl -fsS -o "$TMP_DIR/admin-health.txt" -w '%{http_code}' \
    "http://127.0.0.1:$ADMIN_PORT/_fluxheim/health")
if [ "$health_status" != "200" ]; then
    echo "admin listener smoke failed: expected health HTTP 200, got $health_status" >&2
    cat "$TMP_DIR/admin-health.txt" >&2
    exit 1
fi

status_code=$(curl -fsS -o "$TMP_DIR/admin-status.json" -w '%{http_code}' \
    -H "Authorization: Bearer fluxheim-admin-smoke-token" \
    "http://127.0.0.1:$ADMIN_PORT/_fluxheim/status")
if [ "$status_code" != "200" ]; then
    echo "admin listener smoke failed: expected status HTTP 200, got $status_code" >&2
    cat "$TMP_DIR/admin-status.json" >&2
    exit 1
fi

if ! grep -q '"status":"ok"' "$TMP_DIR/admin-status.json"; then
    echo "admin listener smoke failed: status endpoint did not report ok" >&2
    cat "$TMP_DIR/admin-status.json" >&2
    exit 1
fi

snapshot_code=$(curl -fsS -o "$TMP_DIR/admin-snapshot.json" -w '%{http_code}' \
    -X POST \
    -H "Authorization: Bearer fluxheim-admin-smoke-token" \
    -H "X-Fluxheim-Message: authenticated admin smoke" \
    "http://127.0.0.1:$ADMIN_PORT/_fluxheim/snapshot")
if [ "$snapshot_code" != "201" ]; then
    echo "admin listener smoke failed: expected snapshot HTTP 201, got $snapshot_code" >&2
    cat "$TMP_DIR/admin-snapshot.json" >&2
    exit 1
fi

if ! grep -q '"status":"ok"' "$TMP_DIR/admin-snapshot.json"; then
    echo "admin listener smoke failed: snapshot endpoint did not report ok" >&2
    cat "$TMP_DIR/admin-snapshot.json" >&2
    exit 1
fi

integrity_files=$(find "$TMP_DIR/admin-snapshots/configs" -maxdepth 1 \
    -type f -name '*.integrity.toml' | wc -l)
if [ "$integrity_files" -ne 1 ]; then
    echo "admin listener smoke failed: expected one authenticated manifest" >&2
    find "$TMP_DIR/admin-snapshots" -maxdepth 2 -print >&2
    exit 1
fi

if ! "$ROOT_DIR/target/debug/fluxheim" snapshots \
    --store "$TMP_DIR/admin-snapshots" \
    --integrity-key-file "$TMP_DIR/snapshot-integrity.key" doctor \
    >"$TMP_DIR/snapshot-doctor.txt" 2>&1; then
    echo "admin listener smoke failed: authenticated snapshot doctor failed" >&2
    cat "$TMP_DIR/snapshot-doctor.txt" >&2
    exit 1
fi

if ! grep -q 'healthy: true' "$TMP_DIR/snapshot-doctor.txt"; then
    echo "admin listener smoke failed: snapshot doctor did not report healthy" >&2
    cat "$TMP_DIR/snapshot-doctor.txt" >&2
    exit 1
fi

ops_status_code=$(curl -fsS --unix-socket "$TMP_DIR/run/ops.sock" \
    -o "$TMP_DIR/admin-ops-status.json" -w '%{http_code}' \
    "http://fluxheim/_fluxheim/status")
if [ "$ops_status_code" != "200" ]; then
    echo "admin listener smoke failed: expected ops-socket status HTTP 200, got $ops_status_code" >&2
    cat "$TMP_DIR/admin-ops-status.json" >&2
    exit 1
fi

if ! grep -q '"status":"ok"' "$TMP_DIR/admin-ops-status.json"; then
    echo "admin listener smoke failed: ops-socket status endpoint did not report ok" >&2
    cat "$TMP_DIR/admin-ops-status.json" >&2
    exit 1
fi

ops_post_code=$(curl -sS --unix-socket "$TMP_DIR/run/ops.sock" \
    -o "$TMP_DIR/admin-ops-post.txt" -w '%{http_code}' \
    -X POST "http://fluxheim/_fluxheim/status")
if [ "$ops_post_code" != "405" ]; then
    echo "admin listener smoke failed: expected ops-socket POST status HTTP 405, got $ops_post_code" >&2
    cat "$TMP_DIR/admin-ops-post.txt" >&2
    exit 1
fi

echo "admin listener smoke passed"
