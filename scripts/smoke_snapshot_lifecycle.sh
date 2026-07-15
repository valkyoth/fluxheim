#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SMOKE_TMP_ROOT=$(sh "$ROOT_DIR/scripts/secure-smoke-tmp-root.sh" short)
TMP_DIR=$(mktemp -d "$SMOKE_TMP_ROOT/snapshot-lifecycle.XXXXXX")
KEEP_LOGS=${FLUXHEIM_SMOKE_KEEP_LOGS:-0}
FLUXHEIM_PID=

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

stop_fluxheim() {
    if [ -z "$FLUXHEIM_PID" ]; then
        return
    fi
    kill "$FLUXHEIM_PID" 2>/dev/null || true
    for _ in 1 2 3 4 5 6 7 8 9 10; do
        if ! kill -0 "$FLUXHEIM_PID" 2>/dev/null; then
            wait "$FLUXHEIM_PID" 2>/dev/null || true
            FLUXHEIM_PID=
            return
        fi
        sleep 0.1
    done
    kill -9 "$FLUXHEIM_PID" 2>/dev/null || true
    wait "$FLUXHEIM_PID" 2>/dev/null || true
    FLUXHEIM_PID=
}

cleanup() {
    status=$?
    stop_fluxheim
    if [ "$KEEP_LOGS" = "1" ] || [ "$status" -ne 0 ]; then
        echo "snapshot lifecycle smoke artifacts kept in $TMP_DIR" >&2
    else
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT INT TERM

mkdir -p "$TMP_DIR/baseline-public" "$TMP_DIR/candidate-public" "$TMP_DIR/run" \
    "$TMP_DIR/snapshots"
chmod 0700 "$TMP_DIR/snapshots"
printf '%s\n' 'baseline snapshot response' > "$TMP_DIR/baseline-public/index.html"
printf '%s\n' 'candidate snapshot response' > "$TMP_DIR/candidate-public/index.html"
printf '%s\n' 'fluxheim-snapshot-smoke-token' > "$TMP_DIR/admin-token"
printf '%s' '0123456789abcdef0123456789abcdef' > "$TMP_DIR/snapshot-integrity.key"
chmod 0600 "$TMP_DIR/admin-token" "$TMP_DIR/snapshot-integrity.key"

write_config() {
    config_path=$1
    public_root=$2
    cat > "$config_path" <<EOF
[server]
listen = ["127.0.0.1:$FLUXHEIM_PORT"]
default_vhost = "snapshot.test"
trusted_proxies = []

[server.process]
daemon = false
pid_file = "$TMP_DIR/run/fluxheim.pid"
upgrade_sock = "$TMP_DIR/run/upgrade.sock"
certificate_reload_sock = "$TMP_DIR/run/certificate-reload.sock"
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
snapshot_store = "$TMP_DIR/snapshots"
snapshot_integrity_key_file = "$TMP_DIR/snapshot-integrity.key"

[admin.health]
unauthenticated = true

[proxy]
upstreams = ["127.0.0.1:9"]
upstream_tls = false

[[vhosts]]
name = "snapshot.test"
hosts = ["snapshot.test", "127.0.0.1"]

[vhosts.web]
root = "$public_root"
index_files = ["index.html"]
deny_dotfiles = true
EOF
}

write_config "$TMP_DIR/baseline.toml" "$TMP_DIR/baseline-public"
write_config "$TMP_DIR/candidate.toml" "$TMP_DIR/candidate-public"

(
    cd "$ROOT_DIR"
    cargo build --quiet --no-default-features --features proxy,web
)
FLUXHEIM="$ROOT_DIR/target/debug/fluxheim"

start_fluxheim() {
    log_name=$1
    "$FLUXHEIM" --config "$TMP_DIR/baseline.toml" \
        >"$TMP_DIR/$log_name.log" 2>&1 &
    FLUXHEIM_PID=$!
}

wait_http() {
    url=$1
    log_name=$2
    for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
        if curl -fsS "$url" >/dev/null 2>&1; then
            return
        fi
        sleep 0.2
    done
    echo "snapshot lifecycle smoke failed: timed out waiting for $url" >&2
    cat "$TMP_DIR/$log_name.log" >&2 || true
    exit 1
}

assert_served_body() {
    expected=$1
    output=$2
    curl -fsS -H 'Host: snapshot.test' "http://127.0.0.1:$FLUXHEIM_PORT/" > "$output"
    if ! grep -Fxq "$expected" "$output"; then
        echo "snapshot lifecycle smoke failed: expected body '$expected'" >&2
        cat "$output" >&2
        exit 1
    fi
}

admin_post() {
    path=$1
    output=$2
    curl -fsS -X POST \
        -H 'Authorization: Bearer fluxheim-snapshot-smoke-token' \
        "http://127.0.0.1:$ADMIN_PORT$path" > "$output"
}

json_snapshot_id() {
    python3 -c 'import json,sys; print(json.load(open(sys.argv[1], encoding="utf-8"))["snapshot"])' "$1"
}

assert_status_current() {
    expected=$1
    output=$2
    curl -fsS \
        -H 'Authorization: Bearer fluxheim-snapshot-smoke-token' \
        "http://127.0.0.1:$ADMIN_PORT/_fluxheim/status" > "$output"
    python3 -c 'import json,sys; data=json.load(open(sys.argv[1], encoding="utf-8")); assert data["snapshot_current"] == sys.argv[2], data' \
        "$output" "$expected"
}

start_fluxheim first
wait_http "http://127.0.0.1:$ADMIN_PORT/_fluxheim/health" first
assert_served_body 'baseline snapshot response' "$TMP_DIR/baseline-before.txt"
ORIGINAL_PID=$FLUXHEIM_PID

admin_post '/_fluxheim/snapshot' "$TMP_DIR/baseline-snapshot.json"
BASELINE_ID=$(json_snapshot_id "$TMP_DIR/baseline-snapshot.json")
assert_status_current "$BASELINE_ID" "$TMP_DIR/status-baseline.json"

"$FLUXHEIM" --config "$TMP_DIR/candidate.toml" snapshot \
    --store "$TMP_DIR/snapshots" \
    --integrity-key-file "$TMP_DIR/snapshot-integrity.key" \
    --message 'live candidate' > "$TMP_DIR/candidate-snapshot.txt"
CANDIDATE_ID=$(tr -d '\r\n' < "$TMP_DIR/snapshots/current")
if [ -z "$CANDIDATE_ID" ] || [ "$CANDIDATE_ID" = "$BASELINE_ID" ]; then
    echo "snapshot lifecycle smoke failed: candidate snapshot was not selected" >&2
    cat "$TMP_DIR/candidate-snapshot.txt" >&2
    exit 1
fi

admin_post '/_fluxheim/reload' "$TMP_DIR/reload.json"
if [ "$FLUXHEIM_PID" != "$ORIGINAL_PID" ] || ! kill -0 "$ORIGINAL_PID" 2>/dev/null; then
    echo "snapshot lifecycle smoke failed: live reload replaced the server process" >&2
    exit 1
fi
assert_served_body 'candidate snapshot response' "$TMP_DIR/candidate-live.txt"
assert_status_current "$CANDIDATE_ID" "$TMP_DIR/status-candidate.json"

admin_post '/_fluxheim/rollback?live=true' "$TMP_DIR/rollback.json"
assert_served_body 'baseline snapshot response' "$TMP_DIR/baseline-rollback.txt"
assert_status_current "$BASELINE_ID" "$TMP_DIR/status-rollback.json"
if [ "$(tr -d '\r\n' < "$TMP_DIR/snapshots/current")" != "$BASELINE_ID" ]; then
    echo "snapshot lifecycle smoke failed: rollback did not persist the baseline pointer" >&2
    exit 1
fi

"$FLUXHEIM" snapshots --store "$TMP_DIR/snapshots" \
    --integrity-key-file "$TMP_DIR/snapshot-integrity.key" doctor \
    > "$TMP_DIR/snapshot-doctor.txt"
if ! grep -q 'healthy: true' "$TMP_DIR/snapshot-doctor.txt"; then
    echo "snapshot lifecycle smoke failed: snapshot doctor did not report healthy" >&2
    cat "$TMP_DIR/snapshot-doctor.txt" >&2
    exit 1
fi

stop_fluxheim
start_fluxheim restart
wait_http "http://127.0.0.1:$ADMIN_PORT/_fluxheim/health" restart
assert_served_body 'baseline snapshot response' "$TMP_DIR/baseline-restart.txt"
assert_status_current "$BASELINE_ID" "$TMP_DIR/status-restart.json"

echo "snapshot lifecycle smoke passed"
