#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/fluxheim-lb-smoke.XXXXXX")
KEEP_LOGS=${FLUXHEIM_SMOKE_KEEP_LOGS:-0}

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
ORIGIN_ONE_PORT=$3
ORIGIN_TWO_PORT=$4
METRICS_PORT=$5

ORIGIN_ONE_PID=
ORIGIN_TWO_PID=
FLUXHEIM_PID=

cleanup() {
    status=$?

    for pid in "$FLUXHEIM_PID" "$ORIGIN_ONE_PID" "$ORIGIN_TWO_PID"; do
        if [ -n "$pid" ]; then
            kill "$pid" 2>/dev/null || true
        fi
    done

    sleep 0.2

    for pid in "$FLUXHEIM_PID" "$ORIGIN_ONE_PID" "$ORIGIN_TWO_PID"; do
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill -9 "$pid" 2>/dev/null || true
        fi
    done

    for pid in "$FLUXHEIM_PID" "$ORIGIN_ONE_PID" "$ORIGIN_TWO_PID"; do
        if [ -n "$pid" ]; then
            wait "$pid" 2>/dev/null || true
        fi
    done

    if [ "$KEEP_LOGS" = "1" ] || [ "$status" -ne 0 ]; then
        echo "smoke artifacts kept in $TMP_DIR" >&2
    else
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT INT TERM

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

[server.process]
daemon = false
pid_file = "$TMP_DIR/fluxheim.pid"
upgrade_sock = "$TMP_DIR/fluxheim-upgrade.sock"
certificate_reload_sock = "$TMP_DIR/fluxheim-cert-reload.sock"

[admin]
enabled = true
listen = "127.0.0.1:$ADMIN_PORT"
token_env = "FLUXHEIM_ADMIN_TOKEN"
snapshot_store = "$TMP_DIR/admin-snapshots"

[admin.health]
unauthenticated = true

[metrics]
enabled = true
listen = "127.0.0.1:$METRICS_PORT"
require_loopback = true

[[vhosts]]
name = "smoke"
hosts = ["127.0.0.1"]

[vhosts.proxy]
upstreams = ["127.0.0.1:$ORIGIN_ONE_PORT", "127.0.0.1:$ORIGIN_TWO_PORT"]
upstream_aliases = ["origin-one", "origin-two"]
upstream_tls = false

[vhosts.proxy.load_balance]
max_iterations = 256
all_down_status = 503

[vhosts.proxy.load_balance.health_check]
enabled = true
interval_secs = 1
consecutive_success = 1
consecutive_failure = 1
parallel = true

[[vhosts.routes]]
name = "maglev"
path_prefix = "/maglev/"

[vhosts.routes.proxy]
upstreams = ["127.0.0.1:$ORIGIN_ONE_PORT", "127.0.0.1:$ORIGIN_TWO_PORT"]
upstream_aliases = ["origin-one", "origin-two"]
upstream_tls = false

[vhosts.routes.proxy.load_balance]
selection = "maglev-uri-hash"
max_iterations = 256
all_down_status = 503

[[vhosts.routes]]
name = "sticky"
path_prefix = "/sticky/"

[vhosts.routes.proxy]
upstreams = ["127.0.0.1:$ORIGIN_ONE_PORT", "127.0.0.1:$ORIGIN_TWO_PORT"]
upstream_aliases = ["origin-one", "origin-two"]
upstream_tls = false

[vhosts.routes.proxy.load_balance]
selection = "round-robin"
max_iterations = 256
all_down_status = 503

[vhosts.routes.proxy.load_balance.persistence]
enabled = true
mode = "header"
header = "x-sticky-session"
ttl_secs = 60
table_max_entries = 16
EOF

wait_http() {
    url=$1
    tries=0
    while [ "$tries" -lt 100 ]; do
        if curl -fsS "$url" >/dev/null 2>&1; then
            return 0
        fi
        tries=$((tries + 1))
        sleep 0.1
    done

    echo "timed out waiting for $url" >&2
    return 1
}

python3 "$TMP_DIR/origin.py" 127.0.0.1 "$ORIGIN_ONE_PORT" origin-one >"$TMP_DIR/origin-one.log" 2>&1 &
ORIGIN_ONE_PID=$!
python3 "$TMP_DIR/origin.py" 127.0.0.1 "$ORIGIN_TWO_PORT" origin-two >"$TMP_DIR/origin-two.log" 2>&1 &
ORIGIN_TWO_PID=$!

wait_http "http://127.0.0.1:$ORIGIN_ONE_PORT/"
wait_http "http://127.0.0.1:$ORIGIN_TWO_PORT/"

"$ROOT_DIR/scripts/validate-features.sh" proxy,load-balancer,metrics
(
    cd "$ROOT_DIR"
    cargo build --quiet --no-default-features --features proxy,load-balancer,metrics
)
export FLUXHEIM_ADMIN_TOKEN="smoke-token"
"$ROOT_DIR/target/debug/fluxheim" --config "$TMP_DIR/fluxheim.toml" >"$TMP_DIR/fluxheim.log" 2>&1 &
FLUXHEIM_PID=$!

wait_http "http://127.0.0.1:$FLUXHEIM_PORT/smoke"
wait_http "http://127.0.0.1:$ADMIN_PORT/_fluxheim/health"
wait_http "http://127.0.0.1:$METRICS_PORT/metrics"

RESPONSES="$TMP_DIR/responses.txt"
: > "$RESPONSES"
for _ in 1 2 3 4 5 6; do
    curl -fsS "http://127.0.0.1:$FLUXHEIM_PORT/smoke" >> "$RESPONSES"
done

if ! grep -q '^origin-one$' "$RESPONSES"; then
    echo "origin-one was not selected by the load balancer" >&2
    cat "$RESPONSES" >&2
    exit 1
fi

if ! grep -q '^origin-two$' "$RESPONSES"; then
    echo "origin-two was not selected by the load balancer" >&2
    cat "$RESPONSES" >&2
    exit 1
fi

curl -fsS \
    -H "Authorization: Bearer $FLUXHEIM_ADMIN_TOKEN" \
    "http://127.0.0.1:$ADMIN_PORT/_fluxheim/load-balancer/status" \
    > "$TMP_DIR/load-balancer-status.json"

if ! grep -q '"load_balancer"' "$TMP_DIR/load-balancer-status.json" \
    || ! grep -q '"alias":"origin-one"' "$TMP_DIR/load-balancer-status.json" \
    || ! grep -q '"alias":"origin-two"' "$TMP_DIR/load-balancer-status.json"; then
    echo "load balancer status endpoint did not report configured pool aliases" >&2
    cat "$TMP_DIR/load-balancer-status.json" >&2
    exit 1
fi

curl -fsS "http://127.0.0.1:$METRICS_PORT/metrics" > "$TMP_DIR/metrics-before-disable.txt"
if ! grep -q 'fluxheim_load_balancer_pools{scope="vhost",selection="round_robin"} 1' "$TMP_DIR/metrics-before-disable.txt"; then
    echo "load balancer metrics did not report configured round-robin vhost pool" >&2
    cat "$TMP_DIR/metrics-before-disable.txt" >&2
    exit 1
fi
if ! grep -q 'fluxheim_load_balancer_pools{scope="route",selection="maglev_uri_hash"} 1' "$TMP_DIR/metrics-before-disable.txt"; then
    echo "load balancer metrics did not report configured Maglev route pool" >&2
    cat "$TMP_DIR/metrics-before-disable.txt" >&2
    exit 1
fi

MAGLEV_RESPONSES="$TMP_DIR/maglev-responses.txt"
: > "$MAGLEV_RESPONSES"
for _ in 1 2 3 4 5 6; do
    curl -fsS "http://127.0.0.1:$FLUXHEIM_PORT/maglev/stable-key" >> "$MAGLEV_RESPONSES"
done

if [ "$(sort -u "$MAGLEV_RESPONSES" | wc -l)" -ne 1 ]; then
    echo "Maglev route did not keep the same URI pinned to one selected origin" >&2
    cat "$MAGLEV_RESPONSES" >&2
    exit 1
fi

STICKY_RESPONSES="$TMP_DIR/sticky-responses.txt"
: > "$STICKY_RESPONSES"
for _ in 1 2; do
    curl -fsS \
        -H "x-sticky-session: smoke-session" \
        "http://127.0.0.1:$FLUXHEIM_PORT/sticky/session" >> "$STICKY_RESPONSES"
done

if [ "$(sort -u "$STICKY_RESPONSES" | wc -l)" -ne 1 ]; then
    echo "header persistence route did not keep the same session pinned" >&2
    cat "$STICKY_RESPONSES" >&2
    exit 1
fi

curl -fsS \
    -H "Authorization: Bearer $FLUXHEIM_ADMIN_TOKEN" \
    "http://127.0.0.1:$ADMIN_PORT/_fluxheim/load-balancer/status" \
    > "$TMP_DIR/load-balancer-status-sticky.json"

if ! grep -q '"name":"sticky"' "$TMP_DIR/load-balancer-status-sticky.json" \
    || ! grep -q '"entry_count":1' "$TMP_DIR/load-balancer-status-sticky.json"; then
    echo "load balancer status endpoint did not report route persistence entry" >&2
    cat "$TMP_DIR/load-balancer-status-sticky.json" >&2
    exit 1
fi

curl -fsS -X POST \
    -H "Authorization: Bearer $FLUXHEIM_ADMIN_TOKEN" \
    "http://127.0.0.1:$ADMIN_PORT/_fluxheim/load-balancer/persistence/clear?vhost=smoke&route=sticky" \
    > "$TMP_DIR/persistence-clear.json"

if ! grep -q '"status":"ok"' "$TMP_DIR/persistence-clear.json" \
    || ! grep -q '"scope":"route"' "$TMP_DIR/persistence-clear.json" \
    || ! grep -q '"cleared_entries":1' "$TMP_DIR/persistence-clear.json" \
    || ! grep -q '"persistent":false' "$TMP_DIR/persistence-clear.json"; then
    echo "load balancer persistence clear endpoint did not report cleared route entry" >&2
    cat "$TMP_DIR/persistence-clear.json" >&2
    exit 1
fi

curl -fsS "http://127.0.0.1:$METRICS_PORT/metrics" > "$TMP_DIR/metrics-after-persistence-clear.txt"
if ! grep -q 'fluxheim_load_balancer_events_total{event="persistence_clear",route="sticky",scope="route",upstream="",vhost="smoke"} 1' "$TMP_DIR/metrics-after-persistence-clear.txt"; then
    echo "load balancer metrics missed persistence_clear event" >&2
    cat "$TMP_DIR/metrics-after-persistence-clear.txt" >&2
    exit 1
fi

curl -fsS -X POST \
    -H "Authorization: Bearer $FLUXHEIM_ADMIN_TOKEN" \
    "http://127.0.0.1:$ADMIN_PORT/_fluxheim/load-balancer/member-state?vhost=smoke&member=origin-two&state=disable" \
    > "$TMP_DIR/member-disable.json"

curl -fsS \
    -H "Authorization: Bearer $FLUXHEIM_ADMIN_TOKEN" \
    "http://127.0.0.1:$ADMIN_PORT/_fluxheim/load-balancer/status" \
    > "$TMP_DIR/load-balancer-status-disabled.json"

if ! grep -q '"alias":"origin-two"' "$TMP_DIR/load-balancer-status-disabled.json" \
    || ! grep -q '"runtime_state_override":"disabled"' "$TMP_DIR/load-balancer-status-disabled.json"; then
    echo "load balancer status endpoint did not report disabled runtime override" >&2
    cat "$TMP_DIR/load-balancer-status-disabled.json" >&2
    cat "$TMP_DIR/member-disable.json" >&2
    exit 1
fi

DISABLED_RESPONSES="$TMP_DIR/disabled-responses.txt"
: > "$DISABLED_RESPONSES"
for _ in 1 2 3 4; do
    curl -fsS "http://127.0.0.1:$FLUXHEIM_PORT/control-plane" >> "$DISABLED_RESPONSES"
done

if [ "$(grep -c '^origin-one$' "$DISABLED_RESPONSES")" -ne 4 ]; then
    echo "load balancer member-state disable did not remove origin-two from selection" >&2
    cat "$DISABLED_RESPONSES" >&2
    cat "$TMP_DIR/member-disable.json" >&2
    exit 1
fi

curl -fsS -X POST \
    -H "Authorization: Bearer $FLUXHEIM_ADMIN_TOKEN" \
    "http://127.0.0.1:$ADMIN_PORT/_fluxheim/load-balancer/member-state?vhost=smoke&member=origin-two&state=normal" \
    > "$TMP_DIR/member-normal.json"

kill "$ORIGIN_TWO_PID" 2>/dev/null || true
sleep 2

FAILOVER_RESPONSES="$TMP_DIR/failover-responses.txt"
: > "$FAILOVER_RESPONSES"
tries=0
failover_ok=0
while [ "$tries" -lt 20 ]; do
    : > "$FAILOVER_RESPONSES"
    failed=0
    for _ in 1 2 3 4 5 6; do
        if ! curl -fsS "http://127.0.0.1:$FLUXHEIM_PORT/failover" >> "$FAILOVER_RESPONSES"; then
            failed=1
            break
        fi
    done

    if [ "$failed" -eq 0 ] && [ "$(grep -c '^origin-one$' "$FAILOVER_RESPONSES")" -eq 6 ]; then
        failover_ok=1
        break
    fi

    tries=$((tries + 1))
    sleep 0.2
done

if [ "$failover_ok" -ne 1 ]; then
    echo "load balancer did not fail over to origin-one after origin-two stopped" >&2
    cat "$FAILOVER_RESPONSES" >&2
    exit 1
fi

kill "$ORIGIN_ONE_PID" 2>/dev/null || true
sleep 2

tries=0
while [ "$tries" -lt 20 ]; do
    status=$(curl -sS -o /dev/null -w "%{http_code}" "http://127.0.0.1:$FLUXHEIM_PORT/all-down" || true)
    if [ "$status" = "503" ]; then
        echo "load-balancer smoke passed"
        exit 0
    fi

    tries=$((tries + 1))
    sleep 0.2
done

echo "load balancer did not return configured all-down status 503, got $status" >&2
exit 1
