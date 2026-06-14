#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/fluxheim-udp-smoke.XXXXXX")
KEEP_LOGS=${FLUXHEIM_SMOKE_KEEP_LOGS:-0}
UDP_SMOKE_ITERATIONS=${FLUXHEIM_UDP_SMOKE_ITERATIONS:-25}

case "$UDP_SMOKE_ITERATIONS" in
    '' | *[!0-9]*)
        echo "FLUXHEIM_UDP_SMOKE_ITERATIONS must be a positive integer" >&2
        exit 2
        ;;
esac

if [ "$UDP_SMOKE_ITERATIONS" -eq 0 ]; then
    echo "FLUXHEIM_UDP_SMOKE_ITERATIONS must be greater than zero" >&2
    exit 2
fi

ports=$(python3 - <<'PY'
import socket

sockets = []
try:
    for _ in range(4):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", 0))
        sockets.append(sock)
    print(" ".join(str(sock.getsockname()[1]) for sock in sockets))
finally:
    for sock in sockets:
        sock.close()
PY
)

set -- $ports
DNS_LISTEN_PORT=$1
DNS_UPSTREAM_PORT=$2
SYSLOG_LISTEN_PORT=$3
SYSLOG_UPSTREAM_PORT=$4

FLUXHEIM_PID=
DNS_UPSTREAM_PID=
SYSLOG_UPSTREAM_PID=

cleanup() {
    status=$?

    for pid in "$FLUXHEIM_PID" "$DNS_UPSTREAM_PID" "$SYSLOG_UPSTREAM_PID"; do
        if [ -n "$pid" ]; then
            kill "$pid" 2>/dev/null || true
        fi
    done

    sleep 0.2

    for pid in "$FLUXHEIM_PID" "$DNS_UPSTREAM_PID" "$SYSLOG_UPSTREAM_PID"; do
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill -9 "$pid" 2>/dev/null || true
        fi
    done

    for pid in "$FLUXHEIM_PID" "$DNS_UPSTREAM_PID" "$SYSLOG_UPSTREAM_PID"; do
        if [ -n "$pid" ]; then
            wait "$pid" 2>/dev/null || true
        fi
    done

    if [ "$KEEP_LOGS" = "1" ] || [ "$status" -ne 0 ]; then
        echo "UDP smoke artifacts kept in $TMP_DIR" >&2
    else
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT INT TERM

cat > "$TMP_DIR/udp_backend.py" <<'PY'
import socket
import sys

mode = sys.argv[1]
host = sys.argv[2]
port = int(sys.argv[3])
log_path = sys.argv[4] if len(sys.argv) > 4 else None

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((host, port))

while True:
    payload, peer = sock.recvfrom(65535)
    if mode == "dns":
        if log_path:
            with open(log_path, "ab") as log:
                log.write(payload + b"\n")
                log.flush()
        if payload == b"cap":
            sock.sendto(b"x" * 512, peer)
        else:
            sock.sendto(b"dns:" + payload, peer)
    elif mode == "syslog":
        with open(log_path, "ab") as log:
            log.write(payload + b"\n")
            log.flush()
PY

cat > "$TMP_DIR/udp_request.py" <<'PY'
import socket
import sys
import time

host = sys.argv[1]
port = int(sys.argv[2])
payload = sys.argv[3].encode("ascii")
expected = sys.argv[4].encode("ascii")
deadline = time.monotonic() + 10.0
last_error = None

while time.monotonic() < deadline:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(0.5)
            sock.sendto(payload, (host, port))
            response, _peer = sock.recvfrom(65535)
        if response == expected:
            sys.exit(0)
        last_error = f"expected {expected!r}, got {response!r}"
    except OSError as error:
        last_error = str(error)
    time.sleep(0.1)

print(last_error or "UDP request timed out", file=sys.stderr)
sys.exit(1)
PY

cat > "$TMP_DIR/udp_request_len.py" <<'PY'
import socket
import sys
import time

host = sys.argv[1]
port = int(sys.argv[2])
payload = sys.argv[3].encode("ascii")
expected_len = int(sys.argv[4])
deadline = time.monotonic() + 10.0
last_error = None

while time.monotonic() < deadline:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(0.5)
            sock.sendto(payload, (host, port))
            response, _peer = sock.recvfrom(65535)
        if len(response) == expected_len:
            sys.exit(0)
        last_error = f"expected {expected_len} response bytes, got {len(response)}"
    except OSError as error:
        last_error = str(error)
    time.sleep(0.1)

print(last_error or "UDP request timed out", file=sys.stderr)
sys.exit(1)
PY

cat > "$TMP_DIR/udp_send.py" <<'PY'
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
payload = sys.argv[3].encode("ascii")

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.sendto(payload, (host, port))
PY

cat > "$TMP_DIR/udp_send_bytes.py" <<'PY'
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
size = int(sys.argv[3])
fill = sys.argv[4].encode("ascii")

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.sendto(fill * size, (host, port))
PY

cat > "$TMP_DIR/wait_file_contains.py" <<'PY'
import pathlib
import sys
import time

path = pathlib.Path(sys.argv[1])
expected = sys.argv[2].encode("ascii")
deadline = time.monotonic() + 10.0

while time.monotonic() < deadline:
    if path.exists() and expected in path.read_bytes():
        sys.exit(0)
    time.sleep(0.1)

print(f"timed out waiting for {expected!r} in {path}", file=sys.stderr)
if path.exists():
    print(path.read_text(errors="replace"), file=sys.stderr)
sys.exit(1)
PY

cat > "$TMP_DIR/wait_file_not_contains.py" <<'PY'
import pathlib
import sys
import time

path = pathlib.Path(sys.argv[1])
forbidden = sys.argv[2].encode("ascii")
deadline = time.monotonic() + 3.0

while time.monotonic() < deadline:
    if path.exists() and forbidden in path.read_bytes():
        print(f"unexpected {forbidden!r} in {path}", file=sys.stderr)
        print(path.read_text(errors="replace"), file=sys.stderr)
        sys.exit(1)
    time.sleep(0.1)

sys.exit(0)
PY

cat > "$TMP_DIR/fluxheim.toml" <<EOF
[server]
listen = []
tls_listen = []

[server.process]
pid_file = "$TMP_DIR/fluxheim.pid"
upgrade_sock = "$TMP_DIR/fluxheim-upgrade.sock"
certificate_reload_sock = "$TMP_DIR/fluxheim-cert-reload.sock"

[udp]
enabled = true

[[udp.routes]]
name = "dns-beta"
mode = "dns-load-balance"
listen = ["127.0.0.1:$DNS_LISTEN_PORT"]
upstream = "127.0.0.1:$DNS_UPSTREAM_PORT"
idle_timeout_secs = 1
response_timeout_secs = 1
max_datagram_bytes = 512
max_sessions = 32
max_sessions_per_source = 8
max_responses_per_source_per_second = 64
passive_health_enabled = true
passive_health_failures = 3
passive_health_ejection_secs = 2

[[udp.routes]]
name = "syslog-beta"
mode = "syslog-forward"
listen = ["127.0.0.1:$SYSLOG_LISTEN_PORT"]
upstream = "127.0.0.1:$SYSLOG_UPSTREAM_PORT"
idle_timeout_secs = 1
response_timeout_secs = 1
max_datagram_bytes = 512
max_sessions = 32
max_sessions_per_source = 8
max_responses_per_source_per_second = 64
passive_health_enabled = true
passive_health_failures = 3
passive_health_ejection_secs = 2
EOF

python3 "$TMP_DIR/udp_backend.py" dns 127.0.0.1 "$DNS_UPSTREAM_PORT" "$TMP_DIR/dns-received.log" >"$TMP_DIR/dns-upstream.log" 2>&1 &
DNS_UPSTREAM_PID=$!
python3 "$TMP_DIR/udp_backend.py" syslog 127.0.0.1 "$SYSLOG_UPSTREAM_PORT" "$TMP_DIR/syslog-received.log" >"$TMP_DIR/syslog-upstream.log" 2>&1 &
SYSLOG_UPSTREAM_PID=$!

"$ROOT_DIR/scripts/validate-features.sh" udp-proxy
(
    cd "$ROOT_DIR"
    cargo build --quiet --no-default-features --features udp-proxy
)

"$ROOT_DIR/target/debug/fluxheim" --config "$TMP_DIR/fluxheim.toml" >"$TMP_DIR/fluxheim.log" 2>&1 &
FLUXHEIM_PID=$!

iteration=1
while [ "$iteration" -le "$UDP_SMOKE_ITERATIONS" ]; do
    python3 "$TMP_DIR/udp_request.py" 127.0.0.1 "$DNS_LISTEN_PORT" "query-$iteration" "dns:query-$iteration"
    iteration=$((iteration + 1))
done
python3 "$TMP_DIR/udp_request_len.py" 127.0.0.1 "$DNS_LISTEN_PORT" cap 512
python3 "$TMP_DIR/udp_send_bytes.py" 127.0.0.1 "$DNS_LISTEN_PORT" 513 z
python3 "$TMP_DIR/wait_file_not_contains.py" "$TMP_DIR/dns-received.log" zzzzz
iteration=1
while [ "$iteration" -le "$UDP_SMOKE_ITERATIONS" ]; do
    python3 "$TMP_DIR/udp_send.py" 127.0.0.1 "$SYSLOG_LISTEN_PORT" "<13>fluxheim udp smoke $iteration"
    iteration=$((iteration + 1))
done
python3 "$TMP_DIR/wait_file_contains.py" "$TMP_DIR/syslog-received.log" "fluxheim udp smoke $UDP_SMOKE_ITERATIONS"

echo "UDP proxy smoke passed ($UDP_SMOKE_ITERATIONS iterations)"
