#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SMOKE_TMP_ROOT=$(sh "$ROOT_DIR/scripts/secure-smoke-tmp-root.sh")
tmp="$SMOKE_TMP_ROOT/fluxheim-graceful-drain-smoke-$$"
config="$tmp/fluxheim.toml"
ready="$tmp/client-ready"
continue_file="$tmp/client-continue"
client_result="$tmp/client-result"
server_log="$tmp/server.log"
timeout_log="$tmp/timeout.log"

cleanup() {
    if [ -n "${client_pid:-}" ]; then
        kill "$client_pid" 2>/dev/null || true
        wait "$client_pid" 2>/dev/null || true
    fi
    if [ -n "${server_pid:-}" ]; then
        kill "$server_pid" 2>/dev/null || true
        sleep 0.1
        kill -9 "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
    rm -rf "$tmp"
}

trap cleanup EXIT INT TERM

mkdir -p "$tmp/public" "$tmp/run"
printf '%s\n' 'graceful-drain-ok' > "$tmp/public/index.html"

port=$(python3 - <<'PY'
import socket

with socket.socket() as sock:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
PY
)

cat > "$config" <<EOF
[server]
listen = ["127.0.0.1:$port"]
default_vhost = "drain.test"

[server.process]
pid_file = "$tmp/run/fluxheim.pid"
upgrade_sock = "$tmp/run/fluxheim-upgrade.sock"
certificate_reload_sock = "$tmp/run/fluxheim-cert-reload.sock"
grace_period_seconds = 1
graceful_shutdown_timeout_seconds = 3

[logging]
level = "info"
format = "text"
target = "stderr"

[logging.access]
enabled = false
request_id = false

[proxy]
upstreams = ["127.0.0.1:9"]
upstream_tls = false

[tls]
enabled = false
backend = "rustls"

[cache]
enabled = false

[[vhosts]]
name = "drain.test"
hosts = ["drain.test"]

[vhosts.web]
root = "$tmp/public"
index_files = ["index.html"]
EOF

cargo build --quiet --locked
"$ROOT_DIR/target/debug/fluxheim" --config "$config" >"$server_log" 2>&1 &
server_pid=$!

for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    if python3 - "$port" <<'PY'
import socket
import sys

try:
    with socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=0.2):
        pass
except OSError:
    raise SystemExit(1)
PY
    then
        break
    fi
    sleep 0.1
done

python3 - "$port" "$ready" "$continue_file" "$client_result" <<'PY' &
import pathlib
import socket
import sys
import time

port = int(sys.argv[1])
ready = pathlib.Path(sys.argv[2])
continue_file = pathlib.Path(sys.argv[3])
result = pathlib.Path(sys.argv[4])

def response(sock):
    data = bytearray()
    while b"\r\n\r\n" not in data:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("connection closed before response headers")
        data.extend(chunk)
    head, body = bytes(data).split(b"\r\n\r\n", 1)
    length = None
    for line in head.split(b"\r\n")[1:]:
        name, _, value = line.partition(b":")
        if name.lower() == b"content-length":
            length = int(value.strip())
            break
    if length is None:
        raise RuntimeError("response missing content-length")
    while len(body) < length:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("connection closed before response body")
        body += chunk
    return head, body[:length]

with socket.create_connection(("127.0.0.1", port), timeout=2.0) as sock:
    sock.settimeout(2.0)
    sock.sendall(b"GET / HTTP/1.1\r\nHost: drain.test\r\n\r\n")
    first_head, first_body = response(sock)
    if b"200 OK" not in first_head or b"graceful-drain-ok" not in first_body:
        raise RuntimeError("initial keep-alive request failed")
    ready.touch()
    deadline = time.monotonic() + 5.0
    while not continue_file.exists():
        if time.monotonic() >= deadline:
            raise RuntimeError("timed out waiting to continue drain request")
        time.sleep(0.01)
    sock.sendall(
        b"GET / HTTP/1.1\r\nHost: drain.test\r\nConnection: close\r\n\r\n"
    )
    second_head, second_body = response(sock)
    if b"200 OK" not in second_head or b"graceful-drain-ok" not in second_body:
        raise RuntimeError("established request failed during drain")
    result.write_text("ok\n", encoding="ascii")
PY
client_pid=$!

for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    if [ -f "$ready" ]; then
        break
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
        cat "$server_log" >&2
        echo "graceful drain smoke failed: Fluxheim exited before client readiness" >&2
        exit 1
    fi
    sleep 0.1
done

if [ ! -f "$ready" ]; then
    echo "graceful drain smoke failed: keep-alive client did not become ready" >&2
    exit 1
fi

kill -TERM "$server_pid"
sleep 1.2

if python3 - "$port" <<'PY'
import socket
import sys

try:
    with socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=0.3):
        pass
except OSError:
    raise SystemExit(1)
PY
then
    echo "graceful drain smoke failed: listener accepted after grace period" >&2
    exit 1
fi

if ! kill -0 "$server_pid" 2>/dev/null; then
    cat "$server_log" >&2
    echo "graceful drain smoke failed: process exited before established connection drained" >&2
    exit 1
fi

: > "$continue_file"
wait "$client_pid"
client_pid=""

if [ "$(cat "$client_result")" != "ok" ]; then
    echo "graceful drain smoke failed: established connection result missing" >&2
    exit 1
fi

for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
    if ! kill -0 "$server_pid" 2>/dev/null; then
        wait "$server_pid"
        server_pid=""
        break
    fi
    sleep 0.1
done

if [ -n "$server_pid" ]; then
    cat "$server_log" >&2
    echo "graceful drain smoke failed: Fluxheim exceeded shutdown bound" >&2
    exit 1
fi

grep -q "native runtime draining established work; timeout=3s" "$server_log"

"$ROOT_DIR/target/debug/fluxheim" --config "$config" >"$timeout_log" 2>&1 &
server_pid=$!
rm -f "$ready"
python3 - "$port" "$ready" <<'PY' &
import pathlib
import socket
import sys
import time

port = int(sys.argv[1])
ready = pathlib.Path(sys.argv[2])
deadline = time.monotonic() + 5.0
while True:
    try:
        sock = socket.create_connection(("127.0.0.1", port), timeout=0.2)
        break
    except OSError:
        if time.monotonic() >= deadline:
            raise
        time.sleep(0.05)
sock.settimeout(2.0)
sock.sendall(b"GET / HTTP/1.1\r\nHost: drain.test\r\n\r\n")
data = bytearray()
while b"\r\n\r\n" not in data:
    chunk = sock.recv(4096)
    if not chunk:
        raise RuntimeError("connection closed before timeout-case response")
    data.extend(chunk)
ready.touch()
try:
    time.sleep(10.0)
finally:
    sock.close()
PY
client_pid=$!

for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    if [ -f "$ready" ]; then
        break
    fi
    sleep 0.1
done
if [ ! -f "$ready" ]; then
    cat "$timeout_log" >&2
    echo "graceful drain smoke failed: timeout client did not become ready" >&2
    exit 1
fi

kill -TERM "$server_pid"
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30 31 32 33 34 35 36 37 38 39 40 41 42 43 44 45 46 47 48 49 50; do
    if ! kill -0 "$server_pid" 2>/dev/null; then
        wait "$server_pid"
        server_pid=""
        break
    fi
    sleep 0.1
done

if [ -n "$server_pid" ]; then
    cat "$timeout_log" >&2
    echo "graceful drain smoke failed: stuck connection exceeded hard shutdown bound" >&2
    exit 1
fi
kill "$client_pid" 2>/dev/null || true
wait "$client_pid" 2>/dev/null || true
client_pid=""
grep -q "native runtime graceful drain timed out after 3s" "$timeout_log"

echo "graceful drain smoke passed"
