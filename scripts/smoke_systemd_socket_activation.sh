#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SMOKE_TMP_ROOT=$(sh "$ROOT_DIR/scripts/secure-smoke-tmp-root.sh")
tmp="$SMOKE_TMP_ROOT/fluxheim-systemd-socket-smoke-$$"
config="$tmp/fluxheim.toml"
server_log="$tmp/server.log"

cleanup() {
    if [ -n "${server_pid:-}" ]; then
        kill "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
    rm -rf "$tmp"
}

trap cleanup EXIT INT TERM

mkdir -p "$tmp/public" "$tmp/run"
printf '%s\n' 'socket-activation-ok' > "$tmp/public/index.html"

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
default_vhost = "activation.test"

[server.process]
pid_file = "$tmp/run/fluxheim.pid"
upgrade_sock = "$tmp/run/fluxheim-upgrade.sock"
certificate_reload_sock = "$tmp/run/fluxheim-cert-reload.sock"
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
name = "activation.test"
hosts = ["activation.test"]

[vhosts.web]
root = "$tmp/public"
index_files = ["index.html"]
EOF

cargo build --quiet --locked

python3 - "$ROOT_DIR/target/debug/fluxheim" "$config" "$port" <<'PY' >"$server_log" 2>&1 &
import os
import socket
import sys

binary, config, port_text = sys.argv[1:]
listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
listener.bind(("127.0.0.1", int(port_text)))
listener.listen(128)
if listener.fileno() != 3:
    os.dup2(listener.fileno(), 3, inheritable=True)
else:
    os.set_inheritable(3, True)
environment = os.environ.copy()
environment["LISTEN_FDS"] = "1"
environment["LISTEN_PID"] = str(os.getpid())
environment["LISTEN_FDNAMES"] = "http"
os.execve(binary, [binary, "--config", config], environment)
PY
server_pid=$!

for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
    if python3 - "$port" <<'PY'
import socket
import sys

try:
    with socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=0.2) as sock:
        sock.sendall(
            b"GET / HTTP/1.1\r\nHost: activation.test\r\nConnection: close\r\n\r\n"
        )
        response = bytearray()
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            response.extend(chunk)
except OSError:
    raise SystemExit(1)

if b"HTTP/1.1 200 OK" not in response or b"socket-activation-ok" not in response:
    raise SystemExit(1)
PY
    then
        break
    fi
    if ! kill -0 "$server_pid" 2>/dev/null; then
        cat "$server_log" >&2
        echo "systemd socket activation smoke failed: Fluxheim exited during startup" >&2
        exit 1
    fi
    sleep 0.1
done

if ! kill -0 "$server_pid" 2>/dev/null; then
    cat "$server_log" >&2
    echo "systemd socket activation smoke failed: inherited listener did not remain active" >&2
    exit 1
fi

kill -TERM "$server_pid"
wait "$server_pid"
server_pid=""

if LISTEN_FDS=1 LISTEN_PID=999999 "$ROOT_DIR/target/debug/fluxheim" \
    --config "$config" >"$tmp/wrong-pid.log" 2>&1; then
    echo "systemd socket activation smoke failed: wrong LISTEN_PID was accepted" >&2
    exit 1
fi
grep -q "LISTEN_PID targets process" "$tmp/wrong-pid.log"

if LISTEN_PID=999999 "$ROOT_DIR/target/debug/fluxheim" \
    --config "$config" >"$tmp/partial-environment.log" 2>&1; then
    echo "systemd socket activation smoke failed: partial activation environment was accepted" >&2
    exit 1
fi
grep -q "requires LISTEN_FDS" "$tmp/partial-environment.log"

echo "systemd socket activation smoke passed"
