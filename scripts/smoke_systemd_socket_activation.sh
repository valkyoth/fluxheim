#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SMOKE_TMP_ROOT=$(sh "$ROOT_DIR/scripts/secure-smoke-tmp-root.sh")
tmp="$SMOKE_TMP_ROOT/fluxheim-systemd-socket-smoke-$$"
config="$tmp/fluxheim.toml"
server_log="$tmp/server.log"
notify_log="$tmp/notify.log"
notify_socket="fluxheim-notify-$$"
notify_bound="$tmp/notify-bound"
notify_ready="$tmp/notify-ready"
missing_notify_socket="/tmp/fluxheim-missing-notify-$$.sock"

cleanup() {
    if [ -n "${server_pid:-}" ]; then
        kill "$server_pid" 2>/dev/null || true
        wait "$server_pid" 2>/dev/null || true
    fi
    if [ -n "${notifier_pid:-}" ]; then
        kill "$notifier_pid" 2>/dev/null || true
        wait "$notifier_pid" 2>/dev/null || true
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

python3 - "$notify_socket" "$notify_bound" "$notify_ready" "$notify_log" <<'PY' &
import pathlib
import socket
import sys
import time

name = "\0" + sys.argv[1]
bound = pathlib.Path(sys.argv[2])
ready = pathlib.Path(sys.argv[3])
log = pathlib.Path(sys.argv[4])
messages = []

with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as receiver:
    receiver.bind(name)
    receiver.settimeout(10.0)
    bound.touch()
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        message = receiver.recv(4096).decode("utf-8", errors="strict")
        messages.append(message)
        log.write_text("\n".join(messages), encoding="utf-8")
        if "READY=1" in message:
            ready.touch()
        if "STOPPING=1" in message:
            break
    else:
        raise RuntimeError("timed out waiting for readiness and stopping notifications")
PY
notifier_pid=$!

for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    if [ -f "$notify_bound" ]; then
        break
    fi
    sleep 0.05
done
if [ ! -f "$notify_bound" ]; then
    echo "systemd socket activation smoke failed: notification receiver did not bind" >&2
    exit 1
fi

python3 - "$ROOT_DIR/target/debug/fluxheim" "$config" "$port" "$notify_socket" <<'PY' >"$server_log" 2>&1 &
import os
import socket
import sys

binary, config, port_text, notify_socket = sys.argv[1:]
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
environment["NOTIFY_SOCKET"] = "@" + notify_socket
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
if [ ! -f "$notify_ready" ]; then
    cat "$server_log" >&2
    cat "$notify_log" >&2 2>/dev/null || true
    echo "systemd socket activation smoke failed: READY=1 was not observed" >&2
    exit 1
fi
grep -q "STATUS=Fluxheim native runtime ready" "$notify_log"

kill -TERM "$server_pid"
wait "$server_pid"
server_pid=""
wait "$notifier_pid"
notifier_pid=""
grep -q "STOPPING=1" "$notify_log"
grep -q "STATUS=Fluxheim native runtime draining" "$notify_log"

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

if python3 - "$ROOT_DIR/target/debug/fluxheim" "$config" <<'PY' \
    >"$tmp/non-socket.log" 2>&1
import os
import sys

binary, config = sys.argv[1:]
source = os.open(config, os.O_RDONLY)
if source != 3:
    os.dup2(source, 3, inheritable=True)
else:
    os.set_inheritable(3, True)
environment = os.environ.copy()
environment["LISTEN_FDS"] = "1"
environment["LISTEN_PID"] = str(os.getpid())
environment["LISTEN_FDNAMES"] = "http"
os.execve(binary, [binary, "--config", config], environment)
PY
then
    echo "systemd socket activation smoke failed: regular file was accepted as listener" >&2
    exit 1
fi
grep -q "is not a socket" "$tmp/non-socket.log"

if timeout 5 python3 - "$ROOT_DIR/target/debug/fluxheim" "$config" "$port" <<'PY' \
    >"$tmp/non-listening.log" 2>&1
import os
import socket
import sys

binary, config, local_port_text = sys.argv[1:]
remote = socket.socket()
remote.bind(("127.0.0.1", 0))
remote.listen(1)
connected = socket.socket()
connected.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
connected.bind(("127.0.0.1", int(local_port_text)))
connected.connect(remote.getsockname())
peer, _ = remote.accept()
if connected.fileno() != 3:
    os.dup2(connected.fileno(), 3, inheritable=True)
else:
    os.set_inheritable(3, True)
environment = os.environ.copy()
environment["LISTEN_FDS"] = "1"
environment["LISTEN_PID"] = str(os.getpid())
environment["LISTEN_FDNAMES"] = "http"
os.execve(binary, [binary, "--config", config], environment)
PY
then
    echo "systemd socket activation smoke failed: connected stream was accepted as listener" >&2
    exit 1
fi
grep -q "is not in listening state" "$tmp/non-listening.log"

if NOTIFY_SOCKET="$missing_notify_socket" "$ROOT_DIR/target/debug/fluxheim" \
    --config "$config" >"$tmp/missing-notify.log" 2>&1; then
    echo "systemd socket activation smoke failed: unreachable readiness socket was ignored" >&2
    exit 1
fi
grep -q "failed to send notify datagram" "$tmp/missing-notify.log"

echo "systemd socket activation smoke passed"
