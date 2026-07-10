#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SMOKE_TMP_ROOT=$(sh "$ROOT_DIR/scripts/secure-smoke-tmp-root.sh")
TMP_DIR=$(mktemp -d "$SMOKE_TMP_ROOT/fluxheim-stream-smoke.XXXXXX")
KEEP_LOGS=${FLUXHEIM_SMOKE_KEEP_LOGS:-0}

if ! command -v openssl >/dev/null 2>&1; then
    echo "stream proxy smoke requires openssl to generate a temporary TLS upstream certificate" >&2
    exit 1
fi

ports=$(python3 - <<'PY'
import socket

sockets = []
try:
    for _ in range(9):
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
STREAM_PORT=$1
PRIMARY_PORT=$2
BACKUP_PORT=$3
PROXY_STREAM_PORT=$4
PROXY_UPSTREAM_PORT=$5
PROXY_RECV_STREAM_PORT=$6
PROXY_RECV_UPSTREAM_PORT=$7
TLS_STREAM_PORT=$8
TLS_UPSTREAM_PORT=$9

FLUXHEIM_PID=
PRIMARY_PID=
BACKUP_PID=
PROXY_UPSTREAM_PID=
PROXY_RECV_UPSTREAM_PID=
TLS_UPSTREAM_PID=

cleanup() {
    status=$?

    for pid in "$FLUXHEIM_PID" "$PRIMARY_PID" "$BACKUP_PID" "$PROXY_UPSTREAM_PID" "$PROXY_RECV_UPSTREAM_PID" "$TLS_UPSTREAM_PID"; do
        if [ -n "$pid" ]; then
            kill "$pid" 2>/dev/null || true
        fi
    done

    sleep 0.2

    for pid in "$FLUXHEIM_PID" "$PRIMARY_PID" "$BACKUP_PID" "$PROXY_UPSTREAM_PID" "$PROXY_RECV_UPSTREAM_PID" "$TLS_UPSTREAM_PID"; do
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill -9 "$pid" 2>/dev/null || true
        fi
    done

    for pid in "$FLUXHEIM_PID" "$PRIMARY_PID" "$BACKUP_PID" "$PROXY_UPSTREAM_PID" "$PROXY_RECV_UPSTREAM_PID" "$TLS_UPSTREAM_PID"; do
        if [ -n "$pid" ]; then
            wait "$pid" 2>/dev/null || true
        fi
    done

    if [ "$KEEP_LOGS" = "1" ] || [ "$status" -ne 0 ]; then
        echo "stream smoke artifacts kept in $TMP_DIR" >&2
    else
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT INT TERM

cat > "$TMP_DIR/tcp_server.py" <<'PY'
import socketserver
import sys


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request.recv(4096)
        self.request.sendall(self.server.label.encode("ascii") + b":" + data)


if __name__ == "__main__":
    host = sys.argv[1]
    port = int(sys.argv[2])
    label = sys.argv[3]
    with socketserver.ThreadingTCPServer((host, port), Handler) as server:
        server.allow_reuse_address = True
        server.label = label
        server.serve_forever()
PY

cat > "$TMP_DIR/proxy_protocol_server.py" <<'PY'
import socketserver
import sys


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        line = b""
        while not line.endswith(b"\r\n") and len(line) < 256:
            chunk = self.request.recv(1)
            if not chunk:
                break
            line += chunk
        data = self.request.recv(4096)
        if line.startswith(b"PROXY TCP") and data == b"probe":
            self.request.sendall(b"proxy-v1-ok")
        else:
            self.request.sendall(b"proxy-v1-bad:" + line + data)


if __name__ == "__main__":
    host = sys.argv[1]
    port = int(sys.argv[2])
    with socketserver.ThreadingTCPServer((host, port), Handler) as server:
        server.allow_reuse_address = True
        server.serve_forever()
PY

cat > "$TMP_DIR/tls_server.py" <<'PY'
import socketserver
import ssl
import sys


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request.recv(4096)
        self.request.sendall(b"tls:" + data)


if __name__ == "__main__":
    host = sys.argv[1]
    port = int(sys.argv[2])
    cert = sys.argv[3]
    key = sys.argv[4]
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert, keyfile=key)
    with socketserver.ThreadingTCPServer((host, port), Handler) as server:
        server.allow_reuse_address = True
        server.socket = context.wrap_socket(server.socket, server_side=True)
        server.serve_forever()
PY

cat > "$TMP_DIR/stream_client.py" <<'PY'
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
payload = sys.argv[3].encode("ascii")
expected = sys.argv[4].encode("ascii")

with socket.create_connection((host, port), timeout=3.0) as sock:
    sock.settimeout(3.0)
    sock.sendall(payload)
    sock.shutdown(socket.SHUT_WR)
    received = sock.recv(4096)

if received != expected:
    print(f"expected {expected!r}, got {received!r}", file=sys.stderr)
    sys.exit(1)
PY

cat > "$TMP_DIR/proxy_protocol_client.py" <<'PY'
import socket
import sys

host = sys.argv[1]
port = int(sys.argv[2])
payload = sys.argv[3].encode("ascii")
expected = sys.argv[4].encode("ascii")

with socket.create_connection((host, port), timeout=3.0) as sock:
    sock.settimeout(3.0)
    sock.sendall(
        b"PROXY TCP4 198.51.100.10 203.0.113.20 50000 443\r\n" + payload
    )
    sock.shutdown(socket.SHUT_WR)
    received = sock.recv(4096)

if received != expected:
    print(f"expected {expected!r}, got {received!r}", file=sys.stderr)
    sys.exit(1)
PY

mkdir -p "$TMP_DIR/tls"
openssl req \
    -x509 \
    -newkey rsa:2048 \
    -nodes \
    -sha256 \
    -days 1 \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost" \
    -addext "basicConstraints=critical,CA:FALSE" \
    -addext "keyUsage=digitalSignature,keyEncipherment" \
    -addext "extendedKeyUsage=serverAuth" \
    -keyout "$TMP_DIR/tls/upstream-key.pem" \
    -out "$TMP_DIR/tls/upstream-cert.pem" >/dev/null 2>&1
chmod 600 "$TMP_DIR/tls/upstream-key.pem"

cat > "$TMP_DIR/fluxheim.toml" <<EOF
[server]
listen = []

[server.process]
pid_file = "$TMP_DIR/fluxheim.pid"
upgrade_sock = "$TMP_DIR/fluxheim-upgrade.sock"
certificate_reload_sock = "$TMP_DIR/fluxheim-cert-reload.sock"

[stream]
enabled = true

[[stream.routes]]
name = "stream-main"
listen = ["127.0.0.1:$STREAM_PORT"]
upstreams = ["127.0.0.1:$PRIMARY_PORT", "127.0.0.1:$BACKUP_PORT"]
upstream_weights = [1, 1]
upstream_aliases = ["primary", "backup"]
backup_upstreams = ["127.0.0.1:$BACKUP_PORT"]
connect_timeout_secs = 1
idle_timeout_secs = 5
max_connection_secs = 10
max_connection_bytes = 1024

[[stream.routes]]
name = "stream-proxy-protocol"
listen = ["127.0.0.1:$PROXY_STREAM_PORT"]
upstream = "127.0.0.1:$PROXY_UPSTREAM_PORT"
connect_timeout_secs = 1
idle_timeout_secs = 5
upstream_proxy_protocol = "v1"

[[stream.routes]]
name = "stream-proxy-receive"
listen = ["127.0.0.1:$PROXY_RECV_STREAM_PORT"]
upstream = "127.0.0.1:$PROXY_RECV_UPSTREAM_PORT"
connect_timeout_secs = 1
idle_timeout_secs = 5
downstream_proxy_protocol = "v1"
trusted_proxies = ["127.0.0.1/32"]

[[stream.routes]]
name = "stream-upstream-tls"
listen = ["127.0.0.1:$TLS_STREAM_PORT"]
upstream = "127.0.0.1:$TLS_UPSTREAM_PORT"
connect_timeout_secs = 1
idle_timeout_secs = 5
upstream_tls = true
upstream_sni = "localhost"
upstream_ca_path = "$TMP_DIR/tls/upstream-cert.pem"
EOF

wait_tcp() {
    port=$1
    tries=0
    while [ "$tries" -lt 100 ]; do
        if python3 - "$port" <<'PY' >/dev/null 2>&1; then
import socket
import sys

with socket.create_connection(("127.0.0.1", int(sys.argv[1])), timeout=0.2):
    pass
PY
            return 0
        fi
        tries=$((tries + 1))
        sleep 0.1
    done

    echo "timed out waiting for TCP port $port" >&2
    return 1
}

python3 "$TMP_DIR/tcp_server.py" 127.0.0.1 "$PRIMARY_PORT" primary >"$TMP_DIR/primary.log" 2>&1 &
PRIMARY_PID=$!
python3 "$TMP_DIR/tcp_server.py" 127.0.0.1 "$BACKUP_PORT" backup >"$TMP_DIR/backup.log" 2>&1 &
BACKUP_PID=$!
python3 "$TMP_DIR/proxy_protocol_server.py" 127.0.0.1 "$PROXY_UPSTREAM_PORT" >"$TMP_DIR/proxy-upstream.log" 2>&1 &
PROXY_UPSTREAM_PID=$!
python3 "$TMP_DIR/tcp_server.py" 127.0.0.1 "$PROXY_RECV_UPSTREAM_PORT" pp-recv >"$TMP_DIR/proxy-recv-upstream.log" 2>&1 &
PROXY_RECV_UPSTREAM_PID=$!
python3 "$TMP_DIR/tls_server.py" 127.0.0.1 "$TLS_UPSTREAM_PORT" "$TMP_DIR/tls/upstream-cert.pem" "$TMP_DIR/tls/upstream-key.pem" >"$TMP_DIR/tls-upstream.log" 2>&1 &
TLS_UPSTREAM_PID=$!

wait_tcp "$PRIMARY_PORT"
wait_tcp "$BACKUP_PORT"
wait_tcp "$PROXY_UPSTREAM_PORT"
wait_tcp "$PROXY_RECV_UPSTREAM_PORT"
wait_tcp "$TLS_UPSTREAM_PORT"

"$ROOT_DIR/scripts/validate-features.sh" stream-proxy,tls-rustls,security
(
    cd "$ROOT_DIR"
    cargo build --quiet --no-default-features --features stream-proxy,tls-rustls,security
)

"$ROOT_DIR/target/debug/fluxheim" --config "$TMP_DIR/fluxheim.toml" >"$TMP_DIR/fluxheim.log" 2>&1 &
FLUXHEIM_PID=$!

wait_tcp "$STREAM_PORT"
wait_tcp "$PROXY_STREAM_PORT"
wait_tcp "$PROXY_RECV_STREAM_PORT"
wait_tcp "$TLS_STREAM_PORT"

python3 "$TMP_DIR/stream_client.py" 127.0.0.1 "$STREAM_PORT" probe primary:probe

kill "$PRIMARY_PID" 2>/dev/null || true
wait "$PRIMARY_PID" 2>/dev/null || true
PRIMARY_PID=
sleep 0.3

python3 "$TMP_DIR/stream_client.py" 127.0.0.1 "$STREAM_PORT" probe backup:probe
python3 "$TMP_DIR/stream_client.py" 127.0.0.1 "$PROXY_STREAM_PORT" probe proxy-v1-ok
python3 "$TMP_DIR/proxy_protocol_client.py" 127.0.0.1 "$PROXY_RECV_STREAM_PORT" probe pp-recv:probe
python3 "$TMP_DIR/stream_client.py" 127.0.0.1 "$TLS_STREAM_PORT" probe tls:probe

echo "stream proxy smoke passed"
