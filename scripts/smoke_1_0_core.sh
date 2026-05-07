#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/fluxheim-1-0-core-smoke.XXXXXX")
KEEP_LOGS=${FLUXHEIM_SMOKE_KEEP_LOGS:-0}

if ! command -v openssl >/dev/null 2>&1; then
    echo "1.0 core smoke requires openssl to generate a temporary TLS certificate" >&2
    exit 1
fi

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
FLUXHEIM_TLS_PORT=$2
ORIGIN_PORT=$3

ORIGIN_PID=
FLUXHEIM_PID=

cleanup() {
    status=$?

    for pid in "$FLUXHEIM_PID" "$ORIGIN_PID"; do
        if [ -n "$pid" ]; then
            kill "$pid" 2>/dev/null || true
        fi
    done

    sleep 0.2

    for pid in "$FLUXHEIM_PID" "$ORIGIN_PID"; do
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill -9 "$pid" 2>/dev/null || true
        fi
    done

    for pid in "$FLUXHEIM_PID" "$ORIGIN_PID"; do
        if [ -n "$pid" ]; then
            wait "$pid" 2>/dev/null || true
        fi
    done

    if [ "$KEEP_LOGS" = "1" ] || [ "$status" -ne 0 ]; then
        echo "1.0 core smoke artifacts kept in $TMP_DIR" >&2
    else
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT INT TERM

mkdir -p "$TMP_DIR/public"
mkdir -p "$TMP_DIR/tls"
mkdir -p "$TMP_DIR/run"
printf '%s\n' '<!doctype html><title>Fluxheim 1.0 smoke</title><h1>static-ok</h1>' > "$TMP_DIR/public/index.html"
printf '%s\n' 'secret' > "$TMP_DIR/public/.secret"

openssl req \
    -x509 \
    -newkey rsa:2048 \
    -nodes \
    -sha256 \
    -days 1 \
    -subj "/CN=localhost" \
    -keyout "$TMP_DIR/tls/key.pem" \
    -out "$TMP_DIR/tls/fullchain.pem" >/dev/null 2>&1
chmod 600 "$TMP_DIR/tls/key.pem"

cat > "$TMP_DIR/origin.py" <<'PY'
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def _write_response(self, include_body):
        body = "\n".join(
            [
                "proxy-ok",
                f"path={self.path}",
                f"host={self.headers.get('host', '')}",
                f"xfh={self.headers.get('x-forwarded-host', '')}",
                f"xfp={self.headers.get('x-forwarded-proto', '')}",
                f"xri={self.headers.get('x-real-ip', '')}",
                f"xou={self.headers.get('x-original-uri', '')}",
                f"xpb={self.headers.get('x-proxy-by', '')}",
            ]
        ).encode("ascii")
        self.send_response(200)
        self.send_header("content-type", "text/plain; charset=ascii")
        self.send_header("content-length", str(len(body)))
        self.send_header("server", "origin-test")
        self.send_header("x-powered-by", "origin-test")
        self.end_headers()
        if include_body:
            self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/room") and self.headers.get("upgrade", "").lower() == "websocket":
            self.send_response(101, "Switching Protocols")
            self.send_header("upgrade", "websocket")
            self.send_header("connection", "Upgrade")
            self.send_header("sec-websocket-accept", "HSmrc0sMlYUkAGmm5OPpG2HaGWk=")
            self.send_header("x-upstream-path", self.path)
            self.end_headers()
            data = self.connection.recv(64)
            if data:
                self.connection.sendall(b"echo:" + data)
            self.close_connection = True
            return
        self._write_response(True)

    def do_HEAD(self):
        self._write_response(False)

    def log_message(self, _format, *args):
        return


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
PY

cat > "$TMP_DIR/fluxheim.toml" <<EOF
[server]
listen = ["127.0.0.1:$FLUXHEIM_PORT"]
tls_listen = ["127.0.0.1:$FLUXHEIM_TLS_PORT"]
default_vhost = "static.test"
trusted_proxies = []

[server.process]
daemon = false
pid_file = "$TMP_DIR/run/fluxheim.pid"
upgrade_sock = "$TMP_DIR/run/fluxheim-upgrade.sock"

[server.limits]
max_request_header_bytes = "64KiB"
max_uri_bytes = "8KiB"
max_request_headers = 100
max_request_body_bytes = "1MiB"

[server.https_redirect]
enabled = false
status = 308
target_port = $FLUXHEIM_TLS_PORT

[logging]
level = "warn"
format = "text"

[logging.access]
enabled = false
request_id = false

[headers.request]
enabled = true
strip_inbound_client_ip_headers = true
x_forwarded_for = "replace"
x_real_ip = true
x_forwarded_host = true
x_forwarded_proto = true
forwarded = false
unset = ["x-powered-by"]

[headers.request.set]
x-forwarded-host = "{host}"
x-original-uri = "{uri}"
x-proxy-by = "Fluxheim"

[headers.response]
enabled = true
x_content_type_options = "nosniff"
x_frame_options = "DENY"
referrer_policy = "no-referrer"
unset = ["server", "x-powered-by"]

[headers.response.set]
cache-control = "public, max-age=60"

[proxy]
upstreams = ["127.0.0.1:$ORIGIN_PORT"]
upstream_tls = false

[tls]
enabled = true
backend = "rustls"

[[tls.certificates]]
cert_path = "$TMP_DIR/tls/fullchain.pem"
key_path = "$TMP_DIR/tls/key.pem"

[cache]
enabled = false

[web]
index_files = ["index.html"]
deny_dotfiles = true
cache_control = "public, max-age=60"

[[vhosts]]
name = "static.test"
hosts = ["static.test"]

[vhosts.web]
root = "$TMP_DIR/public"
index_files = ["index.html"]
deny_dotfiles = true
cache_control = "public, max-age=60"

[[vhosts]]
name = "app.test"
hosts = ["app.test"]
max_request_body_bytes = "32B"

[vhosts.proxy]
upstreams = ["127.0.0.1:$ORIGIN_PORT"]
upstream_tls = false

[[vhosts.routes]]
name = "chat"
path_prefix = "/chat/"
strip_prefix = "/chat/"
max_request_body_bytes = "64MiB"

[vhosts.routes.proxy]
upstreams = ["127.0.0.1:$ORIGIN_PORT"]
upstream_tls = false
read_timeout_secs = 600
send_timeout_secs = 600

[[vhosts.routes]]
name = "fallback"
fallback = true

[vhosts.routes.proxy]
upstreams = ["127.0.0.1:$ORIGIN_PORT"]
upstream_tls = false
EOF

wait_http() {
    url=$1
    host=$2
    tries=0
    while [ "$tries" -lt 100 ]; do
        if curl -fsS -H "Host: $host" "$url" >/dev/null 2>&1; then
            return 0
        fi
        tries=$((tries + 1))
        sleep 0.1
    done

    echo "timed out waiting for $url host=$host" >&2
    return 1
}

wait_https() {
    url=$1
    host=$2
    tries=0
    while [ "$tries" -lt 100 ]; do
        if curl -kfsS -H "Host: $host" "$url" >/dev/null 2>&1; then
            return 0
        fi
        tries=$((tries + 1))
        sleep 0.1
    done

    echo "timed out waiting for $url host=$host" >&2
    return 1
}

python3 "$TMP_DIR/origin.py" "$ORIGIN_PORT" >"$TMP_DIR/origin.log" 2>&1 &
ORIGIN_PID=$!

wait_http "http://127.0.0.1:$ORIGIN_PORT/" "origin.test"

(
    cd "$ROOT_DIR"
    scripts/validate-1-0-core.sh check
    if ! cargo run --quiet -- --check-config --check-tls-storage --config "$TMP_DIR/fluxheim.toml" >"$TMP_DIR/tls-storage-check.log" 2>&1; then
        cat "$TMP_DIR/tls-storage-check.log" >&2
        exit 1
    fi
    python3 - "$TMP_DIR/fluxheim.toml" "$TMP_DIR/fluxheim-conflicting-upstreams.toml" "$ORIGIN_PORT" <<'PY'
import sys

source, target, port = sys.argv[1], sys.argv[2], sys.argv[3]
raw = open(source, encoding="utf-8").read()
raw = raw.replace(
    f'[proxy]\nupstreams = ["127.0.0.1:{port}"]',
    f'[proxy]\nupstream = "127.0.0.1:{port}"\nupstreams = ["127.0.0.1:{port}"]',
    1,
)
open(target, "w", encoding="utf-8").write(raw)
PY
    if cargo run --quiet -- --check-config --config "$TMP_DIR/fluxheim-conflicting-upstreams.toml" >"$TMP_DIR/conflicting-upstreams-check.log" 2>&1; then
        echo "1.0 core smoke failed: conflicting proxy upstream aliases were accepted" >&2
        exit 1
    fi
    if ! grep -q "proxy.upstream and proxy.upstreams cannot both be configured" "$TMP_DIR/conflicting-upstreams-check.log"; then
        echo "1.0 core smoke failed: conflicting proxy upstream aliases returned an unexpected error" >&2
        cat "$TMP_DIR/conflicting-upstreams-check.log" >&2
        exit 1
    fi
    cargo build --quiet
)

"$ROOT_DIR/target/debug/fluxheim" --config "$TMP_DIR/fluxheim.toml" >"$TMP_DIR/fluxheim.log" 2>&1 &
FLUXHEIM_PID=$!

wait_http "http://127.0.0.1:$FLUXHEIM_PORT/" "static.test"
wait_https "https://127.0.0.1:$FLUXHEIM_TLS_PORT/" "static.test"

STATIC_BODY="$TMP_DIR/static-body.txt"
curl -fsS -H "Host: static.test" "http://127.0.0.1:$FLUXHEIM_PORT/" > "$STATIC_BODY"
if ! grep -q "static-ok" "$STATIC_BODY"; then
    echo "1.0 core smoke failed: static vhost did not return expected body" >&2
    cat "$STATIC_BODY" >&2
    exit 1
fi

STATIC_HEADERS="$TMP_DIR/static-headers.txt"
curl -fsSI -H "Host: static.test" "http://127.0.0.1:$FLUXHEIM_PORT/" > "$STATIC_HEADERS"
if ! grep -qi '^x-content-type-options: nosniff' "$STATIC_HEADERS"; then
    echo "1.0 core smoke failed: static response missing x-content-type-options" >&2
    cat "$STATIC_HEADERS" >&2
    exit 1
fi
if grep -qi '^server:' "$STATIC_HEADERS"; then
    echo "1.0 core smoke failed: static response exposed server header" >&2
    cat "$STATIC_HEADERS" >&2
    exit 1
fi

dot_status="$(curl -sS -o /dev/null -w '%{http_code}' -H "Host: static.test" "http://127.0.0.1:$FLUXHEIM_PORT/.secret" 2>/dev/null || true)"
if [ "$dot_status" = "200" ]; then
    echo "1.0 core smoke failed: dotfile was served" >&2
    exit 1
fi

TLS_STATIC_BODY="$TMP_DIR/tls-static-body.txt"
curl -kfsS -H "Host: static.test" "https://127.0.0.1:$FLUXHEIM_TLS_PORT/" > "$TLS_STATIC_BODY"
if ! grep -q "static-ok" "$TLS_STATIC_BODY"; then
    echo "1.0 core smoke failed: TLS static vhost did not return expected body" >&2
    cat "$TLS_STATIC_BODY" >&2
    exit 1
fi

PROXY_BODY="$TMP_DIR/proxy-body.txt"
curl -fsS -H "Host: app.test" "http://127.0.0.1:$FLUXHEIM_PORT/api/check" > "$PROXY_BODY"
for expected in "proxy-ok" "path=/api/check" "xfh=app.test" "xfp=http" "xri=127.0.0.1" "xou=/api/check" "xpb=Fluxheim"; do
    if ! grep -q "^$expected$" "$PROXY_BODY"; then
        echo "1.0 core smoke failed: proxied response missing $expected" >&2
        cat "$PROXY_BODY" >&2
        exit 1
    fi
done

VHOST_BODY_STATUS="$(printf '%064d' 0 | curl -sS -o /dev/null -w '%{http_code}' -X POST -H "Host: app.test" --data-binary @- "http://127.0.0.1:$FLUXHEIM_PORT/api/upload" 2>/dev/null || true)"
if [ "$VHOST_BODY_STATUS" != "413" ]; then
    echo "1.0 core smoke failed: vhost body limit returned $VHOST_BODY_STATUS instead of 413" >&2
    exit 1
fi

python3 - "$FLUXHEIM_PORT" <<'PY'
import socket
import sys

port = int(sys.argv[1])
request = (
    "GET /chat/room?id=7 HTTP/1.1\r\n"
    "Host: app.test\r\n"
    "Connection: Upgrade\r\n"
    "Upgrade: websocket\r\n"
    "Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==\r\n"
    "Sec-WebSocket-Version: 13\r\n"
    "\r\n"
).encode("ascii")

with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
    sock.settimeout(5)
    sock.sendall(request)
    response = b""
    while b"\r\n\r\n" not in response:
        chunk = sock.recv(4096)
        if not chunk:
            break
        response += chunk

    header_block = response.decode("iso-8859-1", errors="replace")
    if " 101 " not in header_block.split("\r\n", 1)[0]:
        raise SystemExit(f"upgrade did not return 101:\n{header_block}")
    if "x-upstream-path: /room?id=7" not in header_block.lower():
        raise SystemExit(f"upgrade route did not strip /chat/ prefix:\n{header_block}")

    sock.sendall(b"ping\n")
    echo = sock.recv(64)
    if echo != b"echo:ping\n":
        raise SystemExit(f"upgrade tunnel did not echo bytes: {echo!r}")
PY

PROXY_HEADERS="$TMP_DIR/proxy-headers.txt"
curl -fsSI -H "Host: app.test" "http://127.0.0.1:$FLUXHEIM_PORT/api/check" > "$PROXY_HEADERS"
if grep -qi '^server:' "$PROXY_HEADERS"; then
    echo "1.0 core smoke failed: proxied response exposed server header" >&2
    cat "$PROXY_HEADERS" >&2
    exit 1
fi
if grep -qi '^x-powered-by:' "$PROXY_HEADERS"; then
    echo "1.0 core smoke failed: proxied response exposed x-powered-by header" >&2
    cat "$PROXY_HEADERS" >&2
    exit 1
fi

TLS_PROXY_BODY="$TMP_DIR/tls-proxy-body.txt"
curl -kfsS -H "Host: app.test" "https://127.0.0.1:$FLUXHEIM_TLS_PORT/tls/check" > "$TLS_PROXY_BODY"
for expected in "proxy-ok" "path=/tls/check" "xfh=app.test" "xfp=https" "xri=127.0.0.1" "xou=/tls/check" "xpb=Fluxheim"; do
    if ! grep -q "^$expected$" "$TLS_PROXY_BODY"; then
        echo "1.0 core smoke failed: TLS proxied response missing $expected" >&2
        cat "$TLS_PROXY_BODY" >&2
        exit 1
    fi
done

kill "$FLUXHEIM_PID" 2>/dev/null || true
sleep 0.2
if kill -0 "$FLUXHEIM_PID" 2>/dev/null; then
    kill -9 "$FLUXHEIM_PID" 2>/dev/null || true
fi
wait "$FLUXHEIM_PID" 2>/dev/null || true
FLUXHEIM_PID=

python3 - "$TMP_DIR/fluxheim.toml" "$TMP_DIR/fluxheim-redirect.toml" <<'PY'
import sys
source, target = sys.argv[1], sys.argv[2]
raw = open(source, encoding="utf-8").read()
raw = raw.replace("[server.https_redirect]\nenabled = false", "[server.https_redirect]\nenabled = true", 1)
open(target, "w", encoding="utf-8").write(raw)
PY

"$ROOT_DIR/target/debug/fluxheim" --config "$TMP_DIR/fluxheim-redirect.toml" >"$TMP_DIR/fluxheim-redirect.log" 2>&1 &
FLUXHEIM_PID=$!

tries=0
while [ "$tries" -lt 100 ]; do
    redirect_status="$(curl -sS -o /dev/null -w '%{http_code}' -H "Host: static.test" "http://127.0.0.1:$FLUXHEIM_PORT/" 2>/dev/null || true)"
    if [ "$redirect_status" = "308" ]; then
        break
    fi
    tries=$((tries + 1))
    sleep 0.1
done
if [ "$redirect_status" != "308" ]; then
    echo "1.0 core smoke failed: HTTPS redirect did not return 308" >&2
    cat "$TMP_DIR/fluxheim-redirect.log" >&2
    exit 1
fi

REDIRECT_HEADERS="$TMP_DIR/redirect-headers.txt"
curl -sSI -H "Host: static.test" "http://127.0.0.1:$FLUXHEIM_PORT/" > "$REDIRECT_HEADERS"
if ! grep -qi "^location: https://static.test:$FLUXHEIM_TLS_PORT/" "$REDIRECT_HEADERS"; then
    echo "1.0 core smoke failed: HTTPS redirect location was not safe/expected" >&2
    cat "$REDIRECT_HEADERS" >&2
    exit 1
fi

wait_https "https://127.0.0.1:$FLUXHEIM_TLS_PORT/" "static.test"

echo "1.0 core smoke: ok"
