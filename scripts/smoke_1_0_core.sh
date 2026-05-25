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
    for _ in range(4):
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
ERROR_PORT=$4

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
mkdir -p "$TMP_DIR/repo"
mkdir -p "$TMP_DIR/errors"
mkdir -p "$TMP_DIR/tls"
mkdir -p "$TMP_DIR/run"
printf '%s\n' '<!doctype html><title>Fluxheim 1.0 smoke</title><h1>static-ok</h1>' > "$TMP_DIR/public/index.html"
printf '%s\n' 'secret' > "$TMP_DIR/public/.secret"
printf '%s\n' 'repo-package-ok' > "$TMP_DIR/repo/pkg.txt"
printf '%s\n' '<!doctype html><title>Bad gateway</title><h1>custom-502-ok</h1>' > "$TMP_DIR/errors/502.html"

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

openssl req \
    -x509 \
    -newkey rsa:2048 \
    -nodes \
    -sha256 \
    -days 1 \
    -subj "/CN=app.test" \
    -addext "subjectAltName=DNS:app.test" \
    -keyout "$TMP_DIR/tls/app-key.pem" \
    -out "$TMP_DIR/tls/app-fullchain.pem" >/dev/null 2>&1
chmod 600 "$TMP_DIR/tls/app-key.pem"

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
                f"xcu={self.headers.get('x-client-upgrade', '')}",
                f"xav={self.headers.get('x-api-version', '')}",
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
            self.send_header("x-client-upgrade", self.headers.get("x-client-upgrade", ""))
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
regex_enabled = true

[server.process]
daemon = false
pid_file = "$TMP_DIR/run/fluxheim.pid"
upgrade_sock = "$TMP_DIR/run/fluxheim-upgrade.sock"
certificate_reload_sock = "$TMP_DIR/run/fluxheim-cert-reload.sock"

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
x-client-upgrade = "{http.upgrade}"

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
name = "www-static.test"
hosts = ["www.static.test"]

[vhosts.redirect]
enabled = true
to = "https://static.test{uri}"
status = 308

[[vhosts]]
name = "static.test"
hosts = ["static.test"]

[vhosts.web]
root = "$TMP_DIR/public"
index_files = ["index.html"]
deny_dotfiles = true
cache_control = "public, max-age=60"

[vhosts.acme_challenge]
enabled = true
upstreams = ["127.0.0.1:$ORIGIN_PORT"]

[[vhosts.routes]]
name = "repo"
path_prefix = "/repo"
strip_prefix = "/repo"

[vhosts.routes.web]
root = "$TMP_DIR/repo"
index_files = ["index.html"]
deny_dotfiles = true

[vhosts.routes.web.directory_listing]
enabled = true
exact_size = false

[[vhosts]]
name = "app.test"
hosts = ["app.test"]
max_request_body_bytes = "32B"

[vhosts.tls]
enabled = true

[vhosts.tls.certificate]
cert_path = "$TMP_DIR/tls/app-fullchain.pem"
key_path = "$TMP_DIR/tls/app-key.pem"

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
name = "versioned-api"
path_regex = "^/api/v(?P<version>[0-9]+)/(?P<rest>.*)$"
rewrite_template = "/internal/v{route.regex.version}/{route.regex.rest}"

[vhosts.routes.headers.request.add]
x-api-version = "{route.regex.version}"

[vhosts.routes.proxy]
upstreams = ["127.0.0.1:$ORIGIN_PORT"]
upstream_tls = false

[[vhosts.routes]]
name = "fallback"
fallback = true

[vhosts.routes.proxy]
upstreams = ["127.0.0.1:$ORIGIN_PORT"]
upstream_tls = false

[[vhosts]]
name = "error.test"
hosts = ["error.test"]

[vhosts.proxy]
upstreams = ["127.0.0.1:$ERROR_PORT"]
upstream_tls = false

[[vhosts.proxy.error_pages]]
status = 502
path = "/502.html"

[vhosts.proxy.error_pages.web]
root = "$TMP_DIR/errors"
index_files = ["index.html"]
deny_dotfiles = true
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
    if [ "${FLUXHEIM_SMOKE_SKIP_CORE_MATRIX:-0}" != "1" ]; then
        scripts/validate-1-0-core.sh check
    fi
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
        echo "1.0 core smoke failed: conflicting proxy upstreams were accepted" >&2
        exit 1
    fi
    if ! grep -q "proxy.upstream, proxy.upstreams, and proxy.upstreams_file are mutually exclusive" "$TMP_DIR/conflicting-upstreams-check.log"; then
        echo "1.0 core smoke failed: conflicting proxy upstreams returned an unexpected error" >&2
        cat "$TMP_DIR/conflicting-upstreams-check.log" >&2
        exit 1
    fi
    cargo build --quiet
)

"$ROOT_DIR/target/debug/fluxheim" --config "$TMP_DIR/fluxheim.toml" >"$TMP_DIR/fluxheim.log" 2>&1 &
FLUXHEIM_PID=$!

wait_http "http://127.0.0.1:$FLUXHEIM_PORT/" "static.test"
wait_https "https://127.0.0.1:$FLUXHEIM_TLS_PORT/" "static.test"

SNI_SUBJECT="$(
    printf '' |
        openssl s_client -connect "127.0.0.1:$FLUXHEIM_TLS_PORT" -servername app.test 2>/dev/null |
        openssl x509 -noout -subject
)"
case "$SNI_SUBJECT" in
    *"CN = app.test"*|*"CN=app.test"*) ;;
    *)
        echo "1.0 core smoke failed: rustls SNI did not select app.test certificate" >&2
        echo "$SNI_SUBJECT" >&2
        exit 1
        ;;
esac

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

REPO_LISTING="$TMP_DIR/repo-listing.html"
curl -fsS -H "Host: static.test" "http://127.0.0.1:$FLUXHEIM_PORT/repo/" > "$REPO_LISTING"
if ! grep -q "pkg.txt" "$REPO_LISTING"; then
    echo "1.0 core smoke failed: route directory listing did not include pkg.txt" >&2
    cat "$REPO_LISTING" >&2
    exit 1
fi

REPO_FILE="$TMP_DIR/repo-file.txt"
curl -fsS -H "Host: static.test" "http://127.0.0.1:$FLUXHEIM_PORT/repo/pkg.txt" > "$REPO_FILE"
if ! grep -q "repo-package-ok" "$REPO_FILE"; then
    echo "1.0 core smoke failed: route static alias did not serve pkg.txt" >&2
    cat "$REPO_FILE" >&2
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

REWRITE_BODY="$TMP_DIR/rewrite-template-body.txt"
curl -fsS -H "Host: app.test" "http://127.0.0.1:$FLUXHEIM_PORT/api/v2/users?id=7" > "$REWRITE_BODY"
for expected in "path=/internal/v2/users?id=7" "xav=2"; do
    if ! grep -q "^$expected$" "$REWRITE_BODY"; then
        echo "1.0 core smoke failed: regex rewrite_template response missing $expected" >&2
        cat "$REWRITE_BODY" >&2
        exit 1
    fi
done

VHOST_BODY_STATUS="$(printf '%064d' 0 | curl -sS -o /dev/null -w '%{http_code}' -X POST -H "Host: app.test" --data-binary @- "http://127.0.0.1:$FLUXHEIM_PORT/api/upload" 2>/dev/null || true)"
if [ "$VHOST_BODY_STATUS" != "413" ]; then
    echo "1.0 core smoke failed: vhost body limit returned $VHOST_BODY_STATUS instead of 413" >&2
    exit 1
fi

CUSTOM_ERROR_BODY="$TMP_DIR/custom-error-body.html"
custom_error_status="$(curl -sS -o "$CUSTOM_ERROR_BODY" -w '%{http_code}' -H "Host: error.test" "http://127.0.0.1:$FLUXHEIM_PORT/" 2>/dev/null || true)"
if [ "$custom_error_status" != "502" ]; then
    echo "1.0 core smoke failed: custom proxy error page returned $custom_error_status instead of 502" >&2
    cat "$CUSTOM_ERROR_BODY" >&2
    exit 1
fi
if ! grep -q "custom-502-ok" "$CUSTOM_ERROR_BODY"; then
    echo "1.0 core smoke failed: custom proxy error page body was not served" >&2
    cat "$CUSTOM_ERROR_BODY" >&2
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
    if "x-client-upgrade: websocket" not in header_block.lower():
        raise SystemExit(f"upgrade template was not forwarded:\n{header_block}")

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

CANONICAL_HEADERS="$TMP_DIR/canonical-headers.txt"
canonical_status="$(curl -sS -o /dev/null -w '%{http_code}' -H "Host: www.static.test" "http://127.0.0.1:$FLUXHEIM_PORT/some/path?x=1" 2>/dev/null || true)"
if [ "$canonical_status" != "308" ]; then
    echo "1.0 core smoke failed: canonical redirect returned $canonical_status instead of 308" >&2
    exit 1
fi
curl -sSI -H "Host: www.static.test" "http://127.0.0.1:$FLUXHEIM_PORT/some/path?x=1" > "$CANONICAL_HEADERS"
if ! grep -qi "^location: https://static.test/some/path?x=1" "$CANONICAL_HEADERS"; then
    echo "1.0 core smoke failed: canonical redirect location was not expected" >&2
    cat "$CANONICAL_HEADERS" >&2
    exit 1
fi

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

ACME_BODY="$TMP_DIR/acme-body.txt"
acme_status="$(curl -sS -o "$ACME_BODY" -w '%{http_code}' -H "Host: static.test" "http://127.0.0.1:$FLUXHEIM_PORT/.well-known/acme-challenge/token" 2>/dev/null || true)"
if [ "$acme_status" != "200" ]; then
    echo "1.0 core smoke failed: cleartext challenge exception returned $acme_status instead of 200" >&2
    cat "$ACME_BODY" >&2
    exit 1
fi
if ! grep -q "^proxy-ok$" "$ACME_BODY"; then
    echo "1.0 core smoke failed: cleartext challenge exception did not reach upstream" >&2
    cat "$ACME_BODY" >&2
    exit 1
fi

repo_redirect_status="$(curl -sS -o /dev/null -w '%{http_code}' -H "Host: static.test" "http://127.0.0.1:$FLUXHEIM_PORT/repo/pkg.txt" 2>/dev/null || true)"
if [ "$repo_redirect_status" != "308" ]; then
    echo "1.0 core smoke failed: non-exempt static route returned $repo_redirect_status instead of HTTPS redirect" >&2
    exit 1
fi

wait_https "https://127.0.0.1:$FLUXHEIM_TLS_PORT/" "static.test"

echo "1.0 core smoke: ok"
