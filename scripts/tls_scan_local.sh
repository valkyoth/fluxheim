#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/fluxheim-tls-scan.XXXXXX")
KEEP_LOGS=${FLUXHEIM_TLS_SCAN_KEEP_LOGS:-0}
BUILD_RELEASE=${FLUXHEIM_TLS_SCAN_BUILD:-1}
TESTSSL_TAG=${FLUXHEIM_TESTSSL_TAG:-v3.2.3}
TESTSSL_TIMEOUT=${FLUXHEIM_TESTSSL_TIMEOUT:-180}

if ! command -v openssl >/dev/null 2>&1; then
    echo "TLS scan requires openssl to generate a temporary certificate" >&2
    exit 1
fi

if ! command -v curl >/dev/null 2>&1; then
    echo "TLS scan requires curl to download testssl.sh when FLUXHEIM_TESTSSL_PATH is unset" >&2
    exit 1
fi

if ! command -v tar >/dev/null 2>&1; then
    echo "TLS scan requires tar to unpack testssl.sh when FLUXHEIM_TESTSSL_PATH is unset" >&2
    exit 1
fi

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
        echo "TLS scan artifacts kept in $TMP_DIR" >&2
    else
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT INT TERM

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
FLUXHEIM_TLS_PORT=$2

mkdir -p "$TMP_DIR/public"
mkdir -p "$TMP_DIR/tls"
mkdir -p "$TMP_DIR/run"
printf '%s\n' '<!doctype html><title>Fluxheim TLS scan</title><h1>tls-ok</h1>' > "$TMP_DIR/public/index.html"

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

[logging]
level = "warn"
format = "text"

[logging.access]
enabled = false
request_id = false

[headers.response]
enabled = true
x_content_type_options = "nosniff"
x_frame_options = "DENY"
referrer_policy = "no-referrer"
unset = ["server", "x-powered-by"]

[proxy]
upstreams = ["127.0.0.1:9"]
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
root = "$TMP_DIR/public"
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
EOF

if [ "$BUILD_RELEASE" = "1" ]; then
    cargo build --quiet --release
fi

"$ROOT_DIR/target/release/fluxheim" --config "$TMP_DIR/fluxheim.toml" > "$TMP_DIR/fluxheim.log" 2>&1 &
FLUXHEIM_PID=$!

for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    status="$(curl -ksS -o "$TMP_DIR/body.txt" -w '%{http_code}' -H "Host: static.test" "https://127.0.0.1:$FLUXHEIM_TLS_PORT/" 2>/dev/null || true)"
    if [ "$status" = "200" ]; then
        break
    fi
    sleep 0.2
done

if [ "${status:-}" != "200" ]; then
    echo "TLS scan failed: expected HTTPS 200 before scan, got ${status:-no response}" >&2
    exit 1
fi

if [ -n "${FLUXHEIM_TESTSSL_PATH:-}" ]; then
    TESTSSL="$FLUXHEIM_TESTSSL_PATH"
else
    TESTSSL_DIR="$TMP_DIR/testssl"
    mkdir -p "$TESTSSL_DIR"
    curl -sSfL \
        "https://github.com/testssl/testssl.sh/archive/refs/tags/$TESTSSL_TAG.tar.gz" \
        | tar -xz -C "$TESTSSL_DIR" --strip-components=1
    TESTSSL="$TESTSSL_DIR/testssl.sh"
    chmod +x "$TESTSSL"
fi

if [ ! -x "$TESTSSL" ]; then
    echo "TLS scan failed: testssl.sh is not executable: $TESTSSL" >&2
    exit 1
fi

TESTSSL_CMD="$TESTSSL --warnings off --color 0 -p -S -P https://127.0.0.1:$FLUXHEIM_TLS_PORT/"
if command -v timeout >/dev/null 2>&1; then
    timeout "$TESTSSL_TIMEOUT" sh -c "$TESTSSL_CMD" > "$TMP_DIR/testssl.out" 2>&1
else
    sh -c "$TESTSSL_CMD" > "$TMP_DIR/testssl.out" 2>&1
fi

if grep -Ei '^[[:space:]]*SSLv2[[:space:]]+offered|^[[:space:]]*SSLv3[[:space:]]+offered|^[[:space:]]*TLS 1[[:space:]]+offered|^[[:space:]]*TLS 1\.1[[:space:]]+offered' "$TMP_DIR/testssl.out" >/dev/null; then
    echo "TLS scan failed: deprecated protocol appears to be offered" >&2
    cat "$TMP_DIR/testssl.out" >&2
    exit 1
fi

echo "TLS scan report: $TMP_DIR/testssl.out"
echo "TLS scan: ok"
