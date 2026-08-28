#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SMOKE_TMP_ROOT=$(sh "$ROOT_DIR/scripts/secure-smoke-tmp-root.sh")
TMP_DIR=$(mktemp -d "$SMOKE_TMP_ROOT/fluxheim-upstream-tls-smoke.XXXXXX")
KEEP_LOGS=${FLUXHEIM_SMOKE_KEEP_LOGS:-0}

for command in cargo curl openssl python3; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "upstream TLS smoke requires $command" >&2
        exit 2
    fi
done

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
ORIGIN_PORT=$2

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
        if [ -n "$pid" ]; then
            wait "$pid" 2>/dev/null || true
        fi
    done
    if [ "$KEEP_LOGS" = "1" ] || [ "$status" -ne 0 ]; then
        echo "upstream TLS smoke artifacts kept in $TMP_DIR" >&2
    else
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT INT TERM

mkdir -p "$TMP_DIR/run" "$TMP_DIR/tls"
cat > "$TMP_DIR/tls/ca.cnf" <<'EOF'
[req]
prompt = no
distinguished_name = dn
x509_extensions = v3_ca

[dn]
CN = Fluxheim upstream TLS smoke CA

[v3_ca]
basicConstraints = critical,CA:true
keyUsage = critical,keyCertSign,cRLSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
EOF

cat > "$TMP_DIR/tls/origin.cnf" <<'EOF'
[req]
prompt = no
distinguished_name = dn
req_extensions = v3_req

[dn]
CN = localhost

[v3_req]
basicConstraints = critical,CA:false
keyUsage = critical,digitalSignature,keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost
EOF

openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 \
    -config "$TMP_DIR/tls/ca.cnf" \
    -keyout "$TMP_DIR/tls/ca-key.pem" \
    -out "$TMP_DIR/tls/ca.pem" >/dev/null 2>&1
openssl req -new -newkey rsa:2048 -nodes -sha256 \
    -config "$TMP_DIR/tls/origin.cnf" \
    -keyout "$TMP_DIR/tls/origin-key.pem" \
    -out "$TMP_DIR/tls/origin.csr" >/dev/null 2>&1
openssl x509 -req -sha256 -days 1 \
    -in "$TMP_DIR/tls/origin.csr" \
    -CA "$TMP_DIR/tls/ca.pem" \
    -CAkey "$TMP_DIR/tls/ca-key.pem" \
    -CAcreateserial \
    -extfile "$TMP_DIR/tls/origin.cnf" \
    -extensions v3_req \
    -out "$TMP_DIR/tls/origin.pem" >/dev/null 2>&1
chmod 600 "$TMP_DIR/tls/ca-key.pem" "$TMP_DIR/tls/origin-key.pem"

cat > "$TMP_DIR/fluxheim.toml" <<EOF
[server]
listen = ["127.0.0.1:$FLUXHEIM_PORT"]
default_vhost = "proxy.test"
trusted_proxies = []

[server.process]
daemon = false
threads = 1
listener_tasks_per_fd = 1
pid_file = "$TMP_DIR/run/fluxheim.pid"
upgrade_sock = "$TMP_DIR/run/upgrade.sock"
certificate_reload_sock = "$TMP_DIR/run/certificate-reload.sock"

[[vhosts]]
name = "proxy.test"
hosts = ["proxy.test"]

[vhosts.proxy]
upstreams = ["127.0.0.1:$ORIGIN_PORT"]
upstream_tls = true
upstream_sni = "localhost"
upstream_verify_cert = true
upstream_verify_hostname = true
upstream_ca_path = "$TMP_DIR/tls/ca.pem"
upstream_http_version = "http1"
EOF

openssl s_server \
    -accept "127.0.0.1:$ORIGIN_PORT" \
    -cert "$TMP_DIR/tls/origin.pem" \
    -key "$TMP_DIR/tls/origin-key.pem" \
    -www > "$TMP_DIR/origin.log" 2>&1 &
ORIGIN_PID=$!

origin_ready=0
attempt=0
while [ "$attempt" -lt 80 ]; do
    if printf '\n' | openssl s_client \
        -connect "127.0.0.1:$ORIGIN_PORT" \
        -servername localhost \
        -CAfile "$TMP_DIR/tls/ca.pem" \
        -verify_hostname localhost \
        -verify_return_error >/dev/null 2>&1
    then
        origin_ready=1
        break
    fi
    attempt=$((attempt + 1))
    sleep 0.1
done
[ "$origin_ready" = "1" ] || {
    echo "upstream TLS smoke failed: verified HTTPS origin did not become ready" >&2
    exit 1
}

cd "$ROOT_DIR"
cargo build --quiet --locked --no-default-features \
    --features profile-reverse-proxy --bin fluxheim
"$ROOT_DIR/target/debug/fluxheim" \
    --config "$TMP_DIR/fluxheim.toml" > "$TMP_DIR/fluxheim.log" 2>&1 &
FLUXHEIM_PID=$!

attempt=0
while [ "$attempt" -lt 100 ]; do
    if curl -fsS \
        -H 'Host: proxy.test' \
        "http://127.0.0.1:$FLUXHEIM_PORT/" > "$TMP_DIR/response.txt" 2>/dev/null \
        && grep -F 's_server' "$TMP_DIR/response.txt" >/dev/null
    then
        echo "verified upstream TLS smoke: ok"
        exit 0
    fi
    if ! kill -0 "$FLUXHEIM_PID" 2>/dev/null; then
        echo "upstream TLS smoke failed: Fluxheim exited" >&2
        cat "$TMP_DIR/fluxheim.log" >&2 || true
        exit 1
    fi
    attempt=$((attempt + 1))
    sleep 0.1
done

echo "upstream TLS smoke failed: request did not traverse the verified HTTPS origin" >&2
cat "$TMP_DIR/fluxheim.log" >&2 || true
exit 1
