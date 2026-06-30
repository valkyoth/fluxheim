#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP_ROOT="$ROOT_DIR/target/fluxheim-privacy-smoke"
mkdir -p "$TMP_ROOT"
TMP_DIR=$(mktemp -d "$TMP_ROOT/run.XXXXXX")
KEEP_LOGS=${FLUXHEIM_SMOKE_KEEP_LOGS:-0}
CURL_MAX_TIME=${FLUXHEIM_SMOKE_CURL_MAX_TIME:-5}

ports=$(python3 "$ROOT_DIR/scripts/smoke_ports.py" 2)

set -- $ports
FLUXHEIM_PORT=$1
ORIGIN_PORT=$2

FLUXHEIM_PID=
ORIGIN_PID=

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
        echo "privacy-mode smoke artifacts kept in $TMP_DIR" >&2
    else
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT INT TERM

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "privacy-mode smoke failed: missing required command: $1" >&2
        exit 1
    fi
}

wait_http() {
    url=$1
    tries=0
    while [ "$tries" -lt 100 ]; do
        if curl -fsS --max-time "$CURL_MAX_TIME" "$url" >/dev/null 2>&1; then
            return 0
        fi
        tries=$((tries + 1))
        sleep 0.1
    done

    echo "privacy-mode smoke failed: timed out waiting for $url" >&2
    return 1
}

require_command cargo
require_command curl
require_command python3

if "$ROOT_DIR/scripts/validate-features.sh" profile-privacy,metrics >"$TMP_DIR/invalid-features.log" 2>&1; then
    echo "privacy-mode smoke failed: profile-privacy,metrics was accepted" >&2
    cat "$TMP_DIR/invalid-features.log" >&2
    exit 1
fi

if [ -n "${FLUXHEIM_BIN:-}" ]; then
    fluxheim_bin="$FLUXHEIM_BIN"
else
    (
        cd "$ROOT_DIR"
        cargo build --quiet --no-default-features --features profile-privacy
    )
    fluxheim_bin="$ROOT_DIR/${CARGO_TARGET_DIR:-target}/debug/fluxheim"
fi

mkdir -p "$TMP_DIR/web" "$TMP_DIR/run"
printf 'privacy static ok\n' > "$TMP_DIR/web/index.html"

cat > "$TMP_DIR/origin.py" <<'PY'
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        lines = []
        for name, value in self.headers.items():
            lines.append(f"{name.lower()}: {value}\n")
        body = "".join(sorted(lines)).encode("utf-8")
        self.send_response(200)
        self.send_header("content-type", "text/plain; charset=utf-8")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *args):
        return


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
PY

cat > "$TMP_DIR/fluxheim.toml" <<EOF
[server]
listen = ["127.0.0.1:$FLUXHEIM_PORT"]
default_vhost = "privacy-proxy.test"
trusted_proxies = []

[server.process]
pid_file = "$TMP_DIR/run/fluxheim.pid"
upgrade_sock = "$TMP_DIR/run/fluxheim-upgrade.sock"
certificate_reload_sock = "$TMP_DIR/run/fluxheim-cert-reload.sock"
daemon = false
threads = 1
grace_period_seconds = 1
graceful_shutdown_timeout_seconds = 2

[server.limits]
max_request_header_bytes = "64KiB"
max_uri_bytes = "8KiB"
max_request_headers = 100
max_request_body_bytes = "1MiB"

[logging]
level = "info"
format = "text"
target = "stderr"

[logging.file]
enabled = false

[logging.access]
enabled = false
include_host = false
include_path = false
request_id = false

[headers.request]
enabled = true
strip_inbound_client_ip_headers = true
x_forwarded_for = "off"
x_real_ip = false
x_forwarded_host = false
x_forwarded_proto = false
forwarded = false
remove = ["cf-connecting-ip", "fastly-client-ip", "true-client-ip", "x-forwarded-for", "x-real-ip"]

[headers.response]
enabled = true
remove = ["server", "x-powered-by"]

[tls]
enabled = false
backend = "rustls"

[[vhosts]]
name = "privacy-proxy.test"
hosts = ["privacy-proxy.test"]

[vhosts.proxy]
upstreams = ["127.0.0.1:$ORIGIN_PORT"]
upstream_tls = false

[[vhosts]]
name = "privacy-web.test"
hosts = ["privacy-web.test"]

[vhosts.web]
root = "$TMP_DIR/web"
index_files = ["index.html"]
deny_dotfiles = true
EOF

"$fluxheim_bin" --config "$TMP_DIR/fluxheim.toml" --validate-config

python3 "$TMP_DIR/origin.py" "$ORIGIN_PORT" >"$TMP_DIR/origin.log" 2>&1 &
ORIGIN_PID=$!
wait_http "http://127.0.0.1:$ORIGIN_PORT/"

"$fluxheim_bin" --config "$TMP_DIR/fluxheim.toml" >"$TMP_DIR/fluxheim.log" 2>&1 &
FLUXHEIM_PID=$!

wait_http "http://127.0.0.1:$FLUXHEIM_PORT/"

curl -fsS --max-time "$CURL_MAX_TIME" \
    -H "Host: privacy-proxy.test" \
    -H "X-Forwarded-For: 203.0.113.55" \
    -H "X-Real-IP: 198.51.100.10" \
    -H "CF-Connecting-IP: 192.0.2.10" \
    -H "True-Client-IP: 192.0.2.11" \
    -H "Forwarded: for=203.0.113.56" \
    -H "User-Agent: privacy-smoke-agent" \
    -H "Cookie: privacy_secret=do-not-log" \
    -H "X-Request-ID: privacy-smoke-request" \
    "http://127.0.0.1:$FLUXHEIM_PORT/headers?privacy_secret=do-not-log" \
    > "$TMP_DIR/proxy-response.txt"

for header in \
    "x-forwarded-for:" \
    "x-real-ip:" \
    "cf-connecting-ip:" \
    "true-client-ip:" \
    "forwarded:"
do
    if grep -qi "^$header" "$TMP_DIR/proxy-response.txt"; then
        echo "privacy-mode smoke failed: upstream received stripped header $header" >&2
        cat "$TMP_DIR/proxy-response.txt" >&2
        exit 1
    fi
done

curl -fsS --max-time "$CURL_MAX_TIME" \
    -H "Host: privacy-web.test" \
    "http://127.0.0.1:$FLUXHEIM_PORT/" \
    > "$TMP_DIR/static-response.txt"
if ! grep -q '^privacy static ok$' "$TMP_DIR/static-response.txt"; then
    echo "privacy-mode smoke failed: static web response failed" >&2
    cat "$TMP_DIR/static-response.txt" >&2
    exit 1
fi

for forbidden in \
    "203.0.113.55" \
    "198.51.100.10" \
    "192.0.2.10" \
    "privacy_secret=do-not-log" \
    "privacy-smoke-agent" \
    "privacy-smoke-request" \
    "/headers"
do
    if grep -F -q "$forbidden" "$TMP_DIR/fluxheim.log"; then
        echo "privacy-mode smoke failed: Fluxheim log retained sensitive value: $forbidden" >&2
        cat "$TMP_DIR/fluxheim.log" >&2
        exit 1
    fi
done

echo "privacy-mode smoke passed"
