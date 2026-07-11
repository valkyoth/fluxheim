#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SMOKE_TMP_ROOT=$(sh "$ROOT_DIR/scripts/secure-smoke-tmp-root.sh")
TMP_DIR=$(mktemp -d "$SMOKE_TMP_ROOT/fluxheim-geoip-circl-smoke.XXXXXX")
KEEP_LOGS=${FLUXHEIM_SMOKE_KEEP_LOGS:-0}

CIRCL_DATE=2026-06-26
CIRCL_FILENAME="$CIRCL_DATE-GeoOpen-Country-ASN.mmdb"
CIRCL_URL="https://cra.circl.lu/opendata/geo-open/mmdb-country-asn/$CIRCL_FILENAME"
CIRCL_SHA256=dd2607402f0614e4d4ff7a4bd4627e5e0e9bdedc7a97492d57c6e6a5c91b8423
CIRCL_MAX_DOWNLOAD_BYTES=94371840
CACHE_DIR=${FLUXHEIM_GEOIP_CIRCL_CACHE_DIR:-$SMOKE_TMP_ROOT/circl-geoip-cache}
DATABASE=${FLUXHEIM_GEOIP_CIRCL_DATABASE:-$CACHE_DIR/$CIRCL_FILENAME}

ORIGIN_ONE_PID=
ORIGIN_TWO_PID=
FLUXHEIM_PID=
DOWNLOAD=

cleanup() {
    status=$?
    for pid in "$FLUXHEIM_PID" "$ORIGIN_ONE_PID" "$ORIGIN_TWO_PID"; do
        if [ -n "$pid" ]; then
            kill "$pid" 2>/dev/null || true
        fi
    done
    sleep 0.2
    for pid in "$FLUXHEIM_PID" "$ORIGIN_ONE_PID" "$ORIGIN_TWO_PID"; do
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill -9 "$pid" 2>/dev/null || true
        fi
    done
    for pid in "$FLUXHEIM_PID" "$ORIGIN_ONE_PID" "$ORIGIN_TWO_PID"; do
        if [ -n "$pid" ]; then
            wait "$pid" 2>/dev/null || true
        fi
    done
    if [ -n "$DOWNLOAD" ]; then
        rm -f "$DOWNLOAD"
    fi
    if [ "$KEEP_LOGS" = "1" ] || [ "$status" -ne 0 ]; then
        echo "CIRCL GeoIP smoke artifacts kept in $TMP_DIR" >&2
    else
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT INT TERM

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "CIRCL GeoIP smoke requires $1" >&2
        exit 1
    fi
}

require_command curl
require_command python3
require_command sha256sum

if [ -L "$CACHE_DIR" ]; then
    echo "CIRCL GeoIP cache directory must not be a symlink: $CACHE_DIR" >&2
    exit 1
fi
mkdir -p "$CACHE_DIR"
chmod 700 "$CACHE_DIR"
if [ -L "$DATABASE" ]; then
    echo "CIRCL GeoIP database must not be a symlink: $DATABASE" >&2
    exit 1
fi
if [ ! -f "$DATABASE" ]; then
    if [ -n "${FLUXHEIM_GEOIP_CIRCL_DATABASE:-}" ]; then
        echo "configured CIRCL GeoIP database does not exist: $DATABASE" >&2
        exit 1
    fi
    DOWNLOAD="$DATABASE.download.$$"
    rm -f "$DOWNLOAD"
    echo "downloading pinned CIRCL Geo Open database ($CIRCL_DATE)..." >&2
    curl --fail --location --silent --show-error \
        --connect-timeout 30 --max-time 600 \
        --max-filesize "$CIRCL_MAX_DOWNLOAD_BYTES" \
        "$CIRCL_URL" --output "$DOWNLOAD"
    chmod 600 "$DOWNLOAD"
    mv "$DOWNLOAD" "$DATABASE"
    DOWNLOAD=
fi

actual_sha256=$(sha256sum "$DATABASE" | awk '{print $1}')
if [ "$actual_sha256" != "$CIRCL_SHA256" ]; then
    echo "CIRCL GeoIP database checksum mismatch" >&2
    echo "expected: $CIRCL_SHA256" >&2
    echo "actual:   $actual_sha256" >&2
    exit 1
fi
if [ -z "${FLUXHEIM_GEOIP_CIRCL_DATABASE:-}" ]; then
    chmod 600 "$DATABASE"
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
ORIGIN_ONE_PORT=$2
ORIGIN_TWO_PORT=$3

mkdir -p "$TMP_DIR/public" "$TMP_DIR/run"
printf '%s\n' 'circl-static-ok' > "$TMP_DIR/public/index.html"

cat > "$TMP_DIR/origin.py" <<'PY'
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    label = "origin"

    def do_GET(self):
        body = f"{self.label}\n".encode("ascii")
        self.send_response(200)
        self.send_header("content-type", "text/plain; charset=ascii")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *args):
        return


if __name__ == "__main__":
    Handler.label = sys.argv[2]
    ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
PY

cat > "$TMP_DIR/fluxheim.toml" <<EOF
[server]
listen = ["127.0.0.1:$FLUXHEIM_PORT"]
default_vhost = "static.geo.test"
trusted_proxies = ["127.0.0.1"]

[server.process]
daemon = false
pid_file = "$TMP_DIR/run/fluxheim.pid"
upgrade_sock = "$TMP_DIR/run/fluxheim-upgrade.sock"
certificate_reload_sock = "$TMP_DIR/run/fluxheim-cert-reload.sock"

[logging]
level = "warn"
format = "text"

[logging.access]
enabled = false
request_id = false

[tls]
enabled = false
backend = "rustls"

[cache]
enabled = false

[geoip]
enabled = true
fallback_enabled = true

[[geoip.databases]]
provider = "circl-geo-open"
path = "$DATABASE"

[[vhosts]]
name = "static.geo.test"
hosts = ["static.geo.test"]

[vhosts.access]
allow_countries = ["US"]

[vhosts.web]
root = "$TMP_DIR/public"
index_files = ["index.html"]

[[vhosts]]
name = "proxy.geo.test"
hosts = ["proxy.geo.test"]

[vhosts.access]
allow_asns = [13335]

[vhosts.proxy]
upstreams = ["127.0.0.1:$ORIGIN_ONE_PORT"]
upstream_tls = false

[[vhosts]]
name = "lb.geo.test"
hosts = ["lb.geo.test"]

[vhosts.access]
allow_countries = ["US"]
allow_asns = [13335]

[vhosts.proxy]
upstreams = ["127.0.0.1:$ORIGIN_ONE_PORT", "127.0.0.1:$ORIGIN_TWO_PORT"]
upstream_aliases = ["origin-one", "origin-two"]
upstream_tls = false

[vhosts.proxy.load_balance]
selection = "round-robin"
max_iterations = 64
all_down_status = 503
EOF

python3 "$TMP_DIR/origin.py" "$ORIGIN_ONE_PORT" origin-one >"$TMP_DIR/origin-one.log" 2>&1 &
ORIGIN_ONE_PID=$!
python3 "$TMP_DIR/origin.py" "$ORIGIN_TWO_PORT" origin-two >"$TMP_DIR/origin-two.log" 2>&1 &
ORIGIN_TWO_PID=$!

(cd "$ROOT_DIR" && cargo build --quiet --locked --no-default-features \
    --features proxy,web,load-balancer,geoip --bin fluxheim)

"$ROOT_DIR/target/debug/fluxheim" --config "$TMP_DIR/fluxheim.toml" \
    >"$TMP_DIR/fluxheim.log" 2>&1 &
FLUXHEIM_PID=$!

request_status() {
    host=$1
    client_ip=$2
    output=$3
    curl --silent --show-error --max-time 5 --output "$output" --write-out '%{http_code}' \
        --header "Host: $host" \
        --header "X-Forwarded-For: $client_ip" \
        "http://127.0.0.1:$FLUXHEIM_PORT/" 2>/dev/null || true
}

wait_status=
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    wait_status=$(request_status static.geo.test 1.1.1.1 "$TMP_DIR/wait-body.txt")
    if [ "$wait_status" = "200" ]; then
        break
    fi
    sleep 0.25
done
if [ "$wait_status" != "200" ]; then
    echo "CIRCL GeoIP smoke failed to start: expected static HTTP 200, got ${wait_status:-none}" >&2
    cat "$TMP_DIR/fluxheim.log" >&2
    exit 1
fi

if ! grep -q '^circl-static-ok$' "$TMP_DIR/wait-body.txt"; then
    echo "CIRCL country policy did not continue into static web serving" >&2
    exit 1
fi

country_denied=$(request_status static.geo.test 194.71.11.69 "$TMP_DIR/country-denied.txt")
if [ "$country_denied" != "403" ]; then
    echo "CIRCL country policy did not deny non-US client (got $country_denied)" >&2
    cat "$TMP_DIR/country-denied.txt" >&2
    exit 1
fi

proxy_allowed=$(request_status proxy.geo.test 1.1.1.1 "$TMP_DIR/proxy-allowed.txt")
if [ "$proxy_allowed" != "200" ] || ! grep -q '^origin-one$' "$TMP_DIR/proxy-allowed.txt"; then
    echo "CIRCL ASN policy did not continue into direct proxy serving" >&2
    exit 1
fi

proxy_denied=$(request_status proxy.geo.test 8.8.8.8 "$TMP_DIR/proxy-denied.txt")
if [ "$proxy_denied" != "403" ]; then
    echo "CIRCL ASN policy did not deny AS15169 client (got $proxy_denied)" >&2
    exit 1
fi

: > "$TMP_DIR/lb-responses.txt"
for _ in 1 2 3 4 5 6; do
    lb_status=$(request_status lb.geo.test 1.1.1.1 "$TMP_DIR/lb-response.txt")
    if [ "$lb_status" != "200" ]; then
        echo "CIRCL combined policy blocked allowed load-balancer request (got $lb_status)" >&2
        exit 1
    fi
    cat "$TMP_DIR/lb-response.txt" >> "$TMP_DIR/lb-responses.txt"
done
if ! grep -q '^origin-one$' "$TMP_DIR/lb-responses.txt" \
    || ! grep -q '^origin-two$' "$TMP_DIR/lb-responses.txt"; then
    echo "allowed CIRCL GeoIP load-balancer requests did not reach both origins" >&2
    cat "$TMP_DIR/lb-responses.txt" >&2
    exit 1
fi

lb_denied=$(request_status lb.geo.test 8.8.8.8 "$TMP_DIR/lb-denied.txt")
if [ "$lb_denied" != "403" ]; then
    echo "CIRCL combined policy did not deny mismatched load-balancer client (got $lb_denied)" >&2
    exit 1
fi

echo "CIRCL GeoIP static/proxy/load-balancer smoke passed"
