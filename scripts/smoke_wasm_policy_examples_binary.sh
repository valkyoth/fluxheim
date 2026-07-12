#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SMOKE_TMP_ROOT=$(sh "$ROOT_DIR/scripts/secure-smoke-tmp-root.sh")
TMP_DIR=$(mktemp -d "$SMOKE_TMP_ROOT/fluxheim-wasm-binary-smoke.XXXXXX")
KEEP_LOGS=${FLUXHEIM_SMOKE_KEEP_LOGS:-0}

STABLE_PID=
CANARY_PID=
FLUXHEIM_PID=

cleanup() {
    status=$?
    for pid in "$FLUXHEIM_PID" "$STABLE_PID" "$CANARY_PID"; do
        if [ -n "$pid" ]; then
            kill "$pid" 2>/dev/null || true
        fi
    done
    sleep 0.2
    for pid in "$FLUXHEIM_PID" "$STABLE_PID" "$CANARY_PID"; do
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill -9 "$pid" 2>/dev/null || true
        fi
    done
    for pid in "$FLUXHEIM_PID" "$STABLE_PID" "$CANARY_PID"; do
        if [ -n "$pid" ]; then
            wait "$pid" 2>/dev/null || true
        fi
    done
    if [ "$KEEP_LOGS" = "1" ] || [ "$status" -ne 0 ]; then
        echo "Wasm binary smoke artifacts kept in $TMP_DIR" >&2
    else
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT INT TERM

for command in curl python3 sha256sum; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "Wasm binary smoke requires $command" >&2
        exit 1
    fi
done

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
STABLE_PORT=$2
CANARY_PORT=$3

mkdir -p "$TMP_DIR/plugins" "$TMP_DIR/run"
chmod 700 "$TMP_DIR/plugins" "$TMP_DIR/run"

(cd "$ROOT_DIR" && scripts/build_wasm_policy_examples.sh)
for name in \
    irules-access-policy \
    openresty-header-policy \
    haproxy-spoe-routing-policy \
    cache-lookup-policy \
    cache-store-policy
do
    cp "$ROOT_DIR/target/wasm-policy-examples/$name.wasm" "$TMP_DIR/plugins/$name.wasm"
    chmod 600 "$TMP_DIR/plugins/$name.wasm"
done

digest() {
    sha256sum "$TMP_DIR/plugins/$1.wasm" | awk '{print $1}'
}

IRULES_SHA=$(digest irules-access-policy)
OPENRESTY_SHA=$(digest openresty-header-policy)
HAPROXY_SHA=$(digest haproxy-spoe-routing-policy)
CACHE_LOOKUP_SHA=$(digest cache-lookup-policy)
CACHE_STORE_SHA=$(digest cache-store-policy)

cat > "$TMP_DIR/origin.py" <<'PY'
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    label = "origin"
    requests = 0

    def do_GET(self):
        type(self).requests += 1
        tier = self.headers.get("x-policy-tier", "none")
        body = (
            f"{self.label} count={type(self).requests} tier={tier} path={self.path}\n"
        ).encode("ascii")
        self.send_response(200)
        if self.path.startswith("/static/"):
            self.send_header("content-type", "image/png")
            self.send_header("cache-control", "max-age=60")
        else:
            self.send_header("content-type", "text/plain; charset=ascii")
        self.send_header("x-powered-by", "origin")
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
default_vhost = "irules.test"
trusted_proxies = []

[server.process]
daemon = false
pid_file = "$TMP_DIR/run/fluxheim.pid"
upgrade_sock = "$TMP_DIR/run/upgrade.sock"
certificate_reload_sock = "$TMP_DIR/run/certificate-reload.sock"
grace_period_seconds = 1
graceful_shutdown_timeout_seconds = 2

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
enabled = true

[cache.memory]
enabled = true

[wasm]
enabled = true
plugin_roots = ["$TMP_DIR/plugins"]
max_total_concurrent_executions = 64
max_total_cache_concurrent_executions = 32

[[wasm.plugins]]
name = "irules"
path = "$TMP_DIR/plugins/irules-access-policy.wasm"
sha256 = "$IRULES_SHA"
phases = ["access-decision"]
fail_mode = "fail-closed"

[[wasm.plugins]]
name = "openresty"
path = "$TMP_DIR/plugins/openresty-header-policy.wasm"
sha256 = "$OPENRESTY_SHA"
phases = ["request-headers", "response-headers"]
fail_mode = "fail-closed"

[[wasm.plugins]]
name = "haproxy"
path = "$TMP_DIR/plugins/haproxy-spoe-routing-policy.wasm"
sha256 = "$HAPROXY_SHA"
phases = ["route-decision"]
fail_mode = "fail-closed"

[[wasm.plugins]]
name = "vcl_lookup"
path = "$TMP_DIR/plugins/cache-lookup-policy.wasm"
sha256 = "$CACHE_LOOKUP_SHA"
phases = ["cache-lookup"]
fail_mode = "fail-closed"

[[wasm.plugins]]
name = "vcl_store"
path = "$TMP_DIR/plugins/cache-store-policy.wasm"
sha256 = "$CACHE_STORE_SHA"
phases = ["cache-store"]
fail_mode = "fail-closed"

[[wasm.attachments]]
plugin = "irules"
vhost = "irules.test"
route = "admin"
priority = 100
phases = ["access-decision"]

[[wasm.attachments]]
plugin = "openresty"
vhost = "openresty.test"
route = "gold"
priority = 100
phases = ["request-headers", "response-headers"]

[[wasm.attachments]]
plugin = "haproxy"
vhost = "haproxy.test"
priority = 100
phases = ["route-decision"]

[[wasm.attachments]]
plugin = "vcl_lookup"
vhost = "vcl.test"
route = "static"
priority = 100
phases = ["cache-lookup"]

[[wasm.attachments]]
plugin = "vcl_store"
vhost = "vcl.test"
route = "static"
priority = 100
phases = ["cache-store"]

[[vhosts]]
name = "irules.test"
hosts = ["irules.test"]

[vhosts.proxy]
upstreams = ["127.0.0.1:$STABLE_PORT"]

[[vhosts.routes]]
name = "admin"
path_prefix = "/admin/"

[vhosts.routes.proxy]
upstreams = ["127.0.0.1:$STABLE_PORT"]

[[vhosts]]
name = "openresty.test"
hosts = ["openresty.test"]

[[vhosts.routes]]
name = "gold"
path_prefix = "/gold/"
strip_prefix = "/gold"

[vhosts.routes.proxy]
upstreams = ["127.0.0.1:$STABLE_PORT"]

[[vhosts]]
name = "haproxy.test"
hosts = ["haproxy.test"]

[[vhosts.routes]]
name = "standard"
path_prefix = "/app/"

[vhosts.routes.proxy]
upstreams = ["127.0.0.1:$STABLE_PORT"]

[[vhosts.routes]]
name = "canary"
path_prefix = "/app/"

[vhosts.routes.proxy]
upstreams = ["127.0.0.1:$CANARY_PORT"]

[[vhosts.routes]]
name = "mirror"
path_prefix = "/app/"

[vhosts.routes.proxy]
upstreams = ["127.0.0.1:$STABLE_PORT"]

[[vhosts]]
name = "vcl.test"
hosts = ["vcl.test"]

[[vhosts.routes]]
name = "static"
path_prefix = "/static/"

[vhosts.routes.cache]
enabled = true
status_header = "X-Cache-Status"

[vhosts.routes.cache.memory]
enabled = true

[vhosts.routes.proxy]
upstreams = ["127.0.0.1:$STABLE_PORT"]
EOF

python3 "$TMP_DIR/origin.py" "$STABLE_PORT" stable >"$TMP_DIR/stable.log" 2>&1 &
STABLE_PID=$!
python3 "$TMP_DIR/origin.py" "$CANARY_PORT" canary >"$TMP_DIR/canary.log" 2>&1 &
CANARY_PID=$!

(cd "$ROOT_DIR" && cargo build --quiet --locked --no-default-features \
    --features profile-development,wasm --bin fluxheim)

"$ROOT_DIR/target/debug/fluxheim" --config "$TMP_DIR/fluxheim.toml" \
    >"$TMP_DIR/fluxheim.log" 2>&1 &
FLUXHEIM_PID=$!

request() {
    label=$1
    host=$2
    path=$3
    shift 3
    curl --silent --show-error --max-time 5 \
        --dump-header "$TMP_DIR/$label.headers" \
        --output "$TMP_DIR/$label.body" \
        --write-out '%{http_code}' \
        --header "Host: $host" "$@" \
        "http://127.0.0.1:$FLUXHEIM_PORT$path" 2>/dev/null || true
}

status=
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20; do
    status=$(request wait irules.test /public)
    if [ "$status" = "200" ]; then
        break
    fi
    sleep 0.25
done
if [ "$status" != "200" ]; then
    echo "Wasm binary smoke failed to start (status ${status:-none})" >&2
    cat "$TMP_DIR/fluxheim.log" >&2
    exit 1
fi

status=$(request irules-deny irules.test /admin/panel)
test "$status" = "403"
grep -q '^wasm access denied$' "$TMP_DIR/irules-deny.body"

status=$(request openresty openresty.test /gold/item)
test "$status" = "200"
grep -q 'tier=gold' "$TMP_DIR/openresty.body"
grep -qi '^x-fluxheim-policy-branch: gold' "$TMP_DIR/openresty.headers"
if grep -qi '^x-powered-by:' "$TMP_DIR/openresty.headers"; then
    echo "OpenResty-style response policy did not remove x-powered-by" >&2
    exit 1
fi

status=$(request haproxy-stable haproxy.test /app/item)
test "$status" = "200"
grep -q '^stable ' "$TMP_DIR/haproxy-stable.body"
status=$(request haproxy-canary haproxy.test /app/item --header 'X-Canary: 1')
test "$status" = "200"
grep -q '^canary ' "$TMP_DIR/haproxy-canary.body"

status=$(request vcl-mobile vcl.test /static/item.png --header 'X-Device-Class: mobile')
test "$status" = "200"
grep -qi '^x-cache-status: MISS' "$TMP_DIR/vcl-mobile.headers"
status=$(request vcl-desktop vcl.test /static/item.png --header 'X-Device-Class: desktop')
test "$status" = "200"
grep -qi '^x-cache-status: MISS' "$TMP_DIR/vcl-desktop.headers"
if cmp -s "$TMP_DIR/vcl-mobile.body" "$TMP_DIR/vcl-desktop.body"; then
    echo "VCL-style device-class cache variants collided" >&2
    exit 1
fi
status=$(request vcl-mobile-hit vcl.test /static/item.png --header 'X-Device-Class: mobile')
test "$status" = "200"
grep -qi '^x-cache-status: HIT' "$TMP_DIR/vcl-mobile-hit.headers"
cmp "$TMP_DIR/vcl-mobile.body" "$TMP_DIR/vcl-mobile-hit.body"
grep -qi '^x-fluxheim-cache-policy: wasm' "$TMP_DIR/vcl-mobile-hit.headers"
sleep 1.2
status=$(request vcl-mobile-expired vcl.test /static/item.png --header 'X-Device-Class: mobile')
test "$status" = "200"
grep -qi '^x-cache-status: MISS' "$TMP_DIR/vcl-mobile-expired.headers"
if cmp -s "$TMP_DIR/vcl-mobile.body" "$TMP_DIR/vcl-mobile-expired.body"; then
    echo "VCL-style one-second TTL did not expire" >&2
    exit 1
fi

echo "wasm policy examples standalone binary smoke: ok"
