#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
TMP_ROOT="$ROOT_DIR/target/fluxheim-wasm-container-smoke"
mkdir -p "$TMP_ROOT"
TMP_DIR=$(mktemp -d "$TMP_ROOT/run.XXXXXX")
KEEP_LOGS=${FLUXHEIM_SMOKE_KEEP_LOGS:-0}
CURL_MAX_TIME=${FLUXHEIM_SMOKE_CURL_MAX_TIME:-5}
IMAGE=${FLUXHEIM_WASM_CONTAINER_SMOKE_IMAGE:-fluxheim:wasm-container-smoke}
CONTAINERFILE=${FLUXHEIM_WASM_CONTAINER_SMOKE_CONTAINERFILE:-containers/Containerfile.wolfi}
FEATURES=${FLUXHEIM_WASM_CONTAINER_SMOKE_FEATURES:-profile-wasm,acme-client,metrics,metrics-otlp,otel-tracing,otel-otlp}
CONTAINER_NAME="fluxheim-wasm-container-smoke-$$"

if [ -z "${CONTAINER_HOST:-}" ] && [ -n "${XDG_RUNTIME_DIR:-}" ] \
    && [ -S "$XDG_RUNTIME_DIR/podman/podman.sock" ]; then
    CONTAINER_HOST="unix://$XDG_RUNTIME_DIR/podman/podman.sock"
    export CONTAINER_HOST
fi

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "Wasm container smoke requires $1" >&2
        exit 1
    fi
}

CONTAINER_STARTED=0
ORIGIN_PID=

cleanup() {
    status=$?
    if [ "$CONTAINER_STARTED" -eq 1 ]; then
        podman rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
    fi
    if [ -n "$ORIGIN_PID" ]; then
        kill "$ORIGIN_PID" 2>/dev/null || true
        wait "$ORIGIN_PID" 2>/dev/null || true
    fi
    if [ "$KEEP_LOGS" = "1" ] || [ "$status" -ne 0 ]; then
        echo "Wasm container smoke artifacts kept in $TMP_DIR" >&2
    else
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT INT TERM

for command in curl podman python3 sha256sum; do
    require_command "$command"
done

ports=$(python3 "$ROOT_DIR/scripts/smoke_ports.py" 2)
set -- $ports
FLUXHEIM_PORT=$1
ORIGIN_PORT=$2

mkdir -p "$TMP_DIR/plugins"
chmod 755 "$TMP_DIR" "$TMP_DIR/plugins"

(cd "$ROOT_DIR" && scripts/build_wasm_policy_examples.sh)
cp "$ROOT_DIR/target/wasm-policy-examples/irules-access-policy.wasm" \
    "$TMP_DIR/plugins/irules-access-policy.wasm"
chmod 644 "$TMP_DIR/plugins/irules-access-policy.wasm"
PLUGIN_SHA=$(
    sha256sum "$TMP_DIR/plugins/irules-access-policy.wasm" | awk '{print $1}'
)

cat > "$TMP_DIR/origin.py" <<'PY'
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = f"container origin path={self.path}\n".encode("ascii")
        self.send_response(200)
        self.send_header("content-type", "text/plain; charset=ascii")
        self.send_header("content-length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *args):
        return


ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
PY

cat > "$TMP_DIR/fluxheim.toml" <<EOF
[server]
listen = ["127.0.0.1:$FLUXHEIM_PORT"]
default_vhost = "wasm-container.test"
trusted_proxies = []

[server.process]
daemon = false
pid_file = "/run/fluxheim/wasm-container-smoke.pid"
upgrade_sock = "/run/fluxheim/wasm-container-smoke-upgrade.sock"
certificate_reload_sock = "/run/fluxheim/wasm-container-smoke-cert.sock"
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

[wasm]
enabled = true
plugin_roots = ["/etc/fluxheim/plugins"]
max_total_concurrent_executions = 8

[[wasm.plugins]]
name = "container-access"
path = "/etc/fluxheim/plugins/irules-access-policy.wasm"
sha256 = "$PLUGIN_SHA"
phases = ["access-decision"]
fail_mode = "fail-closed"

[[wasm.attachments]]
plugin = "container-access"
vhost = "wasm-container.test"
route = "admin"
priority = 100
phases = ["access-decision"]

[[vhosts]]
name = "wasm-container.test"
hosts = ["wasm-container.test", "127.0.0.1", "localhost"]

[vhosts.proxy]
upstreams = ["127.0.0.1:$ORIGIN_PORT"]

[[vhosts.routes]]
name = "admin"
path_prefix = "/admin/"

[vhosts.routes.proxy]
upstreams = ["127.0.0.1:$ORIGIN_PORT"]
EOF
chmod 644 "$TMP_DIR/fluxheim.toml"

python3 "$TMP_DIR/origin.py" "$ORIGIN_PORT" >"$TMP_DIR/origin.log" 2>&1 &
ORIGIN_PID=$!

"$ROOT_DIR/scripts/validate-features.sh" "$FEATURES"
if [ -z "${FLUXHEIM_WASM_CONTAINER_SMOKE_IMAGE:-}" ]; then
    (
        cd "$ROOT_DIR"
        podman build \
            --build-arg "FLUXHEIM_FEATURES=$FEATURES" \
            --build-arg "FLUXHEIM_CONFIG=packaging/container/fluxheim.toml" \
            --tag "$IMAGE" \
            --file "$CONTAINERFILE" \
            .
    )
fi

podman rm -f "$CONTAINER_NAME" >/dev/null 2>&1 || true
podman run -d \
    --name "$CONTAINER_NAME" \
    --network host \
    --volume "$TMP_DIR/fluxheim.toml:/etc/fluxheim/fluxheim.toml:ro,Z" \
    --volume "$TMP_DIR/plugins:/etc/fluxheim/plugins:ro,Z" \
    "$IMAGE" \
    --config /etc/fluxheim/fluxheim.toml \
    >"$TMP_DIR/container.id"
CONTAINER_STARTED=1

request() {
    label=$1
    path=$2
    curl --silent --show-error --max-time "$CURL_MAX_TIME" \
        --dump-header "$TMP_DIR/$label.headers" \
        --output "$TMP_DIR/$label.body" \
        --write-out '%{http_code}' \
        --header "Host: wasm-container.test" \
        "http://127.0.0.1:$FLUXHEIM_PORT$path" 2>/dev/null || true
}

status=
for _ in $(seq 1 80); do
    status=$(request wait /public)
    if [ "$status" = "200" ]; then
        break
    fi
    sleep 0.25
done
if [ "$status" != "200" ]; then
    echo "Wasm container failed to become ready (status ${status:-none})" >&2
    podman logs "$CONTAINER_NAME" >&2 || true
    exit 1
fi
grep -q '^container origin path=/public$' "$TMP_DIR/wait.body"

if podman exec "$CONTAINER_NAME" sh -c \
    'printf x > /etc/fluxheim/plugins/write-probe' >/dev/null 2>&1; then
    echo "Wasm container plugin mount was writable" >&2
    exit 1
fi

status=$(request denied /admin/panel)
test "$status" = "403"
grep -q '^wasm access denied$' "$TMP_DIR/denied.body"

status=$(request allowed /public/item)
test "$status" = "200"
grep -q '^container origin path=/public/item$' "$TMP_DIR/allowed.body"

echo "Wasm container read-only plugin mount smoke: ok"
