#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SMOKE_TMP_ROOT=$(sh "$ROOT_DIR/scripts/secure-smoke-tmp-root.sh")
port="${FLUXHEIM_SMOKE_PORT:-18080}"
tmp="$SMOKE_TMP_ROOT/fluxheim-static-smoke-$$"
config="$tmp/fluxheim.toml"
body="$tmp/body.txt"

cleanup() {
    if [ -n "${server_pid:-}" ]; then
        kill "$server_pid" 2>/dev/null || true
        sleep 0.2
        if kill -0 "$server_pid" 2>/dev/null; then
            kill -9 "$server_pid" 2>/dev/null || true
        fi
        wait "$server_pid" 2>/dev/null || true
    fi
    rm -rf "$tmp"
}

trap cleanup EXIT INT TERM

mkdir -p "$tmp/public" "$tmp/run"
printf '%s\n' '<!doctype html><title>Fluxheim smoke</title><h1>Fluxheim smoke ok</h1>' > "$tmp/public/index.html"
printf '%s\n' 'local-static-cache-webp' > "$tmp/public/asset.webp"

cat > "$config" <<EOF
[server]
listen = ["127.0.0.1:$port"]
default_vhost = "static.test"
trusted_proxies = []

[server.process]
pid_file = "$tmp/run/fluxheim.pid"
upgrade_sock = "$tmp/run/fluxheim-upgrade.sock"
certificate_reload_sock = "$tmp/run/fluxheim-cert-reload.sock"

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

[headers.response.set]
cache-control = "public, max-age=60"

[proxy]
upstreams = ["127.0.0.1:9"]
upstream_tls = false

[tls]
enabled = false
backend = "rustls"

[cache]
enabled = false

[[vhosts]]
name = "static.test"
hosts = ["static.test"]

[vhosts.cache]
enabled = true
local_static = true
status_header = "x-cache-status"
status_reason_header = "x-cache-reason"
image_extensions = ["webp"]
content_types = ["image/webp"]
max_object_bytes = "1MiB"

[vhosts.cache.memory]
enabled = true
max_size_bytes = "16MiB"

[vhosts.web]
root = "$tmp/public"
index_files = ["index.html"]
deny_dotfiles = true
cache_control = "public, max-age=60"
EOF

cargo build --quiet
target/debug/fluxheim --config "$config" &
server_pid="$!"

status=""
for _ in 1 2 3 4 5 6 7 8 9 10; do
    status="$(curl -sS -o "$body" -w '%{http_code}' "http://127.0.0.1:$port/" 2>/dev/null || true)"
    if [ "$status" = "200" ]; then
        break
    fi
    sleep 0.2
done

if [ "$status" != "200" ]; then
    echo "static smoke failed: expected HTTP 200, got ${status:-no response}" >&2
    exit 1
fi

if ! grep -q "Fluxheim smoke ok" "$body"; then
    echo "static smoke failed: response body did not contain expected marker" >&2
    exit 1
fi

headers="$(curl -sSI "http://127.0.0.1:$port/")"
case "$headers" in
    *"x-content-type-options: nosniff"*|*"X-Content-Type-Options: nosniff"*) ;;
    *)
        echo "static smoke failed: missing x-content-type-options header" >&2
        echo "$headers" >&2
        exit 1
        ;;
esac

asset_headers="$tmp/asset-headers.txt"
asset_body="$tmp/asset-body.txt"
curl -sS -D "$asset_headers" -o "$asset_body" -H "Host: static.test" "http://127.0.0.1:$port/asset.webp"
if ! grep -q "local-static-cache-webp" "$asset_body"; then
    echo "static smoke failed: local cached asset body mismatch on first request" >&2
    exit 1
fi
if ! grep -qi '^x-cache-status: MISS' "$asset_headers"; then
    echo "static smoke failed: first local static cache request was not MISS" >&2
    cat "$asset_headers" >&2
    exit 1
fi

curl -sS -D "$asset_headers" -o "$asset_body" -H "Host: static.test" "http://127.0.0.1:$port/asset.webp"
if ! grep -q "local-static-cache-webp" "$asset_body"; then
    echo "static smoke failed: local cached asset body mismatch on second request" >&2
    exit 1
fi
if ! grep -qi '^x-cache-status: HIT' "$asset_headers"; then
    echo "static smoke failed: second local static cache request was not HIT" >&2
    cat "$asset_headers" >&2
    exit 1
fi
if ! grep -qi '^age:' "$asset_headers"; then
    echo "static smoke failed: local static cache HIT did not include Age header" >&2
    cat "$asset_headers" >&2
    exit 1
fi

echo "static smoke: ok"
