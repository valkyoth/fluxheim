#!/usr/bin/env sh
set -eu

port="${FLUXHEIM_SMOKE_PORT:-18080}"
tmp="${TMPDIR:-/tmp}/fluxheim-static-smoke-$$"
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

mkdir -p "$tmp/public"
printf '%s\n' '<!doctype html><title>Fluxheim smoke</title><h1>Fluxheim smoke ok</h1>' > "$tmp/public/index.html"

cat > "$config" <<EOF
[server]
listen = ["127.0.0.1:$port"]
trusted_proxies = []

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

[web]
root = "$tmp/public"
index_files = ["index.html"]
deny_dotfiles = true
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

echo "static smoke: ok"
