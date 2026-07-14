#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SMOKE_TMP_ROOT=$(sh "$ROOT_DIR/scripts/secure-smoke-tmp-root.sh")
TMP_DIR=$(mktemp -d "$SMOKE_TMP_ROOT/fluxheim-framing-smoke.XXXXXX")
KEEP_LOGS=${FLUXHEIM_FRAMING_KEEP_LOGS:-0}
BUILD_RELEASE=${FLUXHEIM_FRAMING_BUILD:-1}

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
        echo "request framing smoke artifacts kept in $TMP_DIR" >&2
    else
        rm -rf "$TMP_DIR"
    fi
}
trap cleanup EXIT INT TERM

FLUXHEIM_PORT=$(python3 - <<'PY'
import socket

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    sock.bind(("127.0.0.1", 0))
    print(sock.getsockname()[1])
finally:
    sock.close()
PY
)

mkdir -p "$TMP_DIR/public"
mkdir -p "$TMP_DIR/run"
printf '%s\n' '<!doctype html><title>Fluxheim framing smoke</title><h1>framing-ok</h1>' > "$TMP_DIR/public/index.html"

cat > "$TMP_DIR/fluxheim.toml" <<EOF
[server]
listen = ["127.0.0.1:$FLUXHEIM_PORT"]
default_vhost = "static.test"
trusted_proxies = []

[server.process]
daemon = false
pid_file = "$TMP_DIR/run/fluxheim.pid"
upgrade_sock = "$TMP_DIR/run/fluxheim-upgrade.sock"
certificate_reload_sock = "$TMP_DIR/run/fluxheim-cert-reload.sock"

[server.limits]
max_request_header_bytes = "2KiB"
max_uri_bytes = "512B"
max_request_headers = 8
max_request_body_bytes = "16B"

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
enabled = false
backend = "rustls"

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
    status="$(curl -sS -o "$TMP_DIR/body.txt" -w '%{http_code}' -H "Host: static.test" "http://127.0.0.1:$FLUXHEIM_PORT/" 2>/dev/null || true)"
    if [ "$status" = "200" ]; then
        break
    fi
    sleep 0.2
done

if [ "${status:-}" != "200" ]; then
    echo "request framing smoke failed: expected HTTP 200 before malformed cases, got ${status:-no response}" >&2
    exit 1
fi

python3 - "$FLUXHEIM_PORT" <<'PY'
import socket
import sys

port = int(sys.argv[1])


def status_code(raw: bytes) -> int:
    with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
        sock.sendall(raw)
        sock.shutdown(socket.SHUT_WR)
        data = sock.recv(4096)
    line = data.split(b"\r\n", 1)[0].decode("ascii", "replace")
    parts = line.split()
    if len(parts) < 2 or not parts[1].isdigit():
        raise AssertionError(f"invalid response line: {line!r}")
    return int(parts[1])


cases = [
    (
        "valid_get",
        b"GET / HTTP/1.1\r\nHost: static.test\r\nConnection: close\r\n\r\n",
        {200},
    ),
    (
        "invalid_content_length",
        b"POST / HTTP/1.1\r\nHost: static.test\r\nContent-Length: nope\r\nConnection: close\r\n\r\n",
        {400},
    ),
    (
        "content_length_plus_transfer_encoding",
        b"POST / HTTP/1.1\r\nHost: static.test\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n",
        {400, 411},
    ),
    (
        "valid_chunked_without_content_length",
        b"POST / HTTP/1.1\r\nHost: static.test\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n0\r\n\r\n",
        {404},
    ),
    (
        "content_length_over_limit",
        b"POST / HTTP/1.1\r\nHost: static.test\r\nContent-Length: 17\r\nConnection: close\r\n\r\n",
        {413},
    ),
    (
        "conflicting_absolute_authority",
        b"GET http://public.test/ HTTP/1.1\r\nHost: static.test\r\nConnection: close\r\n\r\n",
        {400},
    ),
    (
        "http10_transfer_encoding",
        b"POST / HTTP/1.0\r\nHost: static.test\r\nTransfer-Encoding: chunked\r\nConnection: keep-alive\r\n\r\n0\r\n\r\n",
        {400},
    ),
    (
        "raw_character_outside_uri_grammar",
        b"GET /raw{brace} HTTP/1.1\r\nHost: static.test\r\nConnection: close\r\n\r\n",
        {400},
    ),
    (
        "overflow_chunk_size",
        b"POST / HTTP/1.1\r\nHost: static.test\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\nffffffffffffffff\r\n",
        {400},
    ),
]

many_headers = b"GET / HTTP/1.1\r\nHost: static.test\r\n" + b"".join(
    f"X-Test-{index}: value\r\n".encode("ascii") for index in range(20)
) + b"Connection: close\r\n\r\n"
cases.append(("too_many_headers", many_headers, {431}))

for name, raw, expected_statuses in cases:
    try:
        actual = status_code(raw)
    except AssertionError as error:
        raise AssertionError(f"{name}: {error}") from error
    if actual not in expected_statuses:
        expected = ", ".join(str(status) for status in sorted(expected_statuses))
        raise AssertionError(f"{name}: expected one of {expected}, got {actual}")
PY

echo "request framing smoke: ok"
