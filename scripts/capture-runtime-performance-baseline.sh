#!/usr/bin/env sh
set -eu

mode="${1:-release}"

case "$mode" in
    release | check)
        ;;
    *)
        echo "usage: scripts/capture-runtime-performance-baseline.sh [release|check]" >&2
        exit 2
        ;;
esac

if [ "$mode" = "check" ]; then
    echo "runtime performance baseline: check mode has no runtime work"
    exit 0
fi

out_dir="${FLUXHEIM_RUNTIME_BASELINE_DIR:-target/release-evidence/runtime-baseline}"
sample_count="${FLUXHEIM_RUNTIME_BASELINE_SAMPLES:-20}"
keepalive_count="${FLUXHEIM_RUNTIME_BASELINE_KEEPALIVE_REQUESTS:-100}"
tmp_dir="$(mktemp -d "${TMPDIR:-/tmp}/fluxheim-runtime-baseline.XXXXXX")"

fluxheim_pid=""
origin_one_pid=""
origin_two_pid=""

cleanup() {
    for pid in "$fluxheim_pid" "$origin_one_pid" "$origin_two_pid"; do
        if [ -n "$pid" ]; then
            kill "$pid" 2>/dev/null || true
        fi
    done

    sleep 0.2

    for pid in "$fluxheim_pid" "$origin_one_pid" "$origin_two_pid"; do
        if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null; then
            kill -9 "$pid" 2>/dev/null || true
        fi
    done

    for pid in "$fluxheim_pid" "$origin_one_pid" "$origin_two_pid"; do
        if [ -n "$pid" ]; then
            wait "$pid" 2>/dev/null || true
        fi
    done

    if [ "${FLUXHEIM_RUNTIME_BASELINE_KEEP_TMP:-0}" = "1" ]; then
        echo "runtime performance baseline: kept $tmp_dir" >&2
    else
        rm -rf "$tmp_dir"
    fi
}
trap cleanup EXIT INT TERM

mkdir -p "$out_dir" "$tmp_dir/public" "$tmp_dir/run" "$tmp_dir/tls"
printf '%s\n' '<!doctype html><title>Fluxheim baseline</title><h1>baseline-ok</h1>' >"$tmp_dir/public/index.html"
printf '%s\n' 'runtime-baseline-cache-object' >"$tmp_dir/public/asset.webp"

if [ ! -x target/release/fluxheim ]; then
    echo "runtime performance baseline: building default release binary"
    cargo build --release --locked --bin fluxheim
fi

ports="$(python3 - <<'PY'
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
)"

set -- $ports
http_port="$1"
tls_port="$2"
origin_one_port="$3"
origin_two_port="$4"

cat >"$tmp_dir/origin.py" <<'PY'
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    label = "origin"

    def do_GET(self):
        body = f"{self.label}\npath={self.path}\n".encode("ascii")
        self.send_response(200)
        self.send_header("content-type", "text/plain; charset=ascii")
        self.send_header("content-length", str(len(body)))
        self.send_header("x-origin", self.label)
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, _format, *args):
        return


if __name__ == "__main__":
    Handler.label = sys.argv[2]
    ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1])), Handler).serve_forever()
PY

cat >"$tmp_dir/keepalive.py" <<'PY'
import http.client
import sys
import time

host = sys.argv[1]
port = int(sys.argv[2])
host_header = sys.argv[3]
path = sys.argv[4]
count = int(sys.argv[5])

conn = http.client.HTTPConnection(host, port, timeout=5)
start = time.perf_counter()
ok = 0
try:
    for _ in range(count):
        conn.request("GET", path, headers={"Host": host_header, "Connection": "keep-alive"})
        response = conn.getresponse()
        response.read()
        if response.status == 200:
            ok += 1
finally:
    conn.close()
elapsed = time.perf_counter() - start
rate = ok / elapsed if elapsed > 0 else 0.0
print(f"{count}\t{ok}\t{elapsed:.6f}\t{rate:.3f}")
PY

origin_one_log="$tmp_dir/origin-one.log"
origin_two_log="$tmp_dir/origin-two.log"
python3 "$tmp_dir/origin.py" "$origin_one_port" origin-one >"$origin_one_log" 2>&1 &
origin_one_pid="$!"
python3 "$tmp_dir/origin.py" "$origin_two_port" origin-two >"$origin_two_log" 2>&1 &
origin_two_pid="$!"

tls_enabled="false"
tls_listen="[]"
tls_cert_block=""
if command -v openssl >/dev/null 2>&1; then
    openssl req \
        -x509 \
        -newkey rsa:2048 \
        -nodes \
        -sha256 \
        -days 1 \
        -subj "/CN=baseline.test" \
        -addext "subjectAltName=DNS:baseline.test,IP:127.0.0.1" \
        -keyout "$tmp_dir/tls/key.pem" \
        -out "$tmp_dir/tls/fullchain.pem" >/dev/null 2>&1
    chmod 600 "$tmp_dir/tls/key.pem"
    tls_enabled="true"
    tls_listen="[\"127.0.0.1:$tls_port\"]"
    tls_cert_block="
[[tls.certificates]]
cert_path = \"$tmp_dir/tls/fullchain.pem\"
key_path = \"$tmp_dir/tls/key.pem\"
"
fi

cat >"$tmp_dir/fluxheim.toml" <<EOF
[server]
listen = ["127.0.0.1:$http_port"]
tls_listen = $tls_listen
default_vhost = "baseline.test"
trusted_proxies = []

[server.process]
daemon = false
pid_file = "$tmp_dir/run/fluxheim.pid"
upgrade_sock = "$tmp_dir/run/fluxheim-upgrade.sock"
certificate_reload_sock = "$tmp_dir/run/fluxheim-cert-reload.sock"

[logging]
level = "warn"
format = "text"

[logging.access]
enabled = false
request_id = false

[headers.response]
enabled = true
x_content_type_options = "nosniff"
unset = ["server", "x-powered-by"]

[proxy]
upstreams = ["127.0.0.1:$origin_one_port"]
upstream_tls = false

[tls]
enabled = $tls_enabled
backend = "rustls"
$tls_cert_block

[cache]
enabled = false

[[vhosts]]
name = "baseline.test"
hosts = ["baseline.test", "127.0.0.1"]

[vhosts.web]
root = "$tmp_dir/public"
index_files = ["index.html"]
deny_dotfiles = true
cache_control = "public, max-age=60"

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

[[vhosts.routes]]
name = "lb"
path_prefix = "/lb/"

[vhosts.routes.proxy]
upstreams = ["127.0.0.1:$origin_one_port", "127.0.0.1:$origin_two_port"]
upstream_aliases = ["origin-one", "origin-two"]
upstream_tls = false

[vhosts.routes.proxy.load_balance]
selection = "round-robin"
max_iterations = 64
all_down_status = 503
EOF

now_ns() {
    date +%s%N
}

fluxheim_log="$tmp_dir/fluxheim.log"
start_ns="$(now_ns)"
target/release/fluxheim --config "$tmp_dir/fluxheim.toml" >"$fluxheim_log" 2>&1 &
fluxheim_pid="$!"

status=""
for _ in $(seq 1 100); do
    status="$(curl -sS --noproxy '*' -o /dev/null -w '%{http_code}' -H "Host: baseline.test" "http://127.0.0.1:$http_port/" 2>/dev/null || true)"
    if [ "$status" = "200" ]; then
        break
    fi
    sleep 0.05
done
ready_ns="$(now_ns)"

if [ "$status" != "200" ]; then
    echo "runtime performance baseline: Fluxheim did not become ready" >&2
    sed -n '1,120p' "$fluxheim_log" >&2 || true
    exit 1
fi

startup_ms="$(((ready_ns - start_ns) / 1000000))"
printf 'scenario\tmilliseconds\nstartup_http_ready\t%s\n' "$startup_ms" >"$out_dir/startup-time.tsv"

sleep 0.2
rss_kb="$(awk '/^VmRSS:/ { print $2; found = 1 } END { if (!found) print 0 }' "/proc/$fluxheim_pid/status" 2>/dev/null || printf '0')"
fd_count="$(find "/proc/$fluxheim_pid/fd" -maxdepth 1 -type l 2>/dev/null | wc -l | tr -d ' ')"
{
    printf 'metric\tvalue\n'
    printf 'rss_kb\t%s\n' "$rss_kb"
    printf 'fd_count\t%s\n' "$fd_count"
    printf 'sample_count\t%s\n' "$sample_count"
    printf 'keepalive_count\t%s\n' "$keepalive_count"
    printf 'tls_enabled\t%s\n' "$tls_enabled"
} >"$out_dir/process-idle.tsv"

curl_sample() {
    scenario="$1"
    iteration="$2"
    url="$3"
    result="$(curl -sS --noproxy '*' -o /dev/null -w '%{http_code} %{time_total}' -H "Host: baseline.test" "$url")"
    set -- $result
    printf '%s\t%s\t%s\t%s\n' "$scenario" "$iteration" "$1" "$2"
}

{
    printf 'scenario\titeration\tstatus\tseconds\n'
    i=1
    while [ "$i" -le "$sample_count" ]; do
        curl_sample static "$i" "http://127.0.0.1:$http_port/"
        i=$((i + 1))
    done
} >"$out_dir/http-latency.tsv"

cache_headers="$tmp_dir/cache-headers.txt"
{
    printf 'scenario\titeration\tstatus\tcache_status\tseconds\n'
    result="$(curl -sS --noproxy '*' -D "$cache_headers" -o /dev/null -w '%{http_code} %{time_total}' -H "Host: baseline.test" "http://127.0.0.1:$http_port/asset.webp")"
    set -- $result
    cache_status="$(awk 'tolower($1) == "x-cache-status:" { gsub("\r", "", $2); print $2; found = 1 } END { if (!found) print "missing" }' "$cache_headers")"
    printf 'cache_miss\t1\t%s\t%s\t%s\n' "$1" "$cache_status" "$2"

    i=1
    while [ "$i" -le "$sample_count" ]; do
        result="$(curl -sS --noproxy '*' -D "$cache_headers" -o /dev/null -w '%{http_code} %{time_total}' -H "Host: baseline.test" "http://127.0.0.1:$http_port/asset.webp")"
        set -- $result
        cache_status="$(awk 'tolower($1) == "x-cache-status:" { gsub("\r", "", $2); print $2; found = 1 } END { if (!found) print "missing" }' "$cache_headers")"
        printf 'cache_hit\t%s\t%s\t%s\t%s\n' "$i" "$1" "$cache_status" "$2"
        i=$((i + 1))
    done
} >"$out_dir/cache-latency.tsv"

lb_headers="$tmp_dir/lb-headers.txt"
{
    printf 'scenario\titeration\tstatus\torigin\tseconds\n'
    i=1
    while [ "$i" -le "$sample_count" ]; do
        result="$(curl -sS --noproxy '*' -D "$lb_headers" -o /dev/null -w '%{http_code} %{time_total}' -H "Host: baseline.test" "http://127.0.0.1:$http_port/lb/request-$i")"
        set -- $result
        origin="$(awk 'tolower($1) == "x-origin:" { gsub("\r", "", $2); print $2; found = 1 } END { if (!found) print "missing" }' "$lb_headers")"
        printf 'round_robin\t%s\t%s\t%s\t%s\n' "$i" "$1" "$origin" "$2"
        i=$((i + 1))
    done
} >"$out_dir/load-balancer-latency.tsv"

{
    printf 'scenario\trequests\tok\tseconds\trequests_per_second\n'
    set -- $(python3 "$tmp_dir/keepalive.py" 127.0.0.1 "$http_port" baseline.test / "$keepalive_count")
    printf 'static\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4"
    set -- $(python3 "$tmp_dir/keepalive.py" 127.0.0.1 "$http_port" baseline.test /lb/keepalive "$keepalive_count")
    printf 'load_balancer\t%s\t%s\t%s\t%s\n' "$1" "$2" "$3" "$4"
} >"$out_dir/keepalive-throughput.tsv"

{
    printf 'scenario\titeration\tstatus\tseconds\n'
    if [ "$tls_enabled" = "true" ]; then
        i=1
        while [ "$i" -le "$sample_count" ]; do
            result="$(curl -k -sS --noproxy '*' -o /dev/null -w '%{http_code} %{time_total}' -H "Host: baseline.test" "https://127.0.0.1:$tls_port/")"
            set -- $result
            printf 'rustls_https\t%s\t%s\t%s\n' "$i" "$1" "$2"
            i=$((i + 1))
        done
    else
        printf 'rustls_https\t0\tskipped\t0\n'
    fi
} >"$out_dir/tls-handshake-latency.tsv"

cat >"$out_dir/performance-README.txt" <<EOF
Fluxheim runtime performance baseline.

Generated by scripts/capture-runtime-performance-baseline.sh.
This is a lightweight local baseline, not a full load test. Compare future
1.6.x cutovers against trends and obvious regressions, not single-sample noise.

Samples: $sample_count
Keepalive requests: $keepalive_count
Release features: ${FLUXHEIM_RUNTIME_BASELINE_FEATURES:-profile-load-balancer}
Temporary config: $tmp_dir/fluxheim.toml
EOF

echo "runtime performance baseline: wrote $out_dir"
