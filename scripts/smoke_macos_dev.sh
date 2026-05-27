#!/usr/bin/env sh
set -eu

ROOT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd -P)"
PORT="${FLUXHEIM_MACOS_SMOKE_PORT:-18088}"
SMOKE_PARENT="${FLUXHEIM_MACOS_SMOKE_PARENT:-$ROOT_DIR/target}"
mkdir -p "$SMOKE_PARENT"
chmod 700 "$SMOKE_PARENT" >/dev/null 2>&1 || true
TMP_DIR="$(mktemp -d "$SMOKE_PARENT/fluxheim-macos-smoke.XXXXXX")"
PID=""

cleanup() {
    if [ -n "$PID" ]; then
        kill "$PID" >/dev/null 2>&1 || true
        sleep 1
        kill -9 "$PID" >/dev/null 2>&1 || true
        wait "$PID" >/dev/null 2>&1 || true
    fi
    if [ "${FLUXHEIM_KEEP_SMOKE:-0}" != "1" ]; then
        rm -rf "$TMP_DIR"
    else
        echo "macOS smoke artifacts kept in $TMP_DIR" >&2
    fi
}
trap cleanup EXIT INT TERM

mkdir -p "$TMP_DIR/site" "$TMP_DIR/logs"
cat >"$TMP_DIR/site/index.html" <<'HTML'
<!doctype html>
<html><body>fluxheim macos smoke</body></html>
HTML

cat >"$TMP_DIR/fluxheim.toml" <<EOF
[server]
listen = ["127.0.0.1:$PORT"]
trusted_proxies = []

[server.process]
daemon = false
pid_file = "$TMP_DIR/fluxheim.pid"
upgrade_sock = "$TMP_DIR/fluxheim-upgrade.sock"
certificate_reload_sock = "$TMP_DIR/fluxheim-cert-reload.sock"
threads = 1
listener_tasks_per_fd = 1
work_stealing = true

[logging]
level = "info"
format = "json"
target = "stderr"

[logging.file]
enabled = true
path = "$TMP_DIR/logs/fluxheim.log"
append = true

[logging.access]
enabled = true
include_host = true
include_path = true
request_id = true

[web]
root = "$TMP_DIR/site"
index_files = ["index.html"]
deny_dotfiles = true
cache_control = "public, max-age=60"
EOF

cd "$ROOT_DIR"
cargo build --quiet --locked --no-default-features --features profile-static-site --bin fluxheim

"$ROOT_DIR/target/debug/fluxheim" --config "$TMP_DIR/fluxheim.toml" >"$TMP_DIR/stdout.log" 2>&1 &
PID="$!"

attempt=0
while [ "$attempt" -lt 80 ]; do
    if curl -fsS "http://127.0.0.1:$PORT/" | grep -q "fluxheim macos smoke"; then
        if [ ! -f "$TMP_DIR/logs/fluxheim.log" ]; then
            echo "macOS smoke failed: file log was not created" >&2
            exit 1
        fi
        echo "macOS developer smoke: ok"
        exit 0
    fi
    attempt=$((attempt + 1))
    sleep 0.1
done

echo "macOS smoke failed: Fluxheim did not serve the test page" >&2
cat "$TMP_DIR/stdout.log" >&2 || true
exit 1
