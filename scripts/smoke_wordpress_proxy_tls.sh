#!/usr/bin/env sh
set -eu

http_port="${FLUXHEIM_WORDPRESS_PROXY_TLS_SMOKE_HTTP_PORT:-18140}"
tls_port="${FLUXHEIM_WORDPRESS_PROXY_TLS_SMOKE_TLS_PORT:-18443}"
backend_port="${FLUXHEIM_WORDPRESS_PROXY_TLS_SMOKE_BACKEND_PORT:-18080}"
network="fluxheim_wp_proxy_tls_smoke_$$"
db_container="fluxheim_wp_proxy_tls_smoke_db_$$"
wp_container="fluxheim_wp_proxy_tls_smoke_wp_$$"
tmp="${TMPDIR:-/tmp}/fluxheim-wordpress-proxy-tls-smoke-$$"
config="$tmp/fluxheim.toml"
cookie_jar="$tmp/cookies.txt"
host="wp.test"
base_url="https://$host:$tls_port"
backend_url="http://127.0.0.1:$backend_port"
admin_password="FluxheimSmoke-12345!"

cleanup() {
    status=$?
    if [ -n "${server_pid:-}" ]; then
        kill "$server_pid" 2>/dev/null || true
        sleep 0.2
        if kill -0 "$server_pid" 2>/dev/null; then
            kill -9 "$server_pid" 2>/dev/null || true
        fi
        wait "$server_pid" 2>/dev/null || true
    fi
    podman rm -f "$wp_container" "$db_container" >/dev/null 2>&1 || true
    podman network rm "$network" >/dev/null 2>&1 || true
    if [ "${FLUXHEIM_WORDPRESS_PROXY_TLS_SMOKE_KEEP:-0}" = "1" ] || [ "$status" -ne 0 ]; then
        echo "wordpress proxy TLS smoke artifacts kept in $tmp" >&2
    else
        rm -rf "$tmp"
    fi
}

trap cleanup EXIT INT TERM

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "wordpress proxy TLS smoke failed: missing required command: $1" >&2
        exit 1
    fi
}

curl_wp() {
    curl -ksS --noproxy '*' --resolve "$host:$tls_port:127.0.0.1" "$@"
}

require_command curl
require_command openssl
require_command podman

mkdir -p "$tmp/tls" "$tmp/run"
openssl req \
    -x509 \
    -newkey rsa:2048 \
    -nodes \
    -sha256 \
    -days 1 \
    -subj "/CN=$host" \
    -addext "subjectAltName=DNS:$host" \
    -keyout "$tmp/tls/key.pem" \
    -out "$tmp/tls/fullchain.pem" >/dev/null 2>&1
chmod 600 "$tmp/tls/key.pem"

cat > "$tmp/wordpress-config-extra.php" <<'PHP'
if (
    (isset($_SERVER['HTTP_X_FORWARDED_PROTO']) && strtolower($_SERVER['HTTP_X_FORWARDED_PROTO']) === 'https')
    || (isset($_SERVER['HTTP_X_FORWARDED_SSL']) && strtolower($_SERVER['HTTP_X_FORWARDED_SSL']) === 'on')
) {
    $_SERVER['HTTPS'] = 'on';
    $_SERVER['REQUEST_SCHEME'] = 'https';
    $_SERVER['SERVER_PORT'] = $_SERVER['HTTP_X_FORWARDED_PORT'] ?? '443';
}
PHP
wp_config_extra="$(cat "$tmp/wordpress-config-extra.php")"

cat > "$config" <<EOF
[server]
listen = ["127.0.0.1:$http_port"]
tls_listen = ["127.0.0.1:$tls_port"]
default_vhost = "$host"
trusted_proxies = []

[server.process]
pid_file = "$tmp/run/fluxheim.pid"
upgrade_sock = "$tmp/run/fluxheim-upgrade.sock"
daemon = false
threads = 2

[server.limits]
max_request_header_bytes = "64KiB"
max_uri_bytes = "8KiB"
max_request_headers = 100
max_request_body_bytes = "64MiB"

[logging]
level = "warn"
format = "text"
target = "stderr"

[logging.access]
enabled = false
request_id = false

[tls]
enabled = true
backend = "rustls"

[[tls.certificates]]
cert_path = "$tmp/tls/fullchain.pem"
key_path = "$tmp/tls/key.pem"

[[vhosts]]
name = "$host"
hosts = ["$host"]
max_request_body_bytes = "64MiB"

[vhosts.tls]
enabled = true

[vhosts.tls.certificate]
cert_path = "$tmp/tls/fullchain.pem"
key_path = "$tmp/tls/key.pem"

[vhosts.headers.request]
enabled = true
strip_inbound_client_ip_headers = true
x_forwarded_for = "replace"
x_real_ip = true
x_forwarded_host = true
x_forwarded_proto = true
forwarded = false

[vhosts.headers.request.add]
x-forwarded-port = "$tls_port"
x-forwarded-ssl = "on"
x-forwarded-scheme = "https"

[vhosts.proxy]
upstreams = ["127.0.0.1:$backend_port"]
upstream_tls = false
connect_timeout_secs = 30
read_timeout_secs = 60
send_timeout_secs = 60
EOF

if [ -n "${FLUXHEIM_BIN:-}" ]; then
    fluxheim_bin="$FLUXHEIM_BIN"
else
    cargo build --quiet --no-default-features --features profile-reverse-proxy
    fluxheim_bin="target/debug/fluxheim"
fi

"$fluxheim_bin" --config "$config" --validate-config

podman network create "$network" >/dev/null
podman run -d \
    --name "$db_container" \
    --network "$network" \
    -e MARIADB_ROOT_PASSWORD=fluxheim \
    -e MARIADB_DATABASE=fluxheim \
    -e MARIADB_USER=fluxheim \
    -e MARIADB_PASSWORD=fluxheim \
    mariadb:12.2 >/dev/null
podman run -d \
    --name "$wp_container" \
    --network "$network" \
    -p "127.0.0.1:$backend_port:80" \
    -e WORDPRESS_DB_HOST="$db_container:3306" \
    -e WORDPRESS_DB_NAME=fluxheim \
    -e WORDPRESS_DB_USER=fluxheim \
    -e WORDPRESS_DB_PASSWORD=fluxheim \
    -e WORDPRESS_CONFIG_EXTRA="$wp_config_extra" \
    docker.io/library/wordpress:php8.3-apache >/dev/null

"$fluxheim_bin" --config "$config" > "$tmp/fluxheim.log" 2>&1 &
server_pid="$!"

install_status=""
for _ in $(seq 1 120); do
    install_status="$(
        curl_wp -o "$tmp/install-get.html" -w '%{http_code}' "$base_url/wp-admin/install.php" \
            2>/dev/null || true
    )"
    if [ "$install_status" = "200" ] \
        && { grep -q 'Welcome' "$tmp/install-get.html" || grep -q 'name=.language.' "$tmp/install-get.html"; }; then
        break
    fi
    sleep 1
done
if [ "$install_status" != "200" ]; then
    echo "wordpress proxy TLS smoke failed: installer not ready through Fluxheim TLS proxy, status=${install_status:-none}" >&2
    if [ -s "$tmp/install-get.html" ]; then
        sed -n '1,80p' "$tmp/install-get.html" >&2
    fi
    if [ -s "$tmp/fluxheim.log" ]; then
        sed -n '1,120p' "$tmp/fluxheim.log" >&2
    fi
    exit 1
fi
if ! grep -q 'Welcome' "$tmp/install-get.html"; then
    language_status="$(
        curl_wp \
            -c "$cookie_jar" \
            -b "$cookie_jar" \
            -o "$tmp/language-post.html" \
            -X POST \
            -d language= \
            "$base_url/wp-admin/install.php?step=1" \
            -w '%{http_code}'
    )"
    if [ "$language_status" != "200" ] || ! grep -q 'Welcome' "$tmp/language-post.html"; then
        echo "wordpress proxy TLS smoke failed: language selection did not reach installer form, status=$language_status" >&2
        sed -n '1,80p' "$tmp/language-post.html" >&2
        exit 1
    fi
fi

install_post_status="$(
    curl_wp \
        -c "$cookie_jar" \
        -b "$cookie_jar" \
        -D "$tmp/install-post.headers" \
        -o "$tmp/install-post.html" \
        -X POST \
        -d weblog_title=FluxheimSmoke \
        -d user_name=admin \
        -d "admin_password=$admin_password" \
        -d "admin_password2=$admin_password" \
        -d admin_email=admin@example.test \
        -d blog_public=0 \
        -d 'Submit=Install WordPress' \
        -d language= \
        "$base_url/wp-admin/install.php?step=2" \
        -w '%{http_code}'
)"
if [ "$install_post_status" != "200" ] || ! grep -q 'Success!' "$tmp/install-post.html"; then
    echo "wordpress proxy TLS smoke failed: install POST failed, status=$install_post_status" >&2
    sed -n '1,120p' "$tmp/install-post.html" >&2
    exit 1
fi

login_get_status="$(
    curl_wp \
        -c "$cookie_jar" \
        -b "$cookie_jar" \
        -D "$tmp/login-get.headers" \
        -o "$tmp/login-get.html" \
        "$base_url/wp-login.php" \
        -w '%{http_code}'
)"
if [ "$login_get_status" != "200" ] || ! grep -q "name=\"testcookie\"" "$tmp/login-get.html"; then
    echo "wordpress proxy TLS smoke failed: login form failed, status=$login_get_status" >&2
    exit 1
fi
if ! grep -q "value=\"$base_url/wp-admin/\"" "$tmp/login-get.html"; then
    echo "wordpress proxy TLS smoke failed: login redirect target did not preserve HTTPS host/port" >&2
    exit 1
fi

login_post_status="$(
    curl_wp \
        -c "$cookie_jar" \
        -b "$cookie_jar" \
        -D "$tmp/login-post.headers" \
        -o "$tmp/login-post.html" \
        -X POST \
        -d log=admin \
        -d "pwd=$admin_password" \
        -d 'wp-submit=Log In' \
        -d "redirect_to=$base_url/wp-admin/" \
        -d testcookie=1 \
        "$base_url/wp-login.php" \
        -w '%{http_code}'
)"
if [ "$login_post_status" != "302" ]; then
    echo "wordpress proxy TLS smoke failed: login POST did not redirect, status=$login_post_status" >&2
    sed -n '1,120p' "$tmp/login-post.html" >&2
    exit 1
fi
if ! grep -qi '^set-cookie: wordpress_logged_in_' "$tmp/login-post.headers"; then
    echo "wordpress proxy TLS smoke failed: login POST did not emit wordpress_logged_in cookie" >&2
    cat "$tmp/login-post.headers" >&2
    exit 1
fi
if ! grep -qi 'secure' "$tmp/login-post.headers"; then
    echo "wordpress proxy TLS smoke failed: WordPress did not mark auth cookies secure behind TLS proxy" >&2
    cat "$tmp/login-post.headers" >&2
    exit 1
fi
if ! grep -qi "^location: $base_url/wp-admin/" "$tmp/login-post.headers"; then
    echo "wordpress proxy TLS smoke failed: login POST redirect location mismatch" >&2
    cat "$tmp/login-post.headers" >&2
    exit 1
fi

admin_status="$(
    curl_wp \
        -b "$cookie_jar" \
        -D "$tmp/admin.headers" \
        -o "$tmp/admin.html" \
        "$base_url/wp-admin/" \
        -w '%{http_code}'
)"
if [ "$admin_status" != "200" ] || ! grep -q 'Dashboard' "$tmp/admin.html"; then
    echo "wordpress proxy TLS smoke failed: authenticated admin did not load, status=$admin_status" >&2
    cat "$tmp/admin.headers" >&2
    exit 1
fi
if ! grep -q 'Log Out' "$tmp/admin.html"; then
    echo "wordpress proxy TLS smoke failed: admin page did not include logged-in controls" >&2
    exit 1
fi

backend_diag="$(
    curl -sS --noproxy '*' "$backend_url/wp-login.php" -o /dev/null -w '%{http_code}' 2>/dev/null || true
)"
case "$backend_diag" in
    200 | 301 | 302) ;;
    *)
        echo "wordpress proxy TLS smoke failed: backend was not reachable for final sanity check, status=${backend_diag:-none}" >&2
        exit 1
        ;;
esac

echo "wordpress proxy TLS smoke: ok"
