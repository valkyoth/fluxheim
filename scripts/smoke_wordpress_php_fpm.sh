#!/usr/bin/env sh
set -eu

port="${FLUXHEIM_WORDPRESS_SMOKE_PORT:-18132}"
fpm_port="${FLUXHEIM_WORDPRESS_SMOKE_FPM_PORT:-19000}"
network="fluxheim_wp_smoke_$$"
db_container="fluxheim_wp_smoke_db_$$"
fpm_container="fluxheim_wp_smoke_fpm_$$"
tmp="${TMPDIR:-/tmp}/fluxheim-wordpress-smoke-$$"
site="$tmp/wordpress"
config="$tmp/fluxheim.toml"
cookie_jar="$tmp/cookies.txt"
host="wp.test"
base_url="http://$host:$port"
admin_password="FluxheimSmoke-12345!"

cleanup() {
    if [ -n "${server_pid:-}" ]; then
        kill "$server_pid" 2>/dev/null || true
        sleep 0.2
        if kill -0 "$server_pid" 2>/dev/null; then
            kill -9 "$server_pid" 2>/dev/null || true
        fi
        wait "$server_pid" 2>/dev/null || true
    fi
    podman rm -f "$fpm_container" "$db_container" >/dev/null 2>&1 || true
    podman network rm "$network" >/dev/null 2>&1 || true
    rm -rf "$tmp"
}

trap cleanup EXIT INT TERM

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "wordpress php-fpm smoke failed: missing required command: $1" >&2
        exit 1
    fi
}

curl_wp() {
    curl -sS --noproxy '*' --resolve "$host:$port:127.0.0.1" "$@"
}

require_command curl
require_command podman
require_command tar

mkdir -p "$tmp/run"
curl -sSfL https://wordpress.org/latest.tar.gz -o "$tmp/wordpress.tar.gz"
tar -xzf "$tmp/wordpress.tar.gz" -C "$tmp"
chmod -R a+rX "$site"

table_prefix="fh$$_"
cat > "$site/wp-config.php" <<EOF
<?php
define('DB_NAME', 'fluxheim');
define('DB_USER', 'fluxheim');
define('DB_PASSWORD', 'fluxheim');
define('DB_HOST', '$db_container:3306');
define('DB_CHARSET', 'utf8mb4');
define('DB_COLLATE', '');
define('AUTH_KEY',         'fluxheim smoke auth key');
define('SECURE_AUTH_KEY',  'fluxheim smoke secure auth key');
define('LOGGED_IN_KEY',    'fluxheim smoke logged in key');
define('NONCE_KEY',        'fluxheim smoke nonce key');
define('AUTH_SALT',        'fluxheim smoke auth salt');
define('SECURE_AUTH_SALT', 'fluxheim smoke secure auth salt');
define('LOGGED_IN_SALT',   'fluxheim smoke logged in salt');
define('NONCE_SALT',       'fluxheim smoke nonce salt');
\$table_prefix = '$table_prefix';
define('WP_HOME', '$base_url');
define('WP_SITEURL', '$base_url');
if ( ! defined( 'ABSPATH' ) ) { define( 'ABSPATH', __DIR__ . '/' ); }
require_once ABSPATH . 'wp-settings.php';
EOF
chmod 644 "$site/wp-config.php"

cat > "$config" <<EOF
[server]
listen = ["127.0.0.1:$port"]
default_vhost = "$host"
trusted_proxies = []

[server.process]
pid_file = "$tmp/run/fluxheim.pid"
upgrade_sock = "$tmp/run/fluxheim-upgrade.sock"
certificate_reload_sock = "$tmp/run/fluxheim-cert-reload.sock"
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
enabled = false
backend = "rustls"

[[vhosts]]
name = "$host"
hosts = ["$host"]

[vhosts.php]
enabled = true
runtime = "php-fpm"
root = "$site"
index = "index.php"
allowed_extensions = ["php"]
request_timeout_secs = 30
max_request_body_bytes = "64MiB"
max_response_bytes = "128MiB"
path_info = "disabled"

[vhosts.php.fpm]
tcp = "127.0.0.1:$fpm_port"

[vhosts.web]
root = "$site"
index_files = ["index.html", "index.php"]
deny_dotfiles = true

[vhosts.web.directory_listing]
enabled = false
EOF

if [ -n "${FLUXHEIM_BIN:-}" ]; then
    fluxheim_bin="$FLUXHEIM_BIN"
else
    cargo build --quiet --no-default-features --features profile-web-server,php-fpm
    fluxheim_bin="${CARGO_TARGET_DIR:-target}/debug/fluxheim"
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
    --name "$fpm_container" \
    --network "$network" \
    -p "127.0.0.1:$fpm_port:9000" \
    -v "$site:$site:Z" \
    docker.io/library/wordpress:php8.3-fpm-alpine >/dev/null

"$fluxheim_bin" --config "$config" &
server_pid="$!"

install_status=""
for _ in $(seq 1 90); do
    install_status="$(
        curl_wp -o "$tmp/install-get.html" -w '%{http_code}' "$base_url/wp-admin/install.php" \
            2>/dev/null || true
    )"
    if [ "$install_status" = "200" ] && grep -q 'Welcome' "$tmp/install-get.html"; then
        break
    fi
    sleep 1
done
if [ "$install_status" != "200" ] || ! grep -q 'Welcome' "$tmp/install-get.html"; then
    echo "wordpress php-fpm smoke failed: installer not ready, status=${install_status:-none}" >&2
    if [ -s "$tmp/install-get.html" ]; then
        sed -n '1,80p' "$tmp/install-get.html" >&2
    fi
    exit 1
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
    echo "wordpress php-fpm smoke failed: install POST failed, status=$install_post_status" >&2
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
    echo "wordpress php-fpm smoke failed: login form failed, status=$login_get_status" >&2
    exit 1
fi
if ! grep -q "value=\"$base_url/wp-admin/\"" "$tmp/login-get.html"; then
    echo "wordpress php-fpm smoke failed: login redirect target did not preserve host/port" >&2
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
    echo "wordpress php-fpm smoke failed: login POST did not redirect, status=$login_post_status" >&2
    sed -n '1,120p' "$tmp/login-post.html" >&2
    exit 1
fi
if ! grep -qi '^set-cookie: wordpress_logged_in_' "$tmp/login-post.headers"; then
    echo "wordpress php-fpm smoke failed: login POST did not emit wordpress_logged_in cookie" >&2
    cat "$tmp/login-post.headers" >&2
    exit 1
fi
if ! grep -qi "^location: $base_url/wp-admin/" "$tmp/login-post.headers"; then
    echo "wordpress php-fpm smoke failed: login POST redirect location mismatch" >&2
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
    echo "wordpress php-fpm smoke failed: authenticated admin did not load, status=$admin_status" >&2
    cat "$tmp/admin.headers" >&2
    exit 1
fi
if ! grep -q 'Log Out' "$tmp/admin.html"; then
    echo "wordpress php-fpm smoke failed: admin page did not include logged-in controls" >&2
    exit 1
fi

echo "wordpress php-fpm smoke: ok"
