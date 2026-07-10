#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
SMOKE_TMP_ROOT=$(sh "$ROOT_DIR/scripts/secure-smoke-tmp-root.sh" short)
mode="${FLUXHEIM_WORDPRESS_SMOKE_MODE:-${1:-both}}"
port_base="${FLUXHEIM_WORDPRESS_SMOKE_PORT:-18132}"
fpm_port_base="${FLUXHEIM_WORDPRESS_SMOKE_FPM_PORT:-19000}"
db_port_base="${FLUXHEIM_WORDPRESS_SMOKE_DB_PORT:-19100}"
php_fpm_binary="${FLUXHEIM_WORDPRESS_SMOKE_PHP_FPM:-/usr/sbin/php-fpm}"
wordpress_db_image="${FLUXHEIM_WORDPRESS_DB_IMAGE:-docker.io/library/mariadb:12.3}"
wordpress_fpm_image="${FLUXHEIM_WORDPRESS_FPM_IMAGE:-docker.io/library/wordpress:php8.3-fpm-alpine}"
run_id="$$"
tmp=$(mktemp -d "$SMOKE_TMP_ROOT/w.XXXXXX")
admin_password="FluxheimSmoke-12345!"
server_pid=""

cleanup() {
    if [ -n "${server_pid:-}" ]; then
        kill "$server_pid" 2>/dev/null || true
        sleep 0.2
        if kill -0 "$server_pid" 2>/dev/null; then
            kill -9 "$server_pid" 2>/dev/null || true
        fi
        wait "$server_pid" 2>/dev/null || true
        server_pid=""
    fi
    container_ids="$(podman ps -aq --filter "name=fh_wp_${run_id}_" 2>/dev/null || true)"
    if [ -n "$container_ids" ]; then
        podman rm -f $container_ids >/dev/null 2>&1 || true
    fi
    podman network rm "fh_wp_${run_id}_ext" >/dev/null 2>&1 || true
    podman network rm "fh_wp_${run_id}_md" >/dev/null 2>&1 || true
    podman network rm "fh_wp_${run_id}_ms" >/dev/null 2>&1 || true
    podman network rm "fh_wp_${run_id}_my" >/dev/null 2>&1 || true
    podman network rm "fh_wp_${run_id}_mo" >/dev/null 2>&1 || true
    podman network rm "fh_wp_${run_id}_mr" >/dev/null 2>&1 || true
    if [ "${FLUXHEIM_SMOKE_KEEP_ARTIFACTS:-0}" = "1" ]; then
        echo "wordpress php-fpm smoke artifacts kept in $tmp" >&2
        return
    fi
    rm -rf "$tmp"
}

trap cleanup EXIT INT TERM

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "wordpress php-fpm smoke failed: missing required command: $1" >&2
        exit 1
    fi
}

stop_server() {
    if [ -n "${server_pid:-}" ]; then
        kill "$server_pid" 2>/dev/null || true
        sleep 0.2
        if kill -0 "$server_pid" 2>/dev/null; then
            kill -9 "$server_pid" 2>/dev/null || true
        fi
        wait "$server_pid" 2>/dev/null || true
        server_pid=""
    fi
}

wait_for_mariadb() {
    container="$1"
    for _ in $(seq 1 90); do
        if podman exec "$container" mariadb-admin ping \
            -h127.0.0.1 \
            -ufluxheim \
            -pfluxheim \
            --silent >/dev/null 2>&1
        then
            return 0
        fi
        sleep 1
    done
    echo "wordpress php-fpm smoke failed: MariaDB did not become ready" >&2
    podman logs "$container" >&2 2>/dev/null || true
    exit 1
}

is_managed_smoke() {
    case "$1" in
        managed|managed-static|managed-dynamic|managed-ondemand|managed-respawn) return 0 ;;
        *) return 1 ;;
    esac
}

managed_process_manager() {
    case "$1" in
        managed-static|managed-respawn) echo "static" ;;
        managed|managed-dynamic) echo "dynamic" ;;
        managed-ondemand) echo "ondemand" ;;
        *)
            echo "wordpress php-fpm smoke failed: unknown managed mode: $1" >&2
            exit 1
            ;;
    esac
}

curl_wp() {
    curl -sS --noproxy '*' --resolve "$wp_host:$wp_port:127.0.0.1" "$@"
}

require_command curl
require_command podman
require_command tar

case "$mode" in
    external|managed|managed-static|managed-dynamic|managed-ondemand|managed-respawn|managed-all|both) ;;
    *)
        echo "wordpress php-fpm smoke failed: mode must be external, managed, managed-static, managed-dynamic, managed-ondemand, managed-respawn, managed-all, or both" >&2
        exit 1
        ;;
esac

if is_managed_smoke "$mode" || [ "$mode" = "managed-all" ] || [ "$mode" = "both" ]; then
    if [ ! -x "$php_fpm_binary" ]; then
        echo "wordpress php-fpm smoke failed: managed mode requires executable php-fpm at $php_fpm_binary" >&2
        exit 1
    fi
fi

mkdir -p "$tmp"
curl -sSfL https://wordpress.org/latest.tar.gz -o "$tmp/wordpress.tar.gz"

if [ -n "${FLUXHEIM_BIN:-}" ]; then
    fluxheim_bin="$FLUXHEIM_BIN"
else
    cargo build --quiet --no-default-features --features profile-web-server,php-fpm
    fluxheim_bin="${CARGO_TARGET_DIR:-target}/debug/fluxheim"
fi

run_wordpress_smoke() {
    smoke_mode="$1"
    offset="$2"
    case "$smoke_mode" in
        external) smoke_slug="ext" ;;
        managed) smoke_slug="md" ;;
        managed-static) smoke_slug="ms" ;;
        managed-dynamic) smoke_slug="my" ;;
        managed-ondemand) smoke_slug="mo" ;;
        managed-respawn) smoke_slug="mr" ;;
        *) smoke_slug="$smoke_mode" ;;
    esac
    wp_port=$((port_base + offset))
    fpm_port=$((fpm_port_base + offset))
    db_port=$((db_port_base + offset))
    wp_host="wp-${smoke_slug}.test"
    base_url="http://$wp_host:$wp_port"
    network="fh_wp_${run_id}_${smoke_slug}"
    db_container="fh_wp_${run_id}_${smoke_slug}_db"
    fpm_container="fh_wp_${run_id}_${smoke_slug}_fpm"
    mode_tmp="$tmp/$smoke_slug"
    site="$mode_tmp/wordpress"
    run_dir="$mode_tmp/r"
    config="$mode_tmp/fluxheim.toml"
    cookie_jar="$mode_tmp/cookies.txt"
    table_prefix="fh${run_id}_${offset}_"

    mkdir -p "$mode_tmp" "$run_dir"
    chmod 700 "$mode_tmp" "$run_dir"
    tar -xzf "$tmp/wordpress.tar.gz" -C "$mode_tmp"
    chmod -R a+rX "$site"

    if is_managed_smoke "$smoke_mode"; then
        db_host="127.0.0.1:$db_port"
    else
        db_host="$db_container:3306"
    fi

    cat > "$site/wp-config.php" <<EOF
<?php
define('DB_NAME', 'fluxheim');
define('DB_USER', 'fluxheim');
define('DB_PASSWORD', 'fluxheim');
define('DB_HOST', '$db_host');
define('DB_CHARSET', 'utf8mb4');
define('DB_COLLATE', '');
define('AUTH_KEY',         'fluxheim smoke auth key $smoke_mode');
define('SECURE_AUTH_KEY',  'fluxheim smoke secure auth key $smoke_mode');
define('LOGGED_IN_KEY',    'fluxheim smoke logged in key $smoke_mode');
define('NONCE_KEY',        'fluxheim smoke nonce key $smoke_mode');
define('AUTH_SALT',        'fluxheim smoke auth salt $smoke_mode');
define('SECURE_AUTH_SALT', 'fluxheim smoke secure auth salt $smoke_mode');
define('LOGGED_IN_SALT',   'fluxheim smoke logged in salt $smoke_mode');
define('NONCE_SALT',       'fluxheim smoke nonce salt $smoke_mode');
\$table_prefix = '$table_prefix';
define('WP_HOME', '$base_url');
define('WP_SITEURL', '$base_url');
define('WP_HTTP_BLOCK_EXTERNAL', true);
define('AUTOMATIC_UPDATER_DISABLED', true);
define('WP_AUTO_UPDATE_CORE', false);
define('DISABLE_WP_CRON', true);
if ( ! defined( 'ABSPATH' ) ) { define( 'ABSPATH', __DIR__ . '/' ); }
require_once ABSPATH . 'wp-settings.php';
EOF
    chmod 644 "$site/wp-config.php"

    cat > "$config" <<EOF
[server]
listen = ["127.0.0.1:$wp_port"]
default_vhost = "$wp_host"
trusted_proxies = []

[server.process]
pid_file = "$run_dir/pid"
upgrade_sock = "$run_dir/up.sock"
certificate_reload_sock = "$run_dir/reload.sock"
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
name = "$wp_host"
hosts = ["$wp_host"]

[vhosts.php]
preset = "wordpress"
enabled = true
runtime = "php-fpm"
root = "$site"
index = "index.php"
allowed_extensions = ["php"]
request_timeout_secs = 30
max_request_body_bytes = "64MiB"
max_response_bytes = "64MiB"
path_info = "disabled"

[vhosts.php.fpm]
EOF

    if is_managed_smoke "$smoke_mode"; then
        process_manager="$(managed_process_manager "$smoke_mode")"
        cat >> "$config" <<EOF
mode = "managed"
php_fpm_binary = "$php_fpm_binary"
socket_dir = "$run_dir/f"
workers = 3
max_requests_per_worker = 100
process_manager = "$process_manager"
listen_backlog = 64
request_terminate_timeout_secs = 30
request_slowlog_timeout_secs = 10
request_slowlog_trace_depth = 16
decorate_workers_output = false
session_save_path = "$run_dir/s"
upload_tmp_dir = "$run_dir/u"
EOF
        case "$process_manager" in
            dynamic)
                cat >> "$config" <<EOF
start_servers = 1
min_spare_servers = 1
max_spare_servers = 2
max_spawn_rate = 8
EOF
                ;;
            ondemand)
                cat >> "$config" <<EOF
process_idle_timeout_secs = 5
EOF
                ;;
        esac
    else
        cat >> "$config" <<EOF
mode = "external"
tcp = "127.0.0.1:$fpm_port"
allow_private_tcp_upstreams = true
EOF
    fi

    cat >> "$config" <<EOF

[vhosts.web]
root = "$site"
index_files = ["index.html", "index.php"]
deny_dotfiles = true

[vhosts.web.directory_listing]
enabled = false
EOF

    "$fluxheim_bin" --config "$config" --validate-config

    podman network create "$network" >/dev/null
    if is_managed_smoke "$smoke_mode"; then
        podman run -d \
            --name "$db_container" \
            --network "$network" \
            -p "127.0.0.1:$db_port:3306" \
            -e MARIADB_ROOT_PASSWORD=fluxheim \
            -e MARIADB_DATABASE=fluxheim \
            -e MARIADB_USER=fluxheim \
            -e MARIADB_PASSWORD=fluxheim \
            "$wordpress_db_image" >/dev/null
    else
        podman run -d \
            --name "$db_container" \
            --network "$network" \
            -e MARIADB_ROOT_PASSWORD=fluxheim \
            -e MARIADB_DATABASE=fluxheim \
            -e MARIADB_USER=fluxheim \
            -e MARIADB_PASSWORD=fluxheim \
            "$wordpress_db_image" >/dev/null
        podman run -d \
            --name "$fpm_container" \
            --network "$network" \
            -p "127.0.0.1:$fpm_port:9000" \
            -v "$site:$site:Z" \
            "$wordpress_fpm_image" >/dev/null
    fi
    wait_for_mariadb "$db_container"

    "$fluxheim_bin" --config "$config" &
    server_pid="$!"

    install_status=""
    for _ in $(seq 1 90); do
        install_status="$(
            curl_wp -o "$mode_tmp/install-get.html" -w '%{http_code}' "$base_url/wp-admin/install.php" \
                2>/dev/null || true
        )"
        if [ "$install_status" = "200" ] && grep -q 'Welcome' "$mode_tmp/install-get.html"; then
            break
        fi
        sleep 1
    done
    if [ "$install_status" != "200" ] || ! grep -q 'Welcome' "$mode_tmp/install-get.html"; then
        echo "wordpress php-fpm smoke ($smoke_mode) failed: installer not ready, status=${install_status:-none}" >&2
        if [ -s "$mode_tmp/install-get.html" ]; then
            sed -n '1,80p' "$mode_tmp/install-get.html" >&2
        fi
        exit 1
    fi

    install_post_status="$(
        curl_wp \
            -c "$cookie_jar" \
            -b "$cookie_jar" \
            -D "$mode_tmp/install-post.headers" \
            -o "$mode_tmp/install-post.html" \
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
    if [ "$install_post_status" != "200" ] || ! grep -q 'Success!' "$mode_tmp/install-post.html"; then
        echo "wordpress php-fpm smoke ($smoke_mode) failed: install POST failed, status=$install_post_status" >&2
        sed -n '1,120p' "$mode_tmp/install-post.html" >&2
        exit 1
    fi

    login_get_status="$(
        curl_wp \
            -c "$cookie_jar" \
            -b "$cookie_jar" \
            -D "$mode_tmp/login-get.headers" \
            -o "$mode_tmp/login-get.html" \
            "$base_url/wp-login.php" \
            -w '%{http_code}'
    )"
    if [ "$login_get_status" != "200" ] || ! grep -q "name=\"testcookie\"" "$mode_tmp/login-get.html"; then
        echo "wordpress php-fpm smoke ($smoke_mode) failed: login form failed, status=$login_get_status" >&2
        exit 1
    fi
    if ! grep -q "value=\"$base_url/wp-admin/\"" "$mode_tmp/login-get.html"; then
        echo "wordpress php-fpm smoke ($smoke_mode) failed: login redirect target did not preserve host/port" >&2
        exit 1
    fi

    login_post_status="$(
        curl_wp \
            -c "$cookie_jar" \
            -b "$cookie_jar" \
            -D "$mode_tmp/login-post.headers" \
            -o "$mode_tmp/login-post.html" \
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
        echo "wordpress php-fpm smoke ($smoke_mode) failed: login POST did not redirect, status=$login_post_status" >&2
        sed -n '1,120p' "$mode_tmp/login-post.html" >&2
        exit 1
    fi
    if ! grep -qi '^set-cookie: wordpress_logged_in_' "$mode_tmp/login-post.headers"; then
        echo "wordpress php-fpm smoke ($smoke_mode) failed: login POST did not emit wordpress_logged_in cookie" >&2
        cat "$mode_tmp/login-post.headers" >&2
        exit 1
    fi
    if ! grep -qi "^location: $base_url/wp-admin/" "$mode_tmp/login-post.headers"; then
        echo "wordpress php-fpm smoke ($smoke_mode) failed: login POST redirect location mismatch" >&2
        cat "$mode_tmp/login-post.headers" >&2
        exit 1
    fi

    admin_status="$(
        curl_wp \
            -b "$cookie_jar" \
            -D "$mode_tmp/admin.headers" \
            -o "$mode_tmp/admin.html" \
            "$base_url/wp-admin/" \
            -w '%{http_code}'
    )"
    if [ "$admin_status" != "200" ] || ! grep -q 'Dashboard' "$mode_tmp/admin.html"; then
        echo "wordpress php-fpm smoke ($smoke_mode) failed: authenticated admin did not load, status=$admin_status" >&2
        cat "$mode_tmp/admin.headers" >&2
        exit 1
    fi
    if ! grep -q 'Log Out' "$mode_tmp/admin.html"; then
        echo "wordpress php-fpm smoke ($smoke_mode) failed: admin page did not include logged-in controls" >&2
        exit 1
    fi

    if [ "$smoke_mode" = "managed-respawn" ]; then
        managed_pid_file=""
        for candidate in "$run_dir"/f/*.pid; do
            [ -f "$candidate" ] || continue
            managed_pid_file="$candidate"
            break
        done
        if [ -z "$managed_pid_file" ]; then
            echo "wordpress php-fpm smoke ($smoke_mode) failed: managed php-fpm pid file missing" >&2
            exit 1
        fi
        managed_pid="$(cat "$managed_pid_file")"
        kill -9 "$managed_pid" 2>/dev/null || true

        respawn_status=""
        for _ in $(seq 1 45); do
            respawn_status="$(
                curl_wp \
                    -b "$cookie_jar" \
                    -D "$mode_tmp/admin-respawn.headers" \
                    -o "$mode_tmp/admin-respawn.html" \
                    "$base_url/wp-admin/" \
                    -w '%{http_code}' 2>/dev/null || true
            )"
            if [ "$respawn_status" = "200" ] && grep -q 'Dashboard' "$mode_tmp/admin-respawn.html"; then
                break
            fi
            sleep 1
        done
        if [ "$respawn_status" != "200" ] || ! grep -q 'Dashboard' "$mode_tmp/admin-respawn.html"; then
            echo "wordpress php-fpm smoke ($smoke_mode) failed: managed php-fpm did not respawn, status=${respawn_status:-none}" >&2
            cat "$mode_tmp/admin-respawn.headers" >&2 2>/dev/null || true
            exit 1
        fi
    fi

    stop_server
    podman rm -f "$fpm_container" "$db_container" >/dev/null 2>&1 || true
    podman network rm "$network" >/dev/null 2>&1 || true

    echo "wordpress php-fpm smoke ($smoke_mode): ok"
}

case "$mode" in
    external)
        run_wordpress_smoke external 0
        ;;
    managed)
        run_wordpress_smoke managed 10
        ;;
    managed-static)
        run_wordpress_smoke managed-static 10
        ;;
    managed-dynamic)
        run_wordpress_smoke managed-dynamic 20
        ;;
    managed-ondemand)
        run_wordpress_smoke managed-ondemand 30
        ;;
    managed-respawn)
        run_wordpress_smoke managed-respawn 40
        ;;
    managed-all)
        run_wordpress_smoke managed-static 10
        run_wordpress_smoke managed-dynamic 20
        run_wordpress_smoke managed-ondemand 30
        ;;
    both)
        run_wordpress_smoke external 0
        run_wordpress_smoke managed-static 10
        run_wordpress_smoke managed-dynamic 20
        run_wordpress_smoke managed-ondemand 30
        ;;
esac
