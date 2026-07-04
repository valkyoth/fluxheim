#!/usr/bin/env sh
set -eu

pull="${FLUXHEIM_SMOKE_IMAGE_PULL:-1}"

require_command() {
    if ! command -v "$1" >/dev/null 2>&1; then
        echo "smoke image check failed: missing required command: $1" >&2
        exit 1
    fi
}

image_line() {
    name=$1
    image=$2
    printf '%-28s %s\n' "$name" "$image"
}

inspect_image() {
    name=$1
    image=$2

    image_line "$name" "$image"
    if [ "$pull" = "1" ]; then
        podman pull "$image" >/dev/null
    fi
    podman image inspect \
        --format "  id={{.Id}} digest={{.Digest}}" \
        "$image" 2>/dev/null || {
            echo "  image is not present locally; set FLUXHEIM_SMOKE_IMAGE_PULL=1 to pull it" >&2
            return 1
        }
}

require_command podman

cat <<'EOF'
Fluxheim smoke dependency images

Override any image with the matching environment variable when testing newer
major versions. By default this script pulls each configured image so the smoke
suite exercises the current registry digest for the selected tag.

EOF

inspect_image "OpenBao" "${FLUXHEIM_OPENBAO_IMAGE:-quay.io/openbao/openbao:2.5}"
inspect_image "WordPress PHP-FPM" "${FLUXHEIM_WORDPRESS_FPM_IMAGE:-docker.io/library/wordpress:php8.3-fpm-alpine}"
inspect_image "WordPress Apache" "${FLUXHEIM_WORDPRESS_APACHE_IMAGE:-docker.io/library/wordpress:php8.3-apache}"
inspect_image "WordPress MariaDB" "${FLUXHEIM_WORDPRESS_DB_IMAGE:-docker.io/library/mariadb:12.2}"
inspect_image "MariaDB health" "${FLUXHEIM_MYSQL_IMAGE:-docker.io/library/mariadb:11.4}"
inspect_image "PostgreSQL health" "${FLUXHEIM_POSTGRES_IMAGE:-docker.io/library/postgres:16-alpine}"
inspect_image "Valkey health" "${FLUXHEIM_REDIS_IMAGE:-docker.io/valkey/valkey:8-alpine}"
inspect_image "Prometheus smoke" "${FLUXHEIM_PROMETHEUS_IMAGE:-docker.io/prom/prometheus:v3.13.0}"
inspect_image "Jaeger smoke" "${FLUXHEIM_JAEGER_IMAGE:-docker.io/jaegertracing/all-in-one:1.76.0}"

echo
echo "smoke image check: ok"
