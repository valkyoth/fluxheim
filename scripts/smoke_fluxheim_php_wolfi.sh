#!/usr/bin/env sh
set -eu

image="${FLUXHEIM_WOLFI_PHP_IMAGE:-fluxheim:php-wolfi-managed-smoke}"
port="${FLUXHEIM_WOLFI_PHP_SMOKE_PORT:-18182}"
container="fluxheim_php_wolfi_smoke_$$"

cleanup() {
    podman rm -f "$container" >/dev/null 2>&1 || true
}

trap cleanup EXIT INT TERM

if [ -z "${FLUXHEIM_WOLFI_PHP_IMAGE:-}" ]; then
    podman build \
        --build-arg FLUXHEIM_FEATURES=profile-web-server,php-fpm,acme-client \
        --build-arg FLUXHEIM_CONFIG=packaging/container/php-managed.toml \
        --build-arg FLUXHEIM_RUNTIME_PACKAGES=php-8.5-fpm \
        -t "$image" \
        -f containers/Containerfile.wolfi .
fi

podman run -d \
    --name "$container" \
    -p "127.0.0.1:$port:8080" \
    "$image" >/dev/null

status=""
for _ in $(seq 1 60); do
    status="$(curl -sS --noproxy '*' -o /tmp/fluxheim-php-wolfi-smoke-$$.txt -w '%{http_code}' "http://127.0.0.1:$port/index.php" 2>/dev/null || true)"
    if [ "$status" = "200" ] && grep -q 'Fluxheim managed PHP-FPM is running' "/tmp/fluxheim-php-wolfi-smoke-$$.txt"; then
        rm -f "/tmp/fluxheim-php-wolfi-smoke-$$.txt"
        echo "fluxheim wolfi managed php-fpm smoke: ok"
        exit 0
    fi
    sleep 1
done

echo "fluxheim wolfi managed php-fpm smoke failed: status=${status:-none}" >&2
podman logs "$container" >&2 || true
if [ -s "/tmp/fluxheim-php-wolfi-smoke-$$.txt" ]; then
    sed -n '1,80p' "/tmp/fluxheim-php-wolfi-smoke-$$.txt" >&2
fi
rm -f "/tmp/fluxheim-php-wolfi-smoke-$$.txt"
exit 1
