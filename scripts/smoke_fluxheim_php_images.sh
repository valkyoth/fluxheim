#!/usr/bin/env sh
set -eu

root="$(git rev-parse --show-toplevel)"
cd "$root"

variants="${FLUXHEIM_PHP_IMAGE_VARIANTS:-wolfi alpine debian suse-bci}"
port="${FLUXHEIM_PHP_SMOKE_PORT:-18182}"
required_modules="packaging/container/php-required-modules.txt"
temporary_root="$root/target/fluxheim-smoke-tmp"
mkdir -p "$temporary_root"
content="$(mktemp -d "$temporary_root/fluxheim-php-images.XXXXXX")"
cp packaging/default/index.php "$content/index.php"
chmod 0644 "$content/index.php"
current_container=""

cleanup() {
    if [ -n "$current_container" ]; then
        podman rm -f "$current_container" >/dev/null 2>&1 || true
    fi
    rm -rf "$content"
}

trap cleanup EXIT INT TERM

for variant in $variants; do
    case "$variant" in
        wolfi)
            image="${FLUXHEIM_WOLFI_PHP_IMAGE:-fluxheim:php-wolfi-managed-smoke}"
            supplied_image="${FLUXHEIM_WOLFI_PHP_IMAGE:-}"
            containerfile="containers/Containerfile.wolfi"
            package_manifest="packaging/container/php-wolfi-runtime-packages.txt"
            ;;
        alpine)
            image="${FLUXHEIM_ALPINE_PHP_IMAGE:-fluxheim:php-alpine-managed-smoke}"
            supplied_image="${FLUXHEIM_ALPINE_PHP_IMAGE:-}"
            containerfile="containers/Containerfile.alpine"
            package_manifest="packaging/container/php-alpine-runtime-packages.txt"
            ;;
        debian)
            image="${FLUXHEIM_DEBIAN_PHP_IMAGE:-fluxheim:php-debian-managed-smoke}"
            supplied_image="${FLUXHEIM_DEBIAN_PHP_IMAGE:-}"
            containerfile="containers/Containerfile.debian"
            package_manifest="packaging/container/php-debian-runtime-packages.txt"
            ;;
        suse-bci)
            image="${FLUXHEIM_SUSE_BCI_PHP_IMAGE:-fluxheim:php-suse-bci-managed-smoke}"
            supplied_image="${FLUXHEIM_SUSE_BCI_PHP_IMAGE:-}"
            containerfile="containers/Containerfile.suse-bci"
            package_manifest="packaging/container/php-suse-bci-runtime-packages.txt"
            ;;
        *)
            echo "fluxheim PHP image smoke: unsupported variant: $variant" >&2
            exit 2
            ;;
    esac

    if [ -z "$supplied_image" ]; then
        runtime_packages="$(paste -sd ' ' "$package_manifest")"
        podman build \
            --build-arg FLUXHEIM_FEATURES=profile-web-server,php-fpm,acme-client \
            --build-arg FLUXHEIM_CONFIG=packaging/container/php-managed.toml \
            --build-arg FLUXHEIM_RUNTIME_PACKAGES="$runtime_packages" \
            -t "$image" \
            -f "$containerfile" .
    fi

    module_output="$content/modules-$variant.txt"
    if ! podman run --rm --entrypoint /usr/bin/php-fpm "$image" -m >"$module_output" 2>&1; then
        echo "fluxheim PHP image smoke ($variant): module probe failed" >&2
        sed -n '1,120p' "$module_output" >&2
        exit 1
    fi
    if grep -Eiq 'PHP (Startup|Warning)|Unable to load dynamic library|undefined symbol' "$module_output"; then
        echo "fluxheim PHP image smoke ($variant): module load failure" >&2
        sed -n '1,120p' "$module_output" >&2
        exit 1
    fi
    while IFS= read -r module; do
        if ! grep -Fqx "$module" "$module_output"; then
            echo "fluxheim PHP image smoke ($variant): missing required module: $module" >&2
            sed -n '1,120p' "$module_output" >&2
            exit 1
        fi
    done < "$required_modules"

    current_container="fluxheim_php_${variant}_smoke_$$"
    podman run -d \
        --name "$current_container" \
        -p "127.0.0.1:$port:8080" \
        -v "$content/index.php:/srv/fluxheim/index.php:ro,Z" \
        "$image" >/dev/null

    status=""
    response_output="$content/response-$variant.txt"
    for _ in $(seq 1 60); do
        status="$(curl -sS --noproxy '*' -o "$response_output" -w '%{http_code}' "http://127.0.0.1:$port/index.php" 2>/dev/null || true)"
        if [ "$status" = "200" ] && grep -q 'Fluxheim managed PHP-FPM is running' "$response_output"; then
            break
        fi
        sleep 1
    done
    if [ "$status" != "200" ] || ! grep -q 'Fluxheim managed PHP-FPM is running' "$response_output"; then
        echo "fluxheim PHP image smoke ($variant) failed: status=${status:-none}" >&2
        podman logs "$current_container" >&2 || true
        if [ -s "$response_output" ]; then
            sed -n '1,80p' "$response_output" >&2
        fi
        exit 1
    fi

    podman rm -f "$current_container" >/dev/null
    current_container=""
    echo "fluxheim managed PHP-FPM image smoke ($variant): ok"
    port=$((port + 1))
done

echo "fluxheim managed PHP-FPM image matrix smoke: ok"
