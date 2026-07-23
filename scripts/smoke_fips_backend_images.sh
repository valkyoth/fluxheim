#!/usr/bin/env sh
set -eu

mode="${1:-all}"
case "$mode" in
    all|openssl|rustls) ;;
    *)
        echo "usage: scripts/smoke_fips_backend_images.sh [all|openssl|rustls]" >&2
        exit 2
        ;;
esac

if command -v podman >/dev/null 2>&1; then
    container_tool="podman"
elif command -v docker >/dev/null 2>&1; then
    container_tool="docker"
else
    echo "fips image evidence: podman or docker is required" >&2
    exit 2
fi

version="$(
    sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml |
        sed -n '1p'
)"
case "$version" in
    ''|*[!0-9A-Za-z._+-]*)
        echo "fips image evidence: invalid Cargo package version: ${version:-<empty>}" >&2
        exit 2
        ;;
esac
openssl_image="fluxheim-fips-openssl-evidence:${version}"
rustls_image="fluxheim-fips-rustls-evidence:${version}"

build_openssl() {
    echo "fips image evidence: building OpenSSL backend"
    case "$container_tool" in
        podman)
            podman build \
                --file containers/fips/Containerfile.openssl \
                --tag "localhost/${openssl_image}" \
                .
            podman run --rm "localhost/${openssl_image}"
            podman image inspect \
                --format 'fips image evidence: OpenSSL image={{.Id}} digest={{.Digest}}' \
                "localhost/${openssl_image}"
            ;;
        docker)
            docker build \
                --file containers/fips/Containerfile.openssl \
                --tag "$openssl_image" \
                .
            docker run --rm "$openssl_image"
            docker image inspect \
                --format 'fips image evidence: OpenSSL image={{.Id}} digests={{json .RepoDigests}}' \
                "$openssl_image"
            ;;
    esac
}

build_rustls() {
    echo "fips image evidence: building rustls/AWS-LC backend"
    case "$container_tool" in
        podman)
            podman build \
                --file containers/fips/Containerfile.rustls \
                --tag "localhost/${rustls_image}" \
                .
            podman run --rm "localhost/${rustls_image}"
            podman image inspect \
                --format 'fips image evidence: rustls image={{.Id}} digest={{.Digest}}' \
                "localhost/${rustls_image}"
            ;;
        docker)
            docker build \
                --file containers/fips/Containerfile.rustls \
                --tag "$rustls_image" \
                .
            docker run --rm "$rustls_image"
            docker image inspect \
                --format 'fips image evidence: rustls image={{.Id}} digests={{json .RepoDigests}}' \
                "$rustls_image"
            ;;
    esac
}

case "$mode" in
    all)
        build_openssl
        build_rustls
        ;;
    openssl) build_openssl ;;
    rustls) build_rustls ;;
esac
