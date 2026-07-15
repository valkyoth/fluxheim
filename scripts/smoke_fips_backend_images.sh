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

build_openssl() {
    echo "fips image evidence: building OpenSSL backend"
    case "$container_tool" in
        podman)
            podman build \
                --file containers/fips/Containerfile.openssl \
                --tag localhost/fluxheim-fips-openssl-evidence:1.7.12 \
                .
            podman run --rm localhost/fluxheim-fips-openssl-evidence:1.7.12
            podman image inspect \
                --format 'fips image evidence: OpenSSL image={{.Id}} digest={{.Digest}}' \
                localhost/fluxheim-fips-openssl-evidence:1.7.12
            ;;
        docker)
            docker build \
                --file containers/fips/Containerfile.openssl \
                --tag fluxheim-fips-openssl-evidence:1.7.12 \
                .
            docker run --rm fluxheim-fips-openssl-evidence:1.7.12
            docker image inspect \
                --format 'fips image evidence: OpenSSL image={{.Id}} digests={{json .RepoDigests}}' \
                fluxheim-fips-openssl-evidence:1.7.12
            ;;
    esac
}

build_rustls() {
    echo "fips image evidence: building rustls/AWS-LC backend"
    case "$container_tool" in
        podman)
            podman build \
                --file containers/fips/Containerfile.rustls \
                --tag localhost/fluxheim-fips-rustls-evidence:1.7.12 \
                .
            podman run --rm localhost/fluxheim-fips-rustls-evidence:1.7.12
            podman image inspect \
                --format 'fips image evidence: rustls image={{.Id}} digest={{.Digest}}' \
                localhost/fluxheim-fips-rustls-evidence:1.7.12
            ;;
        docker)
            docker build \
                --file containers/fips/Containerfile.rustls \
                --tag fluxheim-fips-rustls-evidence:1.7.12 \
                .
            docker run --rm fluxheim-fips-rustls-evidence:1.7.12
            docker image inspect \
                --format 'fips image evidence: rustls image={{.Id}} digests={{json .RepoDigests}}' \
                fluxheim-fips-rustls-evidence:1.7.12
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
