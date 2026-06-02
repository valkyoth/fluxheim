#!/usr/bin/env sh
set -eu

usage() {
    echo "usage: scripts/build_release_assets.sh VERSION [--target TARGET] [--kind linux|macos-dev]" >&2
}

version="${1:-}"
if [ -z "$version" ]; then
    usage
    exit 2
fi
shift

case "$version" in
    *[!0-9A-Za-z._+-]* | "" | .* | *..*)
        echo "release assets: unsafe release version: $version" >&2
        exit 2
        ;;
esac

target="$(rustc -vV | sed -n 's/^host: //p')"
kind="linux"

while [ "$#" -gt 0 ]; do
    case "$1" in
        --target)
            shift
            target="${1:-}"
            if [ -z "$target" ]; then
                usage
                exit 2
            fi
            ;;
        --kind)
            shift
            kind="${1:-}"
            case "$kind" in
                linux | macos-dev) ;;
                *)
                    usage
                    exit 2
                    ;;
            esac
            ;;
        *)
            usage
            exit 2
            ;;
    esac
    shift
done

case "$target" in
    x86_64-unknown-linux-gnu | x86_64-unknown-linux-musl)
        label="x86_64-linux"
        ;;
    aarch64-unknown-linux-gnu | aarch64-unknown-linux-musl)
        label="aarch64-linux"
        ;;
    x86_64-apple-darwin)
        label="x86_64-macos"
        ;;
    aarch64-apple-darwin)
        label="aarch64-macos"
        ;;
    *)
        label="$target"
        ;;
esac

root="$(git rev-parse --show-toplevel)"
cd "$root"
mkdir -p dist

bundle_runtime_profile() {
    profile="$1"
    features="$2"
    dist_name="fluxheim-${version}-${profile}-${label}"

    cargo build --release --locked --target "$target" --no-default-features \
        --features "$features" --bin fluxheim --bin fluxheim-acme

    rm -rf "dist/$dist_name"
    mkdir -p "dist/$dist_name"
    cp "target/$target/release/fluxheim" "dist/$dist_name/"
    cp "target/$target/release/fluxheim-acme" "dist/$dist_name/"
    cp README.md LICENSE CHANGELOG.md "dist/$dist_name/"
    cp -r docs examples packaging release-notes "dist/$dist_name/"
    tar -C dist -czf "dist/${dist_name}.tar.gz" "$dist_name"
    sha256sum "dist/${dist_name}.tar.gz"
}

bundle_config_tester() {
    dist_name="fluxheim-${version}-config-tester-${label}"

    cargo build --release --locked --target "$target" --no-default-features \
        --features profile-development --bin fluxheim-config-tester

    rm -rf "dist/$dist_name"
    mkdir -p "dist/$dist_name"
    cp "target/$target/release/fluxheim-config-tester" "dist/$dist_name/"
    cp README.md LICENSE CHANGELOG.md "dist/$dist_name/"
    tar -C dist -czf "dist/${dist_name}.tar.gz" "$dist_name"
    sha256sum "dist/${dist_name}.tar.gz"
}

bundle_macos_dev() {
    dist_name="fluxheim-${version}-dev-${label}"

    cargo build --release --locked --target "$target" --no-default-features \
        --features profile-development \
        --bin fluxheim --bin fluxheim-acme --bin fluxheim-config-tester

    rm -rf "dist/$dist_name"
    mkdir -p "dist/$dist_name"
    cp "target/$target/release/fluxheim" "dist/$dist_name/"
    cp "target/$target/release/fluxheim-acme" "dist/$dist_name/"
    cp "target/$target/release/fluxheim-config-tester" "dist/$dist_name/"
    cp README.md LICENSE CHANGELOG.md "dist/$dist_name/"
    cp -r docs examples release-notes "dist/$dist_name/"
    tar -C dist -czf "dist/${dist_name}.tar.gz" "$dist_name"
    sha256sum "dist/${dist_name}.tar.gz"
}

case "$kind" in
    linux)
        case "$target" in
            *linux*) ;;
            *)
                echo "release assets: --kind linux requires a linux target, got $target" >&2
                exit 2
                ;;
        esac
        bundle_runtime_profile full profile-full,acme-client,metrics,metrics-otlp,otel-tracing,otel-otlp
        bundle_runtime_profile cache profile-cache-edge,acme-client
        bundle_runtime_profile proxy profile-proxy-edge,acme-client
        bundle_runtime_profile load-balancer profile-load-balancer-edge,acme-client
        bundle_runtime_profile php profile-web-server,php-fpm,acme-client
        bundle_config_tester
        ;;
    macos-dev)
        case "$target" in
            *apple-darwin*) ;;
            *)
                echo "release assets: --kind macos-dev requires an apple-darwin target, got $target" >&2
                exit 2
                ;;
        esac
        bundle_macos_dev
        ;;
esac
