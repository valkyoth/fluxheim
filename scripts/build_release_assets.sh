#!/usr/bin/env sh
set -eu

usage() {
    echo "usage: scripts/build_release_assets.sh VERSION [--target TARGET] [--kind linux|macos-dev] [--profile all|full|wasm|cache|proxy|load-balancer|php|config-tester]" >&2
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
profile="all"

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
        --profile)
            shift
            profile="${1:-}"
            case "$profile" in
                all | full | wasm | cache | proxy | load-balancer | php | config-tester) ;;
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
    python3 scripts/create_release_archives.py "$dist_name"
}

bundle_config_tester() {
    dist_name="fluxheim-${version}-config-tester-${label}"

    cargo build --release --locked --target "$target" --no-default-features \
        --features profile-development --bin fluxheim-config-tester

    rm -rf "dist/$dist_name"
    mkdir -p "dist/$dist_name"
    cp "target/$target/release/fluxheim-config-tester" "dist/$dist_name/"
    cp README.md LICENSE CHANGELOG.md "dist/$dist_name/"
    python3 scripts/create_release_archives.py "$dist_name"
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
    python3 scripts/create_release_archives.py "$dist_name"
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
        if [ "$profile" = "all" ] || [ "$profile" = "full" ]; then
            bundle_runtime_profile full profile-full,acme-client,metrics,metrics-otlp,otel-tracing,otel-otlp
        fi
        if [ "$profile" = "all" ] || [ "$profile" = "wasm" ]; then
            bundle_runtime_profile wasm profile-wasm,acme-client,metrics,metrics-otlp,otel-tracing,otel-otlp
        fi
        if [ "$profile" = "all" ] || [ "$profile" = "cache" ]; then
            bundle_runtime_profile cache profile-cache-edge,acme-client
        fi
        if [ "$profile" = "all" ] || [ "$profile" = "proxy" ]; then
            bundle_runtime_profile proxy profile-proxy-edge,acme-client
        fi
        if [ "$profile" = "all" ] || [ "$profile" = "load-balancer" ]; then
            bundle_runtime_profile load-balancer profile-load-balancer-edge,acme-client
        fi
        if [ "$profile" = "all" ] || [ "$profile" = "php" ]; then
            bundle_runtime_profile php profile-web-server,php-fpm,acme-client
        fi
        if [ "$profile" = "all" ] || [ "$profile" = "config-tester" ]; then
            bundle_config_tester
        fi
        ;;
    macos-dev)
        if [ "$profile" != "all" ]; then
            echo "release assets: --profile is not supported with --kind macos-dev" >&2
            exit 2
        fi
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
