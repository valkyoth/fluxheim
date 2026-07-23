#!/usr/bin/env sh
set -eu

usage() {
    echo "usage: scripts/build_release_assets.sh VERSION [--target TARGET] [--kind linux|macos|windows|macos-dev] [--profile all|full|wasm|cache|proxy|load-balancer|php|config-tester] [--plan]" >&2
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
selected_profile="all"
plan_only=0

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
                linux | macos | windows | macos-dev) ;;
                *)
                    usage
                    exit 2
                    ;;
            esac
            ;;
        --plan)
            plan_only=1
            ;;
        --profile)
            shift
            selected_profile="${1:-}"
            case "$selected_profile" in
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
    *[!0-9A-Za-z_-]* | "" | .* | *..*)
        echo "release assets: unsafe Rust target: $target" >&2
        exit 2
        ;;
esac

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
    x86_64-pc-windows-msvc)
        label="x86_64-windows"
        ;;
    aarch64-pc-windows-msvc)
        label="aarch64-windows"
        ;;
    *)
        label="$target"
        ;;
esac

root="$(git rev-parse --show-toplevel)"
cd "$root"
if [ "$plan_only" -eq 0 ]; then
    mkdir -p dist
fi

case "$target" in
    *-windows-msvc) binary_suffix=".exe" ;;
    *) binary_suffix="" ;;
esac

python_command() {
    if command -v python3 >/dev/null 2>&1; then
        printf '%s\n' python3
    elif command -v python >/dev/null 2>&1; then
        printf '%s\n' python
    else
        echo "release assets: Python 3 is required" >&2
        exit 2
    fi
}

copy_binary() {
    name="$1"
    destination="$2"
    cp "target/$target/release/${name}${binary_suffix}" "$destination/"
}

bundle_runtime_profile() {
    dist_name="$1"
    bundle_features="$2"

    cargo build --release --locked --target "$target" --no-default-features \
        --features "$bundle_features" --bin fluxheim --bin fluxheim-acme

    rm -rf "dist/$dist_name"
    mkdir -p "dist/$dist_name"
    copy_binary fluxheim "dist/$dist_name"
    copy_binary fluxheim-acme "dist/$dist_name"
    cp README.md LICENSE CHANGELOG.md "dist/$dist_name/"
    cp -r docs examples packaging release-notes "dist/$dist_name/"
    "$(python_command)" scripts/create_release_archives.py "$dist_name"
}

bundle_config_tester() {
    dist_name="$1"

    cargo build --release --locked --target "$target" --no-default-features \
        --features profile-development --bin fluxheim-config-tester

    rm -rf "dist/$dist_name"
    mkdir -p "dist/$dist_name"
    copy_binary fluxheim-config-tester "dist/$dist_name"
    cp README.md LICENSE CHANGELOG.md "dist/$dist_name/"
    "$(python_command)" scripts/create_release_archives.py "$dist_name"
}

bundle_macos_dev() {
    dist_name="fluxheim-${version}-dev-${label}"

    cargo build --release --locked --target "$target" --no-default-features \
        --features profile-development \
        --bin fluxheim --bin fluxheim-acme --bin fluxheim-config-tester

    rm -rf "dist/$dist_name"
    mkdir -p "dist/$dist_name"
    copy_binary fluxheim "dist/$dist_name"
    copy_binary fluxheim-acme "dist/$dist_name"
    copy_binary fluxheim-config-tester "dist/$dist_name"
    cp README.md LICENSE CHANGELOG.md "dist/$dist_name/"
    cp -r docs examples release-notes "dist/$dist_name/"
    "$(python_command)" scripts/create_release_archives.py "$dist_name"
}

case "$kind:$target" in
    linux:*-linux-* | macos:*-apple-darwin | windows:*-windows-msvc) ;;
    linux:*)
        echo "release assets: --kind linux requires a Linux target, got $target" >&2
        exit 2
        ;;
    macos:*)
        echo "release assets: --kind macos requires an Apple Darwin target, got $target" >&2
        exit 2
        ;;
    windows:*)
        echo "release assets: --kind windows requires a Windows MSVC target, got $target" >&2
        exit 2
        ;;
esac

release_plan="$("$(python_command)" scripts/portable_release_plan.py "$version" \
    --kind "$kind" --target "$target" --profile "$selected_profile")"
if [ "$plan_only" -eq 1 ]; then
    printf '%s\n' "$release_plan"
    exit 0
fi

case "$kind" in
    linux | macos | windows)
        while IFS='|' read -r dist_name bundle_features bundle_binaries; do
            case "$bundle_binaries" in
                fluxheim-config-tester*)
                    bundle_config_tester "$dist_name"
                    ;;
                *)
                    bundle_runtime_profile "$dist_name" "$bundle_features"
                    ;;
            esac
        done <<EOF
$release_plan
EOF
        ;;
    macos-dev)
        if [ "$selected_profile" != "all" ]; then
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
