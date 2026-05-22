#!/usr/bin/env sh
set -eu

cargo_version="$(
    sed -n 's/^version = "\([^"]*\)"/\1/p' Cargo.toml | sed -n '1p'
)"
cargo_rust_version="$(
    sed -n 's/^rust-version = "\([^"]*\)"/\1/p' Cargo.toml | sed -n '1p'
)"
toolchain_version="$(
    sed -n 's/^channel = "\([^"]*\)"/\1/p' rust-toolchain.toml | sed -n '1p'
)"
container_rust_image="$(
    sed -n 's/^ARG RUST_IMAGE=docker.io\/library\/rust:\([^"]*\)$/\1/p' Containerfile | sed -n '1p'
)"

if [ -z "$cargo_version" ]; then
    echo "release metadata: Cargo.toml package version is missing" >&2
    exit 1
fi

if [ -z "$cargo_rust_version" ]; then
    echo "release metadata: Cargo.toml rust-version is missing" >&2
    exit 1
fi

if [ "$toolchain_version" != "$cargo_rust_version.0" ]; then
    echo "release metadata: rust-toolchain.toml channel $toolchain_version does not match Cargo.toml rust-version $cargo_rust_version" >&2
    exit 1
fi

case "$container_rust_image" in
    "$toolchain_version"-*)
        ;;
    *)
        echo "release metadata: Containerfile Rust image $container_rust_image does not match toolchain $toolchain_version" >&2
        exit 1
        ;;
esac

if ! grep -q '^license = "EUPL-1.2"$' Cargo.toml; then
    echo "release metadata: Cargo.toml must declare license = \"EUPL-1.2\"" >&2
    exit 1
fi

if ! grep -q 'EUROPEAN UNION PUBLIC LICENCE v. 1.2' LICENSE; then
    echo "release metadata: LICENSE does not look like EUPL 1.2" >&2
    exit 1
fi

if ! grep -q "^## $cargo_version " CHANGELOG.md; then
    echo "release metadata: CHANGELOG.md is missing a section for Cargo version $cargo_version" >&2
    exit 1
fi

prometheus_version="$(
    awk '
        /^\[\[package\]\]$/ { in_package = 1; name = ""; version = ""; next }
        in_package && /^name = "prometheus"$/ { name = "prometheus"; next }
        in_package && /^version = / { version = $3; gsub(/"/, "", version); next }
        in_package && /^dependencies = \[/ {
            if (name == "prometheus") {
                print version;
                exit
            }
            in_package = 0
        }
    ' Cargo.lock
)"

if grep -q 'RUSTSEC-2024-0437' deny.toml .cargo/audit.toml \
    && [ "$prometheus_version" != "0.13.4" ]; then
    echo "release metadata: RUSTSEC-2024-0437 suppression must be reviewed because prometheus is $prometheus_version, expected 0.13.4" >&2
    exit 1
fi

echo "release metadata: ok"
