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

case "$cargo_rust_version" in
    *.*.*)
        expected_toolchain_version="$cargo_rust_version"
        ;;
    *.*)
        expected_toolchain_version="$cargo_rust_version.0"
        ;;
    *)
        echo "release metadata: Cargo.toml rust-version $cargo_rust_version is not a supported version shape" >&2
        exit 1
        ;;
esac

if [ "$toolchain_version" != "$expected_toolchain_version" ]; then
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

release_notes="release-notes/RELEASE_NOTES_$cargo_version.md"
if [ ! -f "$release_notes" ]; then
    echo "release metadata: missing $release_notes" >&2
    exit 1
fi

if ! grep -q "^# Fluxheim $cargo_version Release Notes$" "$release_notes"; then
    echo "release metadata: $release_notes has the wrong title" >&2
    exit 1
fi

if ! grep -q "v$cargo_version" README.md; then
    echo "release metadata: README.md does not reference v$cargo_version" >&2
    exit 1
fi

if ! grep -q "v$cargo_version" docs/build-and-podman.md; then
    echo "release metadata: docs/build-and-podman.md does not reference v$cargo_version" >&2
    exit 1
fi

if ! grep -q "^Version:[[:space:]]*$cargo_version$" packaging/rpm/fluxheim.spec; then
    echo "release metadata: packaging/rpm/fluxheim.spec Version does not match $cargo_version" >&2
    exit 1
fi

derivative_version="$(
    awk '
        /^\[\[package\]\]$/ { in_package = 1; name = ""; version = ""; next }
        in_package && /^name = "derivative"$/ { name = "derivative"; next }
        in_package && /^version = / { version = $3; gsub(/"/, "", version); next }
        in_package && /^dependencies = \[/ {
            if (name == "derivative") {
                print version;
                exit
            }
            in_package = 0
        }
    ' Cargo.lock
)"

if grep -q 'RUSTSEC-2024-0388' deny.toml .cargo/audit.toml \
    && [ "$derivative_version" != "2.2.0" ]; then
    echo "release metadata: RUSTSEC-2024-0388 suppression must be reviewed because derivative is ${derivative_version:-absent}, expected 2.2.0" >&2
    exit 1
fi

if grep -q 'RUSTSEC-2024-0388' deny.toml .cargo/audit.toml; then
    current_utc_date="$(date -u +%Y%m%d)"
    if [ "$current_utc_date" -ge 20261101 ]; then
        echo "release metadata: RUSTSEC-2024-0388 suppression passed its scheduled manual review date 2026-11-01" >&2
        exit 1
    fi
fi

if grep -q 'RUSTSEC-2025-0134' deny.toml .cargo/audit.toml \
    && ! grep -q '^name = "rustls-pemfile"$' Cargo.lock; then
    echo "release metadata: RUSTSEC-2025-0134 suppression must be removed because rustls-pemfile is no longer in Cargo.lock" >&2
    exit 1
fi

if grep -q 'RUSTSEC-2025-0134' deny.toml .cargo/audit.toml; then
    current_utc_date="$(date -u +%Y%m%d)"
    if [ "$current_utc_date" -ge 20260901 ]; then
        echo "release metadata: RUSTSEC-2025-0134 suppression passed its scheduled manual review date 2026-09-01" >&2
        exit 1
    fi
fi

if grep -q 'RUSTSEC-2025-0069' deny.toml .cargo/audit.toml \
    && ! grep -q '^name = "daemonize"$' Cargo.lock; then
    echo "release metadata: RUSTSEC-2025-0069 suppression must be removed because daemonize is no longer in Cargo.lock" >&2
    exit 1
fi

if grep -q 'RUSTSEC-2025-0069' deny.toml .cargo/audit.toml; then
    current_utc_date="$(date -u +%Y%m%d)"
    if [ "$current_utc_date" -ge 20260901 ]; then
        echo "release metadata: RUSTSEC-2025-0069 suppression passed its scheduled manual review date 2026-09-01" >&2
        exit 1
    fi
fi

if grep -q 'RUSTSEC-2026-0173' deny.toml .cargo/audit.toml \
    && ! grep -q '^name = "proc-macro-error2"$' Cargo.lock; then
    echo "release metadata: RUSTSEC-2026-0173 suppression must be removed because proc-macro-error2 is no longer in Cargo.lock" >&2
    exit 1
fi

if grep -q 'RUSTSEC-2026-0173' deny.toml .cargo/audit.toml; then
    current_utc_date="$(date -u +%Y%m%d)"
    if [ "$current_utc_date" -ge 20260901 ]; then
        echo "release metadata: RUSTSEC-2026-0173 suppression passed its scheduled manual review date 2026-09-01" >&2
        exit 1
    fi
fi

echo "release metadata: ok"
