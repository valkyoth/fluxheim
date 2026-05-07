#!/usr/bin/env sh
set -eu

first_target="${FLUXHEIM_REPRO_TARGET_A:-target/reproducible-a}"
second_target="${FLUXHEIM_REPRO_TARGET_B:-target/reproducible-b}"
features="${FLUXHEIM_REPRO_FEATURES:-default}"

if command -v git >/dev/null 2>&1 && git rev-parse --git-dir >/dev/null 2>&1; then
    SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-$(git log -1 --format=%ct)}"
else
    SOURCE_DATE_EPOCH="${SOURCE_DATE_EPOCH:-0}"
fi
export SOURCE_DATE_EPOCH

build_once() {
    target_dir="$1"
    if [ "$features" = "default" ]; then
        CARGO_TARGET_DIR="$target_dir" cargo build --release --locked
    else
        scripts/validate-features.sh "$features"
        CARGO_TARGET_DIR="$target_dir" cargo build --release --locked --no-default-features --features "$features"
    fi
}

build_once "$first_target"
build_once "$second_target"

first_binary="$first_target/release/fluxheim"
second_binary="$second_target/release/fluxheim"

if ! cmp -s "$first_binary" "$second_binary"; then
    echo "release binary is not reproducible across two clean target directories" >&2
    sha256sum "$first_binary" "$second_binary" >&2
    exit 1
fi

sha256sum "$first_binary"
