#!/usr/bin/env sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
vendor="$root/vendor/instant-acme"
checksums="$vendor/UPSTREAM-SHA256SUMS"
patch_checksum="$vendor/FLUXHEIM-PATCH-SHA256"
temporary_dir=$(mktemp -d "${TMPDIR:-/tmp}/fluxheim-instant-acme.XXXXXX")
upstream_source="$temporary_dir/upstream-account.rs"
patch_source="$temporary_dir/fluxheim-patch.rs"
trap 'rm -rf -- "$temporary_dir"' EXIT HUP INT TERM

if [ ! -f "$checksums" ]; then
    echo "instant-acme patch policy: missing upstream checksums" >&2
    exit 1
fi
if [ ! -f "$patch_checksum" ]; then
    echo "instant-acme patch policy: missing downstream patch checksum" >&2
    exit 1
fi

begin_count=$(grep -c 'FLUXHEIM PATCH BEGIN: durable caller-key account bootstrap' "$vendor/src/account.rs" || true)
end_count=$(grep -c 'FLUXHEIM PATCH END: durable caller-key account bootstrap' "$vendor/src/account.rs" || true)
if [ "$begin_count" -ne 1 ] || [ "$end_count" -ne 1 ]; then
    echo "instant-acme patch policy: expected exactly one bounded downstream patch" >&2
    exit 1
fi

awk '
    /FLUXHEIM PATCH BEGIN: durable caller-key account bootstrap/ { skip = 1; next }
    /FLUXHEIM PATCH END: durable caller-key account bootstrap/ {
        skip = 0
        trim_blank = 1
        next
    }
    skip { next }
    trim_blank && /^$/ { trim_blank = 0; next }
    { trim_blank = 0; print }
' "$vendor/src/account.rs" >"$upstream_source"

awk '
    /FLUXHEIM PATCH BEGIN: durable caller-key account bootstrap/ { capture = 1; next }
    /FLUXHEIM PATCH END: durable caller-key account bootstrap/ { capture = 0; next }
    capture { print }
' "$vendor/src/account.rs" >"$patch_source"

expected_patch=$(cat "$patch_checksum")
actual_patch=$(sha256sum "$patch_source" | awk '{ print $1 }')
if [ "$actual_patch" != "$expected_patch" ]; then
    echo "instant-acme patch policy: permitted downstream patch body drifted" >&2
    exit 1
fi

while read -r expected path; do
    if [ "$path" = "src/account.rs" ]; then
        actual=$(sha256sum "$upstream_source" | awk '{ print $1 }')
    else
        actual=$(sha256sum "$vendor/$path" | awk '{ print $1 }')
    fi
    if [ "$actual" != "$expected" ]; then
        echo "instant-acme patch policy: upstream file drifted: $path" >&2
        exit 1
    fi
done <"$checksums"

grep -q 'version = "0.8.5"' "$vendor/Cargo.toml"
grep -q 'c8c16a211d01bee3586c2639da00dcd96e70dcd2' "$vendor/PATCH.md"
grep -q '9f05ad37c421b962354c358d347d4a6130151df9407978372d3ad7f0c8f71a64' "$vendor/PATCH.md"

echo "instant-acme patch policy: ok"
