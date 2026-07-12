#!/usr/bin/env sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
vendor="$root/vendor/instant-acme"
checksums="$vendor/UPSTREAM-SHA256SUMS"
patched_checksums="$vendor/FLUXHEIM-PATCHED-SHA256SUMS"
patch_checksum="$vendor/FLUXHEIM-PATCH-SHA256"

if [ ! -f "$checksums" ]; then
    echo "instant-acme patch policy: missing upstream checksums" >&2
    exit 1
fi
if [ ! -f "$patched_checksums" ]; then
    echo "instant-acme patch policy: missing patched source checksums" >&2
    exit 1
fi
if [ ! -f "$patch_checksum" ]; then
    echo "instant-acme patch policy: missing downstream patch checksum" >&2
    exit 1
fi

for marker in \
    'durable caller-key account bootstrap' \
    'protected caller-key account recovery' \
    'protected generated account key'
do
    begin_count=$(grep -c "FLUXHEIM PATCH BEGIN: $marker" "$vendor/src/account.rs" || true)
    end_count=$(grep -c "FLUXHEIM PATCH END: $marker" "$vendor/src/account.rs" || true)
    if [ "$begin_count" -ne 1 ] || [ "$end_count" -ne 1 ]; then
        echo "instant-acme patch policy: expected one bounded $marker patch" >&2
        exit 1
    fi
done

expected_patch=$(cat "$patch_checksum")
actual_patch=$(
    cat "$vendor/Cargo.toml" "$vendor/src/account.rs" "$vendor/src/types.rs" \
        | sha256sum | awk '{ print $1 }'
)
if [ "$actual_patch" != "$expected_patch" ]; then
    echo "instant-acme patch policy: permitted downstream patch set drifted" >&2
    exit 1
fi

while read -r expected path; do
    if grep -Fq "  $path" "$patched_checksums"; then
        continue
    fi
    actual=$(sha256sum "$vendor/$path" | awk '{ print $1 }')
    if [ "$actual" != "$expected" ]; then
        echo "instant-acme patch policy: upstream file drifted: $path" >&2
        exit 1
    fi
done <"$checksums"

while read -r expected path; do
    actual=$(sha256sum "$vendor/$path" | awk '{ print $1 }')
    if [ "$actual" != "$expected" ]; then
        echo "instant-acme patch policy: reviewed patched file drifted: $path" >&2
        exit 1
    fi
done <"$patched_checksums"

grep -q 'version = "0.8.5"' "$vendor/Cargo.toml"
grep -q 'rust-version = "1.85"' "$vendor/Cargo.toml"
grep -q '\[dependencies.sanitization\]' "$vendor/Cargo.toml"
grep -q '\[dependencies.p256\]' "$vendor/Cargo.toml"
grep -q 'p256::SecretKey::try_generate()' "$vendor/src/account.rs"
grep -q 'secret_key.to_pkcs8_der()' "$vendor/src/account.rs"
grep -q 'key_pkcs8: SecretVec' "$vendor/src/types.rs"
grep -q 'decode_secret_staged::<4096>' "$vendor/src/types.rs"
grep -q 'c8c16a211d01bee3586c2639da00dcd96e70dcd2' "$vendor/PATCH.md"
grep -q '9f05ad37c421b962354c358d347d4a6130151df9407978372d3ad7f0c8f71a64' "$vendor/PATCH.md"

echo "instant-acme patch policy: ok"
