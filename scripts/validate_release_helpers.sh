#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
linux_helper="$root/scripts/release_helper.sh"
macos_helper="$root/scripts/release_helper_macos.sh"

bash -n "$linux_helper" "$macos_helper"

for required in \
    'Enter Linux aarch64 SSH key path:' \
    'Enter Windows x86_64 SSH key path:' \
    '## Checksums And Signatures' \
    'SHA256SUMS-x86_64-windows.txt' \
    'REPRODUCIBLE-BUILD-SHA256-x86_64-windows.txt' \
    'base=suse-bci'; do
    grep -F "$required" "$linux_helper" >/dev/null || {
        echo "release helper is missing required behavior: $required" >&2
        exit 1
    }
done

for required in \
    'Apple Silicon Mac' \
    'smoke_macos_native_parity.sh' \
    'SHA256SUMS-aarch64-macos.txt' \
    'seven tar.gz archives'; do
    grep -F "$required" "$macos_helper" >/dev/null || {
        echo "macOS release helper is missing required behavior: $required" >&2
        exit 1
    }
done

if grep -E '/home/[^/]+/|([0-9]{1,3}[.]){3}[0-9]{1,3}' \
    "$linux_helper" "$macos_helper" >/dev/null; then
    echo 'release helpers must not contain personal paths or builder addresses' >&2
    exit 1
fi

echo 'release helpers: ok'
