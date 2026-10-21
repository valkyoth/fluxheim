#!/usr/bin/env bash
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
linux_helper="$root/scripts/release_helper.sh"
macos_helper="$root/scripts/release_helper_macos.sh"

bash -n "$linux_helper" "$macos_helper"

for required in \
    'Enter Linux aarch64 SSH key path:' \
    'Enter Windows x86_64 SSH key path:' \
    'FLUXHEIM_RELEASE_SSH_CONFIG' \
    '-F "$SSH_CONFIG"' \
    'umask 077' \
    '## Checksums And Signatures' \
    'SHA256SUMS-x86_64-windows.txt' \
    'REPRODUCIBLE-BUILD-SHA256-x86_64-windows.txt' \
    'normalize_windows_text_evidence "$OUTPUT_DIR/windows/x86_64"' \
    "sed -i 's/\\r\$//'" \
    'base=suse-bci'; do
    grep -F -- "$required" "$linux_helper" >/dev/null || {
        echo "release helper is missing required behavior: $required" >&2
        exit 1
    }
done

windows_evidence_fixture="$(mktemp)"
trap 'rm -f "$windows_evidence_fixture"' EXIT INT TERM
printf 'commit=test\r\narchive_count=7\r\n' > "$windows_evidence_fixture"
sed -i 's/\r$//' "$windows_evidence_fixture"
grep -Fx 'commit=test' "$windows_evidence_fixture" >/dev/null
grep -Fx 'archive_count=7' "$windows_evidence_fixture" >/dev/null
if LC_ALL=C grep -q $'\r' "$windows_evidence_fixture"; then
    echo 'Windows release evidence normalization retained a carriage return' >&2
    exit 1
fi

for required in \
    'Apple Silicon Mac' \
    'smoke_macos_native_parity.sh' \
    'SHA256SUMS-aarch64-macos.txt' \
    'seven tar.gz archives'; do
    grep -F -- "$required" "$macos_helper" >/dev/null || {
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
