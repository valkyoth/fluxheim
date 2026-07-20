#!/usr/bin/env sh
set -eu

tmp="${TMPDIR:-/tmp}/fluxheim-cargo-update-dry-run.$$"
trap 'rm -f "$tmp"' EXIT INT TERM

cargo update --dry-run >"$tmp" 2>&1

stale_packages="$(
    awk '
        /^[[:space:]]+Updating [^[:space:]]+ v[^[:space:]]+ -> v[^[:space:]]+/ {
            print
        }
    ' "$tmp"
)"

if [ -n "$stale_packages" ]; then
    echo "crate freshness: compatible updates are available:" >&2
    echo "$stale_packages" >&2
    echo "crate freshness: run cargo update for these packages before release" >&2
    exit 1
fi

echo "crate freshness: ok"
