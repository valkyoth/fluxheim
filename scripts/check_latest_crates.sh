#!/usr/bin/env sh
set -eu

tmp="${TMPDIR:-/tmp}/fluxheim-cargo-update-dry-run.$$"
trap 'rm -f "$tmp"' EXIT INT TERM

cargo update --workspace --dry-run >"$tmp" 2>&1

stale_non_pingora="$(
    awk '
        /^[[:space:]]+Updating / {
            package = $2
            if (package !~ /^pingora/) {
                print
            }
        }
    ' "$tmp"
)"

if [ -n "$stale_non_pingora" ]; then
    echo "crate freshness: compatible non-Pingora updates are available:" >&2
    echo "$stale_non_pingora" >&2
    echo "crate freshness: run cargo update for these packages before release" >&2
    exit 1
fi

echo "crate freshness: ok"
