#!/usr/bin/env sh
set -eu

mode="${1:-check}"

case "$mode" in
    check | report)
        ;;
    *)
        echo "usage: scripts/validate-pingora-boundary-policy.sh [check|report]" >&2
        exit 2
        ;;
esac

exceptions="docs/pingora-http-error-boundary-exceptions.tsv"

if [ ! -f "$exceptions" ]; then
    echo "pingora boundary policy: missing $exceptions" >&2
    exit 1
fi

tmp_dir="${TMPDIR:-/tmp}/fluxheim-pingora-boundary-$$"
trap 'rm -rf "$tmp_dir"' EXIT HUP INT TERM
mkdir -p "$tmp_dir"

matches="$tmp_dir/matches.tsv"
allowed="$tmp_dir/allowed.paths"
unexpected="$tmp_dir/unexpected.tsv"
stale="$tmp_dir/stale.paths"

if git grep -n -E 'pingora::http|pingora::Error|pingora::ErrorType|use pingora::\{Error|use pingora::http' -- '*.rs' >"$matches"; then
    :
else
    status="$?"
    if [ "$status" -ne 1 ]; then
        echo "pingora boundary policy: grep failed" >&2
        exit "$status"
    fi
    : > "$matches"
fi

awk -F '\t' '
    /^[[:space:]]*#/ { next }
    NF == 0 { next }
    $1 == "path" { next }
    NF < 2 {
        print "pingora boundary policy: malformed exception line " NR ": " $0 > "/dev/stderr"
        exit 2
    }
    { print $1 }
' "$exceptions" | sort -u >"$allowed"

awk -F ':' -v allowed="$allowed" '
    BEGIN {
        while ((getline path < allowed) > 0) {
            allowed_paths[path] = 1
        }
        close(allowed)
    }
    {
        path = $1
        if (!(path in allowed_paths)) {
            print $0
        }
    }
' "$matches" >"$unexpected"

awk -F ':' '{ print $1 }' "$matches" | sort -u >"$tmp_dir/current.paths"
comm -13 "$tmp_dir/current.paths" "$allowed" >"$stale"

if [ -s "$unexpected" ]; then
    echo "pingora boundary policy: unexpected Pingora HTTP/error usage:" >&2
    cat "$unexpected" >&2
fi

if [ -s "$stale" ]; then
    echo "pingora boundary policy: stale exceptions:" >&2
    cat "$stale" >&2
fi

if [ "$mode" = "check" ] && { [ -s "$unexpected" ] || [ -s "$stale" ]; }; then
    exit 1
fi

echo "pingora boundary policy: ok"
