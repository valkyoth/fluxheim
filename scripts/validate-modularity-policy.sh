#!/usr/bin/env sh
set -eu

mode="${1:-check}"

case "$mode" in
    check | report)
        ;;
    *)
        echo "usage: scripts/validate-modularity-policy.sh [check|report]" >&2
        exit 2
        ;;
esac

limit="${FLUXHEIM_MODULARITY_LINE_LIMIT:-500}"
exceptions="docs/modularity-exceptions.md"

if [ ! -f "$exceptions" ]; then
    echo "modularity policy: missing $exceptions" >&2
    exit 1
fi

tmp="${TMPDIR:-/tmp}/fluxheim-modularity-$$.missing"
trap 'rm -f "$tmp"' EXIT HUP INT TERM
: > "$tmp"

git ls-files '*.rs' | while IFS= read -r path; do
    case "$path" in
        vendor/*|target/*|*/target/*)
            continue
            ;;
    esac
    lines="$(wc -l < "$path" | tr -d ' ')"
    if [ "$lines" -le "$limit" ]; then
        continue
    fi
    printf 'modularity policy: %s lines %s\n' "$lines" "$path"
    if [ "$mode" = "check" ] && ! grep -Fq "| \`$path\` |" "$exceptions"; then
        echo "modularity policy: $path exceeds $limit lines and is not listed in $exceptions" >&2
        printf '%s\n' "$path" >> "$tmp"
    fi
done

if [ "$mode" = "report" ]; then
    echo "modularity policy: report complete"
else
    if [ -s "$tmp" ]; then
        exit 1
    fi
    echo "modularity policy: ok"
fi
