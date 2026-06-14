#!/usr/bin/env sh
set -eu

mode="${1:-check}"

case "$mode" in
    check | report)
        ;;
    *)
        echo "usage: scripts/validate-runtime-fixtures.sh [check|report]" >&2
        exit 2
        ;;
esac

inventory="docs/runtime-parity-fixtures.tsv"

if [ ! -f "$inventory" ]; then
    echo "runtime fixtures: missing $inventory" >&2
    exit 1
fi

missing=0
while IFS="$(printf '\t')" read -r path kind target reason; do
    case "$path" in
        "" | "#"*) continue ;;
        path) continue ;;
    esac

    if [ -z "$kind" ] || [ -z "$target" ] || [ -z "$reason" ]; then
        echo "runtime fixtures: malformed inventory row for $path" >&2
        missing=1
        continue
    fi

    if [ ! -e "$path" ]; then
        echo "runtime fixtures: missing $kind $path" >&2
        missing=1
        continue
    fi

    case "$kind" in
        script)
            if [ ! -x "$path" ]; then
                echo "runtime fixtures: script is not executable: $path" >&2
                missing=1
            fi
            ;;
        config | directory | fixture | doc)
            ;;
        *)
            echo "runtime fixtures: unknown kind '$kind' for $path" >&2
            missing=1
            ;;
    esac

    if [ "$mode" = "report" ]; then
        printf 'runtime fixtures: %-9s %-64s %s\n' "$kind" "$path" "$target"
    fi
done <"$inventory"

if [ "$missing" -ne 0 ]; then
    exit 1
fi

echo "runtime fixtures: ok"
