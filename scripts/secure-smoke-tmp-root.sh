#!/usr/bin/env sh
set -eu

root_dir=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
case "${1:-default}" in
    default)
        default_root="$root_dir/target/fluxheim-smoke-tmp"
        ;;
    short)
        default_root="$root_dir/target/fh"
        ;;
    *)
        echo "usage: scripts/secure-smoke-tmp-root.sh [default|short]" >&2
        exit 2
        ;;
esac
smoke_tmp_root="${FLUXHEIM_SMOKE_TMP_ROOT:-$default_root}"

mkdir -p "$smoke_tmp_root"
chmod 700 "$smoke_tmp_root"
CDPATH= cd -- "$smoke_tmp_root" && pwd
