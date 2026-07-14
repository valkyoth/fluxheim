#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)

cargo build --quiet --locked
python3 "$ROOT_DIR/scripts/smoke_zero_downtime_upgrade.py" \
    "$ROOT_DIR/target/debug/fluxheim"
