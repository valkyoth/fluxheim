#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
boundary="$ROOT_DIR/crates/fluxheim-systemd/src/lib.rs"

if ! rg -q 'receive_descriptors\(false\)' "$boundary"; then
    echo "systemd activation policy: descriptor receipt must preserve LISTEN_*" >&2
    exit 1
fi
if rg -q 'listenfd' "$ROOT_DIR/Cargo.toml" "$ROOT_DIR/Cargo.lock" \
    "$ROOT_DIR/src" "$ROOT_DIR/crates/fluxheim-systemd"; then
    echo "systemd activation policy: listenfd must not re-enter the runtime graph" >&2
    exit 1
fi
if [ "$(rg -c 'unsafe \{ OwnedFd::from_raw_fd\(raw\) \}' "$boundary")" -ne 1 ]; then
    echo "systemd activation policy: expected one audited raw-FD ownership transfer" >&2
    exit 1
fi

echo "systemd activation policy: ok"
