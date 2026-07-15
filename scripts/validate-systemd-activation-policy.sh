#!/usr/bin/env sh
set -eu

ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
boundary="$ROOT_DIR/crates/fluxheim-systemd/src/lib.rs"

if ! rg -q 'receive_descriptors\(false\)' "$boundary"; then
    echo "systemd activation policy: descriptor receipt must preserve LISTEN_*" >&2
    exit 1
fi
preflight_line=$(rg -n 'validate_declared_count\(expected, activation_listener_declaration\(\)\?\.as_deref\(\)\)\?;' "$boundary" | cut -d: -f1 || true)
receipt_line=$(rg -n 'receive_descriptors\(false\)' "$boundary" | cut -d: -f1 || true)
if [ -z "$preflight_line" ] || [ -z "$receipt_line" ] || [ "$preflight_line" -ge "$receipt_line" ]; then
    echo "systemd activation policy: LISTEN_FDS must be bounded before descriptor receipt" >&2
    exit 1
fi
if ! rg -q 'socket_protocol\(&owned\)\?' "$boundary" \
    || ! rg -q 'protocol != Some\(rustix::net::ipproto::TCP\)' "$boundary"; then
    echo "systemd activation policy: inherited stream descriptors must explicitly use TCP" >&2
    exit 1
fi
if ! rg -q 'static ACTIVATION_CONSUMED: AtomicBool' "$boundary" \
    || ! rg -q '\.compare_exchange\(false, true, Ordering::AcqRel, Ordering::Acquire\)' "$boundary"; then
    echo "systemd activation policy: descriptor ownership must be process-wide and one-shot" >&2
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
