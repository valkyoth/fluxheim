#!/usr/bin/env sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$root"

if [ "$(uname -s)" != "Linux" ]; then
    echo "ACME mount-boundary smoke requires Linux" >&2
    exit 1
fi

if ! command -v unshare >/dev/null 2>&1; then
    echo "ACME mount-boundary smoke requires util-linux unshare" >&2
    exit 1
fi

test_name=acme_directory::tests::owned_directory_reconciliation_rejects_bind_mount
build_output=$(cargo test --locked -p fluxheim-acme --features acme-client \
    --no-run --message-format=json)
test_binary=$(printf '%s\n' "$build_output" \
    | sed -n 's/.*"executable":"\([^"]*\/fluxheim_acme-[^"]*\)".*/\1/p' \
    | tail -n 1)
if [ -z "$test_binary" ] || [ ! -x "$test_binary" ]; then
    echo "ACME mount-boundary smoke could not locate the compiled test binary" >&2
    exit 1
fi

unshare --user --map-root-user --mount --propagation private --fork \
    "$test_binary" \
    --exact "$test_name" --ignored --nocapture

echo "ACME mount-boundary smoke passed"
