#!/usr/bin/env sh
# Historical research only. A passing run does not qualify HTTP/3 for release.
set -eu
ROOT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
cd "$ROOT_DIR"
python3 scripts/validate_http3_source_lock.py
python3 scripts/test_http3_source_lock.py
cargo +1.99.0 fmt --manifest-path tools/http3-source-probe/Cargo.toml --check
cargo +1.99.0 test --locked --manifest-path tools/http3-source-probe/Cargo.toml
cargo +1.99.0 test --locked --manifest-path tools/http3-source-probe/Cargo.toml --no-default-features --features aws-lc
RUSTUP_TOOLCHAIN=1.99.0 sh scripts/validate_http3_probe_features.sh
cargo deny --manifest-path tools/http3-source-probe/Cargo.toml --config tools/http3-source-probe/deny.toml --locked check
