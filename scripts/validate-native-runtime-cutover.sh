#!/usr/bin/env sh
set -eu

out_dir="${FLUXHEIM_NATIVE_RUNTIME_CUTOVER_DIR:-target/release-evidence/native-runtime-cutover}"
mkdir -p "$out_dir"

{
    echo "Fluxheim native runtime cutover evidence"
    echo
    echo "This gate proves the current native runtime blocker inventory is"
    echo "compiled and tested. It does not claim production traffic has cut over"
    echo "until the Pingora dependency policy is empty for normal profiles."
    echo
    echo "Version: $(sed -n 's/^version = \"\([^\"]*\)\"/\1/p' Cargo.toml | sed -n '1p')"
    echo "Generated: $(date -u '+%Y-%m-%dT%H:%M:%SZ')"
} >"$out_dir/README.txt"

cargo test --locked -p fluxheim-server native_runtime_cutover_summary \
    >"$out_dir/server-native-runtime-cutover-tests.txt" 2>&1

cargo test --locked -p fluxheim-server native_http2_preview \
    >"$out_dir/server-native-http2-preview-tests.txt" 2>&1

cargo test --locked -p fluxheim-server native_proxy \
    >"$out_dir/server-native-http1-proxy-tests.txt" 2>&1

scripts/validate-pingora-dependency-policy.sh check \
    >"$out_dir/pingora-dependency-policy.txt" 2>&1

echo "native runtime cutover evidence: wrote $out_dir"
echo "native runtime cutover evidence: ok"
