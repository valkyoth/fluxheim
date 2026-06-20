#!/usr/bin/env sh
set -eu

out_dir="${FLUXHEIM_NATIVE_RUNTIME_CUTOVER_DIR:-target/release-evidence/native-runtime-cutover}"
targets="docs/native-runtime-cutover-targets.tsv"
mkdir -p "$out_dir"

if [ ! -f "$targets" ]; then
    echo "native runtime cutover evidence: missing $targets" >&2
    exit 1
fi

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

snapshot_store="$(pwd)/$out_dir/snapshots"
case "$snapshot_store" in
    *\"*|*\\*|*'`'*|*'$'*|*'
'*)
        echo "native runtime cutover evidence: unsafe snapshot_store path" >&2
        exit 1
        ;;
esac
mkdir -p "$snapshot_store"

sample_config="$out_dir/representative-runtime-cutover.toml"
cat >"$sample_config" <<CONFIG
[server]
listen = ["127.0.0.1:18080"]

[admin]
enabled = true
listen = "127.0.0.1:19090"
token_env = "FLUXHEIM_ADMIN_TOKEN"
snapshot_store = "$snapshot_store"

[metrics]
enabled = true
listen = "127.0.0.1:19091"

[proxy]
upstreams = ["127.0.0.1:13000"]
upstream_tls = false

[stream]
enabled = true

[[stream.routes]]
name = "cutover-stream"
listen = ["127.0.0.1:15432"]
upstreams = ["127.0.0.1:5432"]
upstream_tls = false

[udp]
enabled = true

[[udp.routes]]
name = "cutover-udp"
listen = ["127.0.0.1:15353"]
upstream = "127.0.0.1:5353"
CONFIG

cargo test --locked -p fluxheim-server native_runtime_cutover_summary \
    >"$out_dir/server-native-runtime-cutover-tests.txt" 2>&1

cargo test --locked -p fluxheim-server native_http2_preview \
    >"$out_dir/server-native-http2-preview-tests.txt" 2>&1

cargo test --locked -p fluxheim-server native_proxy \
    >"$out_dir/server-native-http1-proxy-tests.txt" 2>&1

scripts/validate-pingora-dependency-policy.sh check \
    >"$out_dir/pingora-dependency-policy.txt" 2>&1

cargo run --quiet --locked --no-default-features --features profile-full,udp-proxy \
    --bin fluxheim-config-tester -- \
    --config "$sample_config" \
    --profile full \
    --no-runtime-paths \
    --runtime-cutover \
    >"$out_dir/representative-runtime-cutover.tsv" 2>&1

expected_blockers="$out_dir/representative-runtime-cutover-expected.tsv"
awk -F '\t' '
    BEGIN {
        expected["native-http2"] = 1
    }
    $0 ~ /^[[:space:]]*#/ || NF == 0 { next }
    $1 in expected { print }
' "$targets" >"$expected_blockers"

awk -F '\t' '
    FNR == NR {
        if ($0 ~ /^[[:space:]]*#/ || NF == 0) {
            next
        }
        if (NF != 3) {
            print "native runtime cutover evidence: malformed target row: " $0 > "/dev/stderr"
            exit 2
        }
        target[$1] = $2 "\t" $3
        next
    }
    /^native-runtime-adapter:/ { next }
    /^config tester: ok$/ { next }
    $1 == "blocker" { next }
    NF == 0 { next }
    NF != 3 {
        print "native runtime cutover evidence: malformed report row: " $0 > "/dev/stderr"
        exit 2
    }
    !($1 in target) {
        print "native runtime cutover evidence: unknown blocker " $1 > "/dev/stderr"
        exit 1
    }
    target[$1] != ($2 "\t" $3) {
        print "native runtime cutover evidence: target drift for " $1 > "/dev/stderr"
        print "  expected: " target[$1] > "/dev/stderr"
        print "  actual:   " $2 "\t" $3 > "/dev/stderr"
        exit 1
    }
' "$targets" "$out_dir/representative-runtime-cutover.tsv" \
    >"$out_dir/representative-runtime-cutover-target-check.txt"

awk -F '\t' '
    FNR == NR {
        if (NF != 3) {
            print "native runtime cutover evidence: malformed expected row: " $0 > "/dev/stderr"
            exit 2
        }
        expected[$1] = $2 "\t" $3
        next
    }
    /^native-runtime-adapter:/ { next }
    /^config tester: ok$/ { next }
    $1 == "blocker" { next }
    NF == 0 { next }
    NF != 3 {
        print "native runtime cutover evidence: malformed report row: " $0 > "/dev/stderr"
        exit 2
    }
    {
        seen[$1] = $2 "\t" $3
    }
    END {
        for (key in expected) {
            if (!(key in seen)) {
                print "native runtime cutover evidence: expected blocker missing from report: " key > "/dev/stderr"
                exit 1
            }
            if (seen[key] != expected[key]) {
                print "native runtime cutover evidence: expected blocker drift for " key > "/dev/stderr"
                print "  expected: " expected[key] > "/dev/stderr"
                print "  actual:   " seen[key] > "/dev/stderr"
                exit 1
            }
        }
    }
' "$expected_blockers" "$out_dir/representative-runtime-cutover.tsv" \
    >"$out_dir/representative-runtime-cutover-expected-check.txt"

echo "native runtime cutover evidence: wrote $out_dir"
echo "native runtime cutover evidence: ok"
