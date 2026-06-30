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
    echo "compiled and tested, and that the Pingora dependency policy remains"
    echo "empty for normal production profiles."
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

FLUXHEIM_PINGORA_POLICY_DIR="$out_dir/pingora-dependency-policy" \
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
printf '# no expected blockers for the representative native-runtime config\n' >"$expected_blockers"

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
    /^native-runtime-plan-adapter:/ || /^native-runtime-target-adapter:/ { next }
    /^config tester: ok$/ { next }
    $1 == "native-http1-proxy-candidate" {
        if (NF != 4) {
            print "native runtime cutover evidence: malformed native-http1-proxy-candidate row: " $0 > "/dev/stderr"
            exit 2
        }
        next
    }
    $1 == "native-runtime-manifest-service" || $1 == "native-runtime-manifest-background-task" {
        if (NF != 4) {
            print "native runtime cutover evidence: malformed native runtime manifest row: " $0 > "/dev/stderr"
            exit 2
        }
        next
    }
    $1 == "native-runtime-launch-plan" {
        if (NF != 6) {
            print "native runtime cutover evidence: malformed native runtime launch-plan row: " $0 > "/dev/stderr"
            exit 2
        }
        next
    }
    $1 == "native-runtime-launch-plan-error" {
        if (NF != 3) {
            print "native runtime cutover evidence: malformed native runtime launch-plan error row: " $0 > "/dev/stderr"
            exit 2
        }
        next
    }
    $1 == "native-runtime-launch-policy" {
        if (NF != 4) {
            print "native runtime cutover evidence: malformed native runtime launch-policy row: " $0 > "/dev/stderr"
            exit 2
        }
        next
    }
    $1 == "native-runtime-launch-service-policy" {
        if (NF != 4) {
            print "native runtime cutover evidence: malformed native runtime launch-service-policy row: " $0 > "/dev/stderr"
            exit 2
        }
        next
    }
    $1 == "native-runtime-launch-listener" {
        if (NF != 6) {
            print "native runtime cutover evidence: malformed native runtime launch-listener row: " $0 > "/dev/stderr"
            exit 2
        }
        next
    }
    $1 == "native-runtime-launch-background-task" {
        if (NF != 4) {
            print "native runtime cutover evidence: malformed native runtime launch-background-task row: " $0 > "/dev/stderr"
            exit 2
        }
        next
    }
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
        if ($0 ~ /^[[:space:]]*#/ || NF == 0) {
            next
        }
        if (NF != 3) {
            print "native runtime cutover evidence: malformed expected row: " $0 > "/dev/stderr"
            exit 2
        }
        expected[$1] = $2 "\t" $3
        next
    }
    /^native-runtime-plan-adapter:/ || /^native-runtime-target-adapter:/ { next }
    /^config tester: ok$/ { next }
    $1 == "native-http1-proxy-candidate" {
        if (NF != 4) {
            print "native runtime cutover evidence: malformed native-http1-proxy-candidate row: " $0 > "/dev/stderr"
            exit 2
        }
        next
    }
    $1 == "native-runtime-manifest-service" || $1 == "native-runtime-manifest-background-task" {
        if (NF != 4) {
            print "native runtime cutover evidence: malformed native runtime manifest row: " $0 > "/dev/stderr"
            exit 2
        }
        next
    }
    $1 == "native-runtime-launch-plan" {
        if (NF != 6) {
            print "native runtime cutover evidence: malformed native runtime launch-plan row: " $0 > "/dev/stderr"
            exit 2
        }
        next
    }
    $1 == "native-runtime-launch-plan-error" {
        if (NF != 3) {
            print "native runtime cutover evidence: malformed native runtime launch-plan error row: " $0 > "/dev/stderr"
            exit 2
        }
        next
    }
    $1 == "native-runtime-launch-policy" {
        if (NF != 4) {
            print "native runtime cutover evidence: malformed native runtime launch-policy row: " $0 > "/dev/stderr"
            exit 2
        }
        next
    }
    $1 == "native-runtime-launch-service-policy" {
        if (NF != 4) {
            print "native runtime cutover evidence: malformed native runtime launch-service-policy row: " $0 > "/dev/stderr"
            exit 2
        }
        next
    }
    $1 == "native-runtime-launch-listener" {
        if (NF != 6) {
            print "native runtime cutover evidence: malformed native runtime launch-listener row: " $0 > "/dev/stderr"
            exit 2
        }
        next
    }
    $1 == "native-runtime-launch-background-task" {
        if (NF != 4) {
            print "native runtime cutover evidence: malformed native runtime launch-background-task row: " $0 > "/dev/stderr"
            exit 2
        }
        next
    }
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

target_adapter="$(sed -n 's/^native-runtime-target-adapter: //p' "$out_dir/representative-runtime-cutover.tsv")"
if [ "$target_adapter" != "NativeRuntime" ]; then
    echo "native runtime cutover evidence: representative config targets $target_adapter instead of NativeRuntime" >&2
    exit 1
fi

launch_status="$(awk -F '\t' '$1 == "native-runtime-launch-plan" && $2 != "status" { print $2; exit }' "$out_dir/representative-runtime-cutover.tsv")"
if [ "$launch_status" != "ready" ]; then
    echo "native runtime cutover evidence: representative launch plan status is $launch_status instead of ready" >&2
    exit 1
fi

if grep -q '^native-runtime-launch-plan-error	' "$out_dir/representative-runtime-cutover.tsv"; then
    echo "native runtime cutover evidence: representative config emitted a launch-plan error" >&2
    exit 1
fi

awk -F '\t' '
    /^native-runtime-plan-adapter:/ || /^native-runtime-target-adapter:/ { next }
    /^config tester: ok$/ { next }
    $1 == "native-http1-proxy-candidate" {
        if (NF != 4) {
            print "native runtime cutover evidence: malformed native-http1-proxy-candidate row: " $0 > "/dev/stderr"
            exit 2
        }
        next
    }
    $1 == "native-runtime-manifest-service" || $1 == "native-runtime-manifest-background-task" {
        if (NF != 4) {
            print "native runtime cutover evidence: malformed native runtime manifest row: " $0 > "/dev/stderr"
            exit 2
        }
        next
    }
    $1 == "native-runtime-launch-plan" {
        if (NF != 6) {
            print "native runtime cutover evidence: malformed native runtime launch-plan row: " $0 > "/dev/stderr"
            exit 2
        }
        next
    }
    $1 == "native-runtime-launch-plan-error" {
        if (NF != 3) {
            print "native runtime cutover evidence: malformed native runtime launch-plan error row: " $0 > "/dev/stderr"
            exit 2
        }
        next
    }
    $1 == "native-runtime-launch-policy" {
        if (NF != 4) {
            print "native runtime cutover evidence: malformed native runtime launch-policy row: " $0 > "/dev/stderr"
            exit 2
        }
        next
    }
    $1 == "native-runtime-launch-service-policy" {
        if (NF != 4) {
            print "native runtime cutover evidence: malformed native runtime launch-service-policy row: " $0 > "/dev/stderr"
            exit 2
        }
        next
    }
    $1 == "native-runtime-launch-listener" {
        if (NF != 6) {
            print "native runtime cutover evidence: malformed native runtime launch-listener row: " $0 > "/dev/stderr"
            exit 2
        }
        next
    }
    $1 == "native-runtime-launch-background-task" {
        if (NF != 4) {
            print "native runtime cutover evidence: malformed native runtime launch-background-task row: " $0 > "/dev/stderr"
            exit 2
        }
        next
    }
    $1 == "blocker" { next }
    NF == 0 { next }
    NF != 3 {
        print "native runtime cutover evidence: malformed report row: " $0 > "/dev/stderr"
        exit 2
    }
    {
        unexpected_blocker_count++
    }
    END {
        if (unexpected_blocker_count > 0) {
            print "native runtime cutover evidence: expected zero representative blockers but found " unexpected_blocker_count > "/dev/stderr"
            exit 1
        }
    }
' "$out_dir/representative-runtime-cutover.tsv" \
    >"$out_dir/representative-runtime-cutover-zero-blockers-check.txt"

echo "native runtime cutover evidence: wrote $out_dir"
echo "native runtime cutover evidence: ok"
