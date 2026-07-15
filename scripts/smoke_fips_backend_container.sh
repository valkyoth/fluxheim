#!/usr/bin/env sh
set -eu

evidence_root="/opt/fluxheim-evidence"
run_root="$evidence_root/run"
ca_certificate="$evidence_root/tls/ca.pem"
certificate="$evidence_root/tls/server-cert.pem"
private_key="$evidence_root/tls/server-key.pem"
config="$run_root/fluxheim.toml"
invalid_config="$run_root/non-fips.toml"
origin_log="$run_root/origin.log"
fluxheim_log="$run_root/fluxheim.log"
client_log="$run_root/client.log"
response_file="$run_root/response.txt"

case "${FLUXHEIM_FIPS_BACKEND:-}" in
    openssl)
        profile="fips-openssl"
        provider_marker="openssl_fips_provider: available"
        dependency_marker="openssl v"
        ;;
    rustls)
        profile="fips-rustls"
        provider_marker="rustls_fips_provider: available"
        dependency_marker="aws-lc-fips-sys v"
        ;;
    *)
        echo "fips image smoke: unsupported backend" >&2
        exit 2
        ;;
esac

origin_pid=""
fluxheim_pid=""
cleanup() {
    if [ -n "$fluxheim_pid" ]; then
        kill "$fluxheim_pid" 2>/dev/null || true
        wait "$fluxheim_pid" 2>/dev/null || true
    fi
    if [ -n "$origin_pid" ]; then
        kill "$origin_pid" 2>/dev/null || true
        wait "$origin_pid" 2>/dev/null || true
    fi
}
trap cleanup EXIT HUP INT TERM

fail() {
    echo "fips image smoke: $1" >&2
    if [ -s "$fluxheim_log" ]; then
        echo "--- fluxheim log ---" >&2
        cat "$fluxheim_log" >&2
    fi
    if [ -s "$origin_log" ]; then
        echo "--- origin log ---" >&2
        cat "$origin_log" >&2
    fi
    if [ -s "$client_log" ]; then
        echo "--- client log ---" >&2
        cat "$client_log" >&2
    fi
    if [ -s "$response_file" ]; then
        echo "--- downstream response ---" >&2
        cat "$response_file" >&2
    fi
    exit 1
}

umask 077
rm -f "$run_root"/*

expected_fluxheim_hash="$(sed -n 's/  target\/release\/fluxheim$//p' "$evidence_root/build/binaries.sha256")"
expected_tester_hash="$(sed -n 's/  target\/release\/fluxheim-config-tester$//p' "$evidence_root/build/binaries.sha256")"
actual_fluxheim_hash="$(sha256sum /usr/local/bin/fluxheim | sed 's/ .*//')"
actual_tester_hash="$(sha256sum /usr/local/bin/fluxheim-config-tester | sed 's/ .*//')"
[ -n "$expected_fluxheim_hash" ] || fail "missing recorded Fluxheim binary hash"
[ -n "$expected_tester_hash" ] || fail "missing recorded config-tester binary hash"
[ "$actual_fluxheim_hash" = "$expected_fluxheim_hash" ] \
    || fail "running Fluxheim binary does not match build evidence"
[ "$actual_tester_hash" = "$expected_tester_hash" ] \
    || fail "running config tester does not match build evidence"

grep -F "$dependency_marker" "$evidence_root/build/cargo-tree.txt" >/dev/null \
    || fail "expected provider dependency is absent from Cargo evidence"

crypto_output="$(/usr/local/bin/fluxheim crypto)"
printf '%s\n' "$crypto_output"
printf '%s\n' "$crypto_output" | grep -F "$provider_marker" >/dev/null \
    || fail "compiled provider is not available"

if [ "$FLUXHEIM_FIPS_BACKEND" = "openssl" ]; then
    openssl list -providers -provider fips -provider base > "$run_root/providers.txt" \
        || fail "OpenSSL FIPS provider cannot be loaded"
    ldd /usr/local/bin/fluxheim > "$run_root/ldd.txt"
    grep -F 'libssl.so' "$run_root/ldd.txt" >/dev/null \
        || fail "OpenSSL evidence binary is not dynamically linked to libssl"
else
    ldd /usr/local/bin/fluxheim > "$run_root/ldd.txt"
    if grep -E 'libssl\.so|libcrypto\.so' "$run_root/ldd.txt" >/dev/null; then
        fail "rustls/AWS-LC evidence binary unexpectedly links to OpenSSL"
    fi
fi

cat > "$invalid_config" <<EOF
[server]
listen = ["127.0.0.1:9080"]

[tls]
enabled = true
backend = "$FLUXHEIM_FIPS_BACKEND"
curve_preferences = ["X25519", "CurveP256"]
cipher_suites = ["TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"]

[tls.fips]
required = true
EOF

if /usr/local/bin/fluxheim-config-tester \
    --config "$invalid_config" \
    --profile "$profile" \
    --no-runtime-paths >/dev/null 2>&1
then
    fail "non-FIPS TLS policy unexpectedly passed validation"
fi

cat > "$config" <<EOF
[server]
listen = []
tls_listen = ["127.0.0.1:9443"]
default_vhost = "fips.test"

[server.process]
threads = 1
listener_tasks_per_fd = 1
pid_file = "$run_root/fluxheim.pid"
upgrade_sock = "$run_root/upgrade.sock"
certificate_reload_sock = "$run_root/certificate-reload.sock"

[tls]
enabled = true
backend = "$FLUXHEIM_FIPS_BACKEND"
profile = "intermediate"
min_protocol = "tls1.2"
alpn = "http1"
curve_preferences = ["CurveP256", "CurveP384"]
cipher_suites = [
  "TLS_AES_256_GCM_SHA384",
  "TLS_AES_128_GCM_SHA256",
  "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
]

[tls.fips]
required = true

[[tls.certificates]]
cert_path = "$certificate"
key_path = "$private_key"

[[vhosts]]
name = "fips.test"
hosts = ["fips.test"]

[vhosts.tls]
enabled = true

[vhosts.tls.certificate]
cert_path = "$certificate"
key_path = "$private_key"

[vhosts.proxy]
upstreams = ["127.0.0.1:9444"]
upstream_tls = true
upstream_sni = "localhost"
upstream_verify_cert = true
upstream_verify_hostname = true
upstream_ca_path = "$ca_certificate"
upstream_http_version = "http1"
EOF

/usr/local/bin/fluxheim-config-tester \
    --config "$config" \
    --profile "$profile" \
    --crypto >/dev/null \
    || fail "live FIPS fixture failed config validation"

openssl s_server \
    -accept 127.0.0.1:9444 \
    -cert "$certificate" \
    -key "$private_key" \
    -www \
    -tls1_2 > "$origin_log" 2>&1 &
origin_pid="$!"

origin_ready=0
attempt=0
while [ "$attempt" -lt 50 ]; do
    if printf '\n' | openssl s_client \
        -connect 127.0.0.1:9444 \
        -CAfile "$ca_certificate" \
        -verify_hostname localhost \
        -verify_return_error \
        -brief >/dev/null 2>&1
    then
        origin_ready=1
        break
    fi
    attempt=$((attempt + 1))
    sleep 0.1
done
[ "$origin_ready" = "1" ] || fail "TLS origin did not become ready"

/usr/local/bin/fluxheim --config "$config" > "$fluxheim_log" 2>&1 &
fluxheim_pid="$!"

proxy_ready=0
attempt=0
while [ "$attempt" -lt 100 ]; do
    printf 'GET / HTTP/1.1\r\nHost: fips.test\r\nConnection: close\r\n\r\n' \
        | openssl s_client \
            -connect 127.0.0.1:9443 \
            -servername fips.test \
            -CAfile "$ca_certificate" \
            -verify_hostname fips.test \
            -verify_return_error \
            -quiet > "$response_file" 2> "$client_log" || true
    if grep -E '^HTTP/1\.[01] 200 ' "$response_file" >/dev/null \
        && grep -F 's_server' "$response_file" >/dev/null
    then
        proxy_ready=1
        break
    fi
    if ! kill -0 "$fluxheim_pid" 2>/dev/null; then
        fail "Fluxheim exited during live TLS validation"
    fi
    attempt=$((attempt + 1))
    sleep 0.1
done

[ "$proxy_ready" = "1" ] \
    || fail "downstream TLS request did not traverse the verified TLS origin"

echo "fips image smoke: $FLUXHEIM_FIPS_BACKEND provider, downstream TLS, and upstream TLS passed"
