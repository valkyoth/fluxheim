#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat >&2 <<'EOF'
usage: scripts/smoke_windows_public_profiles.sh HOST SSH_KEY PROXY_ZIP LOAD_BALANCER_ZIP CACHE_ZIP FULL_ZIP PUBLIC_NAME [PUBLIC_ADDRESS]

Runs the packaged Windows proxy, load-balancer, cache, and full profiles on a
prepared native builder. Requests enter over public HTTP/HTTPS while all test
origins and control paths remain loopback-only or SSH-only.
EOF
}

HOST="${1:-}"
SSH_KEY="${2:-}"
PROXY_ARCHIVE="${3:-}"
LOAD_BALANCER_ARCHIVE="${4:-}"
CACHE_ARCHIVE="${5:-}"
FULL_ARCHIVE="${6:-}"
PUBLIC_NAME="${7:-}"
PUBLIC_ADDRESS="${8:-$HOST}"
BUILD_USER="${FLUXHEIM_WINDOWS_BUILD_USER:-fluxheim-build}"
KNOWN_HOSTS="${FLUXHEIM_WINDOWS_KNOWN_HOSTS:-$HOME/.ssh/known_hosts}"
HTTP_PORT="${FLUXHEIM_WINDOWS_PUBLIC_HTTP_PORT:-80}"
HTTPS_PORT="${FLUXHEIM_WINDOWS_PUBLIC_HTTPS_PORT:-443}"

if [[ -z "$HOST" || -z "$SSH_KEY" || -z "$PROXY_ARCHIVE" || \
      -z "$LOAD_BALANCER_ARCHIVE" || -z "$CACHE_ARCHIVE" || \
      -z "$FULL_ARCHIVE" || -z "$PUBLIC_NAME" ]]; then
    usage
    exit 2
fi
case "$HOST" in *[!0-9A-Za-z:._-]*) echo "unsafe Windows host: $HOST" >&2; exit 2;; esac
case "$PUBLIC_ADDRESS" in *[!0-9A-Za-z:._-]*) echo "unsafe public address: $PUBLIC_ADDRESS" >&2; exit 2;; esac
case "$PUBLIC_NAME" in *[!0-9A-Za-z.-]* | .* | *. | *..*) echo "unsafe public DNS name: $PUBLIC_NAME" >&2; exit 2;; esac
case "$BUILD_USER" in '' | *[!0-9A-Za-z_.-]*) echo 'unsafe Windows build user' >&2; exit 2;; esac
case "$HTTP_PORT" in '' | *[!0-9]*) echo 'HTTP port must be numeric' >&2; exit 2;; esac
case "$HTTPS_PORT" in '' | *[!0-9]*) echo 'HTTPS port must be numeric' >&2; exit 2;; esac
if (( HTTP_PORT < 1 || HTTP_PORT > 65535 || HTTPS_PORT < 1 || HTTPS_PORT > 65535 )); then
    echo 'public smoke ports must be between 1 and 65535' >&2
    exit 2
fi
if [[ "$HTTP_PORT" == "$HTTPS_PORT" ]]; then
    echo 'HTTP and HTTPS smoke ports must differ' >&2
    exit 2
fi
[[ -f "$SSH_KEY" ]] || { echo "SSH private key is missing: $SSH_KEY" >&2; exit 2; }

declare -A ARCHIVES=(
    [proxy]="$PROXY_ARCHIVE"
    [load-balancer]="$LOAD_BALANCER_ARCHIVE"
    [cache]="$CACHE_ARCHIVE"
    [full]="$FULL_ARCHIVE"
)
for profile in proxy load-balancer cache full; do
    archive="${ARCHIVES[$profile]}"
    [[ -f "$archive" ]] || { echo "Windows $profile archive is missing: $archive" >&2; exit 2; }
    case "$(basename "$archive")" in
        fluxheim-*-$profile-x86_64-windows.zip) ;;
        *) echo "archive is not a Windows x86_64 Fluxheim $profile ZIP: $archive" >&2; exit 2;;
    esac
done

for command in awk curl grep mktemp od openssl scp ssh tail tr; do
    command -v "$command" >/dev/null 2>&1 || {
        echo "missing command: $command" >&2
        exit 2
    }
done

ROOT="$(git rev-parse --show-toplevel)"
RUN_TOKEN="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
RUN_ID="public-profiles-$RUN_TOKEN"
REMOTE_ROOT="C:/FluxheimBuild/runs/$RUN_ID"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/fluxheim-windows-public-profiles.XXXXXX")"
REMOTE_LOG="$TMP/windows-harness.log"
CA_KEY="$TMP/ca-key.pem"
CA_CERT="$TMP/ca.pem"
SERVER_KEY="$TMP/private-key.pem"
SERVER_CSR="$TMP/server.csr"
SERVER_CERT="$TMP/certificate.pem"
CERT_EXT="$TMP/certificate.ext"
SSH_PID=''
STOP_SENT=0

SSH_OPTIONS=(
    -F /dev/null
    -i "$SSH_KEY"
    -o BatchMode=yes
    -o IdentitiesOnly=yes
    -o StrictHostKeyChecking=yes
    -o "UserKnownHostsFile=$KNOWN_HOSTS"
)
TARGET="$BUILD_USER@$HOST"

cleanup() {
    status="$?"
    if [[ "$STOP_SENT" -eq 0 ]]; then
        ssh "${SSH_OPTIONS[@]}" "$TARGET" \
            "pwsh.exe -NoProfile -NonInteractive -Command \"Set-Content -LiteralPath 'C:\\FluxheimBuild\\runs\\$RUN_ID\\stop' -Value stop -Encoding ascii -ErrorAction SilentlyContinue\"" \
            >/dev/null 2>&1 || true
    fi
    if [[ -n "$SSH_PID" ]]; then
        wait "$SSH_PID" 2>/dev/null || true
    fi
    if [[ "$status" -eq 0 && "${FLUXHEIM_WINDOWS_PUBLIC_SMOKE_KEEP:-0}" != 1 ]]; then
        ssh "${SSH_OPTIONS[@]}" "$TARGET" \
            "pwsh.exe -NoProfile -NonInteractive -Command \"Remove-Item -LiteralPath 'C:\\FluxheimBuild\\runs\\$RUN_ID' -Recurse -Force -ErrorAction SilentlyContinue\"" \
            >/dev/null 2>&1 || true
    elif [[ "$status" -ne 0 ]]; then
        echo "Windows public profile smoke artifacts kept in $REMOTE_ROOT" >&2
        if [[ -f "$REMOTE_LOG" ]]; then cat "$REMOTE_LOG" >&2; fi
    fi
    rm -rf "$TMP"
    exit "$status"
}
trap cleanup EXIT INT TERM

wait_for_marker() {
    marker="$1"
    for _ in {1..300}; do
        if grep -Fq "$marker" "$REMOTE_LOG"; then return 0; fi
        if ! kill -0 "$SSH_PID" 2>/dev/null; then
            wait "$SSH_PID" || true
            SSH_PID=''
            echo "Windows public profile harness exited before $marker" >&2
            return 1
        fi
        sleep 1
    done
    echo "timed out waiting for Windows profile marker: $marker" >&2
    return 1
}

send_control() {
    control="$1"
    ssh "${SSH_OPTIONS[@]}" "$TARGET" \
        "pwsh.exe -NoProfile -NonInteractive -Command \"Set-Content -LiteralPath 'C:\\FluxheimBuild\\runs\\$RUN_ID\\$control' -Value continue -Encoding ascii\""
}

cache_request() {
    suffix="$1"
    headers="$TMP/cache-$suffix.headers"
    body="$TMP/cache-$suffix.body"
    curl --noproxy '*' --fail-with-body --silent --show-error \
        --cacert "$CA_CERT" \
        --resolve "$PUBLIC_NAME:$HTTPS_PORT:$PUBLIC_ADDRESS" \
        --dump-header "$headers" --output "$body" \
        "https://$PUBLIC_NAME:$HTTPS_PORT/cache-object.webp"
    CACHE_BODY="$(<"$body")"
    CACHE_STATUS="$(awk 'tolower($1) == "x-cache-status:" { print $2 }' "$headers" | tr -d '\r' | tail -n 1)"
}

umask 077
openssl req -x509 -newkey rsa:2048 -nodes -sha256 -days 1 \
    -subj '/CN=Fluxheim Windows public profile smoke CA' \
    -keyout "$CA_KEY" -out "$CA_CERT" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -sha256 \
    -subj "/CN=$PUBLIC_NAME" -keyout "$SERVER_KEY" -out "$SERVER_CSR" >/dev/null 2>&1
printf 'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\nsubjectAltName=DNS:%s\n' \
    "$PUBLIC_NAME" >"$CERT_EXT"
openssl x509 -req -sha256 -days 1 -in "$SERVER_CSR" \
    -CA "$CA_CERT" -CAkey "$CA_KEY" -CAcreateserial \
    -extfile "$CERT_EXT" -out "$SERVER_CERT" >/dev/null 2>&1
openssl x509 -in "$SERVER_CERT" -noout -checkhost "$PUBLIC_NAME" >/dev/null

ssh "${SSH_OPTIONS[@]}" "$TARGET" \
    "pwsh.exe -NoProfile -NonInteractive -Command \"New-Item -ItemType Directory -Force -Path 'C:\\FluxheimBuild\\runs\\$RUN_ID\\tls' | Out-Null\""
scp "${SSH_OPTIONS[@]}" "$PROXY_ARCHIVE" "$TARGET:$REMOTE_ROOT/fluxheim-proxy.zip"
scp "${SSH_OPTIONS[@]}" "$LOAD_BALANCER_ARCHIVE" "$TARGET:$REMOTE_ROOT/fluxheim-load-balancer.zip"
scp "${SSH_OPTIONS[@]}" "$CACHE_ARCHIVE" "$TARGET:$REMOTE_ROOT/fluxheim-cache.zip"
scp "${SSH_OPTIONS[@]}" "$FULL_ARCHIVE" "$TARGET:$REMOTE_ROOT/fluxheim-full.zip"
scp "${SSH_OPTIONS[@]}" "$SERVER_CERT" "$TARGET:$REMOTE_ROOT/tls/certificate.pem"
scp "${SSH_OPTIONS[@]}" "$SERVER_KEY" "$TARGET:$REMOTE_ROOT/tls/private-key.pem"
scp "${SSH_OPTIONS[@]}" "$ROOT/scripts/smoke_windows_public_profiles.ps1" \
    "$TARGET:$REMOTE_ROOT/smoke_windows_public_profiles.ps1"

ssh "${SSH_OPTIONS[@]}" "$TARGET" \
    "pwsh.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\\FluxheimBuild\\runs\\$RUN_ID\\smoke_windows_public_profiles.ps1 -RunId $RUN_ID -PublicName $PUBLIC_NAME -HttpPort $HTTP_PORT -HttpsPort $HTTPS_PORT" \
    >"$REMOTE_LOG" 2>&1 &
SSH_PID="$!"

wait_for_marker 'READY proxy'
PROXY_HTTP="$(curl --noproxy '*' --fail-with-body --silent --show-error \
    --resolve "$PUBLIC_NAME:$HTTP_PORT:$PUBLIC_ADDRESS" \
    "http://$PUBLIC_NAME:$HTTP_PORT/public-proxy")"
PROXY_HTTPS="$(curl --noproxy '*' --fail-with-body --silent --show-error \
    --cacert "$CA_CERT" --resolve "$PUBLIC_NAME:$HTTPS_PORT:$PUBLIC_ADDRESS" \
    "https://$PUBLIC_NAME:$HTTPS_PORT/public-proxy-tls")"
[[ "$PROXY_HTTP" == origin-proxy\|path=/public-proxy\|count=* ]] || {
    echo "unexpected public Windows proxy HTTP response: $PROXY_HTTP" >&2; exit 1;
}
[[ "$PROXY_HTTPS" == origin-proxy\|path=/public-proxy-tls\|count=* ]] || {
    echo "unexpected public Windows proxy HTTPS response: $PROXY_HTTPS" >&2; exit 1;
}
UNKNOWN_STATUS="$(curl --noproxy '*' --silent --output /dev/null --write-out '%{http_code}' \
    --resolve "unconfigured.invalid:$HTTP_PORT:$PUBLIC_ADDRESS" \
    "http://unconfigured.invalid:$HTTP_PORT/")"
[[ "$UNKNOWN_STATUS" == 421 ]] || {
    echo "strict Windows host routing returned $UNKNOWN_STATUS, expected 421" >&2; exit 1;
}
send_control next-proxy

wait_for_marker 'READY load-balancer'
LB_ORIGINS=''
for request_index in {1..8}; do
    body="$(curl --noproxy '*' --fail-with-body --silent --show-error \
        --cacert "$CA_CERT" --resolve "$PUBLIC_NAME:$HTTPS_PORT:$PUBLIC_ADDRESS" \
        "https://$PUBLIC_NAME:$HTTPS_PORT/load-balanced/$request_index")"
    case "$body" in
        origin-lb-one\|*) LB_ORIGINS="$LB_ORIGINS one" ;;
        origin-lb-two\|*) LB_ORIGINS="$LB_ORIGINS two" ;;
        *) echo "unexpected load-balancer response: $body" >&2; exit 1;;
    esac
done
[[ "$LB_ORIGINS" == *' one'* && "$LB_ORIGINS" == *' two'* ]] || {
    echo "public Windows load balancer did not reach both origins:$LB_ORIGINS" >&2; exit 1;
}
send_control stop-lb-origin-one
wait_for_marker 'READY load-balancer-failover'
for request_index in {1..4}; do
    body="$(curl --noproxy '*' --fail-with-body --silent --show-error \
        --cacert "$CA_CERT" --resolve "$PUBLIC_NAME:$HTTPS_PORT:$PUBLIC_ADDRESS" \
        "https://$PUBLIC_NAME:$HTTPS_PORT/failover/$request_index")"
    [[ "$body" == origin-lb-two\|* ]] || {
        echo "load-balancer failover reached an unexpected origin: $body" >&2; exit 1;
    }
done
send_control next-load-balancer

wait_for_marker 'READY cache'
cache_request first
FIRST_CACHE_BODY="$CACHE_BODY"
[[ "$CACHE_STATUS" == MISS ]] || {
    echo "first public Windows cache status was $CACHE_STATUS, expected MISS" >&2; exit 1;
}
[[ "$FIRST_CACHE_BODY" == origin-cache\|path=/cache-object.webp\|count=1 ]] || {
    echo "unexpected first public Windows cache body: $FIRST_CACHE_BODY" >&2; exit 1;
}
cache_request second
[[ "$CACHE_STATUS" == HIT && "$CACHE_BODY" == "$FIRST_CACHE_BODY" ]] || {
    echo "second public Windows cache request was not an identical HIT" >&2; exit 1;
}
send_control restart-cache
wait_for_marker 'READY cache-restarted-origin-offline'
cache_request restarted
[[ "$CACHE_STATUS" == HIT && "$CACHE_BODY" == "$FIRST_CACHE_BODY" ]] || {
    echo "restarted Windows cache did not serve the persistent HIT with origin offline" >&2; exit 1;
}
send_control next-cache

wait_for_marker 'READY full'
FULL_HTTP="$(curl --noproxy '*' --fail-with-body --silent --show-error \
    --resolve "$PUBLIC_NAME:$HTTP_PORT:$PUBLIC_ADDRESS" \
    "http://$PUBLIC_NAME:$HTTP_PORT/")"
FULL_HTTPS="$(curl --noproxy '*' --fail-with-body --silent --show-error \
    --cacert "$CA_CERT" --resolve "$PUBLIC_NAME:$HTTPS_PORT:$PUBLIC_ADDRESS" \
    "https://$PUBLIC_NAME:$HTTPS_PORT/")"
[[ "$FULL_HTTP" == 'fluxheim-windows-public-full-ok' && "$FULL_HTTPS" == "$FULL_HTTP" ]] || {
    echo 'packaged Windows full profile static response mismatch' >&2; exit 1;
}

send_control stop
STOP_SENT=1
wait "$SSH_PID"
SSH_PID=''
if ! grep -Fxq 'Windows public packaged-profile harness: ok' "$REMOTE_LOG" \
    && ! grep -Fxq $'Windows public packaged-profile harness: ok\r' "$REMOTE_LOG"; then
    echo 'Windows public profile harness omitted its completion marker' >&2
    exit 1
fi

echo 'Windows public packaged proxy/load-balancer/cache/full profile smoke: ok'
