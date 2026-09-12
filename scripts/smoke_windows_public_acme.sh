#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat >&2 <<'EOF'
usage: scripts/smoke_windows_public_acme.sh HOST SSH_KEY WINDOWS_FULL_ZIP PUBLIC_NAME CONTACT_EMAIL TERMS_URL [PUBLIC_IP]

Runs an isolated Let's Encrypt staging HTTP-01 issuance on a prepared native
Windows builder, then verifies from this machine that the packaged Fluxheim
binary serves the exact installed certificate over public HTTPS.
EOF
}

HOST="${1:-}"
SSH_KEY="${2:-}"
ARCHIVE="${3:-}"
PUBLIC_NAME="${4:-}"
CONTACT_EMAIL="${5:-}"
TERMS_URL="${6:-}"
PUBLIC_IP="${7:-$HOST}"
BUILD_USER="${FLUXHEIM_WINDOWS_BUILD_USER:-fluxheim-build}"
KNOWN_HOSTS="${FLUXHEIM_WINDOWS_KNOWN_HOSTS:-$HOME/.ssh/known_hosts}"
HTTP_PORT="${FLUXHEIM_WINDOWS_PUBLIC_HTTP_PORT:-80}"
HTTPS_PORT="${FLUXHEIM_WINDOWS_PUBLIC_HTTPS_PORT:-443}"

if [[ -z "$HOST" || -z "$SSH_KEY" || -z "$ARCHIVE" || -z "$PUBLIC_NAME" || \
      -z "$CONTACT_EMAIL" || -z "$TERMS_URL" ]]; then
    usage
    exit 2
fi
case "$HOST" in *[!0-9A-Za-z:._-]*) echo "unsafe Windows host: $HOST" >&2; exit 2;; esac
case "$PUBLIC_IP" in *[!0-9A-Fa-f:.]*) echo "public address must be an IP literal: $PUBLIC_IP" >&2; exit 2;; esac
case "$PUBLIC_NAME" in *[!0-9A-Za-z.-]* | .* | *. | *..*) echo "unsafe public DNS name: $PUBLIC_NAME" >&2; exit 2;; esac
if [[ ! "$CONTACT_EMAIL" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$ ]]; then
    echo 'unsafe contact email' >&2
    exit 2
fi
case "$TERMS_URL" in https://*) ;; *) echo 'staging Terms of Service URL must use HTTPS' >&2; exit 2;; esac
case "$TERMS_URL" in *[!0-9A-Za-z:./_-]*) echo 'unsafe staging Terms of Service URL' >&2; exit 2;; esac
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
[[ -f "$ARCHIVE" ]] || { echo "Windows full archive is missing: $ARCHIVE" >&2; exit 2; }
case "$(basename "$ARCHIVE")" in
    fluxheim-*-full-x86_64-windows.zip) ;;
    *) echo 'archive must be a Windows x86_64 Fluxheim full profile ZIP' >&2; exit 2;;
esac

for command in curl grep mktemp od openssl scp ssh tr; do
    command -v "$command" >/dev/null 2>&1 || {
        echo "missing command: $command" >&2
        exit 2
    }
done

ROOT="$(git rev-parse --show-toplevel)"
RUN_TOKEN="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
RUN_ID="public-acme-$RUN_TOKEN"
REMOTE_ROOT="C:/FluxheimBuild/runs/$RUN_ID"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/fluxheim-windows-public-acme.XXXXXX")"
REMOTE_LOG="$TMP/windows-harness.log"
ISSUED_CHAIN="$TMP/issued-fullchain.pem"
PRESENTED_CHAIN="$TMP/presented-chain.pem"
PRESENTED_LEAF="$TMP/presented-leaf.pem"
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
        echo "Windows public ACME smoke artifacts kept in $REMOTE_ROOT" >&2
        if [[ -f "$REMOTE_LOG" ]]; then cat "$REMOTE_LOG" >&2; fi
    fi
    rm -rf "$TMP"
    exit "$status"
}
trap cleanup EXIT INT TERM

ssh "${SSH_OPTIONS[@]}" "$TARGET" \
    "pwsh.exe -NoProfile -NonInteractive -Command \"New-Item -ItemType Directory -Force -Path 'C:\\FluxheimBuild\\runs\\$RUN_ID' | Out-Null\""
scp "${SSH_OPTIONS[@]}" "$ARCHIVE" "$TARGET:$REMOTE_ROOT/fluxheim-full.zip"
scp "${SSH_OPTIONS[@]}" \
    "$ROOT/scripts/smoke_windows_public_acme.ps1" \
    "$TARGET:$REMOTE_ROOT/smoke_windows_public_acme.ps1"

ssh "${SSH_OPTIONS[@]}" "$TARGET" \
    "pwsh.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\\FluxheimBuild\\runs\\$RUN_ID\\smoke_windows_public_acme.ps1 -RunId $RUN_ID -PublicName $PUBLIC_NAME -ContactEmail $CONTACT_EMAIL -TermsOfServiceUrl $TERMS_URL -HttpPort $HTTP_PORT -HttpsPort $HTTPS_PORT" \
    >"$REMOTE_LOG" 2>&1 &
SSH_PID="$!"

for _ in {1..600}; do
    if grep -q '^READY ' "$REMOTE_LOG"; then break; fi
    if ! kill -0 "$SSH_PID" 2>/dev/null; then
        wait "$SSH_PID" || true
        SSH_PID=''
        echo 'Windows public ACME harness exited before readiness' >&2
        exit 1
    fi
    sleep 1
done
if ! grep -q '^READY ' "$REMOTE_LOG"; then
    echo 'timed out waiting for Windows ACME staging issuance' >&2
    exit 1
fi

scp "${SSH_OPTIONS[@]}" "$TARGET:$REMOTE_ROOT/issued-fullchain.pem" "$ISSUED_CHAIN"
curl --noproxy '*' --fail-with-body --silent --show-error \
    --resolve "$PUBLIC_NAME:$HTTP_PORT:$PUBLIC_IP" \
    "http://$PUBLIC_NAME:$HTTP_PORT/" | grep -qx 'fluxheim-windows-public-acme-ok'
curl --noproxy '*' --insecure --fail-with-body --silent --show-error \
    --resolve "$PUBLIC_NAME:$HTTPS_PORT:$PUBLIC_IP" \
    "https://$PUBLIC_NAME:$HTTPS_PORT/" | grep -qx 'fluxheim-windows-public-acme-ok'

openssl s_client -connect "$PUBLIC_IP:$HTTPS_PORT" -servername "$PUBLIC_NAME" \
    -showcerts </dev/null >"$PRESENTED_CHAIN" 2>"$TMP/openssl.stderr"
sed -n '/-----BEGIN CERTIFICATE-----/,/-----END CERTIFICATE-----/p' \
    "$PRESENTED_CHAIN" | sed -n '1,/-----END CERTIFICATE-----/p' >"$PRESENTED_LEAF"
openssl x509 -in "$PRESENTED_LEAF" -noout -checkhost "$PUBLIC_NAME" >/dev/null
ISSUED_FINGERPRINT="$(openssl x509 -in "$ISSUED_CHAIN" -noout -fingerprint -sha256)"
PRESENTED_FINGERPRINT="$(openssl x509 -in "$PRESENTED_LEAF" -noout -fingerprint -sha256)"
if [[ "$ISSUED_FINGERPRINT" != "$PRESENTED_FINGERPRINT" ]]; then
    echo 'public Windows TLS listener did not serve the certificate installed by ACME' >&2
    exit 1
fi

ssh "${SSH_OPTIONS[@]}" "$TARGET" \
    "pwsh.exe -NoProfile -NonInteractive -Command \"Set-Content -LiteralPath 'C:\\FluxheimBuild\\runs\\$RUN_ID\\stop' -Value stop -Encoding ascii\""
STOP_SENT=1
wait "$SSH_PID"
SSH_PID=''
if ! grep -Fxq 'Windows public ACME staging harness: ok' "$REMOTE_LOG" \
    && ! grep -Fxq $'Windows public ACME staging harness: ok\r' "$REMOTE_LOG"; then
    echo 'Windows public ACME harness omitted its completion marker' >&2
    exit 1
fi

echo "Windows public Let's Encrypt staging ACME HTTP-01 smoke: ok"
