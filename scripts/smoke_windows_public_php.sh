#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat >&2 <<'EOF'
usage: scripts/smoke_windows_public_php.sh HOST SSH_KEY WINDOWS_PHP_ZIP PUBLIC_NAME [PUBLIC_ADDRESS]

Runs a checksum-pinned real-PHP FastCGI harness on a prepared Windows release
builder, then verifies the packaged Fluxheim PHP profile over public HTTP and
HTTPS from this machine. The cloud firewall and Windows Firewall must permit
the selected ports from this machine.
EOF
}

HOST="${1:-}"
SSH_KEY="${2:-}"
ARCHIVE="${3:-}"
PUBLIC_NAME="${4:-}"
PUBLIC_ADDRESS="${5:-$HOST}"
BUILD_USER="${FLUXHEIM_WINDOWS_BUILD_USER:-fluxheim-build}"
KNOWN_HOSTS="${FLUXHEIM_WINDOWS_KNOWN_HOSTS:-$HOME/.ssh/known_hosts}"
HTTP_PORT="${FLUXHEIM_WINDOWS_PUBLIC_HTTP_PORT:-80}"
HTTPS_PORT="${FLUXHEIM_WINDOWS_PUBLIC_HTTPS_PORT:-443}"

if [[ -z "$HOST" || -z "$SSH_KEY" || -z "$ARCHIVE" || -z "$PUBLIC_NAME" ]]; then
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
[[ -f "$ARCHIVE" ]] || { echo "Windows PHP archive is missing: $ARCHIVE" >&2; exit 2; }
case "$(basename "$ARCHIVE")" in
    fluxheim-*-php-x86_64-windows.zip) ;;
    *) echo 'archive must be a Windows x86_64 Fluxheim PHP profile ZIP' >&2; exit 2;;
esac

for command in curl grep mktemp scp ssh; do
    command -v "$command" >/dev/null 2>&1 || {
        echo "missing command: $command" >&2
        exit 2
    }
done

ROOT="$(git rev-parse --show-toplevel)"
RUN_TOKEN="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
RUN_ID="public-php-$RUN_TOKEN"
REMOTE_ROOT="C:/FluxheimBuild/runs/$RUN_ID"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/fluxheim-windows-public-php.XXXXXX")"
REMOTE_LOG="$TMP/windows-harness.log"
CA_FILE="$TMP/ca.pem"
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
        echo "Windows public PHP smoke artifacts kept in $REMOTE_ROOT" >&2
        if [[ -f "$REMOTE_LOG" ]]; then
            cat "$REMOTE_LOG" >&2
        fi
    fi
    rm -rf "$TMP"
    exit "$status"
}
trap cleanup EXIT INT TERM

ssh "${SSH_OPTIONS[@]}" "$TARGET" \
    "pwsh.exe -NoProfile -NonInteractive -Command \"New-Item -ItemType Directory -Force -Path 'C:\\FluxheimBuild\\runs\\$RUN_ID' | Out-Null\""
scp "${SSH_OPTIONS[@]}" \
    "$ARCHIVE" "$TARGET:$REMOTE_ROOT/fluxheim-php.zip"
scp "${SSH_OPTIONS[@]}" \
    "$ROOT/scripts/smoke_windows_public_php.ps1" \
    "$TARGET:$REMOTE_ROOT/smoke_windows_public_php.ps1"

ssh "${SSH_OPTIONS[@]}" "$TARGET" \
    "pwsh.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\\FluxheimBuild\\runs\\$RUN_ID\\smoke_windows_public_php.ps1 -RunId $RUN_ID -HttpPort $HTTP_PORT -HttpsPort $HTTPS_PORT -PublicName $PUBLIC_NAME" \
    >"$REMOTE_LOG" 2>&1 &
SSH_PID="$!"

for _ in {1..180}; do
    if grep -q '^READY ' "$REMOTE_LOG"; then
        break
    fi
    if ! kill -0 "$SSH_PID" 2>/dev/null; then
        wait "$SSH_PID" || true
        SSH_PID=''
        echo 'Windows public PHP harness exited before readiness' >&2
        exit 1
    fi
    sleep 1
done
if ! grep -q '^READY ' "$REMOTE_LOG"; then
    echo 'timed out waiting for the Windows public PHP harness' >&2
    exit 1
fi

scp "${SSH_OPTIONS[@]}" "$TARGET:$REMOTE_ROOT/ca.pem" "$CA_FILE"

EXPECTED_HTTP='fluxheim-windows-public-php-ok|scheme=http|https=off|method=GET|body='
EXPECTED_HTTPS='fluxheim-windows-public-php-ok|scheme=https|https=on|method=POST|body=windows-fastcgi-post'
HTTP_BODY="$(curl --noproxy '*' --fail-with-body --silent --show-error \
    --resolve "$PUBLIC_NAME:$HTTP_PORT:$PUBLIC_ADDRESS" \
    "http://$PUBLIC_NAME:$HTTP_PORT/index.php")"
if [[ "$HTTP_BODY" != "$EXPECTED_HTTP" ]]; then
    echo "unexpected public Windows HTTP/PHP response: $HTTP_BODY" >&2
    exit 1
fi
HTTPS_BODY="$(curl --noproxy '*' --fail-with-body --silent --show-error \
    --cacert "$CA_FILE" \
    --resolve "$PUBLIC_NAME:$HTTPS_PORT:$PUBLIC_ADDRESS" \
    --data-binary 'windows-fastcgi-post' \
    "https://$PUBLIC_NAME:$HTTPS_PORT/index.php")"
if [[ "$HTTPS_BODY" != "$EXPECTED_HTTPS" ]]; then
    echo "unexpected public Windows HTTPS/PHP response: $HTTPS_BODY" >&2
    exit 1
fi

ssh "${SSH_OPTIONS[@]}" "$TARGET" \
    "pwsh.exe -NoProfile -NonInteractive -Command \"Set-Content -LiteralPath 'C:\\FluxheimBuild\\runs\\$RUN_ID\\stop' -Value stop -Encoding ascii\""
STOP_SENT=1
wait "$SSH_PID"
SSH_PID=''
if ! grep -Fxq 'Windows public PHP harness: ok' "$REMOTE_LOG" \
    && ! grep -Fxq $'Windows public PHP harness: ok\r' "$REMOTE_LOG"; then
    echo 'Windows public PHP harness omitted its completion marker' >&2
    exit 1
fi

echo 'Windows public HTTP/HTTPS real-PHP FastCGI smoke: ok'
