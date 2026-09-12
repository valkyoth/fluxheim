#!/usr/bin/env bash
set -euo pipefail

usage() {
    cat >&2 <<'EOF'
usage: scripts/bootstrap_windows_release_builder.sh HOST SSH_KEY [SOURCE_CIDR]

The Windows Server 2025 Desktop Experience host must already accept the SSH
key for Administrator. SOURCE_CIDR defaults to the caller's public IPv4 /32.
EOF
}

HOST="${1:-}"
SSH_KEY="${2:-}"
SOURCE_CIDR="${3:-}"
BUILD_USER="${FLUXHEIM_WINDOWS_BUILD_USER:-fluxheim-build}"
KNOWN_HOSTS="${FLUXHEIM_WINDOWS_KNOWN_HOSTS:-$HOME/.ssh/known_hosts}"
RUST_VERSION="$(sed -n 's/^channel = "\([^"]*\)"/\1/p' rust-toolchain.toml)"

[[ -n "$HOST" ]] || read -r -p 'Windows builder host or IP: ' HOST
[[ -n "$SSH_KEY" ]] || read -r -p 'Administrator SSH private key: ' SSH_KEY
if [[ -z "$HOST" || -z "$SSH_KEY" ]]; then usage; exit 2; fi
case "$HOST" in *[!0-9A-Za-z:._-]*) echo "unsafe Windows host: $HOST" >&2; exit 2;; esac
case "$BUILD_USER" in '' | *[!0-9A-Za-z_.-]*) echo "unsafe Windows build user" >&2; exit 2;; esac
[[ -f "$SSH_KEY" ]] || { echo "SSH private key is missing: $SSH_KEY" >&2; exit 2; }
if [[ -z "$SOURCE_CIDR" ]]; then
    SOURCE_CIDR="$(curl -4 --fail --silent --show-error https://api.ipify.org)/32"
fi
case "$SOURCE_CIDR" in *[!0-9A-Fa-f:./]*) echo "unsafe source CIDR: $SOURCE_CIDR" >&2; exit 2;; esac

for command in curl git scp sed ssh ssh-keygen; do
    command -v "$command" >/dev/null 2>&1 || { echo "missing command: $command" >&2; exit 2; }
done

ROOT="$(git rev-parse --show-toplevel)"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/fluxheim-windows-bootstrap.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT INT TERM

ssh-keygen -y -f "$SSH_KEY" > "$WORK/authorized_key"
SIGNING_KEY="$(git config --get user.signingkey)"
SIGNING_PRINCIPAL="$(git config --get user.email)"
[[ -n "$SIGNING_KEY" && -f "$SIGNING_KEY" ]] || {
    echo 'Git SSH signing public key is not configured or missing' >&2
    exit 2
}
[[ -n "$SIGNING_PRINCIPAL" && "$SIGNING_PRINCIPAL" != *[[:space:]]* ]] || {
    echo 'Git signing principal is unavailable or unsafe' >&2
    exit 2
}
printf '%s %s\n' "$SIGNING_PRINCIPAL" "$(cat "$SIGNING_KEY")" > "$WORK/allowed_signers"

SSH_OPTIONS=(
    -i "$SSH_KEY"
    -o BatchMode=yes
    -o IdentitiesOnly=yes
    -o StrictHostKeyChecking=accept-new
    -o "UserKnownHostsFile=$KNOWN_HOSTS"
)
ADMIN_TARGET="Administrator@$HOST"

echo "--- Verifying native Windows Administrator SSH access ---"
ssh "${SSH_OPTIONS[@]}" "$ADMIN_TARGET" \
    'powershell.exe -NoProfile -NonInteractive -Command "if ([Runtime.InteropServices.RuntimeInformation]::OSArchitecture.ToString() -ne '\''X64'\'') { throw '\''native x86_64 Windows is required'\'' }"'

echo "--- Uploading Fluxheim builder bootstrap ---"
ssh "${SSH_OPTIONS[@]}" "$ADMIN_TARGET" \
    'powershell.exe -NoProfile -NonInteractive -Command "New-Item -ItemType Directory -Force C:\FluxheimBootstrap | Out-Null; & icacls.exe C:\FluxheimBootstrap /setowner '\''Administrators'\'' | Out-Null; if ($LASTEXITCODE -ne 0) { throw '\''failed to set bootstrap directory owner'\'' }; & icacls.exe C:\FluxheimBootstrap /inheritance:r /grant:r '\''SYSTEM:(OI)(CI)F'\'' '\''Administrators:(OI)(CI)F'\'' | Out-Null; if ($LASTEXITCODE -ne 0) { throw '\''failed to secure bootstrap directory'\'' }"'
scp "${SSH_OPTIONS[@]}" \
    "$ROOT/scripts/install_windows_release_builder_tools.ps1" \
    "$ROOT/scripts/prepare_windows_release_builder.ps1" \
    "$ROOT/scripts/windows_release_sshd_config.ps1" \
    "$WORK/authorized_key" \
    "$WORK/allowed_signers" \
    "$ADMIN_TARGET:C:/FluxheimBootstrap/"

echo "--- Installing Windows build tools ---"
ssh "${SSH_OPTIONS[@]}" "$ADMIN_TARGET" \
    "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\\FluxheimBootstrap\\install_windows_release_builder_tools.ps1 -BuildUser $BUILD_USER"

echo "--- Applying the hardened release-builder policy ---"
set +e
ssh "${SSH_OPTIONS[@]}" "$ADMIN_TARGET" \
    "powershell.exe -NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\\FluxheimBootstrap\\prepare_windows_release_builder.ps1 -ExpectedArchitecture X64 -BuildUser $BUILD_USER -AuthorizedKeyFile C:\\FluxheimBootstrap\\authorized_key -AllowedSourceCidr $SOURCE_CIDR -TagAllowedSignersFile C:\\FluxheimBootstrap\\allowed_signers"
PREPARE_STATUS="$?"
set -e
if [[ "$PREPARE_STATUS" -ne 0 ]]; then
    echo 'Administrator SSH ended while sshd was being hardened; verifying the dedicated account.' >&2
fi

BUILD_TARGET="$BUILD_USER@$HOST"
echo "--- Verifying dedicated Windows release account ---"
BUILD_READY=0
for _ in {1..30}; do
    if ssh "${SSH_OPTIONS[@]}" "$BUILD_TARGET" \
        "pwsh.exe -NoProfile -NonInteractive -Command \"\$identity = [Security.Principal.WindowsIdentity]::GetCurrent(); \$principal = [Security.Principal.WindowsPrincipal]::new(\$identity); if (\$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'release build account must not be an administrator' }; \$rustRoot = Join-Path \$env:ProgramData 'FluxheimRust'; \$env:RUSTUP_HOME = Join-Path \$rustRoot 'rustup'; \$env:CARGO_HOME = Join-Path \$rustRoot 'cargo'; \$env:Path = (Join-Path \$env:CARGO_HOME 'bin') + ';' + \$env:Path; rustup.exe toolchain install $RUST_VERSION --profile minimal; if (\$LASTEXITCODE -ne 0) { exit \$LASTEXITCODE }; foreach (\$name in 'git.exe','python.exe','cmake.exe','rustup.exe','rustc.exe','cargo.exe') { if (\$null -eq (Get-Command \$name -ErrorAction SilentlyContinue)) { throw ('missing release command: ' + \$name) } }; Write-Output 'Fluxheim Windows release builder: ready'\""; then
        BUILD_READY=1
        break
    fi
    sleep 2
done

if [[ "$BUILD_READY" -ne 1 ]]; then
    echo 'dedicated Windows release account did not become ready' >&2
    exit 1
fi

echo "--- Verifying Administrator SSH is rejected ---"
if ssh "${SSH_OPTIONS[@]}" -o ConnectTimeout=10 "$ADMIN_TARGET" 'exit 0'; then
    echo 'hardened Windows builder still permits Administrator SSH' >&2
    exit 1
fi

echo 'Fluxheim Windows release builder bootstrap: ok'
