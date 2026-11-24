#!/usr/bin/env sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
test_source="$root/crates/fluxheim-acme/src/acme_directory.rs"
smoke="$root/scripts/smoke_acme_mount_boundary.sh"
ci="$root/.github/workflows/ci.yml"
stable_gate="$root/scripts/stable_release_gate.sh"
deep_gate="$root/scripts/stable_release_deep_gate.sh"
starter="$root/scripts/test_starter.py"

require_text() {
    file=$1
    value=$2
    if ! grep -Fq -- "$value" "$file"; then
        echo "ACME mount-boundary plan missing '$value' in ${file#"$root/"}" >&2
        exit 1
    fi
}

require_text "$test_source" '#[ignore = "requires an isolated privileged mount namespace"]'
require_text "$test_source" 'Some(rustix::io::Errno::XDEV.raw_os_error())'
require_text "$test_source" 'bind-mount traversal must be rejected by RESOLVE_NO_XDEV'
require_text "$smoke" 'unshare --user --map-root-user --mount --propagation private --fork'
require_text "$smoke" '--cap-drop ALL'
require_text "$smoke" '--cap-add SYS_ADMIN'
require_text "$smoke" '--security-opt no-new-privileges'
require_text "$smoke" '--security-opt=apparmor=unconfined'
require_text "$smoke" '--network none'
require_text "$smoke" '--read-only'
require_text "$smoke" '--pids-limit 64'
require_text "$smoke" '--tmpfs /tmp:rw,nosuid,nodev,noexec,size=64m'
require_text "$smoke" '--workdir /tmp'
require_text "$smoke" '--exact "$test_name" --ignored --nocapture'
require_text "$smoke" 'root_broker_refuses_foreign_owner_without_modifying_storage'
# Both tests must run: don't hide the two-UID check inside a backend branch.
if ! awk '/^run_ownership_test$/ { ownership=NR }
         /^if \[ "\$backend" = userns \]; then$/ { dispatch=NR }
         END { exit !(ownership && dispatch > ownership) }' "$smoke"; then
    echo "ACME two-UID check must precede mount backend dispatch" >&2
    exit 1
fi
require_text "$ci" 'scripts/smoke_acme_mount_boundary.sh'
require_text "$ci" 'FLUXHEIM_ACME_MOUNT_TEST_MODE=container'
require_text "$stable_gate" 'scripts/smoke_acme_mount_boundary.sh'
require_text "$deep_gate" 'FLUXHEIM_GATE_ACME_MOUNT_BOUNDARY'
require_text "$starter" '"acme-mount-boundary"'

if grep -Fq -- '--privileged' "$smoke"; then
    echo "ACME mount-boundary plan must not use a privileged container" >&2
    exit 1
fi

echo "ACME mount-boundary plan: ok"
