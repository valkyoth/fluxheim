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
require_text "$smoke" 'unshare --user --map-root-user --mount --propagation private --fork'
require_text "$smoke" '--exact "$test_name" --ignored --nocapture'
require_text "$ci" 'scripts/smoke_acme_mount_boundary.sh'
require_text "$stable_gate" 'scripts/smoke_acme_mount_boundary.sh'
require_text "$deep_gate" 'FLUXHEIM_GATE_ACME_MOUNT_BOUNDARY'
require_text "$starter" '"acme-mount-boundary"'

if grep -Fq -- '--privileged' "$smoke"; then
    echo "ACME mount-boundary plan must not use a privileged container" >&2
    exit 1
fi

echo "ACME mount-boundary plan: ok"
