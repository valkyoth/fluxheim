#!/usr/bin/env sh
set -eu

root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
openssl_container="$root/containers/fips/Containerfile.openssl"
rustls_container="$root/containers/fips/Containerfile.rustls"
container_smoke="$root/scripts/smoke_fips_backend_container.sh"
certificate_generator="$root/scripts/generate_fips_evidence_tls.sh"
host_smoke="$root/scripts/smoke_fips_backend_images.sh"
workflow="$root/.github/workflows/fips-evidence.yml"
stable_gate="$root/scripts/stable_release_gate.sh"
deep_gate="$root/scripts/stable_release_deep_gate.sh"

require_text() {
    file=$1
    value=$2
    if ! grep -Fq -- "$value" "$file"; then
        echo "FIPS image evidence plan missing '$value' in ${file#"$root/"}" >&2
        exit 1
    fi
}

for container in "$openssl_container" "$rustls_container"; do
    require_text "$container" 'ubi-minimal:9.6@sha256:'
    require_text "$container" 'rustup/archive/1.28.2/'
    require_text "$container" 'RUST_TOOLCHAIN=1.97.0'
    require_text "$container" 'binaries.sha256'
    require_text "$container" 'cargo-tree.txt'
    require_text "$container" 'USER 65532:65532'
done

require_text "$openssl_container" '--features profile-fips-openssl'
require_text "$openssl_container" 'openssl list -providers -provider fips -provider base'
require_text "$rustls_container" '--features profile-fips-rustls'
require_text "$rustls_container" 'aws-lc-fips-sys'

require_text "$container_smoke" 'running Fluxheim binary does not match build evidence'
require_text "$container_smoke" 'non-FIPS TLS policy unexpectedly passed validation'
require_text "$container_smoke" 'upstream_verify_cert = true'
require_text "$container_smoke" 'upstream_verify_hostname = true'
require_text "$container_smoke" '-verify_hostname localhost'
require_text "$container_smoke" '-verify_hostname fips.test'
require_text "$container_smoke" 'downstream TLS request did not traverse the verified TLS origin'
require_text "$certificate_generator" 'subjectAltName=DNS:fips.test,DNS:localhost,IP:127.0.0.1'
require_text "$certificate_generator" '-verify_hostname localhost'
require_text "$certificate_generator" '-verify_hostname fips.test'
require_text "$certificate_generator" 'rm -f "$ca_key"'
require_text "$host_smoke" 'containers/fips/Containerfile.openssl'
require_text "$host_smoke" 'containers/fips/Containerfile.rustls'
require_text "$workflow" 'workflow_dispatch:'
require_text "$workflow" 'scripts/smoke_fips_backend_images.sh'
require_text "$stable_gate" 'FLUXHEIM_GATE_FIPS_IMAGES'
require_text "$deep_gate" 'FLUXHEIM_GATE_FIPS_IMAGES="${FLUXHEIM_GATE_FIPS_IMAGES:-1}"'

if grep -Fq -- '--privileged' "$container_smoke" "$host_smoke"; then
    echo "FIPS image evidence must not require privileged containers" >&2
    exit 1
fi

echo "FIPS image evidence plan: ok"
