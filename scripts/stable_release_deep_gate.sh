#!/usr/bin/env sh
set -eu

mode="${1:-release}"

case "$mode" in
    check | release)
        ;;
    *)
        echo "usage: scripts/stable_release_deep_gate.sh [check|release]" >&2
        exit 2
        ;;
esac

FLUXHEIM_GATE_TLS_BACKENDS="${FLUXHEIM_GATE_TLS_BACKENDS:-1}" \
FLUXHEIM_GATE_FIPS_OPENSSL="${FLUXHEIM_GATE_FIPS_OPENSSL:-1}" \
FLUXHEIM_GATE_FIPS_RUSTLS="${FLUXHEIM_GATE_FIPS_RUSTLS:-1}" \
FLUXHEIM_GATE_OWASP_RUN="${FLUXHEIM_GATE_OWASP_RUN:-1}" \
FLUXHEIM_GATE_TLS_SCAN="${FLUXHEIM_GATE_TLS_SCAN:-1}" \
FLUXHEIM_GATE_LOAD="${FLUXHEIM_GATE_LOAD:-1}" \
FLUXHEIM_GATE_FRAMING="${FLUXHEIM_GATE_FRAMING:-1}" \
FLUXHEIM_GATE_FUZZ_CHECK="${FLUXHEIM_GATE_FUZZ_CHECK:-1}" \
scripts/stable_release_gate.sh "$mode"
