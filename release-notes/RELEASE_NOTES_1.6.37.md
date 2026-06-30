# Fluxheim 1.6.37 Release Notes

Fluxheim 1.6.37 is the final pre-Wasm crate-boundary cleanup release after the
Pingora-free runtime cutover and the 1.6.36 structural cleanup.

This release should keep runtime behavior stable while moving obvious remaining
root helpers into focused workspace crates. New substantial code should default
to an existing domain crate, or to a focused new crate when the dependency graph
is clean.

## Highlights

- Start the final pre-Wasm crate-boundary cleanup pass.
- Prepare ACME, observability, header-policy, TLS helper, native proxy, and CLI
  boundaries for smaller crate-owned APIs.
- Remove private root compatibility shims for common errors, filesystem trust
  checks, and OTLP HTTP agents; affected call sites now use
  `fluxheim-common`, `fluxheim-config`, and `fluxheim-observability` directly.
- Remove the single-use root path-safety shim; admin validation now calls the
  `fluxheim-common` path-safety helper directly.
- Remove the root test-support shim; root tests now import shared helpers from
  `fluxheim-common` directly.
- Remove the root cache-header shim; static response planning now calls
  `fluxheim-cache` header helpers directly.
- Remove root reload, snapshot, and load-balancer re-export shims from active
  code; admin and CLI paths now use `fluxheim-config`, `fluxheim-snapshot`, and
  `fluxheim-load-balancer` directly.
- Remove root GeoIP, OTLP trace-exporter, and trace-context re-export shims;
  callers should use `fluxheim-geoip` and `fluxheim-observability` directly.
- Keep the root `fluxheim` crate focused on binary, CLI, admin, and runtime
  orchestration glue.
- Continue enforcing modularity, release metadata, Pingora dependency,
  native-runtime, RPM, container, and smoke gates as blocking release evidence.

## Compatibility Notes

- This release should not change runtime configuration semantics.
- Crate moves should preserve public behavior and move tests with the owned
  logic where practical.

## Verification

- `scripts/validate-release-metadata.sh`
- `scripts/validate-modularity-policy.sh check`
- `scripts/validate-pingora-dependency-policy.sh check`
- `scripts/validate-pingora-boundary-policy.sh check`
- `scripts/validate-native-runtime-cutover.sh`
- `scripts/stable_release_gate.sh check`
