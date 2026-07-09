# Fluxheim 1.7.6 Release Notes

Fluxheim 1.7.6 starts the mature WebAssembly runtime hardening pass after the
initial live hook families landed in 1.7.1 through 1.7.5.

## Wasm Runtime Hardening

- Compiled WebAssembly modules now carry an explicit cache identity made from
  the plugin SHA-256 digest, manifest ABI version, native hook feature surface,
  and Fluxheim crate version.
- The native HTTP/1 hook registry compiles plugins through manifest-derived
  identities, so future module reuse cannot silently cross ABI, feature, or
  release boundaries.
- The runtime rejects a compile request when the supplied compiled-module
  identity does not match the loaded plugin digest.
- Prometheus Wasm plugin metrics now preserve bounded labels for every current
  hook family, including route selection, cache lookup pass/bypass, cache-store
  skip/deny, and the cache-specific global admission scope.
- Authenticated admin status now reports both the general Wasm process-wide
  admission budget and the separate cache-policy process-wide admission budget.

## Test Coverage

- Add runtime tests proving ABI and feature-surface changes produce distinct
  compiled-module identities for the same plugin bytes.
- Add runtime coverage for digest-mismatch rejection before module compilation
  can be accepted under the wrong identity.
- Extend metrics and admin-status tests for the mature hook-family visibility
  fields added in this release.
- Add a live native HTTP/1 cross-family chain regression test that exercises
  access-decision, request-header mutation, route-decision branch selection,
  cache-key mutation, cache-store metadata, cached HIT behavior, and
  response-header mutation in one request flow.
- Add reload classification regressions for Wasm plugin digest changes and
  attachment phase changes so module/hash and hook-chain updates remain
  process-upgrade events.
