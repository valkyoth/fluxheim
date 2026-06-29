# Fluxheim 1.6.34 Release Notes

Fluxheim 1.6.34 is the final Pingora-free proof release in the 1.6 runtime
exit line.

This checkpoint removes the remaining Pingora compatibility runtime from
normal Fluxheim builds after the native listener, TLS, HTTP/1, HTTP/2,
WebSocket, load-balancer, cache, admin, metrics, stream, and background-service
paths have reached parity coverage.

## Highlights

- Remove the final Pingora runtime/listener/TLS adapter crates from normal
  Fluxheim build profiles.
- Keep the native HTTP/1 and HTTP/2 proxy runtime as the normal runtime path
  for supported route, cache, load-balancer, TLS, WebSocket, admin, and metrics
  configurations.
- Wire native admin cache purge, stale disk-cache purge, cache object lookup,
  and live load-balancer stats/mutation handlers to Fluxheim-owned runtime
  handles instead of compatibility shims.
- Align native cache-key/cache-lookup previews with runtime cache routing for
  route-scoped cache policies, preserve the documented `HEAD` temporary-bypass
  reason, and emit disk-cache purge activity metrics from native admin purge
  paths.
- Update the Pingora dependency policy so default, full, cache-edge,
  proxy-edge, load-balancer-edge, PHP, privacy, source, RPM, and container
  release gates fail if a normal build still compiles Pingora crates.
- Refresh the OWASP Top 10 2025 release-gate test inventory so it points at
  the native HTTP/1 controls that replaced the legacy Pingora-era tests.
- Make the historical `pingora-compat` feature marker inert: enabling the
  feature no longer compiles legacy Pingora source paths now that the
  dependency is removed from the manifest.
- Preserve the native runtime cutover evidence and compatibility reporting so
  unsupported configurations fail closed with explicit blockers instead of
  silently falling back to a Pingora adapter.
- Harden native admin cache-preview and cache-purge paths so host matching uses
  the same normalization as runtime routing, regex routes are represented in
  previews, stale disk purges do not hold the registry mutex while doing disk
  I/O, poisoned live config state fails closed, and the root cache API exposes
  only deliberate symbols.
- Refactor native route-proxy construction around typed build contexts so
  clippy release profiles keep the native proxy/server boundary maintainable.

## Compatibility Notes

- Pingora is no longer part of normal Fluxheim builds. If a configuration uses
  a feature that the native runtime still reports as unsupported, Fluxheim
  rejects that cutover path with an explicit native-runtime blocker.
- The `pingora-compat` feature name remains only as a historical compatibility
  marker for older build scripts; it has no dependency payload and does not
  re-enable the removed runtime.
- The `1.6.35` follow-up is reserved for stabilization, soak testing,
  performance comparison, and security-only cleanup after the Pingora-free
  runtime lands.
- The `1.6.36` cleanup follow-up will remove the temporary native proxy shim
  and move cache-preview route matching onto the same precompiled route
  structures used by the serving path.

## Verification

- `scripts/validate-pingora-dependency-policy.sh`
- `scripts/validate-native-runtime-cutover.sh`
- `scripts/stable_release_gate.sh check`
- `scripts/podman_smoke.sh`
