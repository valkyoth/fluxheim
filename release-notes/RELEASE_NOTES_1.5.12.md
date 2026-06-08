# Fluxheim 1.5.12 Release Notes

Fluxheim 1.5.12 starts the Fluxheim-native background task registry line.

This release is intentionally narrow. It moves Fluxheim-owned background work
behind a Fluxheim adapter while keeping Pingora only as the server registration
boundary for now.

## What Changed

- Added `src/background.rs` with Fluxheim-owned shutdown and readiness tokens
  for background tasks.
- Moved cache runtime metrics, stale cache purging, ACME renewal, and the admin
  self-healing watchdog to `FluxBackgroundTask`.
- Moved load-balancer discovery and health refresh services through the shared
  background adapter while preserving readiness after the initial discovery
  update.
- Kept the release boundary clear: no HTTP proxy lifecycle rewrite, no stream
  listener migration, no cache interface rewrite, and no UDP/GSLB, WAF,
  VPN/firewall, or Wasm/iRules/Lua work in this tag.

## Operational Notes

- Existing configuration remains compatible.
- Background shutdown behavior remains graceful and cancellation-aware.
- ACME background automation, cache purging, cache metrics, admin watchdog, and
  load-balancer refresh behavior should match 1.5.11 from an operator
  perspective.

## Packaging Notes

- RPM and container documentation are updated for `1.5.12`.
- The standard release artifacts remain the `full`, `cache`, `proxy`,
  `load-balancer`, and `php` builds.
