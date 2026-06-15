# Fluxheim 1.6.4 Release Notes

Fluxheim 1.6.4 continues the Pingora-exit line by moving shared background
task lifecycle primitives into `fluxheim-runtime`. Runtime behavior is intended
to remain unchanged; the root crate keeps only the current Pingora
`ServiceWithDependents` adapter while Fluxheim-owned tasks use Fluxheim-owned
shutdown, readiness, and service handles.

## Changed

- Moved `FluxShutdown`, `FluxBackgroundReady`, `FluxBackgroundTask`,
  `FluxBackgroundService`, and `background_service` into `fluxheim-runtime`.
- Replaced the root background implementation with a narrow Pingora
  service-registration adapter around the runtime crate primitives.
- Replaced the load-balancer crate's duplicate shutdown/readiness/background
  service implementation with re-exports from `fluxheim-runtime`.
- Kept the load-balancer service as a local wrapper so existing root adapter,
  status, and discovery code keep the same API while the task lifecycle is now
  owned by `fluxheim-runtime`.
- Added typed background task kind metadata to the runtime service handle and
  tagged cache metrics, stale purging, ACME renewal, admin watchdog, and
  load-balancer refresh services without changing scheduling behavior.
- Moved OTLP metrics export from an unmanaged raw thread to the Fluxheim
  background task lifecycle, preserving the existing interval/timeout behavior
  while adding shutdown awareness and typed task metadata.
- Moved the ACME certificate reload control socket from an unmanaged raw thread
  to the Fluxheim background task lifecycle. Startup path validation and socket
  binding remain fail-fast; the accept loop now honors runtime shutdown and
  caps concurrent local reload requests.
- Moved admin self-healing snapshot runtime state into `fluxheim-snapshot`:
  runtime/known-good snapshot IDs, pending validation, validation metrics,
  health-signal outcomes, expiry checks, and applied-snapshot state
  transitions now live with the snapshot domain instead of the admin HTTP
  adapter.

## Security Hardening

- Bounded concurrent handling for the local certificate reload control socket
  so a same-user local client cannot create unbounded blocking reload tasks.
- Added a one-day upper bound for second-based proxy, PHP-FPM, and
  load-balancer health-check timeouts that use the shared timeout validator.
- Extended HTTP discovery private-backend filtering to reject 6to4 and Teredo
  IPv6 literals that embed private, loopback, link-local, documentation, or
  otherwise restricted IPv4 addresses.

## Tests

- Added direct `fluxheim-runtime` unit coverage for shutdown signaling,
  closed-sender shutdown behavior, delayed sleep, one-shot readiness, runtime
  task specs, typed background service metadata, policy epochs, facts, and
  proofs.
- Verified the root proxy/load-balancer/cache/ACME/metrics feature path still
  compiles with the Pingora service adapter boundary.
- Added OTLP metrics exporter construction tests for disabled and invalid
  endpoint configurations.
- Added direct `fluxheim-snapshot` unit coverage for pending validation,
  confirm, error-rate rollback, and expired validation decisions.
- Added regression coverage for unbounded timeout rejection and HTTP discovery
  IPv6 literals that encode restricted IPv4 addresses.
