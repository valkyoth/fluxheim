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

## Tests

- Added direct `fluxheim-runtime` unit coverage for shutdown signaling,
  closed-sender shutdown behavior, delayed sleep, one-shot readiness, runtime
  task specs, policy epochs, facts, and proofs.
- Verified the root proxy/load-balancer/cache/ACME/metrics feature path still
  compiles with the Pingora service adapter boundary.
