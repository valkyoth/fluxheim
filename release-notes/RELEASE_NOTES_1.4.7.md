# Fluxheim 1.4.7 Release Notes

Fluxheim 1.4.7 is planned as a TCP stream hardening follow-up to the 1.4.6
stream proxy foundation.

## Added

- True per-read stream idle timeout. `idle_timeout_secs` now resets whenever
  either direction transfers bytes.
- Optional `max_connection_secs` remains available as a separate wall-clock
  lifetime cap.

## Planned Scope

- Stream upstream TLS and upstream mTLS when they can reuse the existing safe
  certificate/key loading and upstream TLS evidence model.
- Transport-neutral stream load-balancer policy only, such as upstream
  weights, backup/drain state, and health state.
- Expanded stream smoke/security tests for half-close behavior, byte caps, idle
  timeout, upstream TLS/mTLS, PROXY receive/send combinations, and metrics
  labels.

## Out Of Scope

- UDP proxying.
- DNS-specific UDP load balancing.
- HTTP cache, compression, auth subrequest, PHP, header mutation, or body
  policy on stream routes.
- TLS passthrough SNI routing.
- xDS/Kubernetes/Consul discovery.
- Wasm/Lua stream filters.
