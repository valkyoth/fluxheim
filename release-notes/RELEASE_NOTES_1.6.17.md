# Fluxheim 1.6.17 Release Notes

Fluxheim 1.6.17 continues the Pingora-exit line by removing the direct Pingora
dependency from the `fluxheim-load-balancer` crate. The root compatibility
runtime still uses Pingora in this release, but the load-balancer core and its
active health-check client path are now Fluxheim-owned.

## Security and Correctness

- HTTP health checks now use a bounded native HTTP/1.1 probe instead of
  Pingora's HTTP health session. The probe enforces response header/body caps,
  configured connect/read timeouts, configured request headers, expected status
  and header checks, body substring checks, JSON field checks, and degraded
  health-weight headers.
- gRPC health checks now use a native h2 client probe with the existing
  Fluxheim gRPC health request/response framing validation.
- TLS health-check connections use the Fluxheim-owned TCP/TLS connector path,
  including handshake timeout enforcement and protocol-specific ALPN for
  HTTP/1.1 or h2.
- HTTP/1.1 health-check request paths and Host values now reject CR/LF before
  request serialization, closing a native health-probe header-injection gap.
- gRPC health-check response reads now release h2 flow-control capacity and use
  an abort-on-drop driver task guard so error paths cannot leave orphaned h2
  driver tasks behind. h2 driver errors are logged at warning level.
- `scripts/validate-pingora-dependency-policy.sh` now checks
  `cargo tree -p fluxheim-load-balancer` directly, so release gates fail if
  Pingora is reintroduced into the load-balancer crate.

## Tests

- Added a real TCP listener-backed HTTP/1.1 health-check test proving request
  header forwarding, JSON response validation, and health-derived weight
  updates.
- Added a real h2 server-backed gRPC health-check test proving Fluxheim sends
  the standard gRPC health request body and accepts a `SERVING` response.
- The load-balancer container smoke now uses HTTP active health checks and
  fails if `cargo tree -p fluxheim-load-balancer` contains any Pingora crate.
- Verified `cargo test -p fluxheim-load-balancer --locked` passes with 125
  tests.

## Compatibility

- The root runtime adapter remains `PingoraCompatibility` in this release.
  Normal Fluxheim builds may still compile Pingora through the root proxy
  runtime until the next native HTTP/runtime cutover releases.
- `reuse_connection` remains accepted in load-balancer health-check
  configuration for compatibility, but the native HTTP/gRPC health-check client
  currently opens a fresh bounded connection per probe.
