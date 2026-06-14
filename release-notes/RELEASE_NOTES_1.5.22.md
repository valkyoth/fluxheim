# Fluxheim 1.5.22 Release Notes

Fluxheim 1.5.22 continues the crate-boundary preparation work for the later
`1.6.x` Pingora-removal line. Runtime behavior is intended to remain unchanged;
the focus is keeping cache/load-balancer domain logic behind Fluxheim-owned
interfaces before the HTTP runtime is replaced.

## Changed

- Load-balancer persistence key extraction now consumes a Fluxheim-owned
  request view trait instead of depending directly on Pingora request headers.
- The existing Pingora `RequestHeader` support remains as an adapter at the
  load-balancer API boundary.
- Managed-cookie persistence tests now run against a local Fluxheim request
  view, proving the persistence module can validate cookies without a Pingora
  request object.
- `fluxheim-web` symlink-detection tests now use repository-local,
  component-validated test paths from the shared test-support helpers. This
  resolves CodeQL path-expression alerts in test setup/cleanup code without
  changing static-web runtime behavior.
- Cleartext TCP health checks now use a Fluxheim-owned Tokio connect probe.
  TLS TCP health checks intentionally keep the existing Pingora transport
  connector so SNI/TLS handshake behavior stays unchanged in `1.5.22`.
- Cache request bypass, client revalidation, and range-selection decisions now
  run through a Fluxheim-owned cache request view. The root proxy cache module
  keeps a small Pingora `RequestHeader` adapter, so cache behavior is intended
  to remain unchanged while the cache crate owns more policy logic.

## Compatibility

- No configuration changes.
- No load-balancer persistence behavior changes are intended for source-IP,
  URI, header, cookie, or managed-cookie persistence.
- `pingora-load-balancing` and `pingora-cache` remain in the build graph for
  `1.5.22`; actual dependency removal is reserved for the `1.6.x` line.
