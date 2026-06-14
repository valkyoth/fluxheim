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

## Compatibility

- No configuration changes.
- No load-balancer persistence behavior changes are intended for source-IP,
  URI, header, cookie, or managed-cookie persistence.
- `pingora-load-balancing` and `pingora-cache` remain in the build graph for
  `1.5.22`; actual dependency removal is reserved for the `1.6.x` line.
