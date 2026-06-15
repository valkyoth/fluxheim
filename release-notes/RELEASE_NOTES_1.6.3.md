# Fluxheim 1.6.3 Release Notes

Fluxheim 1.6.3 continues the Pingora-exit line by moving TCP stream proxy
runtime logic into a dedicated `fluxheim-stream` crate. Operator-visible stream
route behavior is intended to remain unchanged; this release narrows the root
Pingora-adjacent adapter to service lifecycle, socket accept/connect, and TLS
connector wiring.

## Changed

- Added the internal `fluxheim-stream` crate for TCP stream proxy runtime
  policy and protocol helpers.
- Moved stream upstream selection, weighted primary selection, backup/drain
  ordering, and selected-upstream labels into `fluxheim-stream`.
- Moved stream source allow/deny matching and route-local trusted PROXY source
  parsing into `fluxheim-stream`.
- Moved stream DNS-rebinding guard decisions, copied-byte accounting, idle
  copy-loop timeouts, and max-connection-byte enforcement into
  `fluxheim-stream`.
- Moved downstream PROXY protocol v1/v2 parsing and upstream PROXY protocol
  header writing into `fluxheim-stream`, reusing the existing
  `fluxheim-protocol` header builders so HTTP and stream PROXY behavior stays
  byte-compatible.
- Kept the current root stream adapter as the Pingora service-registration
  boundary until the `1.6.4` background-runtime and later server-bootstrap
  cutovers.
- Updated workspace crate versions, RPM metadata, README image examples, build
  documentation, changelog, and release notes to `1.6.3`.

## Tests

- Added direct `fluxheim-stream` unit coverage for stream source matching,
  upstream selection, DNS-rebinding guards, byte-limit accounting, and PROXY
  protocol parsing.
- Preserved root stream-proxy runtime tests for bidirectional copy behavior,
  connection byte limits, idle/lifetime timeouts, upstream PROXY protocol
  forwarding, and explicit IP-literal upstream resolution.
