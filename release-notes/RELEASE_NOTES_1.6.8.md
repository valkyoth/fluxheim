# Fluxheim 1.6.8 Release Notes

Fluxheim 1.6.8 continues the 1.6 Pingora-exit line by adding native HTTP/1.1
request-head foundations. The active HTTP runtime still uses the Pingora
compatibility adapter in this slice.

## Added

- Added a Fluxheim-owned HTTP/1.0/HTTP/1.1 request-head parser in
  `fluxheim-protocol`.
- Added strict parser bounds for total request-head bytes, header count,
  start-line length, and individual header-line length.
- Rejected obsolete folded header lines, invalid header names, invalid header
  control bytes, malformed request lines, and unsupported HTTP versions at the
  protocol boundary.
- Added downstream HTTP/1 policy defaults to `fluxheim-server` so the native
  server plan carries HTTP/1 parser limits before production traffic is moved
  off the Pingora adapter.
- Added an incremental HTTP/1 request-head buffer for future native socket read
  loops, with fragmented-head support and bounded storage when an incomplete
  head exceeds the configured cap.

## Tests

- Added `fluxheim-protocol` unit tests for complete HTTP/1.1 heads, incomplete
  heads, oversized heads, header-count limits, folded headers, invalid controls,
  invalid methods, and unsupported versions.
- Added `fluxheim-protocol` unit tests for fragmented request heads and
  oversized incomplete chunks that must not be stored unboundedly.
- Added `fluxheim-server` unit coverage for downstream HTTP/1 bounded defaults.

## Verification

- `cargo test --locked -p fluxheim-protocol`
- `cargo test --locked -p fluxheim-server`
- `RUSTFLAGS='-D warnings' cargo check --locked -p fluxheim-protocol`
- `RUSTFLAGS='-D warnings' cargo check --locked -p fluxheim-server`
- `scripts/validate-modularity-policy.sh check`
