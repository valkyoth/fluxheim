# Fluxheim 1.6.15 Release Notes

Fluxheim 1.6.15 continues the Pingora-exit line by adding the first
Fluxheim-owned native HTTP/2 upstream client primitive. The production proxy
still keeps Pingora as the compatibility fallback for HTTP/2 cutover, but the
server crate now has a tested upstream h2 request/response path with the safety
bounds needed for the staged migration.

## Added

- Added `fluxheim-server` native HTTP/2 upstream request and response types.
- Added a native HTTP/2 upstream `send_on_io` path over the `h2` crate with
  bounded request headers, bounded request body size, bounded response headers,
  bounded response body size, request trailer sending, response trailer
  preservation, and absolute write/read deadlines.
- Added in-memory h2 upstream tests for gRPC-style trailer pass-through,
  oversized upstream response rejection, response header-count rejection, and
  upstream stream reset surfacing, and request flow-control write timeout
  handling.

## Changed

- Shared native HTTP/2 prohibited response-header validation between the
  downstream stack probe and the new upstream client path.
- Shared the native HTTP/2 bounded DATA sender between downstream responses and
  upstream request bodies.

## Security

- The native HTTP/2 upstream client fails closed on oversized responses,
  excessive decoded response headers, prohibited HTTP/2 response headers, and
  stalled request-body writes caused by upstream flow-control holds.
- Native HTTP/2 upstream request bodies are now staged in zeroizing memory
  before being copied into h2 DATA frames.
- Native HTTP/2 upstream response body reads now have a dedicated
  response-body timeout instead of reusing the downstream request-body timeout.
- The current native HTTP/2 upstream client documents its intentional
  one-request connection-driver abort so that future pooled HTTP/2 upstream
  connections use a graceful teardown design instead.

## Compatibility

- HTTP/2 production proxy cutover remains gated. The native HTTP/2 upstream
  client is available for staged parity work, but official production profiles
  still use the existing compatibility path until pre-routing HPACK/header-count
  allocation bounds and full proxy integration are proven.
