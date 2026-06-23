# Fluxheim 1.6.30 Release Notes

Fluxheim 1.6.30 continues the Pingora-exit work by moving plaintext upstream
HTTP/2 forwarding into the native HTTP/1 proxy path.

## Highlights

- Native HTTP/1 proxy configs can now use
  `proxy.upstream_http_version = "http2"` with plaintext upstreams that speak
  h2c/prior-knowledge HTTP/2.
- Native upstream HTTP/2 connections are pooled instead of torn down after a
  single request. The pool keeps the h2 connection driver alive, reserves stream
  capacity with `proxy.upstream_h2_max_streams`, invalidates stale handles after
  h2 errors, and retries safe methods once after a pre-response pooled-handle
  failure.
- Native upstream H2 policy now receives `proxy.read_timeout_secs`,
  `proxy.send_timeout_secs`, and `proxy.upstream_h2_max_streams`.
- TLS ALPN-negotiated upstream HTTP/2, `http1-and-http2` fallback negotiation,
  and `proxy.upstream_h2_ping_interval_secs` remain explicit native blockers
  until the final upstream transport cutover.
- Live native proxy tests now prove downstream HTTP/1 requests can be forwarded
  to an in-process HTTP/2 origin, and that two downstream requests reuse one
  upstream H2 connection.

## Security Notes

- Native upstream H2 handshakes are now bounded by the selected H2 policy
  timeout so an origin that accepts TCP and then stalls the HTTP/2 preface cannot
  freeze upstream setup indefinitely.
- Native upstream H2 stream-slot waits are now bounded by the connect timeout so
  later downstream requests cannot wait indefinitely when all upstream H2 stream
  capacity is occupied by slow responses.
- Native upstream H2 requests and responses use the existing bounded H2 client
  policy: decoded header-count/list limits, URI/body limits, response body
  timeout, request upload lifetime, response header validation, and prohibited
  hop-by-hop response-header rejection.
- Pooled native upstream H2 requests now run the same outbound H2 validation as
  one-shot H2 requests before acquiring stream capacity or opening an upstream
  connection.
- Invalid programmatic upstream H2 stream limits now fail closed instead of
  silently reverting to the default policy.
- Native upstream H2 pool creation no longer holds the pool mutex across TCP
  connect and H2 handshake work, avoiding serialized cold-start failures when an
  origin is unavailable.

## Compatibility Notes

- This release enables plaintext h2c/prior-knowledge origins on the native path.
  Operators using TLS ALPN H2, `http1-and-http2` negotiation, or upstream H2
  keepalive pings still use the compatibility runtime until those pieces have
  native parity tests.
