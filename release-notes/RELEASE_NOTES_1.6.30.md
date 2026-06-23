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
  `proxy.send_timeout_secs`, `proxy.upstream_h2_max_streams`, and
  `proxy.upstream_h2_ping_interval_secs`.
- TLS ALPN-negotiated upstream HTTP/2 and `http1-and-http2` fallback
  negotiation remain explicit native blockers until the final upstream
  transport cutover.
- Live native proxy tests now prove downstream HTTP/1 requests can be forwarded
  to an in-process HTTP/2 origin, and that two downstream requests reuse one
  upstream H2 connection.
- Additional native proxy tests prove H2 upstream pools reconnect after an
  origin closes a pooled H2 connection and round-robin across multiple static
  H2 upstreams.

## Security Notes

- Native upstream H2 handshakes are now bounded by the selected H2 policy
  timeout so an origin that accepts TCP and then stalls the HTTP/2 preface cannot
  freeze upstream setup indefinitely.
- Native upstream H2 stream-slot waits are now bounded by the read timeout so
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
- Native upstream H2 pool creation is serialized by a dedicated setup lock, so a
  cold pool or post-invalidation retry cannot open one TCP/H2 connection per
  waiting stream slot.
- `proxy.read_timeout_secs` now also bounds native H2 request readiness and
  response-header waits, not only response-body reads.
- `proxy.upstream_total_connection_timeout_secs` now caps native H2 setup plus
  the first stream-readiness/response-header phase on a newly initialized H2
  connection.
- Stream-scoped H2 failures no longer invalidate the whole H2 pool unless the
  h2 error reports a GOAWAY/connection-level condition.
- Native plaintext upstream H2 keepalive pings run in a separate bounded task,
  wait for PONGs with the selected H2 handler timeout, and abort the connection
  driver when the peer stops acknowledging pings.
- A wire-level native upstream H2 test now observes an actual client PING frame
  through a real h2 server IO wrapper, proving configured keepalive is emitted
  instead of only accepted by config.
- Native upstream H2 stream permits are now named and explicitly released after
  response conversion, keeping the lifetime visible to reviewers and avoiding
  accidental future movement of the permit guard.
- Native upstream H2 outbound request validation now has one enforcement point
  inside the H2 sender, avoiding duplicate prevalidation paths with drift-prone
  policy inputs.
- Native upstream H2 programmatic configuration now enforces the same 1-1024
  stream cap as TOML validation, with a debug assertion on pool construction.
- H2-only knobs on HTTP/1 upstream configs are rejected instead of silently
  ignored, and H1/H2 upstream request writers now share the same predicate for
  Fluxheim-owned header stripping.
- Native diagnostics now distinguish supported plaintext upstream H2 from
  unsupported H2 modes such as TLS ALPN negotiation and `http1-and-http2`
  fallback.

## Compatibility Notes

- This release enables plaintext h2c/prior-knowledge origins on the native path.
  Operators using TLS ALPN H2 or `http1-and-http2` negotiation still use the
  compatibility runtime until those pieces have native parity tests.
