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
- TLS ALPN-negotiated upstream HTTP/2 is now supported for
  `proxy.upstream_http_version = "http2"` with the existing upstream TLS/SNI/CA
  policy. TLS `http1-and-http2` fallback now advertises `h2` and `http/1.1`
  and dispatches each request with the protocol selected by ALPN.
- Plaintext `proxy.upstream_http_version = "http1-and-http2"` can now attempt
  HTTP/1.1 h2c Upgrade only when the new `proxy.upstream_h2c_upgrade = true`
  opt-in is set. The default remains `false`; refused upgrades fall back to a
  fresh HTTP/1.1 connection.
- Live native proxy tests now prove downstream HTTP/1 requests can be forwarded
  to an in-process HTTP/2 origin, and that two downstream requests reuse one
  upstream H2 connection.
- Additional native proxy tests prove H2 upstream pools reconnect after an
  origin closes a pooled H2 connection and round-robin across multiple static
  H2 upstreams.
- Native proxy live tests now also prove weighted static upstream selection
  preserves the configured slot order while forwarding every selected upstream
  request over HTTP/2.
- Native proxy live tests now prove safe-method failover works across static
  HTTP/2 upstreams and that unsafe methods are not replayed to another H2
  upstream after a failed first attempt.
- Native upstream client tests now prove explicit plaintext h2c Upgrade reaches
  a real in-process HTTP/2 origin, and that origins refusing Upgrade fall back
  to HTTP/1.1 without replaying the downstream request during the probe.

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
- A live rustls upstream test now proves the native proxy negotiates `h2` with
  ALPN, forwards downstream HTTP/1.1 requests to a TLS HTTP/2 origin, and sends
  an HTTPS-scheme upstream H2 request.
- Live rustls upstream tests now prove TLS `http1-and-http2` fallback selects
  HTTP/2 when the origin negotiates `h2` and falls back to HTTP/1.1 when no
  HTTP/2 ALPN protocol is selected.
- Native cutover-plan tests now prove TLS `http1-and-http2` upstream fallback
  is native-ready when a TLS backend is compiled, while plaintext
  `http1-and-http2` remains HTTP/1.1-only unless `proxy.upstream_h2c_upgrade`
  is explicitly enabled.
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
- Native diagnostics now distinguish supported upstream H2 modes from invalid
  mixed-mode configurations. Plaintext `http1-and-http2` does not use H2 unless
  the explicit h2c Upgrade opt-in is enabled.
- Native H2-to-HTTP/1 response conversion now strips hop-by-hop and
  proxy-owned headers such as `transfer-encoding`, `upgrade`, `keep-alive`,
  `proxy-connection`, `te`, and `trailer`, in addition to `content-length`,
  `connection`, and `date`.
- Native upstream H2 retry handling now releases the stream-capacity permit
  before rebuilding a failed pooled H2 connection, then reacquires capacity
  immediately before sending the retry stream.
- Non-TLS native builds now support plaintext `http1-and-http2` only through
  the explicit h2c Upgrade opt-in; without it, mixed-mode plaintext fallback
  stays on HTTP/1.1.
- `proxy.upstream_h2c_upgrade` is rejected unless an upstream is configured,
  the upstream is plaintext, and `proxy.upstream_http_version =
  "http1-and-http2"`, keeping h2c Upgrade out of TLS and prior-knowledge H2
  configurations.
- Explicit h2c Upgrade fallback now treats a closed/reset probe connection as
  an upgrade refusal and retries the original downstream request on a fresh
  HTTP/1.1 connection, while still treating probe timeouts as ambiguous and
  non-replayable.
- H2 stream-capacity closure is no longer classified as a transport-level
  broken pipe, so explicit h2c mixed-mode fallback cannot downgrade and replay
  a request after an upstream H2 stream has already been opened.
- The h2c `HTTP2-Settings` header now uses the infallible fixed-input encoder
  added by `base64-ng` 1.2.2, removing the previous local dead error branch
  while keeping Fluxheim on the hardened base64-ng dependency.
- The h2c Upgrade response-head reader now checks only the trailing terminator
  bytes while reading one byte at a time, preserving post-upgrade H2 frames
  without an O(n²) scan.

## Compatibility Notes

- This release enables plaintext h2c/prior-knowledge, TLS ALPN H2 origins, and
  TLS `http1-and-http2` fallback negotiation on the native path. Plaintext
  `http1-and-http2` uses HTTP/1.1 by default; set
  `proxy.upstream_h2c_upgrade = true` only for origins known to implement
  HTTP/1.1 h2c Upgrade. This is intentionally not default because cleartext
  origins have no ALPN negotiation point and h2c Upgrade support varies by
  server.
