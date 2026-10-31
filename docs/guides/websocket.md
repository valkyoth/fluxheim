# WebSocket Proxying

WebSocket starts with an HTTP/1.1 request and, after a successful 101 upgrade,
becomes a bidirectional byte stream. Fluxheim can tunnel that stream to an
HTTP/1 origin, including an HTTPS origin when outbound TLS is configured.
It does not interpret application messages or provide a message broker.

**Current security boundary:** external authorization does not run on the
upgrade takeover path. Do not protect a WebSocket application
solely with `[proxy.auth_request]`. Keep it disabled until corrected, or enforce
authorization independently at the origin. The [authorization guide](external-authorization.md)
describes the open blocker. Documentation of the limit is not acceptance of it.

**Current limitation:** access-decision hooks run before
takeover. Configuration rejects route-decision and request/response-header hooks
on a WebSocket-enabled proxy scope, including vhost-wide hooks when any proxy
route enables WebSocket. Keep those hooks on HTTP-only routes. This applies to
both fail-open and fail-closed header policies. Programmatic configurations
also receive a 503 before origin contact if an unsupported hook applies to the
raw or decoded route. [the local follow-up](../roadmap/observability-commit-plan.md#post-documentation-corrections)
implements this restriction; native qualification and acceptance remain pending.
The [ABI reference](../reference/wasm-policy-abi.md) describes its scope. This
does not fix the separate external-authorization limitation.

**Concurrency limitation:** the takeover path releases vhost/route permits
before the origin handshake and tunnel. Two simultaneous tunnels can pass
`max_in_flight = 1`. These settings are not currently
an active-tunnel cap; see [admission limits](rate-and-concurrency-limits.md).

## Configure A Dedicated Route

The complete [local recipe](../../examples/proxy/websocket.toml) uses a loopback
listener and an origin on port 9001. Its route is:

```toml
[[vhosts.routes]]
name = "socket"
path_prefix = "/socket/"

[vhosts.routes.proxy]
upstreams = ["127.0.0.1:9001"]
upstream_http_version = "http1"
websocket = true
connect_timeout_secs = 2
send_timeout_secs = 2
read_timeout_secs = 30
```

Keep `websocket = false` (the default) for ordinary HTTP routes. The setting
also exists on root/vhost proxy blocks, but a dedicated route makes the boundary
clearer. Do not strip the prefix unless your application expects another path.
Run `fluxheim --config examples/proxy/websocket.toml --validate-config` with the
binary you deploy; use the `proxy` feature/profile. No separate WebSocket Cargo
feature or TOML subsection is needed.

For public `wss://` service, configure the normal [TLS listener](tls.md). To
encrypt the separate origin connection, configure [upstream TLS](upstream-tls.md).
TLS on one side does not enable TLS on the other. HTTP/2 extended CONNECT
WebSockets are not supported by this HTTP/1 upgrade path.

## Upgrade And Message Behavior

The native selector requires GET, a `Connection` token of `Upgrade`,
`Upgrade: websocket`, exactly one `Sec-WebSocket-Key` field and version 13.
The origin receives canonical Connection/Upgrade fields. Fluxheim requires
101 plus upgrade confirmation and a present `Sec-WebSocket-Accept` before
starting the tunnel. Initial bytes already read on either side are retained.
The client and origin remain responsible for valid frame masking, message
format, subprotocol semantics, application authentication and close frames.

After takeover:

- Proxy cache, mirror and ordinary response processing are not the same path as
  a normal HTTP response. Do not assume HTTP-body limits are WebSocket-message
  limits, or that normal response header additions are applied to the 101.
- Static upstream selection chooses one member. Managed load-balancer selection
  can choose a member when that feature is built; it does not move an open
  connection to another origin. Design application reconnect behavior.
- The downstream handshake is rebuilt with Connection/Upgrade plus only
  `Sec-WebSocket-Accept`, `Sec-WebSocket-Protocol` and `Sec-WebSocket-Extensions`
  from the origin. Arbitrary headers, including Set-Cookie, are not copied.
- The current validator checks presence, not the request-key/accept relationship
  or all selected subprotocol/extension relationships. A browser still validates
  its own handshake; do not treat Fluxheim as a complete handshake verifier.

## Timeouts Are Not All Idle Timers

`connect_timeout_secs` controls connection setup. `send_timeout_secs` bounds
the HTTP upgrade request write. `read_timeout_secs` bounds the origin's upgrade
reply and then separately wraps the entire bidirectional copy operation.
Thus the example's **active tunnel closes after roughly 30 seconds**, even if
messages are flowing. It is not a 30-second inactivity timeout. The native
default is also 30 seconds; pick a deliberate value, at most 86400 seconds,
and account for reconnects. Do not assume downstream ordinary-response write
settings cover every pre-tunnel upgrade write.

## Rejection And Troubleshooting

The origin may reject an upgrade for valid reasons, such as an expired session.
Currently a non-101 origin response, including 401/403, is treated as a takeover
error and the downstream connection closes without forwarding that HTTP reply.
This is **Current limitation:**, planned the local follow-up. The same correction will define strict
negotiation validation and explicit allowed handshake-header behavior. Do not
depend on an origin rejection body, redirect, Set-Cookie or WWW-Authenticate
reaching the browser through the current upgrade path.

Check these separately:

1. The route matched and `websocket = true` is on that route's proxy.
2. Both public and origin TLS policies match their respective endpoints.
3. The client really uses HTTP/1.1 upgrade and the origin accepts that path.
4. Authentication is independently enforced at the origin while the documented limitation
   remains open.
5. Disconnect timing matches the absolute tunnel lifetime, not an idle timer.

The [live protocol smoke](../../scripts/smoke_protocol_examples.py) sends a
valid handshake and a fixed masked text frame through the actual local binary,
verifies the echo and characterizes the lost 403. It is a bounded wire fixture,
not a complete WebSocket interoperability or browser conformance suite.
See the [coverage ledger](../reference/documentation-coverage.md) for remaining
platform and correction qualification.
