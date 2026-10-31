# Reverse Proxy

A reverse proxy accepts a request from your visitor, sends it to an application
server (the **origin**), and returns the application's response. Fluxheim owns
the public listener; your application can stay on a private address. The two
connections have independent protocols, TLS settings and deadlines.

Use a binary built with `proxy` or a profile containing it. Local error pages
also require `web`. Outbound HTTPS requires a supported TLS backend. A feature
being understood by the TOML parser does not mean a minimal binary includes it:
validate using the exact binary you will deploy.

## Start With One Application

The complete [transport recipe](../../examples/proxy/transport.toml) includes
the listener, vhost, deadlines and local gateway pages. Its main proxy block is:

```toml
[[vhosts]]
name = "app"
hosts = ["app.example.test"]

[vhosts.proxy]
upstreams = ["127.0.0.1:9001"]
upstream_http_version = "http1"
connect_timeout_secs = 2
upstream_total_connection_timeout_secs = 3
read_timeout_secs = 2
send_timeout_secs = 2
upstream_idle_timeout_secs = 10
```

The upstream is an `address:port`, **not** `http://address/path`. Set outbound
TLS separately. A single `upstream = "127.0.0.1:9001"` is also supported; do not
combine it with `upstreams`. For IPv6 use `[::1]:9001`. The incoming path and
query are forwarded unless a [route rewrite](routing.md) changes them.
The valid request Host is normally preserved; the dial address and TLS SNI
are separate from the application's HTTP authority. See [upstream TLS](upstream-tls.md)
for CA validation, SNI, client certificates and Host overrides.

Put the same options under `[vhosts.routes.proxy]` for a route-specific origin,
or `[proxy]` for the root/default proxy. Do not assume a route inherits every
field of another proxy table. See [routing](routing.md) for selection and
fallback precedence and [load balancing](load-balancer.md) for multiple origins,
discovery, weights, health, retries and per-member admission.

## Reuse Connections Without Confusing Limits

```toml
[server.process]
upstream_keepalive_pool_size = 8
```

This is the maximum **idle HTTP/1 connections per native upstream**, not a
maximum number of active requests or a process-wide socket limit. Zero disables
that pool. More routes/origins can mean more pools. An HTTP/1 connection is
returned only after a complete reusable response; an origin's `Connection:
close` prevents reuse. An HTTP/1.0 origin must explicitly allow keep-alive.

`upstream_idle_timeout_secs` expires pooled HTTP/1 connections when selecting
one for reuse. It is not a background eviction timer or an HTTP/2 idle timeout.
Choose it below the origin's idle close interval. On a stale pooled connection,
Fluxheim may retry once on a fresh connection for a bodyless GET, HEAD, OPTIONS
or TRACE. This is distinct from retrying another load-balanced member; see the
retry limitations in the load-balancer guide. Do not infer safe replay of POST
or a request carrying a body.

TCP keepalive probes detect some broken network paths. They do **not** replace
HTTP request deadlines, connection pooling or HTTP/2 PINGs.

## Select An Upstream Protocol

| Setting | Actual behavior |
| --- | --- |
| `http1` (default) | HTTP/1.1 origin requests; reusable idle connections when enabled |
| `http2`, no TLS | Cleartext HTTP/2 prior knowledge; origin must explicitly support it |
| `http2`, TLS | HTTP/2 using the selected TLS backend; configure verification and SNI |
| `http1-and-http2`, TLS | ALPN chooses H2 or HTTP/1.1; currently a fresh connection per request |
| `http1-and-http2`, plaintext, `upstream_h2c_upgrade = true` | An `OPTIONS *` upgrade probe; H2 when accepted, eligible failures fall back on a fresh HTTP/1 connection |
| `http1-and-http2`, plaintext, upgrade disabled | Currently rejected by the native builder, despite passing general config validation; use `http1` instead |

For a known H2 origin:

```toml
[vhosts.proxy]
upstreams = ["127.0.0.1:9001"]
upstream_http_version = "http2"
upstream_h2_max_streams = 64
upstream_h2_ping_interval_secs = 30
```

`upstream_h2_max_streams` accepts 1-1024. In explicit H2 mode it controls a
shared upstream stream semaphore; waiting for capacity uses `read_timeout_secs`.
The default native H2 limit is 32. The peer's own H2 limits still apply.
Mixed TLS mode does not use this shared
pool/semaphore: setting it to 1 is **not** a one-request-per-origin admission
limit across fresh connections. This mode/pooling discrepancy is the documented limitation,
queued for correction, not fixed by this guide. H2 PING is opt-in; it is not an
application health check. Neither H2 setting is valid with `http1`.

## Set Deadlines Deliberately

| Setting | Current native meaning |
| --- | --- |
| `connect_timeout_secs` | DNS plus TCP connect budget; also a separate TLS handshake budget; default 5 seconds |
| `upstream_total_connection_timeout_secs` | Optional overall setup bound including protocol work on pooled H2; not an end-to-end request deadline |
| `send_timeout_secs` | Upstream request write budget; default 30 seconds for HTTP/1 |
| `read_timeout_secs` | HTTP/1 final response head and complete body together, not a timer reset by each byte; default 30 seconds |
| `downstream_read_timeout_secs` | Request-body read policy; default 60 seconds |
| `downstream_write_timeout_secs` | Downstream response write policy; default 30 seconds |
| `downstream_total_response_timeout_secs` | Downstream response-write lifetime; default 300 seconds, not total time spent at the origin |
| `downstream_min_send_rate_bytes_per_sec` | Optional minimum response-send rate; use only after testing slow legitimate clients |

Optional timeout values, when provided, must be positive and no more than
86400 seconds. For H2, an explicit `read_timeout_secs` sets the response-head/
readiness policy and the body-read policy; these are separate phases. Explicit
`send_timeout_secs` sets the H2 request-write lifetime. The native H2 defaults
are 30 seconds for each of these phases; set them explicitly when tuning budgets.

There is another setup-policy discrepancy: on a **fresh pooled
H2 connection**, the total-connection setting also shortens the first response
header wait. A reused connection does not get that shortening. Until corrected,
do not choose a tiny setup budget while assuming a long read budget always
applies to the first H2 response. Phase budgets are not one cumulative deadline;
retries and waiting for stream capacity can add time.

HTTP/1 responses are buffered subject to native response-size/admission bounds
before forwarding. These settings alone do not promise unbounded response
streaming or make long-lived event streams work. WebSocket is a separate opt-in
takeover; its tunnel currently has an absolute `read_timeout_secs` lifetime,
not a per-message idle timer. Read the [authorization warning](external-authorization.md)
before enabling upgrades on a protected route.

## Serve A Friendly Gateway Error

Create `errors/gateway.html` next to the recipe:

```html
<!doctype html><title>Temporarily unavailable</title>
<h1>Please try again shortly</h1>
```

```toml
[[vhosts.proxy.error_pages]]
status = 502
path = "/gateway.html"
[vhosts.proxy.error_pages.web]
root = "errors"
```

Add a separate entry for 504 as the complete recipe does. `path` is an internal
static request path under that entry's `web.root`, not an origin URL or an
arbitrary host filesystem path. Relative roots resolve from the config file.
This does not publish the error directory as a separate route.

- A final origin transport failure produces 502, or 504 for a timeout.
- A managed pool with no usable members can use its configured all-down status.
- An actual origin response such as 404, 500, 502 or 503 passes through; this is
  **not** an intercept-all-errors feature.
- Auth rejection, routing errors and every other middleware failure are not
  automatically replaced by these pages.
- The original failure status is retained. HEAD has no response body.
  Range and conditional request headers do not turn the fallback into 206/304.
- Duplicate status entries are rejected by configuration validation. The configuration
  accepts 400-599, but accepting a number does not create a new fallback trigger.
- Missing, forbidden, unreadable or oversized pages fall back to the built-in
  error response. Keep pages small and independent of PHP or the failing origin.
- Static-root trust and file access restrictions still apply; use a private,
  service-readable directory. Do not point it at a writable uploads directory.

Validate and start with the deployed binary:

```bash
fluxheim --config examples/proxy/transport.toml --validate-config
fluxheim --config examples/proxy/transport.toml
curl -i -H 'Host: app.example.test' http://127.0.0.1:8080/
```

With no origin listening on 9001 the response should be a custom 502. With a
healthy origin, requests reach that origin. Adjust the public listener and host
names deliberately for deployment; the example is loopback-only.

## Socket Options And Troubleshooting

[Transport options](../reference/proxy-transport-options.md) lists every tuning
field, supported combinations and platform restrictions. Start with defaults.
If a request fails, distinguish:

1. Configuration/startup rejection: unsupported feature, transport mode or path.
2. 502: refusal, TLS/protocol error or invalid/oversized origin response.
3. 504: a transport phase or capacity wait timed out.
4. Origin-produced error: inspect the origin logs; a gateway page is not used.

The socket connector currently tries only the first resolved address of a
hostname; it is not Happy Eyeballs or automatic fallback through every DNS
answer. Explicit healthy pool members/discovery
are a different mechanism. Deterministic multi-address runtime proof is pending.
Use operational events/metrics and origin logs together; avoid leaking raw
request headers or credentials when collecting diagnostics.

See also [external authorization](external-authorization.md),
[traffic mirroring](traffic-mirroring.md), [caching](cache.md) and
[operational status](operational-status.md). Live proof and outstanding
corrections are recorded in the [coverage ledger](../reference/documentation-coverage.md).
