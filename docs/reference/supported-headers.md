# HTTP Header Quick Reference

Use this page to find what a header does in Fluxheim and where to configure it.
Names are case-insensitive. **Forwarding a header does not mean Fluxheim
understands or trusts it.** This is an index of named HTTP behaviors in the
current native runtime, not a whitelist of every application header or a claim
of complete protocol support. Follow the linked guide for limits and examples.

Jump to [HTTP transport](#routing-bodies-and-connection-handling),
[client identity](#forwarding-and-client-identity),
[browser security](#browser-security-and-response-identity), [CORS](#cors),
[cache/compression](#caching-static-files-and-compression),
[authentication/tracing](#authentication-correlation-and-application-metadata),
[WebSocket/gRPC/PHP](#websocket-grpc-and-php) or
[private admin parameters](#private-admin-operation-headers).

## Reading The Tables

- **Read:** Fluxheim interprets the field for the stated operation.
- **Write:** Fluxheim generates, replaces or appends the field on that path.
- **Pass:** application/origin data can be forwarded without interpreting its meaning.
- **Remove:** Fluxheim strips it in the stated policy or transport stage.
- **Limited:** the linked guide describes restrictions; do not infer full support.

Request means client to Fluxheim, then optionally to an origin. Response means
Fluxheim/origin to the client. Admin and metrics listeners are separate from
public website routes. Profile, route, handler and configuration determine which
stages run; response policy does not cover every early error. Defaults below refer
to enabled policies, not every packet. Privacy builds impose additional removal
and feature restrictions; see [privacy mode](../guides/zero-retention-privacy-mode.md).

## Routing, Bodies And Connection Handling

| Header | What it means | Fluxheim behavior | Conditions / detail |
| --- | --- | --- | --- |
| `Host` | Requested site/authority | Read for host routing; sent to proxy origin according to host policy | Not the upstream TLS identity; [routing](../guides/routing.md), [upstream TLS](../guides/upstream-tls.md) |
| `Content-Type` | Body media type | Read by cache/compression/gRPC policies; write for local bodies; pass application values | PHP uses CGI content metadata; [PHP](../guides/php-runtime-support.md), [compression](../guides/compression.md) |
| `Content-Length` | Message body length | Read framing; write/recompute for generated or transformed bodies | Not a free-form framing override; [proxy transport](proxy-transport-options.md) |
| `Transfer-Encoding` | HTTP/1 transfer framing | Read framing; filter/reconstruct across proxy hops | Do not combine manually with Content-Length; [reverse proxy](../guides/reverse-proxy.md) |
| `Connection` | Options for this connection | Read; remove hop-local fields, including names listed by this field | Upgrade handling is separate; [WebSocket](../guides/websocket.md) |
| `Keep-Alive` | HTTP/1 connection hints | Remove from ordinary proxied requests | Does not configure Fluxheim's pool; [transport options](proxy-transport-options.md) |
| `Proxy-Connection` | Legacy proxy connection hints | Remove from ordinary proxied requests | Not an end-to-end application field; [transport options](proxy-transport-options.md) |
| `TE` | Transfer/trailer capability | Hop-by-hop handling, not unrestricted pass-through | Do not infer RPC trailer support; [gRPC limits](../guides/grpc.md) |
| `Trailer` | Names expected in a trailer section | Hop-by-hop filtering | Trailer availability depends on protocol/path; [gRPC limits](../guides/grpc.md) |
| `Upgrade` | Request a protocol change | Read by eligible WebSocket takeover; remove from ordinary proxy forwarding | Requires route support; [WebSocket](../guides/websocket.md) |
| `Allow` | Methods a resource permits | Local handlers can write it; otherwise application data | A response field, not route authorization; [routing](../guides/routing.md) |
| `Retry-After` | Suggested wait before retrying | Local rate/concurrency rejections write a fixed `1` second; origin values can pass | Not an exact queue estimate or automatic client/upstream retry; [admission limits](../guides/rate-and-concurrency-limits.md) |
| `Date` | Response creation timestamp | Origin/local response metadata where emitted | Not an application-configurable clock; [caching](../guides/cache.md) |

HTTP/2 pseudo-fields such as `:method`, `:scheme`, `:authority`, `:path` and
`:status` are protocol metadata, not ordinary names to insert using header
mutation settings. Enabling HTTP/2 does not enable HTTP/3 or every gRPC workflow.

## Forwarding And Client Identity

Configure these through [request header policy](../guides/request-headers.md).
`server.trusted_proxies` controls acceptance of forwarded identity; it is not a
network allowlist. Restoring an address for access policy does not currently
guarantee identical upstream header output. Review the linked guide's limits.

| Header | What it means | Fluxheim behavior / default |
| --- | --- | --- |
| `X-Forwarded-For` | Proxy client-address chain | Read only through the trusted-peer policy; default stripping followed by `replace` generation; `append` and `off` are configurable |
| `X-Real-IP` | Single forwarded client address | Remove inbound and generate by default; not an independent source of trust |
| `X-Forwarded-Host` | Public requested host | Remove inbound and generate from captured Host by default |
| `X-Forwarded-Proto` | Forwarded request scheme | Remove inbound and generate from the connection to Fluxheim by default, not the visitor's earlier connection to a CDN |
| `Forwarded` | Standard proxy metadata | Remove inbound by default; optional generation, disabled by default |
| `CF-Connecting-IP` | Cloudflare visitor-address assertion | Remove under default spoof stripping; no native Cloudflare identity decoder |
| `True-Client-IP` | Provider client-address assertion | Remove under default spoof stripping; not independently trusted |
| `X-Client-IP` | Application/proxy client-address assertion | Remove under default spoof stripping |
| `Client-IP` | Client-address assertion | Remove under default spoof stripping |
| `X-Cluster-Client-IP` | Cluster-forwarded client assertion | Remove under default spoof stripping |
| `Fastly-Client-IP` | Provider client-address assertion | Remove under default spoof stripping |
| `X-Envoy-External-Address` | Proxy external-address assertion | Remove under default spoof stripping |
| `X-Original-Forwarded-For` | Preserved forwarding-chain assertion | Remove under default spoof stripping |
| `X-Azure-ClientIP` | Provider client-address assertion | Remove under default spoof stripping |
| `Fly-Client-IP` | Provider client-address assertion | Remove under default spoof stripping |
| `X-ProxyUser-IP` | Proxy client-address assertion | Remove under default spoof stripping |
| `X-Forwarded-Client-Cert` | Forwarded certificate assertion | Remove under default spoof stripping; not native TLS certificate verification |

Other `CF-*` names, including `CF-Ray` and `CF-IPCountry`, are not automatically
interpreted, authenticated or converted into native trace/GeoIP policy. Do not
assume the stripping list removes every vendor field. See
[CDN origin boundaries](../guides/cloudflare-origin-support.md).

## Browser Security And Response Identity

Configuration and examples: [response headers](../guides/response-headers.md).
Browser enforcement is separate from Fluxheim's server-side access control.

| Header | What it does | Fluxheim behavior / setting |
| --- | --- | --- |
| `X-Content-Type-Options` | Discourages MIME sniffing | Write `nosniff` by default; `x_content_type_options` |
| `X-Frame-Options` | Restricts framing of the page | Write `DENY` by default; `x_frame_options` |
| `Referrer-Policy` | Controls browser referrer disclosure | Write `no-referrer` by default; `referrer_policy` |
| `Strict-Transport-Security` | Browser HTTPS policy | Optional `hsts` table or `strict_transport_security` string; neither enables TLS nor redirects HTTP |
| `Content-Security-Policy` | Browser content restrictions | Optional `content_security_policy`; no automatic nonce or semantic CSP validation |
| `Content-Security-Policy-Report-Only` | Report CSP violations without enforcement | Optional `content_security_policy_report_only` |
| `Permissions-Policy` | Browser feature permissions | Optional typed policy or hardening profile; not application authorization |
| `Cross-Origin-Opener-Policy` | Browsing-context isolation | Optional `cross_origin_opener_policy` or isolation profile |
| `Cross-Origin-Resource-Policy` | Cross-origin resource use policy | Optional `cross_origin_resource_policy` or isolation profile |
| `Cross-Origin-Embedder-Policy` | Cross-origin embedding requirements | Optional `cross_origin_embedder_policy` or isolation profile |
| `X-Permitted-Cross-Domain-Policies` | Legacy cross-domain policy-file control | Optional setting; baseline hardening writes `none`; not CORS |
| `Reporting-Endpoints` | Named browser report destinations | Write from `reporting_endpoints`; no report receiver is created |
| `Server` | Server identification | Local server identity can be `fluxheim`; baseline hardening removes it where policy runs |
| `X-Powered-By` | Application/framework identification | Removed by the default response `unset` policy; replacing that list changes the default |

## CORS

CORS is browser cross-origin response access, **not authentication** or a general
method firewall. Fluxheim's CORS policy is disabled by default. When enabled it
owns the listed response fields on its response paths; an upstream value is not
an automatic fallback. Configuration and examples: [CORS](../guides/cors.md).

| Header | What it does | Fluxheim behavior |
| --- | --- | --- |
| `Origin` | Browser requesting origin | Read against configured origins |
| `Access-Control-Request-Method` | Method proposed by a preflight | Read for local OPTIONS preflight handling |
| `Access-Control-Request-Headers` | Header names proposed by a preflight | Read against the configured explicit header allowlist |
| `Access-Control-Allow-Origin` | Origin allowed to read the response | Write when policy allows; review wildcard/cache variation limits |
| `Access-Control-Allow-Credentials` | Permit credentialed browser access | Write `true` only with configured credentialed policy |
| `Access-Control-Allow-Methods` | Methods admitted by preflight | Write configured method list on handled preflights |
| `Access-Control-Allow-Headers` | Header names admitted by preflight | Write configured allowed names on handled preflights |
| `Access-Control-Expose-Headers` | Response names readable by browser JavaScript | Write configured names; does not create those headers |
| `Access-Control-Max-Age` | Browser preflight caching lifetime | Optional configured seconds; not the HTTP object cache TTL |
| `Access-Control-Allow-Private-Network` | Private-network access permission | Removed by active CORS ownership; no generation option |
| `Access-Control-Request-Private-Network` | Private-network preflight request | No dedicated permission policy; do not infer private-network access support |

## Caching, Static Files And Compression

| Header | What it does | Fluxheim behavior / detail |
| --- | --- | --- |
| `Cache-Control` | Request/response cache and transformation directives | Read selected directives; emit configured local policy. Not every directive has every effect; [caching](../guides/cache.md), [compression](../guides/compression.md) |
| `Pragma` | Legacy cache directives | Request no-cache participates in configured refresh; [caching](../guides/cache.md) |
| `Expires` | Response expiry date | Static handler can emit a configured literal; application response can pass through. Do not assume it supplies proxy-cache TTL; [static files](../guides/static-files.md) |
| `Age` | Cached response age | Read origin age for freshness accounting; write on cached responses; [caching](../guides/cache.md) |
| `Vary` | Request fields distinguishing representations | Read for cache variants; CORS/compression can modify it. Review current variation limits; [cache options](cache-options.md) |
| `ETag` | Representation validator | Generate for static files; use cached/origin validators. Compression removes old validators; [static files](../guides/static-files.md) |
| `Last-Modified` | Representation modification time | Emit static file metadata; use origin/cache revalidation; [static files](../guides/static-files.md) |
| `If-Match` | Require a matching validator | Read by static preconditions; not generic proxy authorization; [static files](../guides/static-files.md) |
| `If-Unmodified-Since` | Require no change since a timestamp | Read by static preconditions; [static files](../guides/static-files.md) |
| `If-None-Match` | Conditional request by validator | Static condition and cache revalidation paths; [static files](../guides/static-files.md), [cache](../guides/cache.md) |
| `If-Modified-Since` | Conditional request by modification time | Static condition and cache revalidation paths; [static files](../guides/static-files.md) |
| `Range` | Request a byte interval | Static and configured cache range paths read it; ordinary origins may handle it; [range limits](../guides/cache-ranges.md) |
| `If-Range` | Conditional range validator | Read by supported static/cache range paths; [range limits](../guides/cache-ranges.md) |
| `Accept-Ranges` | Advertised range unit | Static responses advertise `bytes`; [static files](../guides/static-files.md) |
| `Content-Range` | Returned byte interval | Write partial/static range metadata; validate range-cache responses; suppress compression for partial content; [ranges](../guides/cache-ranges.md) |
| `Accept-Encoding` | Accepted body encodings and priorities | Read by enabled compiled codecs; review identity/negotiation limits; [compression](../guides/compression.md) |
| `Content-Encoding` | Body encoding | Set after compression; already encoded origin bodies are not transparently decoded/recompressed; [compression](../guides/compression.md) |
| `Cookie` | Application session/state | Pass to the application subject to policy; excludes compression. Not a universal cache bypass: configure cookie rules; [cache](../guides/cache.md) |
| `Set-Cookie` | Set application session/state | Pass or configured domain/path rewrite; excludes ordinary cache admission and compression; [response rewriting](../guides/response-headers.md#redirect-and-cookie-rewriting) |
| `Surrogate-Key` | Object purge tags | Read as a bounded tag source, not a freshness directive; [cache operations](../guides/cache-operations.md) |
| `Cache-Tag` | Object purge tags | Read as a bounded tag source; [cache operations](../guides/cache-operations.md) |
| `X-Cache-Tags` | Object purge tags | Read as a bounded tag source; [cache operations](../guides/cache-operations.md) |
| `X-Cache-Status` | Example cache outcome diagnostic | Optional configured `cache.status_header`, not a fixed default name; [cache options](cache-options.md) |
| `X-Cache-Reason` | Example cache decision diagnostic | Optional configured `cache.status_reason_header`, not a fixed default name; [cache options](cache-options.md) |
| `Cache-Status` | Structured cache outcome | Optional response `metadata.cache_status`; distinct from the custom status field; [metadata](response-header-options.md#metadata) |
| `Proxy-Status` | Structured proxy failure | Optional response `metadata.proxy_status`; bounded categories, not raw errors; [metadata](response-header-options.md#metadata) |
| `Content-Digest` | Digest of message content | Optional SHA-256 generation after buffered processing; not a signature; [metadata](response-header-options.md#metadata) |
| `Repr-Digest` | Digest of a complete representation | Optional generation only on eligible complete responses; otherwise removal on that stage; [metadata](response-header-options.md#metadata) |

Load-balancer cookie hashing/persistence also reads selected Cookie values;
managed-cookie affinity can generate Set-Cookie. These are opt-in
[load-balancer policies](../guides/load-balancer.md), not session authentication.

## Authentication, Correlation And Application Metadata

| Header | What it does | Fluxheim behavior / detail |
| --- | --- | --- |
| `Authorization` | Credentials for the addressed service | Read for admin/metrics bearer auth; public application auth is separate. May be forwarded/allowlisted to auth subrequests; presence bypasses proxy cache and compression. [Admin](../guides/admin.md), [metrics](../guides/metrics.md), [external auth](../guides/external-authorization.md) |
| `Proxy-Authorization` | Credentials for a proxy | Cache bypass input and hop-local stripping; not a general forward-proxy login feature; [cache](../guides/cache.md) |
| `WWW-Authenticate` | Authentication challenge | Write on relevant auth failures; selected auth-service denial fields can pass; [metrics](../guides/metrics.md), [external auth](../guides/external-authorization.md) |
| `Proxy-Authenticate` | Proxy authentication challenge | Hop-by-hop request filtering; no implied forward-proxy authentication product; [proxy transport](proxy-transport-options.md) |
| `X-Request-Id` | Diagnostic request identifier | Default managed ID field; accepted only with provenance/syntax checks, otherwise regenerated; [tracing](../guides/opentelemetry-tracing.md) |
| `X-Correlation-Id` | Alternative diagnostic identifier | Optional managed field instead of X-Request-Id; not an authentication credential; [logging](../guides/logging.md) |
| `Traceparent` | W3C trace/parent context | Bounded validated trusted-parent input and generated trace context when enabled; removed inbound even when tracing is disabled; [tracing](../guides/opentelemetry-tracing.md) |
| `Tracestate` | Vendor trace context | Native telemetry removes inbound values; not implicitly propagated/stored; [tracing](../guides/opentelemetry-tracing.md) |
| `Baggage` | Cross-service trace metadata | Native telemetry removes inbound values; not implicitly propagated/stored; [tracing](../guides/opentelemetry-tracing.md) |
| `X-Original-URI` | Original-target context for an auth service | Synthesized when selected in auth `forward_headers`; reflects the current request at that stage; [external auth](../guides/external-authorization.md) |
| `X-Forwarded-URI` | Target context for an auth service | Same current-target synthesis when explicitly allowlisted; [external auth](../guides/external-authorization.md) |
| `X-Auth-Request-Redirect` | Redirect-context name used by auth services | Synthesizes the current target, not an absolute login URL, when allowlisted; [external auth](../guides/external-authorization.md) |
| `X-Auth-Request-User` | Example identity returned by an auth service | Configured allowlisted output, not a built-in identity authority. Strip untrusted input explicitly; [external auth](../guides/external-authorization.md) |
| `Location` | Redirect destination | Write for local redirects or pass/rewrite origin values; selected auth denial propagation; [routing](../guides/routing.md), [response rewriting](../guides/response-headers.md#redirect-and-cookie-rewriting) |
| `Refresh` | Timed browser navigation | Optional literal-prefix URL rewriting; not a general URL allowlist; [response rewriting](../guides/response-headers.md#redirect-and-cookie-rewriting) |
| `Content-Disposition` | Download/display filename hint | Application data or explicit generic response mutation; not a filename-based access rule; [response headers](../guides/response-headers.md) |

## WebSocket, gRPC And PHP

| Header | What it does | Fluxheim behavior / detail |
| --- | --- | --- |
| `Sec-WebSocket-Key` | Client handshake key | Upgrade request processing/forwarding; not application authentication; [WebSocket](../guides/websocket.md) |
| `Sec-WebSocket-Version` | Requested WebSocket handshake version | Handshake input; review supported path and validation limits; [WebSocket](../guides/websocket.md) |
| `Sec-WebSocket-Accept` | Origin handshake response | Tunnel handshake response handling; do not infer complete negotiation validation; [WebSocket](../guides/websocket.md) |
| `Sec-WebSocket-Protocol` | Application subprotocol negotiation | Handshake forwarding, with current negotiation limits; [WebSocket](../guides/websocket.md) |
| `Sec-WebSocket-Extensions` | WebSocket extension negotiation | Handshake data, not Fluxheim frame/extension processing; [WebSocket](../guides/websocket.md) |
| `Grpc-Status` | RPC result status | Local gRPC rejection paths write it; routed trailer delivery remains limited; [gRPC](../guides/grpc.md) |
| `Grpc-Message` | RPC result explanation | Local rejection metadata or origin data; not proof of complete gRPC support; [gRPC](../guides/grpc.md) |
| `Grpc-Timeout` | RPC deadline | No dedicated native deadline contract; ordinary pass-through is not enforcement; [gRPC](../guides/grpc.md) |
| `Status` | CGI response status | PHP response parser input, not a replacement for an HTTP status line supplied by a client; [PHP runtime](../guides/php-runtime-support.md) |
| `Proxy` | HTTP proxy-environment assertion | Excluded from PHP HTTP_* translation; [PHP runtime](../guides/php-runtime-support.md) |
| `X-Accel-Redirect` | Proposed internal file offload | Stripped from PHP replies without native offload effect; [PHP runtime](../guides/php-runtime-support.md) |
| `X-Sendfile` | Proposed file offload | Stripped from PHP replies without native offload effect; [PHP runtime](../guides/php-runtime-support.md) |
| `X-Accel-Expires` | Proposed offload/cache expiry | Stripped from PHP replies without native expiry effect; [PHP runtime](../guides/php-runtime-support.md) |

## Private Admin Operation Headers

These are request parameters on the documented admin routes, **not commands on
public website listeners**. Authentication, role, method, path, feature and scope
checks still apply. Do not put credentials into custom diagnostic fields.

| Header | Meaning | Detailed guide |
| --- | --- | --- |
| `X-Client-Cert-SHA256` | Default configurable forwarded certificate fingerprint for the explicit trusted admin TLS-terminator mode; not automatically trusted on public routes | [Admin TLS termination](../guides/admin.md) |
| `X-Fluxheim-Health` | Report candidate health to the recovery controller | [Snapshots](../guides/config-snapshots.md) |
| `X-Fluxheim-Message` | Optional snapshot message | [Snapshots](../guides/config-snapshots.md) |
| `X-Fluxheim-Rollback-To` | Select rollback snapshot | [Snapshots](../guides/config-snapshots.md) |
| `X-Fluxheim-Live-Apply` | Request supported live application during rollback | [Snapshots](../guides/config-snapshots.md) |
| `X-Fluxheim-Lb-Vhost` | Select load-balancer vhost | [Load balancing](../guides/load-balancer.md) |
| `X-Fluxheim-Lb-Route` | Select optional load-balancer route | [Load balancing](../guides/load-balancer.md) |
| `X-Fluxheim-Lb-Member` | Select or supply member identity, depending on operation | [Load balancing](../guides/load-balancer.md) |
| `X-Fluxheim-Lb-State` | Requested member state | [Load balancing](../guides/load-balancer.md) |
| `X-Fluxheim-Lb-Weight` | Requested member weight | [Load balancing](../guides/load-balancer.md) |
| `X-Fluxheim-Lb-New-Member` | Replacement member address | [Load balancing](../guides/load-balancer.md) |
| `X-Fluxheim-Lb-Address` | Alias for replacement member address | [Load balancing](../guides/load-balancer.md) |
| `X-Fluxheim-Cache-Vhost` | Select cache vhost | [Cache operations](../guides/cache-operations.md) |
| `X-Fluxheim-Cache-Route` | Select optional route cache | [Cache operations](../guides/cache-operations.md) |
| `X-Fluxheim-Cache-Host` | Object key's host | [Cache operations](../guides/cache-operations.md) |
| `X-Fluxheim-Cache-Method` | Object key's method | [Cache operations](../guides/cache-operations.md) |
| `X-Fluxheim-Cache-Path` | Exact object path, also bulk-path fallback | [Cache operations](../guides/cache-operations.md) |
| `X-Fluxheim-Cache-Paths` | Comma-separated bulk paths | [Cache operations](../guides/cache-operations.md) |
| `X-Fluxheim-Cache-Query` | Object key's query | [Cache operations](../guides/cache-operations.md) |
| `X-Fluxheim-Cache-Path-Prefix` | Prefix for indexed traversal | [Cache operations](../guides/cache-operations.md) |
| `X-Fluxheim-Cache-Path-Pattern` | Pattern for indexed traversal | [Cache operations](../guides/cache-operations.md) |
| `X-Fluxheim-Cache-Tag` | Object tag to purge | [Cache operations](../guides/cache-operations.md) |
| `X-Fluxheim-Cache-Limit` | Per-batch work limit | [Cache operations](../guides/cache-operations.md) |
| `X-Fluxheim-Cache-Batches` | Maximum traversal batches | [Cache operations](../guides/cache-operations.md) |
| `X-Fluxheim-Cache-Soft` | Request supported soft-purge behavior | [Cache operations](../guides/cache-operations.md) |
| `X-Fluxheim-Cache-Dry-Run` | Request stale-purge preview; review current limitations before use | [Cache operations](../guides/cache-operations.md) |

## Custom Names And Examples

An unlisted valid application header can pass through the ordinary proxy path
unless framing, hop-by-hop filtering, privacy, an auth policy or configured
mutations remove it. This does not implement a new standard, establish trust or
make an arbitrary `{http.<name>}` template work.

Configured names can also supply route matching, load-balancer hash/persistence
keys, cache variation/bypass and auth-service input/output allowlists. Such names
are selected by configuration rather than a fixed built-in list. Apply each
feature's validation and trust rules; a matching name alone grants no authority.

Use these complete examples instead of inventing a header-specific TOML switch:

- [Request forwarding and mutations](../../examples/headers/request.toml).
- [Browser response policy and rewriting](../../examples/headers/response.toml).
- [CORS origin/method/header allowlists](../../examples/headers/cors.toml).
- [Caching with optional diagnostics](../guides/cache.md#try-a-public-asset).
- [Tracing and managed diagnostic IDs](../guides/opentelemetry-tracing.md).

Use generic remove/replace/append operations only where appropriate. Do not
override protocol framing, append identity assertions, or log secrets to debug
header handling. Inspect both the client-visible response and a controlled
origin's received request: they are different sides of the proxy.

## Source And Verification

The tables are reconciled against [shared header policy](../../crates/fluxheim-headers/src/lib.rs),
[hop-by-hop policy](../../crates/fluxheim-headers/src/hop_by_hop.rs),
[native response policy](../../crates/fluxheim-server/src/native_http1_route_response_headers.rs),
[CORS](../../crates/fluxheim-server/src/native_http1_cors.rs),
[response metadata](../../crates/fluxheim-server/src/native_http1_response_metadata.rs),
[request telemetry](../../crates/fluxheim-server/src/native_request_telemetry.rs),
cache/static/PHP consumers and [admin dispatch](../../src/admin/request_router.rs).
Automated inventory checks catch missing names in key fixed sets; linked guides
and live tests establish behavior. Neither a listed header nor a static inventory
test is complete native-platform qualification or release acceptance.
