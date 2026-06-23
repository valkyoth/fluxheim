# Fluxheim 1.6.29 Release Notes

Fluxheim 1.6.29 continues the Pingora-exit work by moving inherited
compression, header-policy behavior, and safe forwarded-header ownership into
the native HTTP/1 proxy path.

## Highlights

- Native HTTP/1 plain proxy responses can now use inherited global/vhost
  compression policy when gzip, brotli, or zstd support is compiled.
- Native HTTP/1 route proxy responses now inherit global/vhost compression
  when a route does not override compression locally.
- Native route proxy construction now merges root/vhost header policy with the
  route overlay before building native request and response header policies.
- Root and vhost header mutation policy no longer blocks native HTTP/1 proxy
  cutover when it only uses supported header set/remove/append behavior.
- Native HTTP/1 proxy handling now owns the safe forwarded-client-IP header
  modes: `X-Forwarded-For = off`, `X-Forwarded-For = replace`, `X-Real-IP`,
  `X-Forwarded-Host`, `X-Forwarded-Proto`, and RFC `Forwarded`.
- Native HTTP/1 route proxy handling now owns trusted-chain
  `X-Forwarded-For = append` for routes and programmatic builders, preserving
  inbound chains only when the direct peer matches configured trusted sources.
- Native HTTP/1 route proxy handling now owns regex route matching and
  path-only `rewrite_template` capture expansion, including exact route,
  longest-prefix route, first-regex route, and fallback precedence.
- Native HTTP/1 route proxy handling now owns IP/CIDR allow/deny access policy
  at both vhost and route scope, using trusted `X-Forwarded-For` client
  restoration when configured trusted sources identify the direct peer.
- Native HTTP/1 route proxy handling now owns vhost and route concurrency
  limits, including immediate rejection and bounded queued waits.
- Native HTTP/1 route proxy handling now owns vhost and route local rate
  limits, including token-bucket rejection and delay-mode admission.
- Native HTTP/1 proxy responses now carry configured downstream write timeout,
  total response timeout, and minimum send-rate policy.
- Native HTTP/1 upstream establishment now honors
  `proxy.upstream_total_connection_timeout_secs` across DNS, TCP connect, and
  optional TLS handshake setup.
- Native HTTP/1 upstream socket creation now honors
  `proxy.upstream_tcp_recv_buffer_bytes`, `proxy.upstream_dscp`, and the
  upstream TCP keepalive triple before connecting. On targets with
  `TCP_USER_TIMEOUT`, it also honors `proxy.upstream_tcp_user_timeout_ms`.
- Native HTTP/1 request-body parsing now honors
  `proxy.downstream_read_timeout_secs` selected by the matched proxy before
  forwarding to upstreams.
- Native HTTP/1 requests now carry typed optional TLS client identity and Geo
  context fields. Rustls and OpenSSL listener tests prove downstream TLS
  request context is populated with negotiated protocol, cipher, and peer
  certificate fingerprint where available.
- Native route-proxy access evaluation now enforces client-certificate
  fingerprint and Geo country/ASN rules when typed request context is present,
  so cert/Geo policy no longer blocks the native HTTP/1 cutover inventory.
- Managed local ACME HTTP-01 challenge serving now has a native route action.
  Live route-proxy tests prove direct and alias vhost challenge ownership, safe
  token-file loading, GET/HEAD handling, and `405 Allow: GET, HEAD` behavior.
- Native ACME HTTP-01 challenge file loading now runs on Tokio's blocking pool
  instead of blocking the async worker thread.
- Native HTTP/1 proxy handling now supports safe-method traffic mirroring when
  the `traffic-mirror` feature is compiled, including recursion protection,
  sampling, forwarded-header selection, mirror response caps, and per-target
  in-flight limits.
- Native HTTP/1 proxy handling now supports `proxy.auth_request` when the
  `auth-request` server feature is compiled, including trusted context header
  synthesis, bounded blocking subrequests, response-header allowlisting, and
  deny-before-forwarding behavior.
- Native HTTP/1 route proxy handling now honors route-scoped
  `[vhosts.routes.grpc]` validation, rejecting non-POST requests, duplicate
  `Content-Type` headers, and non-gRPC content types before forwarding.
- The compatibility proxy's gRPC route `Content-Type` gate now matches the
  native gate by rejecting duplicate `Content-Type` headers and accepting
  case-insensitive gRPC media types.
- Root and vhost compression no longer blocks native HTTP/1 proxy cutover when
  a matching compression backend feature is compiled.
- Native route-proxy construction now mirrors the compatibility route order for
  vhost synthetic routes: explicit ACME HTTP-01 upstream challenge routes,
  configured routes, then vhost redirect fallback routes.
- Vhost redirects and explicit ACME HTTP-01 upstream challenge routes no longer
  block the native cutover inventory when their generated route policies are
  otherwise native-safe.
- Live native listener tests now prove plain-proxy gzip compression, inherited
  route gzip compression, inherited request-header mutation, inherited
  response-header mutation, and standard response security headers.

## Security Notes

- Inherited native compression keeps the same guarded behavior as route-level
  compression: bounded input/output size, negotiated `Accept-Encoding`, safe
  method/status checks, and privacy-sensitive header exclusions.
- Native compression strips origin `ETag` and `Content-Length`, appends
  `Vary: accept-encoding`, and lets native response framing compute the final
  compressed length.
- Native route request headers are removed or overwritten before the upstream
  request is sent, matching the compatibility-path policy order for the
  supported mutation subset.
- The low-level native upstream writer no longer hardcodes client-IP forwarding;
  proxy/header policy now owns `X-Forwarded-For` so privacy-mode and ordinary
  builds share one explicit policy boundary.
- Native route request-header overlay builders now start from the same secure
  forwarded-header baseline as config-driven policy, so omitted overlay fields
  still strip spoofable inbound client-IP headers and synthesize owned
  forwarding context.
- Future trusted-chain append handling reads the inbound `X-Forwarded-For` chain
  after any configured spoofable-header stripping, so strip-plus-append degrades
  to the direct peer address instead of preserving attacker-supplied hops.
- Native route tests prove ACME challenge paths are selected before a vhost
  redirect fallback, preserving the HTTP-01 exception ordering used by the
  compatibility path for explicit upstream challenge forwarding.
- Native cutover now rejects route request-header overlays that set
  `enabled = false`, because disabling the request header policy would also
  disable forwarded-client-IP sanitation on that native route.
- Native vhost fallback proxy traffic now receives the merged root/vhost header
  policy, so requests that miss named routes still strip spoofable
  client-IP headers and synthesize owned forwarding context.
- Privacy-mode native route request headers are stripped after all configured
  request-header mutations, preventing operator `set` or `append` rules from
  reintroducing spoofable forwarded-client-IP fields.
- Programmatic native route constructors now start with the same safe default
  request-header policy used by config-built routes, instead of a no-op policy.
- Native trusted append uses the same effective-client-IP restoration helper as
  the compatibility path, so untrusted direct peers cannot preserve spoofed
  inbound forwarding chains.
- Native regex rewrite templates percent-encode bounded capture values and
  reject rewritten paths that would traverse or introduce unsafe forwarding
  paths before any upstream connection is opened.
- Native regex rewrite captures now encode slash characters and fail closed
  under the native safe-forward-path policy, so regex captures cannot introduce
  path hierarchy that was not present in the static rewrite template.
- Native access policy denies before redirects, static-web actions, or upstream
  proxying run, so rejected requests cannot be transformed into downstream
  effects first.
- Native vhost access policy uses the same trusted forwarded-chain restoration
  helper as forwarded-header synthesis, so allow/deny decisions see the
  effective client IP only when the direct peer is trusted.
- Native route access policy also checks a percent-decoded policy path, matching
  the compatibility path's encoded-route bypass hardening for access decisions.
- Native concurrency limits are enforced before rewrite, local static,
  redirect, or upstream proxy actions run; permits are held until the native
  response is produced.
- Native rate limits are enforced before rewrite, local static, redirect, or
  upstream proxy actions run; excess requests are rejected before the native
  upstream path is reached, and delay-mode sleeps run before concurrency permit
  acquisition so delayed requests cannot exhaust configured concurrency budgets.
- Native trusted-proxy client restoration joins duplicate inbound
  `X-Forwarded-For` headers before ACL and rate-limit identity decisions.
- Malformed `X-Forwarded-For` trusted-proxy chains now fail closed on both the
  native header crate path and the compatibility proxy path, falling back to
  the direct peer address instead of skipping poisoned hops.
- Native rate-limit table eviction sweeps are bounded so a full bucket table
  cannot trigger repeated full-table scans on every new identity.
- Native rate-limit tables are now sharded so stale-entry pruning only blocks
  one shard of identities at a time.
- Native proxy config now accepts response-side downstream policy and per-proxy
  downstream request-read timeout policy on the native path.
- Native proxy config now accepts total upstream connection timeout while
  keeping TCP Fast Open as an explicit native transport blocker.
- The configuration reference now documents that
  `proxy.upstream_tcp_fast_open` remains compatibility-runtime only during the
  1.6 native preview until a safe native socket path has parity tests.
- Native proxy config and live loopback tests now prove receive-buffer and DSCP
  socket options plus TCP keepalive and supported TCP user-timeout are accepted
  and still connect through the native proxy path.
- Native listener tests now prove plain HTTP requests leave TLS client identity
  and Geo context unset by default.
- Native route tests now prove client-certificate fingerprint and Geo
  country/ASN policies reject requests before upstream forwarding when the
  typed request context does not satisfy the configured policy.
- Native HTTP/1 proxy tests now prove traffic mirroring reaches a local mirror
  endpoint without changing the origin response.
- Native HTTP/1 proxy tests now prove auth-request allow responses can inject
  configured upstream headers and auth-request deny responses stop before any
  upstream connection is made.
- Native cutover-plan tests now prove `proxy.auth_request` and safe-method
  traffic mirroring are native-ready only when their matching server feature
  gates are compiled.
- Native traffic mirroring now honors only Fluxheim's signed internal mirror
  marker for loop prevention, so client-supplied `X-Fluxheim-Mirror` headers
  cannot suppress the configured mirror feed.
- Native proxy forwarding now strips inbound `X-Fluxheim-Mirror` and
  `X-Fluxheim-Mirror-Signature` headers before forwarding to the origin.
- Native traffic-mirror marker signatures are now compared through
  `sanitization::ct::ConstantTimeEq`; this release also updates
  `sanitization` to 1.2.1 and `rustls` to 0.23.41.
- Native auth-request 2xx response bodies that are read only for the configured
  size cap are now zeroized before release, and allowlisted auth response
  headers use zeroizing temporary storage before being copied into the upstream
  request.
- Native proxy tests now prove a slow request body times out before any
  upstream connection is attempted when `proxy.downstream_read_timeout_secs`
  is selected.
- Native proxy and cutover-plan tests now prove upstream HTTP/2 and H2 tuning
  knobs remain explicit native blockers for the dedicated 1.6.30 upstream H2
  connection-manager slice.
- Native route tests now prove gRPC policy rejects non-gRPC requests, rejects
  duplicate `Content-Type`, emits gRPC status metadata on local rejections, and
  forwards valid case-insensitive `application/grpc*` requests.
- Compatibility-path gRPC policy tests now prove duplicate `Content-Type`
  headers are rejected and case-insensitive `application/grpc*` media types are
  accepted.
- Native HTTP/1 now sends `408 Request Timeout` before closing connections that
  exceed the selected request-body timeout.
- Native route proxy timeout selection no longer lets redirect or static-web
  routes inherit a fallback proxy's longer request-body timeout.
- Native DSCP fallback compilation now covers targets without Tokio IPv6
  traffic-class support, and the receive-buffer conversion rejects an
  impossible oversized value with a dedicated diagnostic instead of silently
  ignoring it.
- Config validation and native regex route compilation now apply the same
  explicit NFA and DFA cache limits.
- Privacy-mode native route proxy handling now strips spoofable
  `X-Forwarded-Host` and `X-Forwarded-Proto` headers along with client-IP
  forwarding headers.
- Native trusted-source CIDR matching now rejects directly constructed invalid
  prefix lengths without relying on implicit shift arithmetic.
- Programmatic request-header policy defaults now match TOML deserialization for
  `X-Real-IP`, avoiding divergent native route behavior between config-built and
  builder-created routes.
- Privacy-mode native proxy builds strip spoofable inbound client-IP headers and
  do not compile the non-privacy forwarded-header synthesis helpers.
- Native route responses now apply inherited standard security headers such as
  `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy`, CSP, and HSTS
  where configured.
- The configuration reference now warns that disabling inbound forwarded-header
  stripping while also disabling owned `X-Forwarded-Host` or
  `X-Forwarded-Proto` synthesis permits client-supplied values for those
  headers to reach upstreams.

## Compatibility

This release does not remove Pingora from normal builds yet. The remaining
compatibility blockers are upstream TCP Fast Open, cache lookup/fill/stale
behavior, PHP-FPM routing, dynamic discovery, health-aware load balancing,
persistence, priority/backup/drain state, hash-based load-balancer selection,
and upstream HTTP/2 connection-manager parity.
