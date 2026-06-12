# Fluxheim 1.5.19 Release Notes

Fluxheim 1.5.19 moves the Fluxheim-owned load-balancer core into the internal
`fluxheim-load-balancer` workspace crate and includes security hardening found
during the v1.5.19 review cycle.

## Security Fixes

- Fixed fallback proxy cache auth ordering so cache fallback handling cannot
  run before the configured authorization decision.
- Applied decoded route matching to edge policy checks, closing mismatches
  between encoded request paths and policy enforcement.
- Preserved private cache-control directives for status-specific TTL handling
  so restrictive origin cache headers are not weakened by cache policy.
- Hardened PHP-FPM path handling by denying scripts after resolved-path
  normalization and covering directory-index resolution under denied PHP path
  prefixes.
- Fixed proxy-only route decode feature wiring so shared path safety remains
  available in proxy builds without cache.
- Isolated upstream CA bundle material in peer reuse keys to avoid reusing
  upstream TLS peers across distinct trust material.
- Added a default stream proxy connection cap to avoid unbounded accepted TCP
  stream connections.
- Detached self-healing probes from public proxy traffic paths.
- Preserved restrictive PHP cache headers when PHP-FPM responses are converted
  into Fluxheim responses.
- Rejected PHP-FPM `PHP_VALUE` and `PHP_ADMIN_VALUE` style ini-control
  parameters so configured PHP params cannot rewrite php-fpm runtime policy.
- Cleaned pending PHP request-body spool files on retry/error paths.
- Added `php.max_in_flight`, defaulting to `8`, to cap concurrent PHP-FPM
  requests before request body buffering and FastCGI dispatch.
- Added `proxy.load_balance.passive_health.min_healthy_backends`, defaulting to
  `1`, so passive outlier ejection cannot fail-closed an entire load-balanced
  pool by default. Operators can set it to `0` to retain strict fail-closed
  passive-health behavior.
- Hardened managed-cookie load-balancer persistence so missing or invalid
  affinity cookies no longer create server-side persistence-table entries or
  trigger least-session table scans until the signed cookie is returned by the
  client.
- Rejected verified HTTP proxy upstream TLS configs that target an IP-addressed
  upstream without explicit `upstream_sni`, preventing the Pingora connector
  from falling into empty-SNI certificate-verification bypass behavior.
- Hardened HTTP load-balancer discovery so private, loopback, link-local,
  metadata, multicast, reserved, and documentation IP-literal backends are
  rejected by default unless the operator explicitly enables
  `proxy.upstreams_http_allow_private_backends`.
- Added `proxy.downstream_read_timeout_secs`, defaulting to 60 seconds, and
  wired it into vendored Pingora HTTP/2 downstream request-body reads so
  slow-body clients cannot hold proxy forwarding tasks indefinitely while
  withholding DATA frames or END_STREAM.
- Applied the downstream read timeout before PHP-FPM request-body collection and
  drain paths, covering PHP routes that read the body before FastCGI execution
  begins.
- Hardened downstream HTTP/2 flow-control defaults by capping per-stream send
  buffering at 256 KiB, keeping DATA frames at 16 KiB, fixing the receive
  window at 64 KiB, and reducing pending-accept reset-stream pressure.
- Removed encrypted filesystem disk-cache fill heap amplification for the local
  provider by committing streamed cache bodies through bounded AEAD chunks, and
  bounded the OpenBao Transit whole-object fallback heap budget.
- Hardened DNS-refreshed upstream discovery against DNS rebinding pivots by
  rejecting private, loopback, link-local, multicast, reserved, documentation,
  metadata, and unspecified resolved addresses unless
  `proxy.upstream_dns_allow_private_backends = true` is set.
- Hardened split-config trusted-proxy handling by extending
  `server.trusted_proxies` fragments instead of replacing the main list, and by
  rejecting catch-all or near-global trusted-proxy ranges such as `0.0.0.0/0`
  and `::/0`.
- Hardened split-config proxy handling by applying field-level `[proxy]`
  fragment merges so a later timeout-only proxy fragment cannot silently clear
  upstream TLS verification, auth request, mirror, or load-balancer policy.
- Hardened split-config handling for `[compression]`, `[cache]`,
  `[cache_purger]`, `[web]`, and `[stream]` so partial fragments cannot
  silently drop previously configured compression limits, cache encryption,
  static-file safety policy, or stream routes.
- Hardened split-config admin handling by applying field-level `[admin]`
  fragment merges so a later ops-socket or health-only admin fragment cannot
  silently disable the admin API or clear token and snapshot-store settings.
- Hardened cache peer-fill request construction so client-controlled `Host`
  headers and absolute-form URI authorities are not forwarded as the peer
  request `Host`.
- Added an inbound peer-fill recursion guard so requests marked with
  `X-Fluxheim-Peer-Fill: 1` cannot launch another outbound peer-fill fetch in
  cyclic peer topologies.
- Decoded percent-encoded cache bypass query names and values before comparing
  `bypass_query_params` and `bypass_query_values`, closing encoded preview or
  private-mode cache bypass evasion.
- Aligned configured cache Vary request headers with the 16-field runtime Vary
  cap and rejected effective origin-plus-configured Vary overflows at cache
  admission instead of dropping variance.
- Hardened auth-request response header handling so allowed auth response
  headers cannot override Fluxheim's upstream request header policy on name
  collisions.
- Hardened auth-request forwarded context handling so allow-listed
  `X-Original-URI`, `X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Host`, and
  `X-Forwarded-Proto` values are synthesized from Fluxheim's trusted request
  context instead of copied from spoofable client headers.
- Matched auth-request split `Cookie` handling to the origin request path by
  joining repeated `Cookie` fields with `; ` instead of `, ` before sending
  the authorization subrequest.
- Hardened Unix admin-token and file-log opening by using rustix
  architecture-correct `NOFOLLOW` flags instead of hand-coded constants.
- Hardened trusted-proxy `X-Forwarded-For` parsing so any malformed hop rejects
  the forwarded chain and falls back to the direct peer IP instead of silently
  attributing traffic to a trusted proxy hop.
- Normalized IPv4-mapped IPv6 client addresses before trusted-proxy,
  access-policy, rate-limit, and GeoIP decisions so IPv4 CIDR policy also
  applies on dual-stack listeners that report IPv4 peers as `::ffff:...`.
- Restricted WebSocket-enabled proxy routes to the `websocket` upgrade token so
  valid but unrelated protocol upgrades such as `h2c` are not forwarded to
  upstreams.
- Stripped HTTP/1 `Connection` and `Upgrade` request headers when
  `proxy.websocket = false`, preventing normal proxy routes from tunneling
  upgraded protocols by accident.
- Removed vendored Pingora upstream TLS underscore-to-hyphen hostname
  verification rewriting so certificates are checked against the exact
  configured SNI or alternative name.
- Stripped client-controlled hop-by-hop request headers before forwarding to
  upstreams, including `Connection`-listed extension headers and non-WebSocket
  `Upgrade` values.
- Hardened response `Location` and `Refresh` prefix rewrites so absolute URL
  prefixes only match the intended authority boundary and cannot rewrite
  userinfo-style URLs such as `http://origin@evil.example/`.
- Hardened traffic mirroring by rejecting unsafe mirrored paths/queries before
  outbound URL construction and suppressing recursive mirror requests marked
  with `X-Fluxheim-Mirror`.
- Added stream route `allow_sources` and `deny_sources` IP/CIDR policies so raw
  TCP stream listeners can reject unauthorized sources before connecting
  upstream.
- Hardened stream hostname upstreams against DNS-rebinding pivots by rejecting
  private or reserved DNS answers unless the route explicitly sets
  `upstream_dns_allow_private_addresses = true`.
- Rejected horizontal tabs in configured static header values so operator
  header policies cannot pass HTTP/1.x-only whitespace into HTTP/2 upstream
  requests or responses.
- Rewrote quoted `Refresh` response URLs for configured prefix rewrite rules,
  covering both single-quoted and double-quoted URL forms.
- Hardened runtime file-log opening by rejecting symlinked log path components
  immediately before creating or appending the log file.
- Hardened `Accept-Encoding` qvalue parsing so non-finite or malformed values
  such as `NaN` and `Infinity` cannot influence compression negotiation.
- Added `admin.ops_socket.require_bearer_token` so local Unix ops-socket status
  endpoints can require the same bearer token as the TCP admin control plane.

## What Changed

- Added `crates/fluxheim-load-balancer` as the internal owner of load-balancer
  backend snapshots, discovery adapters, active health checks, selection
  algorithms, runtime policy overrides, persistence, queue policy, state files,
  background task glue, and tests.
- Kept root `crate::load_balancer` as a compatibility shim so admin, proxy,
  runtime, status endpoints, release profiles, RPM/container packaging, and
  operator config syntax remain unchanged.
- Preserved the existing `profile-load-balancer-edge` image/profile and the
  full build's load-balancer support.
- Added narrow integration hooks for root-owned metrics recording and
  compliance HMAC signing, avoiding a dependency from the load-balancer crate
  back into proxy, admin, cache, web, or PHP internals.
- Kept the load-balancer crate's tests with the code they review, including
  selection, passive health, discovery, runtime mutation, persistence, and
  database/protocol health-check coverage.

## Compatibility

- Existing config files remain valid.
- Stream routes that use hostname upstreams resolving to private or reserved
  addresses must now set `upstream_dns_allow_private_addresses = true` when
  that resolution is intentional. IP-literal upstreams are unchanged.
- Existing admin load-balancer status and mutation APIs remain unchanged.
- Existing feature profiles and release artifact names are unchanged.
- Existing RPM and container production feature sets are unchanged.
- `fluxheim-load-balancer` is an internal workspace crate and is not published
  to crates.io.

## Not Included

- No new load-balancer features in this release.
- No removal of `pingora-load-balancing` yet.
- No removal of `pingora-cache` yet.
- No cache, web, PHP, or HTTP proxy orchestrator crate extraction in this
  release.
- No production UDP/GSLB promotion, HTTP/3/QUIC, WAF, VPN/firewall appliance
  behavior, Wasm/iRules/Lua runtime, or full Pingora HTTP proxy replacement in
  this release.

## Packaging Notes

- Release assets continue to publish the same `full`, `cache`, `proxy`,
  `load-balancer`, `php`, and `config-tester` artifacts.
- The load-balancer image remains the focused package for HTTP/TCP
  load-balancer deployments.
