# Fluxheim 1.6.32 Release Notes

Fluxheim 1.6.32 continues the final native-runtime cutover work after the
cache/PHP adapter slice.

This checkpoint focuses on native runtime dispatch, native load-balancer state
sharing, and the first native WebSocket upgrade tunnel path. Rich proxy cache
remains an explicit compatibility gate until its native adapter proves full
lookup/fill/stale behavior in a later `1.6.x` stop.

## Highlights

- Metrics configuration now supports an optional `metrics.token_file`
  bearer-token source for the native metrics service. The token file path is
  resolved with the normal safe-path rules and rejected when it is empty,
  unsafe, or below a group/world-writable parent.
- Native metrics service construction now loads the configured token source,
  stores it in zeroizing memory, redacts it from debug output, and enforces it
  with constant-time comparison for `GET`/`HEAD /metrics`. It also exposes a
  Fluxheim-native background service factory that binds the native HTTP/1
  metrics listener under the native supervisor.
- Native metrics listener startup and runtime failures are fail-fast: bind
  failures and unexpected accept-loop failures now log at error level and exit
  instead of leaving a silent metrics blind spot after native cutover.
- Non-Unix metrics token-file loading now rejects a symlink leaf before opening
  the file, matching the Unix `O_NOFOLLOW` hardening as closely as the portable
  filesystem API allows.
- The Pingora compatibility metrics listener still relies on listener binding
  and network ACLs for access control until the final native runtime owns that
  listener, but Fluxheim now validates the native metrics token source at
  startup so bad token configuration fails before the cutover.
- The native runtime launch plan now carries a metrics service-policy row that
  records whether the final native `MetricsHttp` listener must enforce bearer
  auth, making token enforcement a diffable cutover contract instead of an
  implicit root-runtime detail.
- Stream and UDP proxy routes now expose Fluxheim-native background service
  task factories beside their Pingora compatibility services. The compatibility
  runtime validates those native factories at startup whenever stream or UDP
  services are enabled, so final native service registration exercises the same
  route parsing and listener task construction before the cutover.
- Load-balancer refresh services now expose a native-supervisor handoff while
  retaining the Pingora compatibility wrapper. This lets the final native
  runtime spawn the existing Fluxheim-owned discovery/health refresh loop
  directly instead of routing it through Pingora's service adapter.
- The Pingora compatibility load-balancer adapter now stores that native
  service handoff internally and dispatches through `FluxBackgroundTask`,
  keeping the compatibility path and final native supervisor path on the same
  task boundary.
- Native runtime launch plans now include `LoadBalancerRefresh` background-task
  inventory only for load-balanced pools that actually need a background loop:
  active health checks, file discovery, HTTP discovery, or DNS refresh. Static
  ordered/weighted pools with `load_balance.health_check.enabled = false` stay
  native-ready without a detached refresh task.
- That load-balancer service and background-task inventory is now gated by the
  `fluxheim-server/load-balancer` feature, so non-load-balancer builds do not
  advertise native supervisor work they cannot construct.
- Native runtime launch planning now rejects duplicate background-task kinds
  before supervisor startup, matching the existing duplicate listener binding
  guard and preventing ambiguous task ownership in the final native runner.
- Native runtime launch planning also rejects duplicate service kinds before
  listener expansion, so a final native runner cannot accidentally register two
  owners for the same service role.
- The compatibility runtime now also validates the native HTTP/1 host-router
  factory when the server plan reports the proxy surface as native-ready. This
  proves exact/wildcard host routing, default-vhost selection, trusted-proxy
  source parsing, and route proxy construction can be assembled as one native
  router before the production runner switches away from Pingora.
- Native HTTP/1 proxy planning now accepts static round-robin upstream pools
  that explicitly disable active load-balancer health checks, matching the
  native proxy's current static-upstream capability while still rejecting
  advanced load-balancer policies.
- Native HTTP/1 proxy planning now rejects active load-balancer health checks
  until the final native load-balancer bridge shares health/discovery state
  with the actual native upstream selector. This avoids a false native-ready
  signal where a compatibility refresh task would run but native traffic would
  not consume its state.
- The native runtime cutover evidence gate now fails if the representative
  blocker-free config does not target `NativeRuntime`, if the launch plan is not
  `ready`, or if a launch-plan error is emitted.
- `fluxheim-config-tester --runtime-cutover` now labels the compatibility
  adapter row as `native-runtime-compat-adapter`, so blocker-free reports do
  not look like they will still start through Pingora when
  `native-runtime-target-adapter` is already `NativeRuntime`.
- Native HTTP/1 proxy planning now treats disabled root request-header policy
  as native-ready, matching the native request-header policy implementation
  instead of keeping that supported configuration behind the compatibility
  adapter.
- Native HTTP/1 route and vhost planning now also treats disabled request
  header overlays as native-ready. Runtime coverage proves a disabled route
  overlay suppresses inherited request-header mutations before proxying.
- The server crate now has a Fluxheim-owned native HTTP/1 proxy runtime boundary
  that binds proxy HTTP listeners from the native launch plan, builds the native
  host router once, serves requests through `serve_native_http1_listener`, and
  shuts down through the native background supervisor. HTTPS and downstream
  PROXY protocol listeners still fail closed at this boundary until their
  native listener handling lands.
- Rustls-backed native proxy HTTPS listeners can now bind from the native launch
  plan when `tls.alpn = "http1"`. The runtime builds the downstream Rustls
  server config through `fluxheim-tls`, preserving certificate resolver and
  client-auth policy; HTTP/2 ALPN and downstream PROXY protocol remain
  fail-closed until their native listener dispatch is added.
- Plaintext native proxy listeners now accept trusted downstream PROXY protocol
  v1 and v2 from the native launch plan. The parsed source address is carried
  through access policy, rate-limit identity, and generated forwarding headers,
  while untrusted direct peers still fail closed before request parsing.
- Root startup now enters the Fluxheim-native runtime dispatcher when the
  server plan is blocker-free and targets `NativeRuntime`. The dispatcher
  starts the native HTTP proxy runtime plus native admin, metrics, stream, UDP,
  and load-balancer refresh tasks under `NativeBackgroundSupervisor` instead of
  the Pingora server loop.
- Native Rustls proxy HTTPS startup now exposes its certificate resolver to the
  root native runtime, so ACME renewal and the local certificate-reload control
  task can reload downstream certificates without the Pingora listener adapter.
- Native OpenSSL proxy HTTPS startup now binds through the Fluxheim-owned
  OpenSSL listener path for OpenSSL-only/FIPS builds when `tls.alpn = "http1"`.
  It builds its downstream acceptor through `fluxheim-tls`, preserves the
  configured certificate and client-auth policy, and keeps HTTP/2 ALPN
  fail-closed until the native HTTP/2 listener dispatch is enabled. The native
  OpenSSL listener also preserves configured TLS policy and client-auth
  settings, installs SNI certificate selection through OpenSSL's callback API,
  and exposes the certificate store to the root native runtime so ACME renewal
  and local certificate reloads no longer require the Pingora listener adapter.
- Native runtime cutover evidence no longer treats downstream HTTP/2 listener
  dispatch as a standalone blocker once the TLS ALPN route can enter the
  native multi-stream H2 adapter. Remaining native proxy blockers are tied to
  HTTP/1 proxy/cache feature parity rather than the H2 listener handoff itself.
- Native HTTPS listeners can now dispatch selected `h2` ALPN connections into
  the native multi-stream HTTP/2 route adapter, while `http/1.1` and no-ALPN
  connections continue through the native HTTP/1 route path when the configured
  TLS ALPN policy permits HTTP/1. Live rustls and OpenSSL runtime tests prove
  `tls.alpn = "http1-and-http2"` negotiates HTTP/2 and reaches an ordinary
  native proxy upstream on both supported TLS backends.
- The machine-readable native cutover target table now points the downstream
  HTTP/2 blocker at the final rich-proxy parity release instead of the earlier
  preview milestone, keeping `fluxheim-config-tester --runtime-cutover` output
  consistent with the current Pingora-exit plan.
- The native HTTP/2 preview connection loop now accepts and serves multiple
  streams on one connection instead of dropping every stream after the first
  probe response. Tests cover same-connection multi-stream responses and the
  native TLS runtime now routes selected downstream H2 traffic into that stack.
- Added a native HTTP/2-to-native-route adapter that maps ordinary H2 requests
  into the existing native HTTP/1 route handler pipeline and converts native
  responses back to H2 without collapsing duplicate response headers such as
  `Set-Cookie`. Native requests now carry request trailers, and tests prove H2
  request trailers reach the native route handler and H2 upstream request
  builder; connection takeover remains fail-closed because HTTP/2 upgrade
  semantics are separate from HTTP/1 tunnels.
- Native PHP-FPM routes now support Fluxheim-managed php-fpm process ownership
  through `fluxheim-php-fpm`, not the root crate. Managed routes create the
  private php-fpm config, validate the php-fpm binary path against symlink and
  insecure-parent traversal, start php-fpm on a private Unix socket, keep the
  process owner alive for the native route lifetime, and retain the bounded
  watchdog/restart behavior used by the legacy runtime.
- The legacy root PHP-FPM module now re-exports the managed process owner from
  `fluxheim-php-fpm` instead of carrying a second supervisor implementation.
  This keeps the Pingora compatibility route stable while removing duplicate
  process lifecycle code from the root crate.
- Native HTTP/1 proxy routing now shares Fluxheim-owned
  `UpstreamLoadBalancer` state with the native load-balancer refresh service.
  Static advanced pool policy, active health, dynamic file/HTTP/DNS discovery,
  persistence, passive health, backup/drain/disabled state, priority groups,
  locality preference, per-upstream in-flight caps, aliases/tags, and runtime
  weight handling are selected through the same native load-balancer state the
  background service updates.
- Dynamic native load-balancer selections now clone the already-vetted
  upstream transport policy onto selected discovery authorities. This preserves
  the configured TLS, HTTP version, timeout, socket, PROXY-protocol, and
  forwarding-header policy without accepting per-request transport changes from
  discovery data.
- Added Fluxheim-owned nginx/Pingora Ketama-compatible static-ring hash modes
  for operators migrating cache-stateful upstream pools that need nginx-style
  request-to-backend mapping. The new selections are
  `nginx-consistent-source-hash` (`nginx-consistent-hash` / `ketama` aliases),
  `nginx-consistent-uri-hash`, `nginx-consistent-header-hash`, and
  `nginx-consistent-cookie-hash`; they build a static CRC32 continuum from the
  configured `proxy.upstreams` pool and intentionally reject dynamic discovery
  pools and runtime backend-set mutations in this release.
- Native Ketama startup now rejects file, HTTP, and DNS discovery sources
  before building the ring, and logs if CRC32 point collisions reduce the
  continuum. The release documentation now calls out that Ketama remains
  unsalted for nginx/Pingora compatibility and is therefore not the right mode
  for attacker-controlled hash keys.
- Native HTTP/1 now has a connection-takeover handoff that preserves any
  bytes read after the request head. This prevents early WebSocket frames sent
  in the same TCP packet as the upgrade request from being lost when a handler
  takes ownership of the downstream stream.
- Native WebSocket proxying is now available for strict WebSocket upgrade
  requests on forced HTTP/1 static upstream routes. The native adapter writes a
  canonical upstream `Connection: Upgrade` / `Upgrade: websocket` request,
  validates the upstream `101 Switching Protocols` response with the shared
  HTTP/1 parser, forwards prebuffered bytes in both directions, and runs the
  bidirectional tunnel under the configured upstream read timeout.
- Native WebSocket proxying now strips hop-by-hop request headers, including
  headers named by the downstream `Connection` field, before forwarding the
  upgrade upstream. The downstream `101 Switching Protocols` response is now
  emitted as a canonical WebSocket handshake response instead of forwarding
  arbitrary upstream `101` headers such as `Set-Cookie` or `Server`.
- Native WebSocket proxying now also works with native load-balanced upstream
  pools. The proxy performs one normal load-balancer selection at upgrade time,
  then pins the tunnel to that selected upstream for the lifetime of the
  connection; HTTP/2 WebSocket upstream mode remains fail-closed because it
  does not use the HTTP/1 hop-by-hop upgrade mechanism.
- The native server crate now has an internal PHP-FPM request-planning adapter
  under the `php-fpm` feature. It maps native HTTP/1 requests into the FastCGI
  parameter set using Fluxheim's existing PHP path-safety helpers:
  `SCRIPT_NAME`/`PATH_INFO`, deny prefixes, split `PATH_INFO`, UTF-8
  `DOCUMENT_ROOT`/`SCRIPT_FILENAME`, request headers, protected custom params,
  TLS scheme, and restored client address are all covered before the live
  FastCGI execution path is enabled.
- The same staged native PHP-FPM adapter now translates PHP stdout into a
  native response plan. It uses the shared PHP response parser, strips
  hop-by-hop headers, configured hidden headers, PHP internal offload headers,
  and Fluxheim-owned `Content-Length`, preserves HEAD response length without a
  body, and marks configured intercepted status codes before the live response
  writer is enabled.
- Native static-web resolution now exposes a PHP-specific, feature-gated
  script resolver for the upcoming live PHP-FPM adapter. It reuses the same
  canonical web-root/symlink-safe resolver as static serving while applying PHP
  `SCRIPT_NAME`, front-controller, deny-prefix, directory-index redirect, and
  decline-existing-static decisions.
- PHP-FPM in-memory request bodies now keep their FastCGI replay buffer inside
  `Zeroizing<Vec<u8>>` instead of cloning sensitive request bytes into a plain
  heap vector for the duration of the FastCGI exchange.
- `metrics.token_env` is parsed but rejected. Rust 2024 treats process
  environment mutation as unsafe, Fluxheim forbids unsafe code in the root
  crate, and leaving bearer tokens in `/proc/self/environ` is not acceptable
  for the native metrics listener. Use `metrics.token_file` instead.
- Native nginx/Pingora Ketama-compatible backend iteration now tracks seen
  backends with a set, preserving existing `max_iterations` behavior while
  avoiding quadratic duplicate checks on large weighted rings.
- The native admin control-plane and local ops listeners remain explicitly
  PROXY-protocol disabled even when the public HTTP/HTTPS listeners enable
  trusted downstream PROXY protocol. The server-plan tests continue to assert
  that only public HTTP/HTTPS listeners inherit that trust boundary.
- The staged native PHP-FPM adapter now has request-body planning for the
  upcoming live execution path. It enforces `php.max_request_body_bytes`, keeps
  small bodies in memory, and uses Fluxheim's existing private PHP spool-file
  creator/cleanup path when `php.request_body_spool_threshold_bytes` and
  `php.request_body_spool_dir` require a spooled body.
- The staged native PHP-FPM adapter now has a FastCGI execution wrapper that
  uses Fluxheim-owned endpoint selection, pooled or one-shot Unix/TCP
  connections, bounded connect/request timeouts, configured response-size
  limits, retryable error/status handling, STDERR failure-pattern handling, and
  the staged native response planner.
- Native HTTP/1 route/vhost PHP-FPM configs can now build a native PHP route
  action for external php-fpm endpoints. The route action resolves scripts
  through the native static resolver, enforces PHP in-flight/request-body
  limits, builds the shared FastCGI parameter plan, executes the staged
  FastCGI wrapper, and returns parsed native PHP responses.
- Native PHP-FPM routes now honor configured PHP custom error pages for
  intercepted statuses by rendering the configured static error page through
  the native static-file responder.
- The remaining rich-proxy native gates are now documented as intentional
  parity blockers rather than hidden launch blockers: proxy cache still needs
  native lookup/fill/stale/purge behavior before cache-enabled proxy routes
  can leave the compatibility path.
- HTTP/2 stream handling now treats bounded per-stream failures as stream
  responses instead of connection-level failures. Oversized request bodies,
  request-body timeouts, header-count rejection, oversized URIs, and handler
  timeouts return the matching 4xx/5xx response on that stream while allowing
  sibling streams on the same connection to continue.
- Native HTTP/1 request bodies now use zeroizing storage through the H2-to-H1
  route adapter so request-body copies do not lose the zero-on-drop behavior
  used by native H2.
- Native metrics bearer-token checks now compare fixed-size digests instead of
  branching on token length before the constant-time comparison. Metrics bearer
  auth now uses `metrics.token_file`; `metrics.token_env` is rejected to avoid
  local process-environment exposure.
- Native proxy listener accept-loop failures now mirror the metrics listener
  behavior: unexpected listener exit logs an error and terminates the process
  instead of leaving a live process that silently stopped accepting traffic.

## Tests

- Added config tests for metrics bearer-token parsing and the fail-closed
  `metrics.token_env` rejection.
- Added native metrics tests for token loading from a file source,
  authenticated scrape acceptance, unauthenticated rejection, and debug
  redaction.
- Added native metrics listener tests proving the bearer-token policy works
  over an actual local TCP scrape request and that the background service task
  binds and stops under the native supervisor, not only through the in-memory
  handler.
- Added a native-supervisor load-balancer test that spawns the refresh service,
  observes readiness after the initial discovery update, checks the
  `LoadBalancerRefresh` task kind, and shuts it down through the Fluxheim
  supervisor path.
- Added adapter coverage proving the Pingora compatibility wrapper preserves
  native `LoadBalancerRefresh` task metadata.
- Added server-plan coverage proving active-health/dynamic load-balanced pools
  schedule the `LoadBalancerRefresh` task in the native runtime launch TSV,
  while static health-disabled pools do not.
- Added paired default-build and load-balancer-feature tests for
  `LoadBalancerHealthChecks`/`LoadBalancerRefresh` inventory.
- Added launch-plan coverage proving duplicate background-task kinds fail
  closed before task supervision begins.
- Added launch-plan coverage proving duplicate service kinds fail closed before
  listener registration begins.
- Extended native runtime launch-plan tests and cutover evidence validation to
  cover metrics bearer-token service policy.
- Added a runtime test proving a native-ready HTTP/1 proxy config builds the
  full native host-router factory, not only the individual proxy candidate.
- Added native proxy and server-plan coverage for static load-balanced pools
  with `load_balance.health_check.enabled = false`, plus rejection coverage for
  custom disabled-health-check policies that would otherwise be silently
  ignored by the native static proxy.
- Added native proxy planning coverage proving default active-health
  multi-upstream pools remain on the compatibility path until native
  load-balancer refresh state is wired into the native request path.
- Extended `scripts/validate-native-runtime-cutover.sh` so release validation
  proves the representative native runtime config is not only blocker-free but
  also selects the native target adapter and a ready launch plan.
- Added a live native runtime test that binds a planned HTTP proxy listener on
  an ephemeral address, proxies a real request to a local upstream through the
  native host router, and shuts the listener down through
  `NativeBackgroundSupervisor`.
- Added a Rustls native runtime listener test that generates a temporary
  certificate, binds a planned HTTPS listener, completes a real TLS handshake,
  proxies a request to a local upstream, and shuts the native listener down
  through the supervisor.
- Added an OpenSSL native runtime listener test that generates a temporary
  certificate, binds a planned HTTPS listener under the OpenSSL-only server
  feature, completes a real OpenSSL TLS handshake, proxies a request to a local
  upstream, and shuts the native listener down through the supervisor.
- Added live native runtime tests for trusted downstream PROXY protocol v1 and
  v2 listeners, proving the native listener parses the PROXY header and forwards
  the restored client IP to the upstream as `X-Real-IP`.
- Added root runtime coverage proving blocker-free plans select the native
  runtime target and that certificate background tasks are rejected unless a
  native reloader is available.
- Re-ran the admin listener smoke against the native startup path, proving the
  production binary serves the admin TCP listener and Unix ops socket under the
  native runtime dispatcher.
- Added native proxy coverage for shared load-balancer selection and refresh
  service state, including active-health/static advanced policy and dynamic DNS
  discovery construction.
- Added configuration and load-balancer tests for the nginx-compatible Ketama
  selectors, including alias parsing, header-hash requirements, dynamic
  discovery rejection for static-ring selections, native selection
  construction, and runtime backend-set mutation rejection.
- Added Ketama startup coverage proving dynamic discovery sources are rejected
  for nginx-compatible static-ring selections.
- Added HTTP/2 stream-isolation coverage proving an oversized request body on
  one stream returns `413` without aborting a sibling stream on the same
  connection.
- Added WebSocket request/response sanitization tests proving hop-by-hop
  request headers are stripped and arbitrary upstream `101` response headers
  are not forwarded downstream.
- Added a live native HTTP/1 runtime test that binds a real listener and serves
  a downstream request through a nginx-compatible Ketama URI-hash upstream pool.
- Added native runtime launch-plan tests proving `proxy.websocket = true` is
  native-ready at root, vhost, and route scope when the upstream mode is forced
  HTTP/1, plus rejection coverage for WebSocket with HTTP/2 upstream mode.
- Added live native HTTP/1 proxy and route-proxy WebSocket tests. Both tests
  perform a real downstream `101 Switching Protocols` upgrade through a local
  upstream listener and prove bytes sent immediately after the downstream
  request head are preserved and tunneled.
- Added live native load-balanced WebSocket coverage proving a configured
  `proxy.load_balance` pool can select an upstream once and tunnel WebSocket
  bytes through that pinned backend.
- Added focused native connection-takeover coverage proving handlers receive
  prebuffered downstream bytes when taking ownership of a parsed HTTP/1
  connection.
- Added PHP-FPM feature tests for the native FastCGI request planner, including
  core CGI parameter mapping, duplicate request-header joining, protected
  custom-param rejection, denied script-prefix rejection, and unsafe
  `PATH_INFO` rejection.
- Added PHP-FPM feature tests for the native response planner, including
  hop-by-hop/configured/internal header stripping, HEAD content-length
  preservation, and intercepted status classification.
- Added PHP-FPM feature tests proving the native static-web resolver can
  resolve explicit PHP scripts, use the front controller for missing paths,
  decline existing non-PHP static files when configured, and reject denied
  script prefixes.
- Added PHP-FPM feature tests for native request-body planning, including
  memory bodies, configured body-limit rejection, spool-file creation, and
  cleanup on request-body drop.
- Added PHP-FPM feature tests for the staged native FastCGI execution boundary,
  including fail-closed rejection when no PHP-FPM endpoint is configured.
- Added native route-proxy PHP-FPM tests proving PHP routes reject missing
  roots and fail closed with `502 Bad Gateway` when a configured external
  php-fpm endpoint is unavailable.
- Added a live native route-proxy PHP-FPM test with a minimal in-test FastCGI
  responder, proving the native route sends FastCGI records, parses PHP stdout,
  strips configured PHP response headers, and returns the parsed HTTP response.
