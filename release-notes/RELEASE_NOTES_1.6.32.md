# Fluxheim 1.6.32 Release Notes

Fluxheim 1.6.32 continues the final native-runtime cutover work after the
cache/PHP adapter slice.

## Highlights

- Metrics configuration now supports optional `metrics.token_env` and
  `metrics.token_file` bearer-token sources for the native metrics service.
  The token file path is resolved with the normal safe-path rules and rejected
  when it is empty, unsafe, or below a group/world-writable parent.
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
  inventory whenever a load-balanced pool is configured. This keeps the final
  supervisor contract aligned with the service intent that already detects
  static pools, file discovery, HTTP discovery, and DNS refresh.
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
- The native runtime cutover evidence gate now fails if the representative
  blocker-free config does not target `NativeRuntime`, if the launch plan is not
  `ready`, or if a launch-plan error is emitted.
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
  Non-Rustls native TLS reload paths still fail closed until their native
  backend handoff lands.

## Tests

- Added config tests for metrics bearer-token parsing, `token_env` parsing, and
  conflicting token sources.
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
- Added server-plan coverage proving load-balanced pools schedule the
  `LoadBalancerRefresh` task in the native runtime launch TSV.
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
- Added live native runtime tests for trusted downstream PROXY protocol v1 and
  v2 listeners, proving the native listener parses the PROXY header and forwards
  the restored client IP to the upstream as `X-Real-IP`.
- Added root runtime coverage proving blocker-free plans select the native
  runtime target and that certificate background tasks are rejected unless a
  native reloader is available.
- Re-ran the admin listener smoke against the native startup path, proving the
  production binary serves the admin TCP listener and Unix ops socket under the
  native runtime dispatcher.
