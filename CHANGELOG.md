# Changelog

All notable Fluxheim changes should be recorded here before a release tag is
created.

Fluxheim follows semantic versioning once `1.0.0` is released. Before `1.0.0`,
minor versions may still change configuration shape, feature names, and runtime
behavior when the change improves security or project direction.

## 1.6.23 - 2026-06-20

### Changed

- Cut stream and UDP proxy service startup over to Fluxheim-owned native task
  boundaries while keeping the Pingora runtime adapter as a thin compatibility
  registration layer.
- Mark config-derived stream and UDP service plans native-ready in the runtime
  cutover report.
- Extend native runtime cutover evidence with a representative UDP route and
  prove that stream/UDP no longer remain 1.6.23 blockers.
- Update release metadata, RPM metadata, and container tag documentation for
  `v1.6.23`.

### Security

- Add a native shutdown wait primitive that handles both already-requested and
  future shutdown requests, avoiding stalled service tasks during supervisor
  handoff.
- Make native background-task joins abort-on-cancel and make the shutdown waiter
  cancellation-safe for native `tokio::select!` loops.
- Preserve query strings on pathless absolute-form admin request targets instead
  of dropping them during native admin request parsing.
- Preserve live stream and UDP smoke coverage while changing their startup
  lifecycle, including real listener-backed stream and UDP proxy checks.
- Keep HTTP/2 and final HTTP proxy runtime parity as the remaining native
  runtime blockers for the final Pingora-free proof release.

## 1.6.22 - 2026-06-20

### Changed

- Start the native admin/metrics serving slice of the Pingora-exit line.
- Keep production admin and metrics compatibility conservative while native
  control-plane HTTP handlers and parity tests are introduced behind Fluxheim-owned
  server primitives.
- Update release metadata, RPM metadata, and container tag documentation for
  `v1.6.22`.

### Security

- Preserve auth-first admin behavior as the required compatibility contract for
  native admin/control-plane serving.
- Mark config-derived admin, ops-socket, and metrics service plans native-ready
  only after adding native handler parity tests.
- Harden native background handles so dropped handles abort instead of silently
  detaching tasks, document critical-handle abort behavior, and make shutdown
  initiation results `#[must_use]`.
- Reject newline-bearing native runtime cutover evidence paths before generating
  TOML fixtures.
- Document that native admin target matching intentionally uses raw,
  percent-encoded paths.
- Keep the native runtime cutover blocker gate active for stream, UDP, HTTP/2,
  and final proxy-runtime blockers while this slice advances.

## 1.6.21 - 2026-06-20

### Changed

- Start the native background-service orchestration slice of the Pingora-exit
  line for Fluxheim-owned tasks such as certificate reload, ACME renewal, cache
  maintenance, observability export, and load-balancer refresh.
- Add `fluxheim_runtime::NativeBackgroundSupervisor` as the first Pingora-free
  task-runner primitive for typed background services, raw async tasks,
  readiness callbacks, shutdown fan-out, and join/abort supervision.
- Keep the final Pingora-free proof target at 1.6.24 while this release focuses
  on task-supervision boundaries instead of changing production listener
  behavior.
- Update release metadata, RPM metadata, and container tag documentation for
  `v1.6.21`.

### Notes

- Normal proxy profiles still retain the Pingora compatibility runtime in this
  release.
- The first-party `zeroize` to `sanitization` migration remains planned for the
  post-Pingora stabilization release so it can be tested as a focused
  hardening pass.

### Security

- Add native critical background-task watchdog support so critical tasks can
  request supervisor shutdown when they exit unexpectedly before the production
  background-task wiring moves off Pingora.
- Harden native supervisor shutdown delivery for pre-spawn shutdown, last-handle
  drop, and clone-drop edge cases.
- Harden the native runtime cutover evidence script against unsafe TOML path
  interpolation and missing expected blocker rows in the representative report.
- Mark background-service `threads()` as Pingora compatibility-only so native
  task supervision cannot be mistaken for a per-service thread-pool contract.

## 1.6.20 - 2026-06-20

### Changed

- Start the next Pingora-exit slice as a native runtime cutover contract rather
  than a premature production switch.
- Re-scope the remaining Pingora runtime removal across focused 1.6.x releases:
  native background task orchestration, admin/metrics serving, stream/UDP
  listener startup, final Pingora-free proof, and stabilization.
- Move the remaining Pingora dependency exception targets to the documented
  1.6.24 final proof release while keeping the cargo-tree policy gate active.
- Add a native runtime cutover evidence gate that runs blocker-summary,
  native HTTP/2 preview, native HTTP/1 proxy, and Pingora dependency policy
  checks during release gates.
- Add `fluxheim-config-tester --runtime-cutover` with stable native-runtime
  blocker keys and target releases.
- Add a committed native-runtime cutover target map and validate generated
  blocker reports against it during release gates.
- Update release metadata, RPM metadata, and container tag documentation for
  `v1.6.20`.

### Notes

- Normal proxy profiles still use the Pingora compatibility runtime in this
  release. Native TLS-only web proof profiles remain Pingora-free.
- The dependency policy still rejects new undocumented Pingora edges and will
  fail once the documented final proof target is reached if any listed Pingora
  crate remains.

### Security

- Wrap OpenSSL downstream private-key PEM file buffers in `sanitization::SecretVec`
  before parsing, so Fluxheim's owned PEM copy is wiped after the OpenSSL key
  import path completes.

## 1.6.19 - 2026-06-19

### Changed

- Add an explicit `pingora-compat` feature for the remaining root compatibility
  runtime, making the Pingora boundary visible in Cargo features instead of
  hiding it behind the generic `ingress` feature.
- Stop native TLS-only web builds from enabling `pingora/rustls` or
  `pingora/openssl` when the Pingora compatibility runtime is not selected.
- Move rustls downstream SNI certificate resolution, reloadable certificate
  storage, and PEM certificate/private-key parsing into `fluxheim-tls` so the
  native listener cutover no longer depends on Pingora's listener key-loading
  helper.
- Add a Fluxheim-owned native rustls downstream `ServerConfig` builder covering
  cipher suites, key-exchange groups, minimum protocol, ALPN, client-auth
  verifier construction, and FIPS reporting checks without Pingora listener
  panic paths.
- Add a Fluxheim-owned native OpenSSL downstream `SslAcceptor` builder for the
  fallback-certificate listener path, covering certificate/key loading,
  ciphers, curves, minimum protocol, ALPN, and client-auth CA policy with typed
  errors.
- Move OpenSSL downstream SNI certificate storage, reload, pending-managed-cert
  handling, and certificate application into `fluxheim-tls`; the root runtime
  now keeps only the Pingora `TlsAccept` adapter.
- Add a native rustls HTTP/1 downstream listener preview in `fluxheim-server`
  that reuses the existing native HTTP/1 parser/handler path, listener
  connection budget, and request-head timeout as the TLS handshake bound.
- Add the matching native OpenSSL HTTP/1 downstream listener preview for
  OpenSSL-only builds, with the same connection budget, bounded TLS handshake,
  and real client/server TLS socket coverage.
- Add a native runtime cutover summary to `ServerPlan` so startup diagnostics
  and release tests can report the remaining compatibility blockers before the
  1.6.20 runtime removal slice.
- Add a root integration test proving the `fluxheim-tls` rustls downstream
  server-config builder can drive the native `fluxheim-server` HTTP/1 listener
  with a real client handshake and request.
- Add the matching OpenSSL integration test proving the `fluxheim-tls`
  acceptor builder can drive the native OpenSSL HTTP/1 listener.
- Update the test-only `rcgen` dependency to `0.14.8`.
- Extend the Pingora dependency policy with a `native-web-tls` cargo-tree
  profile that proves `--no-default-features --features web,tls-rustls` does
  not compile Pingora crates.

### Notes

- Root proxy profiles still use the compatibility runtime in this cut. The
  remaining server/admin/metrics/proxy compatibility removal is moved to the
  next Pingora-exit slice so it can be tested as a runtime change rather than
  hidden inside a feature cleanup.
- The vendored Pingora rustls listener still wraps downstream TLS accepts until
  listener cutover, but Fluxheim now owns SNI selection and cert/key parsing.
- The native rustls server-config builder is available for the listener cutover;
  the compatibility runtime still applies the same TLS policy to Pingora's
  temporary listener shim in this release.
- The native rustls and OpenSSL listeners are test-backed but not wired into
  official proxy profiles yet; production traffic remains on the compatibility
  runtime until the full listener/runtime cutover.
- The native runtime cutover summary is diagnostic-only in this release. It
  does not select the native runtime yet.

## 1.6.18 - 2026-06-19

### Changed

- Start the next Pingora-exit slice for normal builds. This release focuses on
  shrinking the remaining root compatibility surface and preparing the
  proxy/cache/runtime paths for release-gate proof that official profiles no
  longer compile Pingora proxy/cache/pool crates.
- Keep the load-balancer crate Pingora-free after 1.6.17 and plan the native
  health-check implementation split by protocol so each probe can be reviewed
  independently.
- Split native HTTP/1.1 and gRPC/h2 health-check helpers out of the
  load-balancer health orchestration module. The new protocol helper files stay
  below the modularity policy's 500-line target.
- Split Redis, MySQL, and PostgreSQL active health probes into a database
  health helper module, keeping each new protocol/probe module below the
  modularity policy target.
- Split exec active health checks into a small helper module covering command
  launch, environment scrubbing, timeout handling, and exit-status mapping.
- Split TCP health checks, TCP/TLS handshake setup, ALPN selection, and shared
  HTTP health-stream connection handling into a transport helper module.
- Move root-profile Pingora dependency exception targets to 1.6.19 while
  keeping the dedicated `fluxheim-load-balancer` crate covered by the
  Pingora-free policy gate.

### Security

- Carry forward the 1.6.17 native load-balancer health-probe hardening as the
  baseline for 1.6.18 release gates.
- Preserve the 1.6.17 HTTP/1.1 CR/LF rejection, gRPC h2 flow-control release,
  and h2 driver abort-on-drop behavior across the protocol split.
- Guard native gRPC health-check frame length conversion, validate
  `grpc-status: 0` trailers, reject overlarge protobuf varints, and reject
  userinfo in configured health-check hosts.
- Limit native HTTP/1.1 health response headers to 8 KiB instead of sharing the
  64 KiB body cap.
- Re-enforce `exec_allowed_commands` inside the native exec health-check
  builder so programmatic `ProxyConfig` construction cannot bypass the config
  validator's allowlist check.

## 1.6.17 - 2026-06-19

### Changed

- Remove the direct Pingora dependency from the `fluxheim-load-balancer` crate.
  HTTP health checks now use a Fluxheim-owned bounded HTTP/1.1 probe, and gRPC
  health checks now use a Fluxheim-owned h2 client probe.
- Keep TCP, Redis, MySQL, PostgreSQL, exec, passive-health, persistence, and
  selection logic on the existing native load-balancer code paths.
- Add `fluxheim-load-balancer` to the Pingora dependency policy so future
  changes cannot reintroduce Pingora into the load-balancer core unnoticed.

### Security

- Bound native HTTP health-check response headers and bodies independently of
  Pingora's HTTP session machinery.
- Preserve TLS handshake timeouts for HTTP/gRPC health checks through the
  Fluxheim-owned TCP/TLS connector path.
- Add real listener-backed tests proving native HTTP/1.1 health checks send
  configured headers, validate JSON responses, and apply degraded health
  weights.
- Add a real h2 server test proving native gRPC health checks send the
  standard health-check request body and accept a `SERVING` response.

## 1.6.16 - 2026-06-19

### Changed

- Start the native proxy cutover gate by tightening `fluxheim-server`'s native
  HTTP/1.1 proxy eligibility checks. Configurations using auth subrequests,
  traffic mirroring, proxy error pages, advanced upstream transport options,
  per-proxy downstream throttling, advanced load-balancer policy, vhost ACME
  challenge routing, vhost redirects, or route strip/rewrite transforms now
  stay explicitly on the Pingora compatibility adapter until those semantics
  are implemented in the native pipeline.
- Add a native HTTP/1.1 proxy cutover summary on `ServerPlan` so future runtime
  wiring can distinguish no-proxy, fully native-ready, mixed, and
  compatibility-required configurations without reinterpreting individual
  candidate rows.
- Log native HTTP/1.1 proxy cutover readiness at startup, including the
  compatibility-only reason for each unsupported proxy path.
- Align TOML serde defaults for proxy downstream write and total-response
  timeouts with `ProxyConfig::default()` so native cutover readiness uses the
  same baseline for parsed production configs and test-built configs.

### Security

- Fail closed in native HTTP/1.1 cutover planning when a route would require
  request-path transformation before upstream forwarding. This prevents the
  staged native path from being marked eligible for route configurations whose
  strip/rewrite behavior it does not yet enforce.
- Add focused native HTTP/1.1 proxy and server-plan tests covering the new
  compatibility blockers so future cutover work cannot silently accept
  unsupported policy layers.
- Add server-plan tests for aggregate native HTTP/1.1 cutover readiness states.
- Add TOML parsing coverage for proxy downstream timeout defaults and make
  native HTTP/1.1 TLS proxy test fixture cleanup panic-safe.

## 1.6.15 - 2026-06-18

### Added

- Add a Fluxheim-owned native HTTP/2 upstream client primitive in
  `fluxheim-server`, including request body/trailer sending, response
  body/trailer collection, bounded response header counts, bounded response
  bodies, and absolute request-write / response-read deadlines.
- Add in-memory h2 client/server tests proving native HTTP/2 upstream trailer
  preservation for gRPC-style responses, oversized response rejection, response
  header-count rejection, upstream stream reset surfacing, and request
  flow-control write timeout behavior.

### Changed

- Share native HTTP/2 prohibited response-header validation between the
  downstream stack probe and the new upstream client path.
- Share the native HTTP/2 bounded DATA sender between downstream responses and
  upstream request bodies.
- Keep production HTTP/2 cutover gated until the native path has full
  pre-routing HPACK/header-count allocation proof and integration through the
  production proxy pipeline.

### Security

- Stage native HTTP/2 upstream request bodies in zeroizing memory before
  copying them into h2 DATA frames.
- Add a dedicated native HTTP/2 upstream response-body timeout so upstream
  response reads no longer reuse the downstream request-body timeout setting.
- Document the current native HTTP/2 upstream client as a one-request preview
  client whose hard connection-driver abort must not be copied into future
  pooled upstream connections.

## 1.6.14 - 2026-06-18

### Added

- Add native rustls and OpenSSL upstream TLS support to the staged HTTP/1.1
  proxy path in `fluxheim-server`, including explicit SNI, configured CA
  bundles, optional upstream client certificates, and certificate verification
  controls.
- Add real native HTTPS upstream proxy coverage with an in-test CA and
  localhost SAN leaf certificate.
- Add real native upstream mTLS coverage for rustls and OpenSSL by requiring a
  client certificate on the test origin, including the failure path when the
  proxy has no upstream client certificate configured.
- Fix native HTTP/1 server-plan TLS failure-reason coverage for OpenSSL-only
  builds.
- Add real native upstream TLS hostname-policy coverage for default mismatch
  rejection, `upstream_alternative_cn`, and `upstream_verify_hostname = false`
  across rustls and OpenSSL builds.
- Add direct native upstream TLS file-reader tests for oversized-file and final
  symlink rejection.
- Make the native HTTP/1 proxy builder fail closed on invalid upstream TLS
  material combinations even when called outside the full config loader.
- Restrict native HTTP/1 stale pooled-connection retries to safe methods so
  unsafe requests are not replayed after a pooled socket failure.
- Harden the native OpenSSL upstream TLS connector with a TLS 1.2 minimum and
  explicit AEAD-only TLS 1.2 / TLS 1.3 cipher suite allowlists.
- Make the native upstream TLS file reader canonicalize the parent directory
  before opening certificate/key material so CodeQL and reviewers see the
  filesystem trust boundary explicitly.
- Add native HTTP/1 ordered static upstream failover for safe request methods,
  with socket tests proving `GET` can fall through to the next configured
  upstream while unsafe methods are not replayed.

### Changed

- Store native HTTP/1 upstream pooled connections as Fluxheim-owned boxed IO
  streams so the same retry/reuse path works for plain TCP and TLS upstreams.
- Wire root rustls and OpenSSL feature aliases into `fluxheim-server` so native
  upstream TLS is compiled in the same TLS profiles operators use today.
- Keep dynamic upstream discovery and advanced load-balancer policy on the
  Pingora compatibility path; the native HTTP/1 path now accepts only plain
  static upstream lists as ordered failover candidates.

### Security

- Fail closed when native HTTPS upstream conversion sees any IP-addressed
  configured static upstream with certificate verification enabled and no
  explicit `upstream_sni`.
- Read native upstream TLS CA, certificate, and key files through bounded
  no-follow regular-file handling.

## 1.6.13 - 2026-06-18

### Added

- Add bounded native HTTP/1.1 upstream connection pooling in
  `fluxheim-server` for safe content-length and no-body origin responses.
- Wire `server.process.upstream_keepalive_pool_size` into native HTTP/1 proxy
  candidates and honor `proxy.upstream_idle_timeout_secs` for native pooled
  upstream connections.

### Hardened

- Keep the native HTTP/1.1 pool conservative: do not reuse close-delimited
  responses, chunked responses, responses with `Connection: close`, or
  responses where extra bytes were buffered beyond the declared body.
- Keep unsupported upstream TLS/mTLS, HTTP/2 upstreams, dynamic discovery,
  load balancing, upstream PROXY protocol, websocket upgrade, and broader
  policy layers on the Pingora compatibility path until later 1.6 cutover
  releases prove parity.

### Tests

- Add real socket tests for native upstream connection reuse, idle-pool expiry,
  and `Connection: close` non-reuse behavior.

## 1.6.12 - 2026-06-18

### Added

- Add a reusable native HTTP/2 connection primitive in `fluxheim-server` with
  handler-owned request/response types, bounded request-body collection, and
  response trailer support for gRPC-style status propagation.
- Add native HTTP/2 tests that pass request trailers into the handler and send
  response trailers back to the client over a real h2 client/server exchange.

### Hardened

- Refresh non-Pingora dependency patches: `getrandom` 0.4.3, `openssl`
  0.10.81, `brotli` 8.0.4, and `h2` 0.4.15. Keep Pingora pinned at 0.8.0
  while the 1.6 exit line removes it.
- Add an explicit downstream HTTP/2 response-write lifetime budget and wrap the
  whole response send path in one absolute timeout, so flow-control window holds
  cannot keep a response write alive indefinitely.
- Add an explicit native HTTP/2 handler execution timeout so slow handler work
  cannot hold a stream indefinitely between request-body drain and response
  write.
- Send response DATA through h2 capacity reservation/polling instead of
  unbounded implicit buffering.
- Reject HTTP/2-prohibited response headers and trailers before sending
  responses from the native HTTP/2 primitive.
- Zeroize collected native HTTP/2 request bodies on drop and preallocate the
  request-body buffer with a bounded hint.
- Treat a zero-capacity h2 send-side wakeup as a closed response-capacity path
  to avoid a defensive spin loop.
- Advance the native HTTP/2 preview gate: response-write lifetime and
  trailer/gRPC preservation are now satisfied; pre-routing HPACK/header-count
  allocation proof remains the explicit blocker before production cutover.

### Tests

- Add a regression test that holds the client response flow-control window and
  confirms the native HTTP/2 response lifetime expires.
- Add regression tests for handler timeout, prohibited response headers, and
  empty-body response trailers.

## 1.6.11 - 2026-06-17

### Added

- Add a native HTTP/2 runtime preview gate in `fluxheim-server` that records
  every required safety hook before any production cutover is allowed.
- Add a native HTTP/2 stack probe using the Rust `h2` stack with bounded
  header-list, decoded header-count, URI, request-body, stream, frame,
  send-buffer, and rapid-reset policy values.
- Add real HTTP/2 probe tests for successful responses, bounded request
  bodies, oversized request bodies, oversized URIs, decoded header-count
  rejection, body flow-control release, and slow-body timeouts.
- Add downstream HTTP/1.0 socket tests for missing-Host acceptance, default
  close semantics, and explicit keep-alive handling.

### Hardened

- Keep native HTTP/2 cutover blocked until pre-routing HPACK/header-count
  allocation bounds, absolute response-write lifetime, and trailer/gRPC
  pass-through parity are implemented and fixture-covered.
- Release HTTP/2 request-body flow-control capacity after consumed DATA frames
  and keep the h2 connection driven while request bodies drain so WINDOW_UPDATE
  frames can flush.
- Enforce `[server.limits].max_uri_bytes` on native HTTP/2 request URIs, matching
  the HTTP/1 request-target budget.
- Log post-shutdown HTTP/2 probe streams at debug level instead of silently
  dropping them.

### Tests

- Add `scripts/smoke_native_http2_preview.sh` and register it in the runtime
  parity fixture inventory.
- Extend native HTTP/1 coverage with real downstream HTTP/1.0 socket behavior.

## 1.6.10 - 2026-06-17

### Added

- Add a Fluxheim-owned bounded native HTTP/1 upstream client for plain static
  upstream proxying, including request serialization, response-head parsing,
  fixed-length, chunked, and close-delimited response body reads.
- Add native proxy candidate inventory in `fluxheim-server` so eligible
  vhost/route proxy configurations can be identified before production cutover.
- Add a staged native proxy handler for plain static upstreams, while keeping
  the production default on the Pingora compatibility adapter until full route,
  policy, cache, PHP-FPM, ACME, observability, and failure-semantics parity is
  green.
- Add native proxy-owned `Via` and `X-Forwarded-For` forwarding parity, with
  privacy-mode builds suppressing `X-Forwarded-For`.

### Hardened

- Native upstream forwarding now strips inbound hop-by-hop framing headers,
  prior `Via`, and prior `X-Forwarded-For` before writing Fluxheim-owned proxy
  headers.
- Native close-delimited upstream responses now accept exact-size bodies and
  reject oversized bodies immediately instead of waiting for EOF.
- Native proxy eligibility fails closed for unsupported policy layers,
  dynamic discovery, load balancing, upstream TLS, upstream PROXY protocol,
  HTTP/2 upstreams, and websocket upgrade.

### Tests

- Add native upstream tests for chunked responses, close-delimited responses,
  exact body limits, oversized bodies, timeout handling, invalid headers, and
  Fluxheim-owned proxy headers.
- Extend the native HTTP/1 smoke script with a real TCP downstream listener to
  native proxy to upstream socket test.
- Add a privacy-mode regression test proving native upstream forwarding does
  not emit `X-Forwarded-For`.

## 1.6.9 - 2026-06-17

### Added

- Add a Fluxheim-owned native HTTP/1 connection and listener runtime over Tokio
  IO, using the bounded HTTP/1 parser from `fluxheim-protocol` and keeping the
  production proxy path on the Pingora compatibility adapter until parity is
  green.
- Add a staged native static-file adapter that reuses Fluxheim's safe web-root
  resolver, conditional-response planner, and body reader while writing through
  native HTTP/1 response types.
- Map `[server.limits]` request-head, URI, header-count, and request-body
  limits into the native downstream HTTP/1 policy.
- Add real TCP socket tests for native HTTP/1 keep-alive, fixed-length and
  chunked bodies, listener shutdown, static files, HEAD framing, directory
  listings, slow-client timeouts, peer-address propagation, and connection-cap
  shedding.

### Hardened

- Bound native HTTP/1 request-head and request-body reads with explicit
  deadlines to prevent slowloris and slow-body tasks from living indefinitely.
- Bound native HTTP/1 listener concurrency with a policy connection cap and
  safe zero-cap fallback to the default.
- Make native HTTP/1 response framing runtime-owned for `Content-Length`,
  `Connection`, and `Date`, and validate handler-supplied headers before
  writing.
- Sanitize native static 500 responses so filesystem and OS error details stay
  in logs instead of HTTP response bodies.
- Tighten native HTTP/1 head and chunked-body secondary buffer guards, and keep
  derived start-line limits within the total request-head limit.

## 1.6.8 - 2026-06-17

### Added

- Add a Fluxheim-owned HTTP/1.0/HTTP/1.1 request-head parser in
  `fluxheim-protocol` with bounded head size, header count, start-line length,
  header-line length, CRLF termination, UTF-8 validation, and obs-fold
  rejection.
- Add downstream HTTP/1 policy defaults to `fluxheim-server` so the native
  server cutover can carry HTTP/1 limits through the Fluxheim server plan before
  production traffic leaves the Pingora compatibility adapter.
- Add an incremental HTTP/1 request-head buffer for future native socket reads,
  including fragmented-head handling and bounded storage for oversized
  incomplete heads.
- Add strict HTTP/1 request body-framing classification for `Content-Length`
  and `Transfer-Encoding`, rejecting ambiguous `Content-Length` /
  `Transfer-Encoding` combinations before the native runtime cutover.
- Add HTTP/1.1 required `Host` boundary validation for the native parser,
  rejecting missing, duplicate, empty, or whitespace-containing host fields.
- Add HTTP/1 connection persistence classification for the native parser,
  covering HTTP/1.0 close-by-default, HTTP/1.1 persistent-by-default, explicit
  `Connection: close`, and HTTP/1.0 `Connection: keep-alive`.
- Add a bounded complete-buffer HTTP/1 chunked body decoder that writes into a
  caller-owned output buffer and enforces chunk, body, output, and CRLF limits.
- Split the HTTP/1 chunked decoder into a focused `fluxheim-protocol` module so
  the native HTTP parser remains under the reviewability target as the 1.6
  Pingora-exit line grows.
- Add native HTTP/1 request-target classification for origin-form,
  absolute-form, CONNECT authority-form, and OPTIONS asterisk-form requests,
  including percent-encoding and forbidden-fragment/backslash checks.
- Add a bounded native HTTP/1 response-head parser for future upstream response
  handling, reusing the same strict header-count, line-length, UTF-8, and
  obsolete-folding checks as request-head parsing.
- Harden the native HTTP/1 parser by rejecting deprecated authority userinfo,
  non-ASCII obs-text in strict header values and response reason phrases, all
  duplicate `Content-Length` fields, and unbounded chunked body defaults.

## 1.6.7 - 2026-06-16

### Changed

- Start the 1.6.7 server bootstrap cutover by making `fluxheim-server` build
  a Fluxheim-owned `ServerPlan` from validated config.
- Move HTTP, HTTPS, admin, metrics, stream, and UDP listener inventory plus
  process bootstrap settings into `fluxheim-server` plan types while keeping
  the current Pingora server as the compatibility adapter.
- Route the ACME certificate-reload control socket path through
  `fluxheim-server` process planning instead of reading it directly from root
  runtime config.
- Update root runtime to consume the server plan for process configuration and
  HTTP, HTTPS, admin, and metrics listener registration.
- Update root background-service registration gates to consume Fluxheim
  server-plan task metadata for cache purging, cache metrics, OTLP metrics
  export, ACME renewal, and certificate reload control.
- Add Fluxheim-owned foreground service intent metadata for proxy, admin, ops
  socket, metrics, stream proxy, and UDP proxy service registration, then make
  the root Pingora adapter consume those gates for non-proxy services.
- Add an explicit `RuntimeAdapterKind::PingoraCompatibility` marker to the
  server plan so the current Pingora runtime remains a named adapter boundary
  before the native server cutover.
- Add `ServerPlan` listener lookup helpers and route HTTP, HTTPS, admin, and
  metrics listener address lookups through `fluxheim-server` instead of
  hand-rolled adapter-side filtering.
- Remove duplicated downstream TLS listener-address storage from
  `fluxheim-tls`; HTTPS listener addresses now come from `fluxheim-server`
  while TLS planning owns certificate selection and policy.
- Move downstream PROXY protocol listener policy and trusted-source parsing
  into `fluxheim-server`, leaving root runtime as a Pingora listener-policy
  adapter.
- Split `fluxheim-server` process planning and PROXY protocol planning into
  focused modules so the new server crate stays below the 500-line target while
  the bootstrap cutover continues.
- Move private Unix listener creation for the certificate reload control socket
  into `fluxheim-server`, including stale socket replacement, mode `0600`, and
  nonblocking setup.
- Split server listener and foreground service inventory types into focused
  `fluxheim-server` modules before the native bootstrap work adds more runtime
  state.
- Move downstream HTTP/2 hardening limits into a Pingora-neutral
  `fluxheim-server` policy plan, with the root runtime only adapting those
  values into Pingora `H2Options`.
- Move certificate reload control socket policy into `fluxheim-server` so the
  socket path, concurrency cap, and request read timeout are planned outside
  the Pingora runtime adapter.
- Add server-plan lookup helpers for foreground services and background tasks,
  then make the root runtime adapter consume planned names when registering
  services.
- Add load-balancer health-check service intent to `ServerPlan` so load-balancer
  foreground registration is planned alongside proxy, admin, metrics, stream,
  and UDP services.
- Split server service-intent and background-task intent detection into focused
  `fluxheim-server` modules, reducing the server crate root while preserving the
  same runtime plan.
- Split listener inventory construction into the `fluxheim-server` listener
  module, keeping HTTP, HTTPS, admin, metrics, stream, and UDP listener parsing
  out of the server crate root.
- Move certificate reload control-plan construction into the focused
  `fluxheim-server` control module beside the control socket policy type.
- Add listener-protocol ownership to foreground service specs so the server
  plan can map proxy, admin, metrics, stream, and UDP services back to their
  planned listeners.
- Update the admin and metrics runtime adapters to consume service-owned
  listener lookups from the server plan.
- Add protocol-filtered service listener lookup and move proxy HTTP/HTTPS
  listener registration onto the service-owned lookup path.
- Add a background-service adapter helper that consumes planned
  `BackgroundTaskSpec` values directly, removing duplicated task kind/name
  wiring from plan-driven runtime services.
- Update admin service construction to consume planned control-plane and
  ops-socket service names from `ServerPlan`.
- Convert the admin self-healing watchdog registration to the typed background
  task spec path and remove the old name/kind free helper.
- Add admin self-healing watchdog intent to `ServerPlan` so the admin adapter
  consumes the planned `RuntimeWatchdog` task instead of creating it locally.
- Split the `ServerPlan` implementation into a focused `fluxheim-server` plan
  module, leaving the crate root as the public export and error surface.
- Add an admin ops-socket endpoint plan to `ServerPlan` and update the admin
  adapter to consume planned socket path and mode values.
- Add a first-service-listener lookup to `ServerPlan` and update admin service
  construction/logging to use the planned admin listener.
- Add borrow-based service listener iterators to `ServerPlan`, keeping the
  allocation-based address helpers as adapter conveniences.
- Update proxy HTTP and metrics listener registration to consume the
  borrow-based service listener views directly before adapting into Pingora.
- Harden private Unix listener setup by binding under a temporary private
  umask, using fd-based `fchmod` after bind, and using `rustix` path operations
  for stale socket cleanup.
- Remove the duplicate admin ops-socket mode parser from `fluxheim-server`;
  server planning now delegates to the validated config accessor.
- Document that `ListenerSpec::proxy_protocol_enabled()` reports only the
  server-level HTTP/HTTPS downstream PROXY protocol policy.

### Tests

- Add focused `fluxheim-server` tests for listener inventory, background-task
  intent, process-plan adaptation, invalid listener handling, and shutdown
  runner boundaries.
- Add a live admin-listener smoke test that starts Fluxheim and verifies the
  normal HTTP listener, admin health/status endpoints, and local read-only ops
  socket.
- Verify plan-gated foreground service registration with live admin,
  observability, stream proxy, and UDP proxy smokes.
- Split `fluxheim-server` tests into a separate module so new server code stays
  under the 500-line modularity target.
- Verify the split server crate modules remain below the modularity target with
  the release-gated modularity policy check.
- Add a `fluxheim-server` regression test proving private Unix listener paths
  replace stale sockets, reject non-socket files, and enforce private
  permissions.
- Add a `fluxheim-server` regression test for the downstream HTTP/2 hardening
  defaults consumed by the runtime adapter.
- Add a `fluxheim-server` regression test for the certificate reload control
  socket plan and keep the live admin listener smoke in the verification set.
- Extend `fluxheim-server` tests to cover planned service and background-task
  lookup by kind.
- Add a `fluxheim-server` regression test for load-balancer service intent and
  verify the runtime path with the live load-balancer smoke.
- Keep the split server intent modules covered by `cargo test -p
  fluxheim-server` and the release-gated modularity policy check.
- Verify the listener-planning split with `cargo test -p fluxheim-server` and
  the live admin listener smoke.
- Split private Unix listener regression coverage into a focused Unix-only test
  module so the main server test module remains well below the 500-line target.
- Add `fluxheim-server` regression coverage for service-owned listener address
  lookup.
- Add `fluxheim-server` regression coverage for protocol-filtered service
  listener lookup.
- Extend `fluxheim-server` background-task inventory coverage to include the
  planned admin self-healing watchdog.
- Split server background-task inventory tests into a focused module so the
  main server test file stays comfortably below the 500-line target.
- Add `fluxheim-server` regression coverage for admin ops-socket path and mode
  planning.
- Add `fluxheim-server` regression coverage for first service-listener lookup.
- Add `fluxheim-server` regression coverage for service listener iterator
  views.
- Add `proxy,acme-client` runtime test coverage for disabled certificate reload
  control service planning.

## 1.6.6 - 2026-06-16

### Changed

- Continue the 1.6 Pingora-exit line by adding `fluxheim-tls` as the
  Fluxheim-owned downstream TLS listener planning and provider-policy
  boundary.
- Move downstream TLS listener plans, SNI certificate selection, wildcard
  matching, ALPN/cipher/curve policy helpers, and rustls/OpenSSL provider/FIPS
  checks into `fluxheim-tls`.
- Update the runtime TLS listener adapter to consume `fluxheim-tls` plans while
  the current Pingora listener path remains the compatibility adapter for this
  release.
- Keep `pingora-rustls` documented as a temporary dependency until the native
  server/listener cutover, since 1.6.6 extracts planning but does not yet
  replace the active listener adapter.

### Security

- Fix `fluxheim-tls` feature gates so default, OpenSSL-only, and OpenSSL-FIPS
  builds do not re-export rustls-only policy/provider helpers.
- Harden downstream SNI certificate lookup to fall back to the default
  certificate instead of direct-indexing if a future selector refactor violates
  the internal index invariant.
- Move PROXY protocol v2 signature validation into the public parser instead of
  relying on every caller to satisfy the precondition.
- Reject non-canonical trusted PROXY protocol CIDR entries with host bits set.

## 1.6.5 - 2026-06-16

### Changed

- Continue the 1.6 Pingora-exit line with the first dedicated
  `fluxheim-headers` boundary for header policy helpers that do not need
  Pingora session or header types.
- Move response `Location`, `Refresh`, and `Set-Cookie` rewrite algorithms,
  spoofable client-IP header constants, trusted X-Forwarded-For restoration,
  `Forwarded` header construction, hop-by-hop request header policy, and
  repeated-header joining helpers into `fluxheim-headers`.
- Move stream downstream PROXY protocol v1/v2 byte parsers and size constants
  into `fluxheim-protocol`.
- Broaden the Pingora boundary policy gate so direct `pingora::` usage remains
  documented at adapter boundaries during the 1.6 removal line.
- Gate privacy-sensitive forwarded-client-IP parsing helpers in privacy-mode
  builds and reject PROXY-protocol trusted CIDR prefixes that exceed the
  address family width.
- Align access-policy and header-forwarding X-Forwarded-For parsing so both
  skip malformed hops and continue walking the trusted chain.

## 1.6.4 - 2026-06-15

### Changed

- Continue the 1.6 Pingora-exit line by moving shared background task lifecycle
  primitives into `fluxheim-runtime`.
- Replace the root background implementation with a narrow Pingora
  service-registration adapter around Fluxheim-owned shutdown, readiness, and
  background-service handles.
- Reuse the shared runtime background primitives from the load-balancer crate
  and tag background services with typed task metadata.
- Move OTLP metrics export and the ACME certificate reload control socket into
  the Fluxheim background task lifecycle.
- Move admin self-healing snapshot runtime state, pending validation, validation
  metrics, and rollback decisions into `fluxheim-snapshot`.
- Harden the local certificate reload control socket with a concurrency cap,
  reject over-one-day shared timeout values, and extend HTTP discovery
  private-backend filtering for 6to4/Teredo embedded IPv4 literals.

## 1.6.3 - 2026-06-15

### Changed

- Continue the 1.6 Pingora-exit line by adding `fluxheim-stream` as the
  internal TCP stream proxy runtime boundary.
- Move stream upstream selection, weighted primary ordering, backup/drain
  policy, selected-upstream labels, source allow/deny matching, and trusted
  PROXY source parsing into `fluxheim-stream`.
- Move stream DNS-rebinding guard decisions, copied-byte accounting,
  byte-limited copy-loop timeout handling, and max-connection-byte enforcement
  into `fluxheim-stream`.
- Move downstream PROXY protocol v1/v2 parsing and upstream PROXY protocol
  header writing into `fluxheim-stream` while reusing the shared
  `fluxheim-protocol` header builders.
- Keep the root stream adapter as the temporary Pingora service-registration,
  socket accept/connect, and TLS connector boundary until the broader
  background/runtime cutovers.
- Add direct `fluxheim-stream` unit coverage and preserve the stream proxy
  smoke/runtime tests for PROXY protocol, limits, and timeout behavior.

## 1.6.2 - 2026-06-14

### Changed

- Start the cache-independence release in the 1.6 Pingora-exit line.
- Move cache key identity, serialized object envelopes, disk index entries, and
  disk index management into `fluxheim-cache`.
- Move plaintext disk cache object header sizing, encoding, and parsing into
  `fluxheim-cache`; encrypted disk cache handling remains in the root adapter
  until the native HTTP/cache cutover.
- Move storage-bin layout, manifest, index-entry, object-location, and free-map
  allocation helpers into `fluxheim-cache` while leaving safe file opening and
  symlink checks in the root adapter.
- Add a Pingora-neutral `FluxCacheStorage` interface in `fluxheim-cache` with
  serialized metadata, hit handlers, miss handlers, purge, and metadata-update
  semantics.
- Adapt memory, filesystem disk, storage-bin disk, disk-backend, and tiered
  cache storage to the crate-owned cache interface while preserving the current
  Pingora HTTP runtime adapter.
- Move cache-tag grammar, normalization, encoding, decoding, limits, and
  default tag-header names into `fluxheim-cache`.
- Add regression coverage proving memory and tiered cache backends can
  round-trip objects through the native cache interface.
- Add a Rust integration test that enforces
  `docs/pingora-dependency-exceptions.tsv` removal targets against
  `Cargo.lock`, so expired Pingora dependency exceptions fail in normal
  `cargo test` runs as well as release gates.
- Keep final `pingora-cache` compile removal scheduled for the native HTTP
  runtime cutover because the current Pingora proxy runtime still imports
  `pingora::cache`.

## 1.6.1 - 2026-06-14

### Changed

- Start the first Pingora-exit implementation release after the `1.6.0`
  foundation tag.
- Fix the container image workflow so load-balancer images are built for
  normal `v1.6.x` tag pushes instead of being limited to `v1.5.x` refs.
- Bump workspace, RPM, release notes, and image documentation to `1.6.1`.
- Remove the remaining `pingora-load-balancing` and `pingora-ketama`
  dependencies from full and load-balancer image profiles by storing
  Fluxheim-native backend sets in `fluxheim-load-balancer`.
- Replace Pingora's TCP health-check backend adapter with a Fluxheim-owned TCP
  connector and rustls/OpenSSL handshake paths.
- Add a focused Podman load-balancer runtime smoke that builds the
  load-balancer-edge image, runs it against two local origins, verifies
  round-robin/header persistence behavior, and checks that the image profile
  does not compile Pingora load-balancing crates.
- Split load-balancer API/runtime DTOs and parser helpers into
  `crates/fluxheim-load-balancer/src/api.rs`, keeping public re-exports stable
  while reducing the crate root orchestration surface.
- Move the Pingora `ServiceWithDependents` adapter for load-balancer discovery
  and health-check background work into the root runtime crate. The
  load-balancer crate now exposes Fluxheim-owned shutdown/ready service
  primitives and no longer imports Pingora service/listener/shutdown types.
- Move load-balancer request-key extraction behind a public
  `LoadBalancerRequestView` trait. The root proxy now adapts Pingora request
  headers at the runtime boundary, keeping load-balancer selection and
  persistence logic transport-neutral.
- Bound native TLS TCP health-check handshakes with the configured connect
  timeout so a backend that accepts TCP and stalls TLS cannot freeze the
  load-balancer health/discovery loop.

## 1.6.0 - 2026-06-14

### Added

- Start the 1.6 Pingora-exit foundation line. Runtime behavior is intended to
  remain unchanged in this first 1.6 release while the project records baseline
  evidence and guardrails for staged dependency removal.
- Add `docs/modularity-exceptions.md` and
  `scripts/validate-modularity-policy.sh` to make the 500-line modularity
  policy measurable at release time. Existing oversized Rust files are listed
  as legacy exceptions with split targets instead of hidden as normal debt.
- Add `docs/runtime-baseline.md` and
  `scripts/capture-runtime-baseline.sh` to record locked dependency trees,
  per-profile Pingora dependency presence, release metadata, and default
  release-binary size before the runtime cutover work begins.
- Add `scripts/capture-runtime-performance-baseline.sh` and wire it into
  release-mode runtime baseline capture. It records local startup time, idle
  RSS/file descriptors, static HTTP latency, cache MISS/HIT latency,
  load-balancer route timing, keep-alive throughput, and fresh TLS connection
  timing.
- Add `docs/pingora-dependency-exceptions.tsv` and
  `scripts/validate-pingora-dependency-policy.sh` so the 1.6 line has a
  release-gated inventory of allowed Pingora crates per official profile.
- Add `docs/runtime-parity-fixtures.md`, `docs/runtime-parity-fixtures.tsv`,
  and `scripts/validate-runtime-fixtures.sh` to pin the smoke scripts,
  examples, and TLS fixtures that define runtime parity before
  HTTP/cache/LB/TLS cutovers begin.
- Add initial `fluxheim-runtime` and `fluxheim-server` workspace crates for
  Fluxheim-owned shutdown, background task, listener, and server-runner
  boundary traits. The current Pingora runtime path is unchanged.
- Add typed `PolicyEpoch`, `PolicyProof`, `RuntimeFact`, decision, reason, and
  visibility primitives in `fluxheim-runtime` for later policy-proof adoption.
  They are not wired into request handling in this release.
- Add `docs/extraction-dependency-graph.md` to record the intended split order
  for `snapshot`, protocol, tracing/observability, headers, ACME,
  runtime/server, cache, proxy, and admin modules before the Pingora cutover.
- Add `docs/runtime-facts-and-policy-proofs.md` to guide typed, bounded,
  redacted decision evidence for route policy, cache admission,
  load-balancer selection, admin mutation, config promotion, and future Wasm
  host calls.

### Changed

- Bump workspace, RPM, release notes, and image documentation to `1.6.0`.
- Update README wording so the 1.5 load-balancer line is closed and future
  load-balancer health-check work is no longer described as a later 1.5.x
  item.
- Refresh `ROADMAP.md` so `1.6.x` is consistently documented as the
  Pingora-exit line, shared Wasm extensibility is moved to `1.7`, and HTTP/3
  remains after the runtime boundary is stable.
- Harden `scripts/validate-pingora-dependency-policy.sh` so documented
  Pingora removal targets are enforced against the current Fluxheim version
  instead of acting as a set-membership inventory only.
- Tighten release-gate scripts by requiring modularity exceptions to be listed
  as structured table rows and by giving the UDP smoke negative assertion a
  longer observation window.

## 1.5.23 - 2026-06-14

### Added

- Add cache origin-protection configuration with per-vhost or per-route
  `max_concurrent_fills` budgets for Fluxheim-owned origin fill paths. The
  first protected path is range slice fill: when the budget is saturated,
  Fluxheim refuses the protected fill with `503` instead of falling through to
  origin.
- Expose cache origin-protection rollout through admin cache status and
  low-cardinality metrics:
  `fluxheim_cache_origin_protection_enabled_policies`,
  `fluxheim_cache_origin_protection_max_concurrent_fills`, and bounded
  `origin_protected` cache policy activity.
- Extend `fluxheim cache-key` and `fluxheim cache-lookup` previews with
  origin-protection policy state and expectation flags for release gates.

### Changed

- Consolidate slice-fill, peer-fill, and origin-fill cache concurrency permits
  into one shared limiter implementation so future hardening of the DoS budget
  primitive applies uniformly.

## 1.5.22 - 2026-06-14

### Changed

- Start the next cache/load-balancer crate-boundary pass by moving
  load-balancer persistence key extraction behind a Fluxheim-owned request
  view trait. The Pingora `RequestHeader` adapter remains at the
  load-balancer API boundary, so routing, persistence, managed-cookie, header,
  cookie, URI, and source-IP selection behavior is unchanged.
- Add persistence-module tests that exercise managed-cookie validation through
  the Fluxheim request view directly, reducing Pingora coupling in unit-level
  load-balancer coverage.
- Harden `fluxheim-web` filesystem tests that exercise symlink detection by
  using repository-local, component-validated test paths instead of raw
  `temp_dir()`-derived paths, resolving CodeQL path-expression alerts without
  changing runtime web behavior.
- Move cleartext TCP health checks to a Fluxheim-owned Tokio connect probe.
  TLS TCP health checks still use the existing Pingora transport connector for
  SNI/TLS handshake compatibility until the larger `1.6.x` connector-removal
  work.
- Move cache request bypass, client revalidation, and range-selection
  decisions behind a Fluxheim-owned cache request view. The root proxy cache
  module now adapts Pingora request headers into that view, keeping runtime
  behavior unchanged while shrinking the Pingora-facing cache surface.
- Move cache response admission policy for status, content type, response
  no-store headers, Vary handling, and range responses into the cache crate,
  leaving the root proxy cache module as the Pingora response adapter.
- Move cache storage interface result enums for purge type and miss completion
  into the cache crate, keeping Pingora conversions in the root adapter layer.
- Move range/slice cache-key component construction into the cache crate so
  the proxy cache module only adapts the Pingora cache-key container.
- Harden UDP beta passive health so local downstream drop conditions
  (`response_rate_limited` and oversized upstream responses) do not count as
  upstream failures, and rate-limit passive-ejection warning logs.

## 1.5.21 - 2026-06-13

### Added

- Added UDP beta per-source pressure controls with
  `max_sessions_per_source`, released when each datagram session completes.
- Added UDP beta per-source response-rate limiting with
  `max_responses_per_source_per_second` for request/response UDP routes.
- Added UDP Prometheus metrics for accepted/sent/error datagrams, drops, and
  active route sessions.
- Added `GET /_fluxheim/udp/status` for admin-visible UDP route configuration,
  listener exposure warnings, and configured UDP limits.
- Added UDP beta passive upstream health: consecutive request/response
  failures can temporarily eject a member from route selection, and successful
  exchanges clear the ejection state.

### Changed

- UDP `dns-load-balance` routes now emit a security warning when configured on
  non-loopback listeners during the beta period.
- Updated UDP beta documentation and smoke coverage for the new production
  readiness guardrails.
- Extended UDP smoke coverage to verify exact-cap responses are accepted and
  oversized downstream datagrams are dropped before reaching the upstream.
- Added optional stable-gate UDP beta smoke via `FLUXHEIM_GATE_UDP=1`, with
  `FLUXHEIM_UDP_SMOKE_ITERATIONS` for longer local soak runs.
- Hardened UDP beta hot paths by removing per-response full-map scans from
  source response-rate limiting and bounding passive-health fallback selection
  by upstream count instead of total configured weight.

## 1.5.20 - 2026-06-13

### Changed

- Start the `fluxheim-cache` crate boundary by moving shared cache-header
  request/response directive parsing into `crates/fluxheim-cache`. The root
  crate keeps `crate::cache_headers` as a compatibility re-export, so runtime
  behavior and call sites are unchanged.
- Move pure cache admin request/result/preview DTOs into
  `crates/fluxheim-cache::api`, with root `crate::cache_api` and
  `crate::proxy` re-exports kept for compatibility. Pure runtime totals and
  activity-reset DTOs also moved.
- Move cache object metadata, activity stats, tier stats, object lookup, and
  vhost/route runtime stats into `crates/fluxheim-cache::api`. Root
  `crate::cache` and `crate::cache_api` keep compatibility re-exports so admin,
  CLI, metrics, and proxy call sites are unchanged.
- Move cache storage-plan DTOs into `crates/fluxheim-cache::plan`, keeping
  root `crate::cache` re-exports while the Pingora storage adapters remain in
  the root cache runtime.
- Move cached object DTOs and `CacheStoreError` into
  `crates/fluxheim-cache::object`, keeping root `crate::cache` re-exports for
  memory-cache and test call sites.
- Move cache request/key DTOs into `crates/fluxheim-cache::request`, with root
  `crate::cache` re-exports and root cache-key builders preserving the existing
  behavior.
- Move cache range/slice request DTOs, single-range parsing, client range
  parsing, client-range resolution, and required-slice planning into
  `crates/fluxheim-cache::request`, leaving root `crate::proxy_cache` as the
  Pingora request-header and cache-key adapter.
- Move Content-Range parsing into `crates/fluxheim-cache::request`, so
  range-cache admission and slice-object reconstruction share one pure parser.
- Move pure cache freshness helpers for remaining TTL and synthesized
  Cache-Control freshness directives into `crates/fluxheim-cache::headers`.
- Move Vary header parsing and configured request-header variance policy into
  `crates/fluxheim-cache::headers`, keeping root `crate::proxy_cache` focused
  on Pingora request hashing and adapter logic.
- Move Vary request hash material framing into
  `crates/fluxheim-cache::headers`; root `crate::proxy_cache` now only adapts
  Pingora request headers and calls the Pingora hash function.
- Move cacheable response Content-Type matching into
  `crates/fluxheim-cache::headers`, leaving root cache admission as the
  status/header adapter.
- Move cache-bypass cookie and query-string matching, including percent-decoded
  query comparisons, into `crates/fluxheim-cache::headers`.
- Move cache stale-serving event and status/error allow policy into
  `crates/fluxheim-cache::headers`, keeping Pingora error classification in
  root `crate::proxy_cache`.
- Move response `Age` and `Cache-Control` max-age/s-maxage parsers into
  `crates/fluxheim-cache::headers`, leaving root response helpers as thin
  Pingora header adapters.
- Move Cache-Control directive merge/replacement into
  `crates/fluxheim-cache::headers`, leaving root response mutation as a
  Pingora header adapter.
- Move range response `Content-Range` and `Content-Length` validation into
  `crates/fluxheim-cache::request`, leaving root range-cache admission as the
  Pingora status/header adapter.
- Move cache-key component formatting and the temporary HEAD cache bypass
  predicate into `crates/fluxheim-cache::request`, keeping root compatibility
  wrappers for existing proxy callers.
- Move multipart slice range policy sizing into
  `crates/fluxheim-cache::request`, leaving root `crate::proxy_cache` as the
  config adapter.
- Move cache Prometheus label classifiers into `crates/fluxheim-cache`,
  keeping root `crate::metrics` as recorder wiring.
- Move cache purge-index state, purge-entry DTOs, storage-local purge result
  counters, and cache-key path matching helpers into
  `crates/fluxheim-cache::purge_index`. Root `crate::cache` keeps the existing
  compatibility type names while the Pingora storage implementations remain in
  the root runtime adapter.
- Start the `fluxheim-web` crate boundary by moving static directory-listing
  data/rendering helpers into `crates/fluxheim-web`. The root `crate::web`
  module re-exports the same types and renderer while keeping Pingora response
  serving in the root adapter.
- Move static byte-range parsing into `crates/fluxheim-web`, keeping
  `crate::web` compatibility re-exports for the existing static response
  planner and tests.
- Move static response planning, conditional request evaluation, weak ETag
  construction, and range response plan DTOs into `crates/fluxheim-web`.
  `crate::web` keeps the existing `StaticRequestConditions` compatibility
  adapter so proxy call sites and cache-refresh semantics are unchanged.
- Move safe relative path and directory-listing path helpers into
  `crates/fluxheim-web`, leaving root static serving responsible for filesystem
  canonicalization and symlink checks.
- Move configured web-root symlink detection into `crates/fluxheim-web`, keeping
  root `StaticFileServer` construction as the filesystem adapter.
- Move static cache identity formatting into `crates/fluxheim-web`, keeping
  root `StaticFile` as the filesystem metadata adapter.
- Start the `fluxheim-php-fpm` crate boundary by moving PHP-FPM timeout
  classification and bounded error-outcome helpers into
  `crates/fluxheim-php-fpm`, with the root PHP-FPM module re-exporting the same
  names for existing runtime and test code.
- Move managed PHP-FPM restart-backoff and sanitized `PATH` fallback helpers
  into `crates/fluxheim-php-fpm`, again keeping the root module as the
  compatibility surface for existing code.
- Move managed PHP-FPM config rendering and its config-value validators into
  `crates/fluxheim-php-fpm`, leaving root PHP-FPM process supervision as the
  compatibility adapter.
- Move PHP-FPM effective timeout calculation, retry attempt/deadline policy,
  retryable status matching, and retryable error classification into
  `crates/fluxheim-php-fpm`, with root `crate::php_fpm` retaining the
  `StatusCode` compatibility adapter.
- Move PHP-FPM endpoint selection and endpoint DTOs into
  `crates/fluxheim-php-fpm`, with root `crate::php_fpm` keeping compatibility
  re-exports for the proxy runtime and tests.
- Move PHP-FPM response-header name/value safety guards into
  `crates/fluxheim-php-fpm`, keeping root response parsing as the Pingora
  header adapter.
- Move PHP-FPM response split, `Status` parsing, ASCII trimming, and header
  colon splitting into `crates/fluxheim-php-fpm`, leaving root response parsing
  as the Pingora response-header adapter.
- Move managed PHP-FPM instance-name generation and metric-pool sanitization
  into `crates/fluxheim-php-fpm`, leaving root process supervision as the Unix
  runtime adapter.
- Start the `fluxheim-geoip` crate boundary by moving `GeoContext` and the
  optional local MMDB runtime into `crates/fluxheim-geoip`, with root
  `crate::geo_context` and `crate::geoip` compatibility re-exports.
- Start the `fluxheim-compression` crate boundary by moving response
  compression encoder lifecycle and output-limit accounting into
  `crates/fluxheim-compression`, while keeping Pingora header selection and
  response mutation in the root adapter.
- Move Accept-Encoding token and qvalue parsing into
  `crates/fluxheim-compression`, keeping root response-header selection as the
  Pingora adapter.
- Move compression response policy string matching for Cache-Control directives
  and Content-Type eligibility into `crates/fluxheim-compression`, leaving root
  response-header iteration as the adapter.
- Move active Content-Encoding classification and compression input-size bounds
  into `crates/fluxheim-compression`, keeping root response headers/config as
  adapters.
- Start the `fluxheim-observability` crate boundary by moving W3C Trace Context
  parsing, generation, and traceparent normalization into
  `crates/fluxheim-observability`, with root `crate::trace_context` kept as a
  compatibility re-export.
- Move the shared OTLP HTTP agent and symlink-safe custom CA bundle loader into
  `crates/fluxheim-observability` behind its `otlp-http` feature, while keeping
  the root `crate::otlp_http` module as the metrics/tracing adapter.
- Move OTLP HTTP endpoint parsing into `crates/fluxheim-observability`, keeping
  the Prometheus metrics payload conversion in the root metrics adapter.
- Move the Prometheus-to-OTLP metrics payload builder into
  `crates/fluxheim-observability` behind its `otlp-metrics` feature, leaving
  root metrics OTLP as exporter lifecycle and HTTP post wiring.
- Move access-log helper logic for request-id validation/generation,
  shared low-cardinality status classes, response byte counting, and Unix
  nanosecond timestamps into `crates/fluxheim-observability`, while the root
  access-log module keeps Pingora request-header integration and JSON event
  assembly and Prometheus metrics reuses the shared status-class helper.
- Move shared JSON string escaping for access logs and runtime JSON logs into
  `crates/fluxheim-observability`, keeping both root log schemas unchanged.
- Move proxy metrics outcome, method, and status-class label bucketing into
  `crates/fluxheim-observability`, keeping root `crate::metrics` as the
  Prometheus registry/recorder adapter.
- Move general Prometheus label classifiers for host-routing, admin-auth,
  compression, edge-policy, load-balancer event/queue/upstream, stream, ACME,
  PHP/PHP-FPM, and metrics-OTLP exporter events into `crates/fluxheim-observability`,
  further narrowing root `crate::metrics` to recorder wiring.
- Move Prometheus numeric helper logic for bounded ratios and saturating gauge
  conversions into `crates/fluxheim-observability`, leaving root metrics as the
  registry/recorder adapter.
- Move `LoadBalanceSelection` metric-label mapping into `fluxheim-config`,
  keeping root `crate::metrics` as a compatibility wrapper.
- Move config-derived cache and load-balancer metrics summary aggregation into
  `fluxheim-config`, leaving root metrics to only publish the Prometheus
  gauges.
- Move the OTLP trace exporter and trace-span payload builder into
  `crates/fluxheim-observability` behind its `otlp-trace` feature, with root
  `crate::otel_otlp` kept as a compatibility re-export.
- Start the `fluxheim-protocol` crate boundary by moving PROXY protocol v1/v2
  upstream header framing into `crates/fluxheim-protocol`, while the root
  `crate::proxy_protocol` module keeps the Pingora L4 connector adapter.
- Move route method matching and prefix-boundary helpers into
  `crates/fluxheim-protocol`, keeping root `crate::route_policy` as the config,
  regex-capture, and Pingora request adapter.
- Start the `fluxheim-snapshot` crate boundary by moving the durable config
  snapshot store, metadata validation, rollback pointer handling, and
  symlink-safe filesystem writes into `crates/fluxheim-snapshot`, with root
  `crate::snapshot` kept as a compatibility re-export.
- Move reload-impact classification into `crates/fluxheim-config`, with root
  `crate::reload` kept as a compatibility re-export for admin and CLI reload
  reporting.
- Move load-balancer runtime/member weight parser helpers into
  `crates/fluxheim-load-balancer`, leaving root admin as the HTTP/query
  endpoint adapter.
- Move cache admin summary math helpers into `crates/fluxheim-cache::api`,
  leaving root admin JSON assembly as the response adapter.
- Move runtime cache-purger `usize` metric saturation into
  `crates/fluxheim-observability`, keeping root runtime as the background-task
  adapter.
- Move downstream PROXY-protocol trusted-source parsing into
  `crates/fluxheim-protocol`, leaving root runtime as the Pingora listener
  adapter.
- Move HTTP Upgrade token grammar validation into `crates/fluxheim-protocol`,
  leaving root proxy as the Pingora request-header adapter.
- Move Fluxheim `Via` header value formatting into `crates/fluxheim-protocol`,
  leaving root proxy as the Pingora header mutation adapter.
- Move multipart cache Content-Type sanitization into
  `crates/fluxheim-cache::headers`, leaving root proxy as the slice response
  assembly adapter.
- Move cache slice metadata first-header extraction into
  `crates/fluxheim-cache::headers`, leaving root proxy as the slice identity
  adapter.
- Move hop-by-hop `Connection` option token validation onto the shared
  `crates/fluxheim-protocol` HTTP token grammar helper.
- Move response header rewrite prefix authority-boundary matching into
  `crates/fluxheim-protocol`, leaving root header policy as the mutation
  adapter.
- Move cache CLI header-name validation onto the shared
  `crates/fluxheim-protocol` HTTP token grammar helper.
- Move config HTTP token validation onto the shared `crates/fluxheim-protocol`
  grammar while preserving method-specific uppercase checks.
- Move cache object lookup summary formatting into `crates/fluxheim-cache`,
  leaving the CLI as the command/output adapter.
- Move cache-warm count summaries and bounded status labels into
  `crates/fluxheim-cache`, leaving the CLI to print the prepared summaries.
- Use the shared `crates/fluxheim-cache` storage-tier helper directly from
  admin cache status JSON.

### Fixed

- Harden the vendored HTTP/1 request parser to reject requests that carry both
  `Transfer-Encoding` and `Content-Length`, matching Fluxheim's raw
  request-framing release smoke and avoiding ambiguous downstream body
  framing.
- Document the shared protocol HTTP token grammar as case-permissive and warn
  when accepted IPv6 trusted-proxy CIDR entries are broader than `/32`.
- Fix cache-only builds after shared cache stats moved purge-index and activity
  fields into the always-present cache API shape.
- Allow real provider IPv6 trusted-proxy ranges such as Cloudflare's
  `2a06:98c0::/29`. The `1.5.19` config-crate split preserved runtime IPv6
  CIDR support but made config validation too strict by rejecting trusted proxy
  IPv6 prefixes broader than `/32`.

## 1.5.19 - 2026-06-12

### Security

- Fix fallback proxy cache auth ordering so cache fallback handling cannot run
  before the configured authorization decision.
- Reject ambiguous dot-segment proxy request paths before route selection,
  route-local policy checks, cache keying, or upstream forwarding.
- Treat incoming method casing as equivalent for route method filters so
  lowercase HTTP/1 method tokens cannot miss method-scoped route policy.
- Restrict accepted inbound request IDs to an identifier-safe alphabet so
  URL-like or email-like values are regenerated before reaching logs, traces,
  templates, or upstream headers.
- Release response-compression output buffers after each emitted chunk while
  preserving the cumulative `max_output_bytes` cap.
- Make route prefix matching and prefix stripping path-segment aware so sibling
  paths such as `/repoadmin` cannot enter a `/repo` route or rewrite to
  unintended upstream paths.
- Percent-encode URI-special bytes in route regex capture substitutions before
  applying rewrite templates, preserving slash-spanning captures while removing
  raw matrix/userinfo/list delimiters from rewritten upstream paths.
- Normalize `Set-Cookie` `Domain` and `Path` attribute values before response
  rewrites, covering leading-dot domains, quoted attribute values, and trailing
  ASCII whitespace so alternate cookie syntax cannot bypass configured rewrite
  rules.
- Harden range slice-cache origin fill so dynamic-only upstream discovery
  cannot fall back to the default loopback upstream, unsafe dot-segment origin
  paths are rejected, and multipart range requests are bounded by range count
  and response-wrapper overhead.
- Resolve exact local-static purge identities through the same route rewrite
  logic used by static serving, including `rewrite_prefix`.
- Apply decoded route matching to edge policy checks, closing mismatches between
  encoded request paths and policy enforcement.
- Preserve private cache-control directives for status-specific TTL handling so
  restrictive origin cache headers are not weakened by cache policy.
- Harden PHP-FPM path handling by denying scripts after resolved-path
  normalization and covering directory-index resolution under denied PHP path
  prefixes.
- Fix proxy-only route decode feature wiring so shared path safety remains
  available in proxy builds without cache.
- Isolate upstream CA bundle material in peer reuse keys to avoid reusing
  upstream TLS peers across distinct trust material.
- Add a default stream proxy connection cap to avoid unbounded accepted TCP
  stream connections.
- Detach self-healing probes from public proxy traffic paths.
- Preserve restrictive PHP cache headers when PHP-FPM responses are converted
  into Fluxheim responses.
- Reject PHP-FPM `PHP_VALUE` and `PHP_ADMIN_VALUE` style ini-control parameters
  so configured PHP params cannot rewrite php-fpm runtime policy.
- Clean pending PHP request-body spool files on retry/error paths.
- Add `php.max_in_flight`, defaulting to `8`, to cap concurrent PHP-FPM requests
  before request body buffering and FastCGI dispatch.
- Add `proxy.load_balance.passive_health.min_healthy_backends`, defaulting to
  `1`, so passive outlier ejection cannot fail-closed an entire load-balanced
  pool by default. Operators can set it to `0` to retain strict fail-closed
  passive-health behavior.
- Harden managed-cookie load-balancer persistence so invalid affinity cookies
  no longer create server-side persistence-table entries, while newly issued
  signed cookies immediately record one bounded table entry for the selected
  backend so the next request remains pinned.
- Reject verified HTTP proxy upstream TLS configs that target an IP-addressed
  upstream without explicit `upstream_sni`, preventing the Pingora connector
  from falling into empty-SNI certificate-verification bypass behavior.
- Harden HTTP load-balancer discovery so private, loopback, link-local,
  metadata, multicast, reserved, and documentation IP-literal backends are
  rejected by default unless the operator explicitly enables
  `proxy.upstreams_http_allow_private_backends`.
- Add `proxy.downstream_read_timeout_secs`, defaulting to 60 seconds, and wire
  it into vendored Pingora HTTP/2 downstream request-body reads so slow-body
  clients cannot hold proxy forwarding tasks indefinitely while withholding
  DATA frames or END_STREAM.
- Apply the downstream read timeout before PHP-FPM request-body collection and
  drain paths, covering PHP routes that read the body before FastCGI execution
  begins.
- Revalidate managed PHP-FPM binary paths immediately before spawning child
  processes and reject symlinked binaries at config validation so local path
  swaps cannot replace the supervised executable between reload and spawn.
- Harden downstream HTTP/2 flow-control defaults by capping per-stream send
  buffering at 256 KiB, keeping DATA frames at 16 KiB, fixing the receive
  window at 64 KiB, and reducing pending-accept reset-stream pressure.
- Remove encrypted filesystem disk-cache fill heap amplification for the local
  provider by committing streamed cache bodies through bounded AEAD chunks, and
  bound the OpenBao Transit whole-object fallback heap budget.
- Harden DNS-refreshed upstream discovery against DNS rebinding pivots by
  rejecting private, loopback, link-local, multicast, reserved, documentation,
  metadata, and unspecified resolved addresses unless
  `proxy.upstream_dns_allow_private_backends = true` is set.
- Harden HTTP and DNS discovery backend filtering by applying the IPv4 private
  address policy to IPv4-mapped and IPv4-compatible IPv6 literals before they
  can be accepted as upstream addresses.
- Harden split-config trusted-proxy handling by extending
  `server.trusted_proxies` fragments instead of replacing the main list, and by
  rejecting catch-all or near-global trusted-proxy ranges such as `0.0.0.0/0`
  and `::/0`.
- Harden split-config proxy handling by applying field-level `[proxy]`
  fragment merges so a later timeout-only proxy fragment cannot silently clear
  upstream TLS verification, auth request, mirror, or load-balancer policy.
- Complete recursive split-config merges for `[proxy.auth_request]`,
  `[proxy.mirror]`, and `[proxy.load_balance]` so partial nested fragments
  cannot reset established auth, shadow-traffic, persistence, health-check,
  retry, or load-balancer selection policy back to defaults.
- Harden split-config handling for `[compression]`, `[cache]`,
  `[cache_purger]`, `[web]`, and `[stream]` so partial fragments cannot
  silently drop previously configured compression limits, cache encryption,
  static-file safety policy, or stream routes.
- Harden split-config admin handling by applying field-level `[admin]`
  fragment merges so a later ops-socket or health-only admin fragment cannot
  silently disable the admin API or clear token and snapshot-store settings.
- Harden cache peer-fill request construction so peer lookups use the selected
  vhost's canonical `Host`, while client-controlled `Host` headers and
  absolute-form URI authorities cannot pivot peer requests to another vhost.
- Add an inbound peer-fill recursion guard so requests marked with
  `X-Fluxheim-Peer-Fill: 1` cannot launch another outbound peer-fill fetch in
  cyclic peer topologies.
- Decode percent-encoded cache bypass query names and values before comparing
  `bypass_query_params` and `bypass_query_values`, closing encoded preview or
  private-mode cache bypass evasion.
- Align configured cache Vary request headers with the 16-field runtime Vary
  cap and reject effective origin-plus-configured Vary overflows at cache
  admission instead of dropping variance.
- Harden auth-request response header handling so allowed auth response
  headers cannot override Fluxheim's upstream request header policy on name
  collisions.
- Harden auth-request forwarded context handling so allow-listed
  `X-Original-URI`, `X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Host`, and
  `X-Forwarded-Proto` values are synthesized from Fluxheim's trusted request
  context instead of copied from spoofable client headers.
- Match auth-request split `Cookie` handling to the origin request path by
  joining repeated `Cookie` fields with `; ` instead of `, ` before sending the
  authorization subrequest.
- Harden Unix admin-token and file-log opening by using rustix
  architecture-correct `NOFOLLOW` flags instead of hand-coded constants.
- Harden trusted-proxy `X-Forwarded-For` parsing so any malformed hop rejects
  the forwarded chain and falls back to the direct peer IP instead of silently
  attributing traffic to a trusted proxy hop.
- Normalize IPv4-mapped IPv6 client addresses before trusted-proxy,
  access-policy, rate-limit, and GeoIP decisions so IPv4 CIDR policy also
  applies on dual-stack listeners that report IPv4 peers as `::ffff:...`.
- Restrict WebSocket-enabled proxy routes to the `websocket` upgrade token so
  valid but unrelated protocol upgrades such as `h2c` are not forwarded to
  upstreams.
- Strip HTTP/1 `Connection` and `Upgrade` request headers when
  `proxy.websocket = false`, preventing normal proxy routes from tunneling
  upgraded protocols by accident.
- Remove vendored Pingora upstream TLS underscore-to-hyphen hostname
  verification rewriting so certificates are checked against the exact
  configured SNI or alternative name.
- Strip client-controlled hop-by-hop request headers before forwarding to
  upstreams, including `Connection`-listed extension headers and non-WebSocket
  `Upgrade` values.
- Harden response `Location` and `Refresh` prefix rewrites so absolute URL
  prefixes only match the intended authority boundary and cannot rewrite
  userinfo-style URLs such as `http://origin@evil.example/`.
- Reject redirect templates that place `{query}` inside the URL authority so
  attacker-controlled query strings cannot turn operator redirect rules into
  authority-changing redirects.
- Harden Host and authority normalization by rejecting percent signs,
  consecutive dots, leading/trailing label hyphens, overlong labels, and
  numeric-only final labels in DNS hostnames.
- Harden OpenBao Transit cache encryption calls by disabling HTTP redirects
  and reading Transit JSON responses through a bounded buffer before parsing.
- Harden PHP-FPM path handling by rejecting protocol-relative directory-slash
  redirects and decoded control characters in path-derived FastCGI params.
- Harden PHP-FPM TCP endpoint validation by rejecting unsafe IP literals and
  requiring `allow_private_tcp_upstreams = true` for loopback,
  private/link-local IPs.
- Reject stream routes that enable upstream TLS certificate verification for
  IP-addressed upstreams without an explicit `upstream_sni`, matching the HTTP
  proxy validation rule and avoiding runtime hostname-verification skips.
- Harden traffic mirroring by rejecting unsafe mirrored paths/queries before
  outbound URL construction and suppressing recursive mirror requests marked
  with `X-Fluxheim-Mirror`.
- Add stream route `allow_sources` and `deny_sources` IP/CIDR policies so raw
  TCP stream listeners can reject unauthorized sources before connecting
  upstream.
- Harden stream hostname upstreams against DNS-rebinding pivots by rejecting
  private or reserved DNS answers unless the route explicitly sets
  `upstream_dns_allow_private_addresses = true`.
- Reject horizontal tabs in configured static header values so operator header
  policies cannot pass HTTP/1.x-only whitespace into HTTP/2 upstream requests
  or responses.
- Rewrite quoted `Refresh` response URLs for configured prefix rewrite rules,
  covering both single-quoted and double-quoted URL forms.
- Harden runtime file-log opening by rejecting symlinked log path components
  immediately before creating or appending the log file.
- Harden `Accept-Encoding` qvalue parsing so non-finite or malformed values
  such as `NaN` and `Infinity` cannot influence compression negotiation.
- Add `admin.ops_socket.require_bearer_token` so local Unix ops-socket status
  endpoints can require the same bearer token as the TCP admin control plane.
- Require bearer-token authentication for `GET /_fluxheim/snapshots` on the
  Unix ops socket even when other read-only status endpoints are local-only.

### Changed

- Move the Fluxheim-owned load-balancer core into the internal
  `crates/fluxheim-load-balancer` workspace crate.
- Keep the root `crate::load_balancer` compatibility shim so admin, proxy,
  runtime, config, release profiles, and operator-facing behavior remain
  unchanged.
- Move load-balancer backend snapshots, discovery adapters, health checks,
  selection algorithms, runtime policy overrides, persistence, queue policy,
  state files, background task glue, and tests together under the new crate.
- Add narrow root-to-crate hooks for metrics event recording and compliance
  HMAC signing without making the load-balancer crate depend on proxy, admin,
  cache, web, or PHP internals.
- Keep `pingora-load-balancing` and Pingora health-check adapter removal as
  later 1.5.x work; this release is an ownership/boundary extraction only.

## 1.5.18 - 2026-06-12

### Changed

- Move the Fluxheim configuration schema, parsing, validation, config-source
  loading, and config tests into the internal `crates/fluxheim-config`
  workspace crate.
- Keep the root `crate::config` and `crate::config_*` compatibility shims so
  runtime modules, release profiles, config tester behavior, and operator config
  syntax remain unchanged.
- Add a config-crate `test-support` feature so root integration tests retain
  repository-local process paths without changing production defaults.

### Security

- Harden downstream HTTP/2 response handling against the HTTP/2 Bomb
  window-stall half by adding an absolute
  `proxy.downstream_total_response_timeout_secs` response-write lifetime bound.
- Clarify and test that `server.limits.max_request_headers` counts duplicate
  request header values, including split HTTP/2 `Cookie` crumbs, before routing.

## 1.5.17 - 2026-06-11

### Changed

- Start the workspace and shared-crate foundation line.
- Convert the repository into a Cargo workspace with `crates/fluxheim-common`
  as the first internal shared crate.
- Move the Fluxheim-owned `FluxError`/`FluxResult` boundary into
  `fluxheim-common` while keeping the root `crate::flux_error` adapter for
  existing runtime code.
- Move shared forward-path safety validation into `fluxheim-common` while
  keeping the root `crate::path_safety` adapter for existing proxy/cache code.
- Move repository-local test path helpers behind the `fluxheim-common`
  `test-support` feature while keeping the root `crate::test_support` adapter
  for existing tests.
- Update `regex` from `1.12.3` to `1.12.4`.
- Add a release-gate freshness check for compatible non-Pingora crate updates
  and strengthen release metadata validation for release notes, README,
  build/container docs, and RPM version alignment.
- Copy workspace crates into all container build stages so release images build
  correctly after the workspace split.
- Make `scripts/stable_release_gate.sh release` require the root image smoke
  plus representative Debian and Alpine variant image smokes before tagging.
- Fix the OpenSSL FIPS support build-script hex literal grouping so Rust 1.96
  clippy accepts the vendored support crate under `-D warnings`.
- Keep all feature profiles, binaries, release scripts, RPM/container behavior,
  config syntax, and runtime behavior unchanged in this first workspace slice.

## 1.5.16 - 2026-06-10

### Changed

- Start the UDP/GSLB exploration line with a separate `[udp]` beta
  configuration namespace and runtime service instead of extending TCP stream
  routes with UDP semantics.
- Add the `udp-proxy` feature gate and bounded UDP route schema for explicitly
  scoped future modes: `dns-load-balance`, `syslog-forward`,
  `quic-pass-through`, and `game-proxy`.
- Add beta UDP listener/runtime support for DNS-style request/response
  forwarding and syslog-style one-way forwarding.
- Validate UDP route names, listeners, upstreams, upstream weights, upstream
  aliases, idle/session timeouts, datagram caps, and session caps before any
  datagram forwarding starts.
- Add `response_timeout_secs` for UDP routes, defaulting to `3`, so unanswered
  DNS-style request/response datagrams do not hold route slots for the full
  idle timeout.
- Remove the unused beta `max_session_secs` UDP field before release; current
  beta modes process one datagram at a time and use `response_timeout_secs` for
  upstream waits.
- Drop oversized upstream UDP responses instead of forwarding truncated
  datagrams, and rate-limit high-volume UDP drop warnings.
- Default UDP route `max_sessions` to `4096`; `0` remains an explicit
  unlimited setting.
- Add `scripts/smoke_udp_proxy.sh` to prove the beta UDP runtime through the
  Fluxheim binary with local UDP backends.
- Refresh low-risk dependency and workflow pins: `base64-ng` 1.0.8, `http`
  1.4.2, manifest `log` 0.4.32, and exact current GitHub Action tags for
  checkout and Docker image workflows.
- Keep `udp-proxy` out of the normal full/proxy/load-balancer feature profiles
  until a reviewed runtime exists. Configs with `udp.enabled = true` fail
  clearly unless built with the beta feature.
- Keep QUIC pass-through, game-server UDP proxying, generic UDP proxying,
  authoritative DNS/GSLB, WAF, VPN/firewall appliance behavior, HTTP/3 ingress,
  and Wasm/iRules/Lua scripting outside this stop line.
- Document that `dns-load-balance` remains beta and must not be exposed as an
  open public DNS reflector without network ingress filtering and future
  response-rate-limit work.

## 1.5.15 - 2026-06-10

### Changed

- Start the database/protocol-aware health-check line with bounded Redis
  `PING`, MySQL/MariaDB handshake, and PostgreSQL SSLRequest active health
  checks for load-balancer pools.
- Add `protocol = "redis"` for `proxy.load_balance.health_check`; the probe
  opens a bounded TCP connection to the selected backend, sends one fixed RESP
  `PING` frame, and requires a simple-string `+PONG` response.
- Read Redis health-check responses until CRLF within the existing 64-byte cap
  so fragmented `+PONG\r\n` responses do not falsely mark healthy Redis
  backends down.
- Add `protocol = "mysql"` for `proxy.load_balance.health_check`; the probe
  opens a bounded TCP connection to the selected backend, reads one MySQL
  server greeting packet, and requires a protocol-10 handshake without sending
  a login packet or SQL query.
- Add `protocol = "postgres"` for `proxy.load_balance.health_check`; the probe
  opens a bounded TCP connection to the selected backend, sends PostgreSQL's
  pre-auth SSLRequest, and requires a one-byte `S` or `N` response without
  sending a StartupMessage or SQL query.
- Reject HTTP/gRPC response matchers, request headers, host overrides,
  connection reuse, port overrides, and parallel checking on Redis, MySQL, and
  PostgreSQL probes so database checks remain health probes rather than a
  command/query engine.
- Add `examples/load-balancer-redis-health.toml`,
  `examples/load-balancer-mysql-health.toml`,
  `examples/load-balancer-postgres-health.toml`, and include them in the local
  example config validation gate.
- Add `scripts/smoke_redis_health_check.sh` to prove Redis health checks
  against Valkey in Podman, including observed Redis `PING` commandstats and
  unhealthy transition after the backend stops.
- Add `scripts/smoke_mysql_health_check.sh` to prove MySQL health checks
  against MariaDB in Podman, including observed unauthenticated handshake
  accounting and unhealthy transition after the backend stops.
- Add `scripts/smoke_postgres_health_check.sh` to prove PostgreSQL health
  checks against PostgreSQL in Podman, including observed pre-auth connection
  logging and unhealthy transition after the backend stops.
- Document that repeated idle MySQL/MariaDB pre-auth handshake probes can count
  toward non-loopback server host-cache error budgets (`max_connect_errors`);
  operators should raise that limit, tune probe intervals, or use an
  authenticated `exec` check such as `mysqladmin ping` where needed.
- Log ACME managed-certificate install recovery failures instead of silently
  discarding cleanup or backup-restore errors, making cert/key mismatch recovery
  failures visible to operators.
- Harden two defensive panic surfaces: delay-mode rate limiting now rejects
  impossible non-finite/non-positive local rates before computing a wait
  duration, and load-balancer persistence warning text no longer depends on an
  `unreachable!()` branch.
- Keep Redis TLS, MySQL TLS/authenticated readiness, PostgreSQL TLS/authenticated
  readiness, SMTP/LDAP send-expect, authenticated agent checks, UDP/GSLB, WAF,
  VPN/firewall appliance behavior, and Wasm/iRules/Lua scripting as
  future-version work.

## 1.5.14 - 2026-06-09

### Changed

- Start the local exec health-check line. The stop line is opt-in, bounded
  command probes for health checks that cannot be represented by TCP/TLS,
  HTTP, gRPC, JSON, or later database protocol probes.
- Add `protocol = "exec"` for load-balancer active health checks with an
  absolute `exec_command`, exact `exec_allowed_commands` allow-list,
  bounded literal argv through `exec_args`, and `exec_timeout_secs`.
- Reject `.` and `..` components in exec health-check command paths so the
  allow-list reflects the binary path being reviewed.
- Reject parallel exec checks and unrelated network/HTTP health-check fields on
  exec checks, keeping process execution serial per pool in this release.
- Run exec health checks without a shell, with a cleared inherited
  environment, null stdio, and explicit backend context variables:
  `FLUXHEIM_HEALTH_BACKEND_ADDR`, `FLUXHEIM_HEALTH_BACKEND_HOST`, and
  `FLUXHEIM_HEALTH_BACKEND_PORT`.
- Expose the active health-check protocol in load-balancer runtime status for
  operator visibility without exposing exec command paths or arguments.
- Keep exec health-check backend summaries to `via exec`, avoiding command
  path exposure in log-facing health-check strings.
- Add `examples/load-balancer-exec-health.toml` and include it in the local
  example config validation gate.
- Reject HTTP/gRPC response matchers and request-header fields on exec checks
  so local command probes remain a separate monitor type rather than a
  scripting or response-inspection subsystem.
- Keep authenticated agent checks, database protocol probes, arbitrary
  scripting/Wasm, runtime backend mutation, UDP/GSLB, WAF, and VPN/firewall
  appliance behavior as future-version work.

## 1.5.13 - 2026-06-09

### Changed

- Start the Fluxheim-owned cache interface line. The stop line is the cache
  interface boundary only: existing memory, disk, encrypted disk, storage-bin,
  tiered, purge, stale, cache-lock, range/slice, and predictor behavior remains
  unchanged.
- Add `FluxCacheStorage`, `FluxHandleHit`, and `FluxHandleMiss` as
  Fluxheim-owned cache traits so cache implementations no longer implement
  Pingora's session-bound `Storage`, `HandleHit`, and `HandleMiss` traits
  directly.
- Add narrow Pingora cache adapters for the current HTTP proxy path. Pingora
  remains the HTTP session/cache caller for now, but the implementation side now
  has a Fluxheim-owned boundary for future crate extraction.
- Move cache unit coverage that exercises storage behavior onto the Fluxheim
  cache interface while preserving the Pingora adapter for proxy integration.
- Harden slice-cache multipart range responses by replacing deterministic
  length-derived MIME boundaries with per-response random boundaries and by
  stripping CR/LF from cached upstream `Content-Type` values before writing
  MIME part headers.
- Fix cache-only test imports so cache feature CI builds do not depend on
  proxy-gated Flux cache trait names unless the proxy feature is enabled.
- Keep `privacy-cache` as an explicit future design only. Normal cache remains
  incompatible with `privacy-mode`; a future public-asset cache must enforce no
  client-IP keys, no `Cookie`/`Authorization` admission, no per-user variants,
  no private/no-store/Set-Cookie storage, strict query defaults, and bounded
  memory or encrypted short-TTL disk storage.

## 1.5.12 - 2026-06-08

### Changed

- Start the Fluxheim-native background task registry line. The stop line is
  Fluxheim-owned background work only: cache runtime metrics, stale cache
  purging, ACME renewal scheduling, admin self-healing watchdog work,
  load-balancer refresh loops, and future discovery workers.
- Add `src/background.rs` as a Fluxheim-owned background task adapter with a
  Tokio watch-based shutdown handle and one-shot readiness callback, so
  background task implementations no longer depend directly on Pingora's
  generic `GenBackgroundService` helper, raw `ShutdownWatch` handling, or
  `ServiceReadyNotifier`.
- Move cache metrics, stale cache purging, ACME renewal, and the admin
  self-healing watchdog to the new `FluxBackgroundTask` interface while
  preserving their previous startup and shutdown behavior.
- Move load-balancer discovery/health refresh services through the shared
  Fluxheim background adapter while preserving the existing readiness ordering:
  the service marks ready only after its first discovery update has run.
- Add regression coverage for the Fluxheim background adapter shutdown/ready
  behavior and load-balancer background-service readiness ordering.
- Keep Pingora's service trait boundary only as the server registration adapter
  for this release. HTTP proxy request handling, stream listener ownership,
  cache interfaces, UDP/GSLB, WAF, VPN/firewall appliance behavior, and
  Wasm/iRules/Lua scripting remain future-version work.

## 1.5.11 - 2026-06-08

### Changed

- Start the service-discovery and control-plane integration line. The stop line
  is one or more bounded discovery adapters such as Kubernetes, Consul, or xDS
  after local DNS/file discovery and runtime backend mutation are stable, with
  authentication/trust boundaries, churn limits, safe fallback, status,
  audit/metrics, and reload behavior.
- Update Fluxheim and the vendored `pingora-core` metrics dependency from
  Prometheus 0.13 to 0.14, which moves the transitive protobuf dependency from
  vulnerable 2.x to 3.7.2.
- Remove the obsolete `RUSTSEC-2024-0437` protobuf suppression and its release
  metadata review gate now that the Prometheus/protobuf dependency path is
  fixed.
- Keep Pingora pinned at `=0.8.0` so routine dependency refreshes cannot bypass
  Fluxheim's patched vendored Pingora core.
- Harden downstream HTTP/2 defaults against the HTTP/2 Bomb class by installing
  bounded H2 handshake options and defaulting downstream write timeout to 30
  seconds.
- Add bounded pull-based HTTP upstream discovery for load-balancer pools through
  `proxy.upstreams_http_url`, with optional bearer-token authentication, 64 KiB
  response limits, 2-64 unique authority validation, and 1-300 second refresh
  intervals.
- Report each load-balancer pool's discovery mode and refresh status in runtime
  status, including update frequency, success/failure counters, last
  success/failure timestamps, and a bounded last-error field.
- Emit bounded `fluxheim_load_balancer_events_total` events for background
  discovery refresh successes and failures using the existing vhost/route pool
  labels.
- Harden reload classification for load-balancer discovery services: static
  pool membership, route-local pools, file/DNS/HTTP discovery sources, refresh
  intervals, and HTTP discovery bearer-token files now all require the
  process-upgrade path because their refresh loops are registered at startup.
- Harden HTTP upstream discovery by sending `Accept: application/json` and
  `Cache-Control: no-store`, rejecting non-JSON response `Content-Type` values
  when present, and rejecting empty or whitespace-bearing bearer-token files
  before sending authorization headers.
- Add `examples/load-balancer-http-discovery.toml` as a minimal
  control-plane-backed load-balancer example.
- Refresh load-balancer migration boundary documentation so runtime
  add/remove/update behavior, local runtime-state persistence, and HTTP
  discovery limits match the current `1.5.x` implementation.
- Harden HTTP discovery bearer-token handling by zeroizing Fluxheim's formatted
  Authorization header copy after request construction, and check the
  discovered-upstream cap before allocating the rejected entry.

## 1.5.10 - 2026-06-07

### Changed

- Start the runtime backend-set mutation line. The stop line is authenticated
  add, remove, and update operations for configured load-balancer pool members
  through atomic backend-set swaps.
- Keep the explicit boundary for this release: runtime mutations must include
  validation, audit events, status and metrics visibility, drain behavior, and
  clear selector limitations for hash, ring, Maglev, and power-of-two policies.
  This release does not add xDS/Kubernetes/Consul discovery, UDP/GSLB, WAF,
  VPN/firewall appliance behavior, or Wasm/iRules/Lua scripting.
- Add authenticated admin endpoints for static load-balancer pools:
  `POST /_fluxheim/load-balancer/member-add`,
  `POST /_fluxheim/load-balancer/member-remove`, and
  `POST /_fluxheim/load-balancer/member-update`.
- Publish backend-set and readiness changes as one atomic runtime snapshot, and
  reject runtime backend-set mutations for DNS/file-discovery pools and Maglev
  selectors in this release.
- Require in-flight requests to drain before removing a member or retargeting it
  to a new address.
- Harden privacy-mode load-balancer mutation output so response/log member
  fields use configured aliases or `redacted`, and metrics keep alias-only
  member labels.
- Document that runtime-added or retargeted members carry address and
  configured weight only; aliases, tags, backup/locality/priority metadata, and
  per-upstream caps remain static-config fields.
- Clear per-backend runtime overrides and passive-health state when an admin
  explicitly removes or retargets a runtime backend member, so re-adding the
  same address starts from clean runtime state.
- Start retargeted backend addresses with fresh readiness state instead of
  carrying the previous address's health-check state across the key change.
- Move the "at least one backend remains" remove guard under the runtime
  backend-set mutation lock and cap runtime backend sets at 256 members.
- Save new backend-set mutations through the background runtime-state save path
  and warn if a narrow post-check race leaves a request completing against a
  removed or retargeted address.
- Normalize backend-set mutation `member` fields to the resolved backend
  address while keeping configured aliases in the separate `alias` field.

## 1.5.9 - 2026-06-07

### Changed

- Start the restart-persistent load-balancer state line. The stop line is
  versioned, size-limited, atomically written, auditable local persistence for
  selected runtime member overrides and bounded persistence tables after the
  Fluxheim-native backend model stabilized in the `1.5.7` and `1.5.8` lines.
- Keep the explicit boundary for this release: corrupt or incompatible
  persisted state must be ignored and rebuilt, not poison a pool; this release
  does not add cross-node state sync, runtime add/remove-member, dynamic
  discovery control planes, UDP/GSLB, or Wasm/iRules/Lua scripting.
- Add a versioned load-balancer runtime state snapshot API for runtime member
  overrides and local persistence tables. Snapshot restore validates version,
  entry limits, duplicate keys, override states, runtime weights, persistence
  key size, TTLs, and live backend membership before replacing current state.
- Add optional `proxy.load_balance.runtime_state_file` for local
  restart-persistent load-balancer state. The file is loaded best-effort,
  ignored on corrupt/incompatible input, and written atomically after runtime
  member-state, runtime weight, persistence-table, and persistence-clear
  changes.
- Report `persistent: true` from load-balancer admin mutation responses when a
  pool has `proxy.load_balance.runtime_state_file` configured, and keep
  `persistent: false` for in-memory-only pools.

### Security

- Move request-path persistence state-file writes to the blocking worker pool
  with serialized snapshot writes, while keeping admin mutation saves
  synchronous and ordered.
- Harden runtime state files with fd-based permission setting, temp-file
  cleanup on failed writes, and all-or-nothing restore validation for mixed
  policy/persistence state.
- Document and warn when raw header or cookie persistence writes client affinity
  identifiers to `proxy.load_balance.runtime_state_file`; prefer
  `managed-cookie` or encrypted, access-restricted storage for session-bearing
  identifiers.

## 1.5.8 - 2026-06-07

### Added

- Add bounded custom request headers for HTTP active health checks. Operators
  can now check authenticated or tenant-scoped health endpoints with
  `proxy.load_balance.health_check.request_headers`.
- Add standard gRPC active health checks with optional
  `proxy.load_balance.health_check.grpc_service`.
- Add bounded `expected_body_json` scalar matching for JSON HTTP health
  responses.
- Add health-derived degraded backend weights through `X-Health-Weight`, exposed
  as `health_weight_percent` in runtime status and kept separate from
  configured/admin runtime weights.

### Security

- Validate HTTP health-check request headers at config load time: headers are
  HTTP/gRPC-only, capped at 16 entries and 1024 bytes per value, duplicate
  names are rejected case-insensitively, `Host` stays controlled by the
  existing `host` setting, and hop-by-hop/proxy-control headers are rejected.
- Keep configured health-check request header values out of metrics labels and
  runtime status surfaces.
- Keep gRPC health checks strict: Fluxheim sends the standard HTTP/2 request and
  rejects conflicting HTTP status/header/body matcher config for gRPC protocol
  checks.
- Evaluate load-balancer selection and runtime status from one loaded
  backend/health snapshot per operation, removing the remaining conservative
  mismatch window between backend membership and readiness reads.

## 1.5.7 - 2026-06-06

### Changed

- Start the Fluxheim-native load-balancer core line. The stop line remains
  replacing the `pingora-load-balancing` substrate while preserving current
  config, admin API, status shape, metrics, privacy-mode behavior,
  managed-cookie behavior, and selector results as far as possible.
- Add a Fluxheim-owned backend/backend-set model and route static, file, and
  DNS upstream discovery through it.
- Move load-balancer key, passive-health, slow-start, connection-counter,
  latency, and backend-policy helpers onto a Fluxheim-owned backend identity
  abstraction so those subsystems no longer require Pingora's concrete backend
  type.
- Build Maglev lookup tables from Fluxheim backend identities instead of
  adapting static upstreams to Pingora backend values during table
  construction.
- Move file-refreshed and DNS-refreshed backend discovery behind a
  Fluxheim-owned discovery trait.
- Route runtime backend stats, bounded-load weight accounting, and disabled
  upstream parsing through the same backend identity/adapter layer.
- Move slow-start state regression coverage onto Fluxheim backend identities,
  keeping Pingora backend construction only in runtime-selection tests.
- Replace Pingora's FNV weighted-hash selector for source, URI, header, and
  cookie hash modes with Fluxheim-owned weighted-first FNV selection over the
  current backend container.
- Seed Fluxheim-owned FNV and consistent-hash selectors with per-boot routing
  secrets so clients cannot precompute keys that target a chosen backend.
- Replace Pingora's random selector dependency for power-of-two choices with a
  Fluxheim-owned weighted random first pick and unique backend fallback scan.
- Replace Pingora's consistent-hash selector dependency with Fluxheim-owned
  rendezvous candidate ordering for consistent and bounded-load consistent
  hash modes, while preserving dynamic discovery support through the Fluxheim
  runtime backend container. This is a valid consistent-hash algorithm change
  and can remap existing consistent-hash affinity keys once during the 1.5.7
  upgrade.
- Collapse the load-balancer factory, stats, and priority-check helpers onto a
  concrete readiness container now that Fluxheim owns all shipped selection
  algorithms, removing the remaining generic Pingora selector trait plumbing.
- Centralize runtime backend container operations behind Fluxheim-owned
  adapter helpers so readiness, backend enumeration, and health-check metadata
  have one migration boundary.
- Route static upstream pools through the same Fluxheim-owned discovery
  adapter as file-refreshed and DNS-refreshed pools, removing Pingora's static
  discovery wrapper from load-balancer construction.
- Replace Pingora's generic `GenBackgroundService` wrapper for load-balancer
  pools with a Fluxheim-owned `ServiceWithDependents` implementation while
  preserving the current update and health-check loop.
- Introduce a Fluxheim backend-container trait and move selection/stat modules
  onto that trait instead of the concrete Pingora `LoadBalancer<RoundRobin>`
  type.
- Centralize the remaining concrete runtime backend value type behind the
  backend adapter module so orchestration and discovery use Fluxheim's adapter
  alias while the final value-type replacement remains isolated.
- Wrap load-balanced pools in a Fluxheim runtime type before handing them to
  selection, status, and background-service code.
- Return Fluxheim runtime-wrapped load-balancer pools from discovery so
  selection-mode construction no longer repeats Pingora container wrapping.
- Keep the selector-facing backend-container trait implemented only by the
  Fluxheim runtime wrapper.
- Replace Pingora's load-balancer `Backends` container, discovery adapter, and
  background update loop with Fluxheim-owned backend storage, readiness state,
  discovery refresh, health-check scheduling, and shutdown handling. Existing
  Pingora health-check implementations remain adapted for this slice.
- Move load-balancer health checks behind a Fluxheim-owned health-check trait,
  keeping Pingora TCP/HTTP health-check connector code only inside the
  adapter layer while runtime readiness depends on Fluxheim's trait.
- Hide the remaining runtime backend value type behind the load-balancer
  backend adapter so selector and health-check modules import Fluxheim's
  boundary type instead of `pingora::lb::Backend` directly.
- Serialize per-backend load-balancer health state updates so enable/disable
  changes and active health observations cannot overwrite each other under
  concurrent health checks.
- Store refreshed backend sets before refreshed health maps and use checked
  wake-time arithmetic in the load-balancer background loop.
- Clarify stream upstream TLS warnings for mixed hostname and IP upstream
  routes where only IP connections skip hostname verification without
  `upstream_sni`.

## 1.5.6 - 2026-06-06

### Changed

- Start the Fluxheim-native stream-proxy runtime line. The stop line is stream
  connect/copy/shutdown ownership and error-boundary cleanup while preserving
  existing TCP stream route config, route-local PROXY protocol behavior,
  weighted upstream selection, byte/lifetime/idle limits, metrics, and release
  profiles.
- Move stream connect, copy, shutdown, upstream resolution, upstream PROXY
  header writes, byte-limit enforcement, and lifetime/idle timeout helpers onto
  `FluxResult` while keeping `io::Error` adaptation only at legacy runtime
  boundaries.
- Make the stream copy/proxy data path generic over Tokio
  `AsyncRead + AsyncWrite` streams instead of requiring Pingora's stream wrapper
  in the internal helper signatures.
- Replace the stream proxy's Pingora `ServerApp` / listening-service entrypoint
  with a Fluxheim-owned Tokio listener loop registered as a service in the
  existing process supervisor.
- Add Fluxheim-owned bounded downstream PROXY protocol v1/v2 receive parsing
  and trusted-source matching for stream routes.
- Move stream data-path tests off Pingora's stream wrapper and add regression
  coverage for downstream PROXY parser and trusted CIDR matching.
- Replace the stream upstream connection return type with a Fluxheim-owned
  async IO boundary so plain TCP upstreams stay as Tokio `TcpStream` values
  instead of being wrapped in Pingora's L4 stream type. TLS upstreams are
  adapted behind the same boundary.
- Split stream upstream TLS connector wiring into a dedicated `stream_tls`
  adapter module. The stream proxy orchestration file no longer owns Pingora
  `TransportConnector` / `HttpPeer` setup directly.
- Replace the stream upstream TLS connector adapter with Fluxheim-native
  `tokio-rustls` / `tokio-openssl` connectors. Stream upstream TLS now uses
  Fluxheim-owned TCP connect, TLS handshake, trust-root loading, SNI derivation,
  hostname/certificate verification policy, and upstream mTLS client material
  while preserving the existing route configuration.
- Extend the local stream smoke to exercise a route-local rustls upstream TLS
  connection with generated server certificate, explicit SNI, and custom trust
  root validation.
- Clarify stream upstream TLS hostname verification semantics, warn when a
  verified stream TLS route contains any IP-address upstream without explicit
  `upstream_sni`, and document rustls parsed private-key DER zeroing limits.
- Accept HAProxy PROXY protocol v1 `UNKNOWN` lines with optional trailing
  address fields.
- Remove the nested stream TLS handshake timeout so the route connect timeout
  consistently covers DNS lookup, TCP connect, and TLS handshake.

## 1.5.5 - 2026-06-05

### Changed

- Start the Fluxheim-native HTTP/error type boundary line while preserving
  Pingora runtime adapters.
- Add internal `http_types` aliases for standard `http` crate values and
  explicit Pingora request/response adapter names.
- Add a direct `thiserror` dependency plus `FluxError` / `FluxResult` for
  internal error propagation.
- Convert the upstream PROXY-protocol connector to use the typed internal error
  surface and convert back to Pingora errors only at the connector boundary.
- Extend HTTP boundary aliases into load-balancer health/persistence and static
  web response helpers, and route selected compression/cache errors through
  `FluxError` before Pingora adaptation.
- Move load-balancer tests, access-log tests, and the cache-key CLI request
  builder through explicit HTTP adapter aliases.
- Fix proxy HTTP adapter feature gates so the macOS developer CI matrix can
  check static-site, reverse-proxy, full, and development profiles consistently.
- Move header policy request/response signatures and tests through the explicit
  Pingora HTTP adapter aliases.
- Route load-balancer HTTP health-check response/header/body validation through
  the internal `FluxError` surface before adapting back to Pingora health-check
  errors.
- Route load-balancer HTTP health-check response body size-limit failures
  through the same internal error adapter.
- Route load-balancer file/DNS discovery helper failures through the internal
  `FluxError` surface before adapting back to Pingora `ServiceDiscovery`
  errors.
- Split cache range/slice key construction into internal `FluxResult` helpers
  with Pingora adaptation kept at the proxy cache boundary.
- Move static-file body read/open validation onto `FluxResult` while keeping
  Pingora adaptation at static serving and proxy cache call sites.
- Move response compression encoder initialization and chunk emission onto
  `FluxResult`, with Pingora adaptation kept at compression setup and proxy body
  filter boundaries.
- Move route regex matcher construction onto `FluxResult`, with conversion back
  to `io::Error` kept at the legacy vhost route-construction boundary.
- Move auth subrequest fetch failures and response body-limit enforcement onto
  `FluxResult`, with Pingora adaptation kept at the proxy authorization
  boundary.
- Move traffic mirror dispatch failures and response body-limit enforcement
  onto `FluxResult` inside the fire-and-forget mirror task.
- Move trusted-proxy parsing and runtime access-policy construction onto
  `FluxResult`, with conversion back to `io::Error` kept at proxy runtime
  construction boundaries.
- Move Maglev table construction validation onto `FluxResult`, with conversion
  back to `io::Error` kept at the load-balancer discovery factory boundary.
- Move static load-balancer backend construction onto `FluxResult`, with
  conversion back to `io::Error` kept at load-balancer discovery setup.
- Move stream downstream PROXY trusted-source parsing onto `FluxResult`, with
  conversion back to `io::Error` kept at stream service construction.
- Move stream route app construction validation onto `FluxResult`, with
  conversion back to `io::Error` kept at stream service registration.
- Move stream downstream PROXY protocol listener setup onto `FluxResult`, with
  conversion back to `io::Error` kept at stream service registration.
- Move proxy static-file server construction context wrapping onto
  `FluxResult`, with conversion back to `io::Error` kept at proxy runtime
  construction.
- Move HTTP health-check request-header setup onto `FluxResult`, with
  conversion back to `io::Error` kept at the health-check factory boundary.
- Move cache peer-fill and origin-slice request validation plus blocking fetch
  helper failures onto `FluxResult`.
- Move PHP `X-Accel-Expires` response header mutation failures onto
  `FluxResult`, with Pingora adaptation kept at the PHP response boundary.
- Move PHP FastCGI response-header construction failures onto `FluxResult`,
  with conversion back to `io::Error` kept at the PHP response parser boundary.
- Route PHP FastCGI response split/status parsing through `FluxError` while
  preserving `InvalidData` at the parser boundary.
- Replace the PROXY-protocol connector's string-matched write-error
  classification with a typed `FluxError::WriteProxyHeader` variant.
- Use each `FluxError`'s display message as the primary Pingora error
  description at adapter boundaries.
- Tighten `http_types` exports to active boundary items and move proxy/cache
  tests off direct `pingora::http` request/response header imports.

## 1.5.4 - 2026-06-04

### Changed

- Remove incomplete `tls-boringssl` and `tls-s2n` backend support from the
  supported feature/config matrix.
- Keep rustls as the default/recommended TLS backend and OpenSSL as the
  supported alternative for non-FIPS and FIPS/ISO evidence paths.
- Reject removed TLS backend config values and update tests around the reduced
  backend enum.
- Simplify TLS backend validation tooling and release documentation around the
  rustls/OpenSSL-only support matrix.

## 1.5.3 - 2026-06-04

### Changed

- Start the managed affinity-cookie and HA persistence release line. The stop
  line is signed/opaque load-balancer cookie insertion, cookie rotation,
  privacy-mode constraints, cache/compression/header-policy interaction,
  cookie-mirroring design for active-active HA, and focused smoke coverage.
- Number the remaining `1.5.x` roadmap stops through UDP/GSLB exploration so
  the load-balancer line does not spill into the `1.6` Wasm line.
- Add `proxy.load_balance.persistence.mode = "managed-cookie"` for
  signed/opaque, process-local load-balancer affinity cookies. Fresh 2xx/3xx
  backend responses receive `Set-Cookie`, and later requests with a valid
  managed cookie reuse the selected backend while it remains selectable.
- Rotate local managed-cookie signing keys daily and verify against the current
  or previous key generation so normal key rotation does not immediately break
  in-flight affinity cookies.
- Add managed-cookie validation for path/domain/max-age/SameSite attributes
  and keep persistence rejected in `privacy-mode` builds.
- Add `docs/load-balancer-ha.md` to pin the future active-active
  cookie-mirroring and persistence-state replication design boundaries.
- Harden managed-cookie pentest findings: enforce ASCII-only cookie
  domain/path attributes, bind the HMAC tag to the configured cookie name,
  zeroize retired signing keys on rotation/drop, and label HMAC abort logs by
  caller context.

## 1.5.2 - 2026-06-04

### Changed

- Start the runtime load-balancer weight-control release line. The stop line is
  authenticated runtime weight overrides for configured members, audit/status
  visibility, migration documentation, and focused smoke coverage. Managed
  affinity-cookie insertion, cross-node state synchronization, UDP/GSLB, WAF,
  VPN/firewall appliance behavior, and iRules/Lua/Wasm scripting remain later
  roadmap tracks.
- Add authenticated runtime load-balancer member weight mutation through
  `POST /_fluxheim/load-balancer/member-weight` for configured members in
  `round-robin`, `least-connections`, `least-sessions`, and `least-time` pools.
- Report configured weight, effective weight, runtime weight override, and
  runtime weight transition timestamp in load-balancer backend status.
- Count successful, invalid, and not-found runtime member-weight operations as
  bounded load-balancer events.
- Omit backend addresses from member-state and member-weight mutation responses
  and structured mutation logs in `privacy-mode`, and label successful mutation
  metrics only by configured upstream alias.
- Bound retained runtime load-balancer override state and preserve runtime
  weight overrides across dynamic backend churn while the same backend is
  explicitly disabled or forced down.
- Emit successful runtime member-state and member-weight mutations to the
  `fluxheim::audit` log target in addition to operational load-balancer logs.
- Restore backend metric attribution for unaliased member mutations in
  non-privacy builds, while keeping privacy-mode alias-only behavior.
- Reject configured load-balancer upstream pools whose backend identity keys
  collide.

## 1.5.1 - 2026-06-03

### Changed

- Start the enterprise load-balancer stabilization release after the `1.5.0`
  control-plane launch. The stop line is load-balancer correctness,
  documentation, migration polish, and release-profile fixes; new large feature
  surfaces stay in later `1.5.x` milestones.
- Keep load-balancer persistence-clear metrics distinct from member-state
  mutation metrics for clearer admin audit dashboards.
- Prune stale transient load-balancer drain overrides when dynamic discovery
  removes backends, while preserving explicit runtime `disabled` and
  `forced_down` operator decisions until an authenticated admin clears them.
- Prune persistence-table entries that point at removed dynamic-discovery
  backends from the periodic backend-state cleanup path, while keeping normal
  selection and status persistence counts read-only.
- Clarify the current `1.5.x` load-balancer boundaries in README, config,
  migration, and container documentation so local persistence/runtime overrides
  are not mistaken for managed affinity cookies, restart-persistent HA state,
  runtime weight mutation, runtime member add/remove, or cross-node
  synchronization.
- Extend the local load-balancer smoke to exercise route-scoped header
  persistence, authenticated persistence-table clear, and the
  `persistence_clear` metrics event.
- Add a focused `packaging/container/load-balancer.toml` template and wire the
  load-balancer image/profile validation to that config instead of the generic
  proxy container template.

## 1.5.0 - 2026-06-01

### Changed

- Start the enterprise load-balancer/control-plane development release.
- Promote the `profile-load-balancer-edge` image line from prepared/manual
  testing to the planned `1.5` release artifact set.
- Add the focused Linux `load-balancer` runtime archive to the release asset
  builder and release documentation.
- Expand the `1.5` roadmap around F5/HAProxy/Envoy-class load-balancer
  operations: runtime pool/member mutation, persistence, priority groups,
  slow-start, adaptive health, circuit breaking, locality/failure-domain
  policy, richer selection algorithms, and migration fixtures.
- Make `least-connections` weight-aware so heterogeneous pools respect
  configured `upstream_weights` while still using in-flight request permits.
- Accept `weighted-least-connections` and `ratio-least-connections` as
  migration-friendly aliases for the weighted least-connections selector.
- Add `least-sessions` load-balancer selection backed by the bounded
  persistence table for sticky-session-aware distribution.
- Add `least-time` selection using weighted EWMA upstream latency plus
  in-flight request counts for latency-sensitive application pools.
- Make the `power-of-two` / `weighted-random-two-choice` selector compare
  weighted in-flight pressure after Pingora's weighted random sampling.
- Add bounded-load consistent-hash selections
  (`bounded-load-consistent-source-hash`,
  `bounded-load-consistent-uri-hash`,
  `bounded-load-consistent-header-hash`, and
  `bounded-load-consistent-cookie-hash`) so hash-persistent pools can skip an
  overloaded hash target before falling back to normal consistent selection.
- Add static `upstream_priority_groups` for F5-style preferred/fallback
  selection across configured static upstream pools.
- Add `upstream_priority_group_min_active` so lower priority groups activate
  when preferred groups fall below a selectable-member threshold.
- Add static `upstream_localities` and `preferred_upstream_localities` for
  locality/failure-domain preferred selection with automatic fallback when no
  preferred backend is selectable.
- Add static per-upstream `upstream_tags` metadata for load-balancer runtime
  status grouping and migration notes without affecting selection.
- Add static per-upstream `upstream_max_in_flight` caps so saturated members
  are skipped consistently across load-balancing selectors.
- Add opt-in bounded load-balancer queue policy so saturated pools can wait
  briefly for capacity before returning the configured all-down status.
- Count load-balancer queue wait, full, and timeout outcomes in
  `fluxheim_load_balancer_events_total` when metrics are compiled.
- Add `fluxheim_load_balancer_queue_wait_seconds` to observe bounded
  load-balancer queue wait and timeout duration by configured vhost/route.
- Add `GET /_fluxheim/load-balancer/status` so operators can retrieve
  load-balancer runtime pool state without parsing the full admin status body;
  the same read-only view is available on the local ops socket.
- Add `fluxheim_load_balancer_pools` to report configured load-balancer pool
  counts by scope and bounded selection algorithm.
- Add low-cardinality OTLP trace attributes for load-balanced requests:
  configured upstream alias and retry count only, with raw upstream URLs
  rejected from trace payloads.
- Add static `disabled_upstreams` so configured members can be kept in the pool
  definition while being administratively removed from selection and reported
  distinctly from drained members; disabled members also show as not ready in
  load-balancer runtime status.
- Extend HTTP active health checks with configurable request methods and exact
  expected response header validation.
- Add HTTP active health-check `expected_status_ranges` for inclusive status
  range monitors such as `200..=399`.
- Add HTTP active health-check `expected_body_contains` substring validation
  with a bounded 64 KiB probe-body read ceiling.
- Add active health-check `connect_timeout_secs` and `read_timeout_secs`
  overrides so probes can be tuned independently from normal upstream traffic.
- Add `proxy.load_balance.all_down_status` for explicit 5xx responses when a
  configured load-balanced pool has no selectable backend.
- Add read-only load-balancer runtime status to `GET /_fluxheim/status`,
  including pool/backend readiness, configured policy metadata, in-flight
  counts, passive ejection, slow-start, and least-time latency state.
- Expand load-balancer runtime status with pool-level selection, iteration,
  all-down, health-check frequency/parallel mode, passive-health, and
  slow-start policy metadata.
- Include load-balancer retry policy metadata in runtime status, including
  safe methods, status/status-range retry rules, and retry budget settings.
- Include ready and policy-available backend counts in load-balancer runtime
  status so pool capacity is visible without client-side backend inference.
- Include primary/backup availability counts plus drain, disabled, passive
  ejection, and saturation summary counts in load-balancer runtime status.
- Include explicit runtime member override state and runtime override summary
  counts in load-balancer runtime status.
- Include per-backend runtime member-state transition timestamps in
  load-balancer runtime status while a manual override remains active.
- Add authenticated in-memory load-balancer member-state operations through
  `POST /_fluxheim/load-balancer/member-state` for existing configured
  members: normal, drain, disable, forced-down, and manual-resume by configured
  address or alias.
- Add runtime `manual_resume` for load-balancer members to clear passive-health
  failure/ejection state and restart slow-start ramp without a config reload.
- Return explicit `scope` and `persistent = false` metadata from load-balancer
  runtime member-state operations.
- Emit load-balancer audit logs for successful and rejected runtime
  member-state operations.
- Count successful, invalid, and not-found load-balancer member-state
  operations in `fluxheim_load_balancer_events_total` when metrics are
  compiled.
- Add active TCP health-check transition coverage proving configured failure
  and recovery thresholds flip backend readiness.
- Add bounded local source-IP load-balancer persistence with TTL, table-size
  limits, admin status entry counts, and automatic fallback when the stored
  backend is no longer selectable.
- Add bounded local request-header load-balancer persistence with explicit
  header-name validation and the same TTL/table limits as source-IP
  persistence.
- Add bounded local request-cookie load-balancer persistence for explicitly
  named application or upstream cookies.
- Add authenticated runtime clearing for vhost or route load-balancer
  persistence tables through
  `POST /_fluxheim/load-balancer/persistence/clear`.
- Report per-backend persistence-entry counts in load-balancer runtime status
  so operators can spot sticky-session skew.
- Count load-balancer persistence hits, misses, and fallbacks in
  `fluxheim_load_balancer_events_total` when metrics are compiled.
- Add a validated `examples/load-balancer-enterprise.toml` migration fixture
  for HAProxy/F5-style weighted pools, priority groups, health policy,
  persistence, retry budgets, and all-down behavior.
- Add `docs/load-balancer-migration.md` with nginx, HAProxy, and F5 LTM pool
  mappings plus explicit boundaries for UDP, GSLB, WAF, VPN, and scripting
  roadmap items.
- Document the `1.5.0` load-balancer boundaries clearly: no managed affinity
  cookie insertion, no restart-persistent LB runtime state, no runtime weight
  changes or add/remove-member operations, and no cross-instance state sync yet.
- Extend the local load-balancer smoke to use temporary process paths and verify
  configured all-down status after all checked origins are unavailable.
- Extend the local load-balancer smoke to exercise authenticated runtime
  member disable/normal operations through the 1.5 admin control plane.
- Expose passive-health ejection as per-backend `circuit_state` plus a
  pool-level `circuit_open_backend_count` in load-balancer runtime status.
- Make slow-start admission vary per selection attempt instead of using only
  the backend identity hash, so warming members receive a bounded traffic
  sample rather than a fixed backend-key class during the ramp window.
- Prune stale passive-health backend state during periodic load-balancer state
  cleanup while preserving active ejections until their deadline.
- Extract HTTP/TCP load-balancer health-check construction, validation, and
  response-body handling into `src/load_balancer/health.rs` so monitor logic is
  reviewable without navigating the full load-balancer orchestration module.
- Split load-balancer backend state, persistence, selection, backend policy,
  and discovery/factory code into focused `src/load_balancer/*` modules while
  keeping `crate::load_balancer::*` stable for callers.
- Align read-only slow-start status with the sampled admission mechanism instead
  of the old backend-key-only gate.
- Include passive-health ejection remaining time in load-balancer runtime
  status so temporary ejections are explainable through the admin plane.
- Include per-backend passive-health consecutive failure counts in
  load-balancer runtime status.
- Add `proxy.load_balance.passive_health.failure_status_ranges` for bounded
  passive outlier detection on inclusive 5xx status ranges.
- Add `proxy.load_balance.retry.statuses` for bounded safe-method redispatch
  on explicitly configured upstream HTTP 5xx responses before response
  streaming starts.
- Add `proxy.load_balance.retry.status_ranges` for bounded safe-method
  redispatch on inclusive upstream HTTP 5xx status ranges.
- Accept `power-of-two-choices`, `two-choice`, `weighted-two-choice`, and
  `weighted-random-two-choice` as aliases for `power-of-two` selection.
- Add bounded static-pool Maglev hashing selections (`maglev`,
  `maglev-uri-hash`, `maglev-header-hash`, and `maglev-cookie-hash`) with a
  fixed 65,537-slot lookup table and policy-aware fallback probing. Dynamic
  file/DNS-refreshed pools reject Maglev until table rebuild semantics are
  promoted in a later control-plane slice.
- Harden load-balancer state handling after SAST review by capping
  client-derived persistence keys, secret-salting Maglev route lookup,
  consolidating runtime member-state overrides behind one mutex, pruning stale
  per-backend runtime maps periodically, using stable backend identity hashes,
  and applying the 64 KiB health-check body cap to drain-only probes.

## 1.4.7 - 2026-05-31

### Changed

- Start the TCP stream hardening development release.
- Add true per-read stream idle timeout and make `max_connection_secs` an
  optional lifetime cap instead of the default stream timeout.
- Add stream upstream TLS controls and upstream mTLS material loading for
  rustls, OpenSSL, and BoringSSL builds. s2n remains fail-closed for custom
  stream upstream trust/client files.
- Add stream-local transport-neutral upstream policy: weighted selection,
  aliases, drained upstream exclusion, and backup upstream connect fallback.
- Add a localhost stream smoke script covering raw TCP forwarding,
  drained/backup fallback, upstream PROXY protocol v1 send, and downstream
  PROXY protocol v1 receive from trusted sources.
- Add stream unit coverage for wall-clock lifetime caps and upstream PROXY
  protocol v2 framing.
- Bound stream upstream TLS DNS resolution under `connect_timeout_secs`, add
  stream write/shutdown deadlines, avoid derived IP-literal SNI, and zeroize
  temporary upstream mTLS private-key buffers after parsing.

## 1.4.6 - 2026-05-30

### Changed

- Release the TCP stream proxy foundation.
- Add route-local downstream PROXY protocol receive for TCP stream routes with
  mandatory route-local `trusted_proxies`; HTTP `server.proxy_protocol` no
  longer applies to stream listeners.
- Rename stream `idle_timeout_secs` to `max_connection_secs` to reflect the
  wall-clock connection lifetime cap, and add optional
  `max_connection_bytes` per-direction byte caps.
- Track the transitive `RUSTSEC-2024-0388` `derivative` advisory with an
  explicit review deadline while Pingora still pulls the unmaintained crate.

## 1.4.5 - 2026-05-29

### Changed

- Start the bounded GeoIP/Geo-Context development release.
- Add the optional `geoip` feature with provider-agnostic local MMDB loading for
  MaxMind GeoIP2/GeoLite2 and CIRCL Geo Open datasets.
- Add vhost and route access-policy Geo-Context rules:
  `allow_countries`, `deny_countries`, `allow_asns`, and `deny_asns`.
- Add optional `geo_country` and `geo_asn` fields to structured access logs
  when `geoip` is compiled and a lookup succeeds.
- Raise the pinned Rust toolchain and minimum supported Rust version from
  1.95 to 1.96.
- Track a future `fluxheim-sdk` Rust companion crate for application-side
  health/drain, trusted request context, tracing, cache-control, and purge
  helpers.
- Align GeoIP deny-only access policy with the documented contract: unresolved
  Geo-Context now defaults to allow unless an allow list is configured.

## 1.4.4 - 2026-05-28

### Changed

- Start the Apple Silicon macOS Level 1 developer-support release. Scope is
  local build/check/smoke coverage and Mac-safe development runtime paths, not
  production macOS packaging, FIPS evidence, notarized binaries, Homebrew
  distribution, or launchd service support.

## 1.4.3 - 2026-05-27

### Changed

- Harden path forwarding safety against triple-encoded traversal segments,
  zeroize copied auth-request forwarded header values, and rename the private
  admin empty-path validator to avoid confusion with full path-safety checks.
- Harden admin auth throttling so a full per-source table evicts the stalest
  tracked source instead of immediately promoting a new source to global
  lockout, and route cache purge path validation through the shared path-safety
  decoder.
- Start the config module split and maintenance architecture release. This
  release is intentionally scoped to behavior-preserving extraction of the
  large `config.rs` surface into focused loading, validation, and domain slices
  before adding GeoIP or other advanced policy features.
- Move the remaining `1.4.x` plan so `1.4.3` is the config split, `1.4.4` is
  Apple Silicon macOS Level 1 developer support, `1.4.5` is GeoIP/Geo-Context,
  and `1.4.6` is TCP stream proxying.
- Extract path-safe TOML source discovery and bounded config-file loading into
  `config_loader`, preserving the existing `crate::config::*` public API.
- Move config load errors and the shared `ByteSize` parser/serializer into
  focused config support modules while keeping their existing
  `crate::config::*` re-export paths stable.
- Move file-refreshed proxy upstream pool loading into `config_loader`, keeping
  the existing `crate::config::read_proxy_upstreams_file` internal path stable.
- Extract host normalization and upstream/trusted-proxy authority validation
  helpers into `config_net`, preserving the public `crate::config::normalize_*`
  API used by runtime modules.
- Extract HTTP/OTLP endpoint URL validation and local FIPS endpoint exception
  helpers into `config_http`, with shared HTTP authority parsing in
  `config_net`.
- Extract generic config path inspection, symlink checks, parent-permission
  checks, and process path validation into `config_path`.
- Extract header mutation, dynamic header-template, TLS identity append, and
  response/cookie rewrite validation helpers into `config_header`.
- Extract access allow/deny and client-certificate SHA-256 list validation into
  `config_access`.
- Extract route path, regex matcher, method, rewrite-template, and redirect
  target validation helpers into `config_route`.
- Extract PHP custom parameter validation and protected FastCGI parameter guards
  into `config_php`, preserving `crate::config::protected_php_param_name` for
  PHP-FPM runtime code.
- Move PHP-FPM retry method/status validation and PHP intercepted-error status
  validation into `config_php`.
- Move PHP index, allowed-extension, denied-prefix, stderr failure-pattern, and
  hidden-response-header validation into `config_php`.
- Move managed PHP-FPM process-manager, identity, timeout, socket-directory,
  and generated pool-file safety validation into `config_php`.
- Move OTLP CA certificate path and service-name validation into
  `config_http`.
- Move `CompressionConfig`, compression defaults, and compression policy
  validation into `config_compression` while re-exporting
  `crate::config::CompressionConfig`.
- Move load-balancer selection, health-check, passive-health, slow-start, and
  retry policy config into `config_load_balance` while preserving the existing
  `crate::config::*` type paths.
- Move logging and access-log config into `config_logging`, including file-log
  path validation and request-id header validation.
- Move metrics and tracing config into `config_observability`, keeping OTLP
  endpoint validation routed through the shared HTTP config helpers.
- Move static web serving config into `config_web`, including index-file,
  cache-control, expires, root path, and directory-listing validation.
- Move admin API config into `config_admin`, including auth source, ops socket,
  client-certificate header, health, throttle, and self-healing validation.
- Move server listener, downstream PROXY protocol, HTTPS redirect, host-routing,
  server limits, and process runtime path config into `config_server`.
- Start the cache config split by moving cache purger config and validation
  into `config_cache`.
- Move cache policy, range/slice, storage tier, peer fill, and disk encryption
  config into `config_cache`, keeping existing `crate::config::*` type paths
  stable.
- Move the large config unit-test module into `config_tests.rs` so
  `config.rs` contains only production orchestration and shared error types.
- Move ACME issuer, renewal, automation, challenge, and external-account-binding
  config into `config_acme`.
- Move listener TLS policy, TLS compliance mode, client-auth config, TLS cipher
  and curve policy, and static certificate path validation into `config_tls`.
- Move header policy config structs, overlay merge logic, HSTS defaults, and
  response rewrite policy types into `config_header`.
- Move access policy, rate limit, and concurrency limit config into
  `config_access`.
- Move vhost TLS and vhost ACME challenge config into the existing TLS/ACME
  config modules.
- Move PHP and managed PHP-FPM config types, defaults, and path validation into
  `config_php`.
- Move route, gRPC route, route redirect, and vhost redirect config into
  `config_route`.
- Move proxy upstream, auth-request, traffic-mirror, and proxy error-page
  config into `config_proxy`.

## 1.4.2 - 2026-05-27

### Changed

- Start the proxy module split and maintenance architecture release. This
  release is intentionally scoped to behavior-preserving extraction of the large
  proxy runtime into focused domains before adding more large proxy features.
- Extract structured access-log formatting, request-id generation, status-class
  labeling, and response-body byte accounting from `proxy.rs` into a focused
  `access_log` module.
- Extract response compression negotiation, encoder lifecycle, output bounding,
  and `Vary: Accept-Encoding` mutation from `proxy.rs` into a focused
  `compression` module while preserving the existing vhost and route policy
  behavior.
- Extract `auth_request` input construction and outbound decision fetching from
  `proxy.rs` into a focused `auth_request` module.
- Extract traffic-mirror request construction, sampling, in-flight limits, and
  outbound shadow delivery from `proxy.rs` into a focused `traffic_mirror`
  module.
- Extract trusted-proxy parsing, access policy checks, rate limiting, and
  request concurrency admission into a focused `edge_policy` module.
- Extract route matcher construction, method checks, regex capture extraction,
  and path rewrite rendering into a focused `route_policy` module.
- Extract managed PHP-FPM process lifecycle, watchdog/cleanup handling,
  generated pool configuration, and PHP request-body spool file handling into a
  focused `php_fpm` module.
- Extract PHP-FPM endpoint construction, keepalive pool transport,
  timeout/retry classification, FastCGI response buffering, and CGI response
  header parsing into `php_fpm`. The remaining PHP code in `proxy.rs` is the
  Pingora session integration layer that resolves requests, builds CGI params,
  applies response policy, and coordinates static offload.
- Start the proxy-cache split with a focused `proxy_cache` module for
  request-side cache policy helpers: request identity conversion,
  bypass/revalidation checks, and header/cookie/query matching.
- Move response-side cache admission and `Vary` policy helpers into
  `proxy_cache`, including content-type admission, no-store checks, configured
  response-header rejection, range-response admission, and variance hashing.
- Move range-cache request selection, bounded `Range` parsing, range cache-key
  derivation, and partial-response admission checks into `proxy_cache`; the
  remaining cache code in `proxy.rs` is storage, slice assembly, and Pingora
  request/session orchestration.
- Move fixed-slice range parsing, slice-bound planning, slice policy admission,
  and slice cache-key derivation into `proxy_cache`. The remaining slice code
  in `proxy.rs` is object lookup/fill/composition tied to Pingora storage and
  response streaming.
- Move stateless cache freshness, status-header, stale-serving, and
  response-header mutation policy into `proxy_cache`. Stateful min-use/pass
  counters remain in `proxy.rs` until their optional-cache dependencies are
  split behind a cleaner cache-runtime boundary.
- Move cache admin/API request and result DTOs into `cache_api`, while
  preserving the existing `crate::proxy::*` public re-export paths for current
  callers.
- Extract outbound PROXY protocol v1/v2 frame construction and the L4 connector
  that writes those frames before upstream traffic into a focused
  `proxy_protocol` module.
- Extract traversal-safe forwarded path validation into `path_safety`, giving
  peer-fill, route rewrites, and future forwarding code one shared security
  helper outside the proxy orchestration layer.
- Extract upstream TLS trust-root and client-certificate material loading into
  `upstream_tls`, keeping O_NOFOLLOW, regular-file, and size-limit checks out
  of the proxy orchestration layer.
- Document the source-boundary rule for future work: new feature domains should
  start in focused modules once they have their own validation, tests, metrics,
  dependencies, or security boundary. The same audit tracks future split
  candidates in `config.rs`, `cache.rs`, `admin.rs`, and `cli.rs`.

### Fixed

- Harden traffic-mirror sampling with a process-local random salt so request
  paths cannot be precomputed into predictable mirror include/exclude buckets.
- Keep ACME certificate installation portable across Linux and macOS by using
  platform-specific `rustix` file mode conversion without tripping Linux
  Clippy's useless-conversion lint.

## 1.4.1 - 2026-05-26

### Added

- Added opt-in regex route matching through `server.regex_enabled = true` and
  route-level `path_regex`. Regex routes are validated with Rust's bounded
  regex engine at config load time and are selected after exact and longest
  prefix routes, before fallback routes.
- Added bounded regex route capture variables for request-header templates:
  `{route.regex.0}`, numbered captures through `{route.regex.15}`, and named
  captures such as `{route.regex.version}`.
- Added bounded regex-route `rewrite_template` support for path-only upstream
  URI rewriting with capture variables. Rendered paths keep the original query
  string and pass the same traversal/encoded-separator safety checks as
  `strip_prefix`.
- Added route-level `methods = ["GET", "HEAD"]` matching. Method lists are
  optional, bounded, uppercase HTTP tokens and let one path route to different
  actions or upstreams by request method.
- Added explicit HTTP/1.1 upgrade proxying with `proxy.websocket = true`.
  Upgrade requests preserve the required `Connection: upgrade` and `Upgrade`
  token upstream, require `upstream_http_version = "http1"`, and bypass proxy
  cache policy for long-lived websocket-style connections.
- Added `[proxy.auth_request]` external authorization for proxy actions. The
  first slice sends bounded `GET` subrequests, forwards only configured request
  headers, copies allow-listed auth response headers into the upstream request
  on 2xx, and constrains FIPS/ISO-required deployments to numeric local
  `http://` auth sidecars.
- Added opt-in `[proxy.mirror]` traffic shadowing behind the `traffic-mirror`
  feature. The first slice mirrors safe bodyless methods only, uses
  deterministic per-mille sampling, copies only allow-listed headers, drains a
  bounded mirror response, caps per-vhost/route in-flight mirror worker tasks,
  records low-cardinality mirror outcomes through edge policy metrics when
  metrics are enabled, and never changes the primary response.
- Added `[admin.ops_socket]`, a Unix-only read-only local operational socket
  for status, cache status, snapshots, and health checks. The socket is
  owner/group permission constrained and does not route mutating admin
  operations.
- Added richer structured access-log fields for load-balanced proxy requests:
  `upstream_alias` and `upstream_retries`. The alias follows
  `logging.access.include_upstream` so operators can still suppress backend
  identity from logs.
- Added file-refreshed upstream pools for load-balancer builds with
  `upstreams_file` and bounded refresh intervals. The first format is one
  authority per line with safe file handling and no weights/aliases yet.
- Added DNS-refreshed upstream pools for load-balancer builds with
  `upstream_dns_refresh_secs`, intended for container/service-name targets.
  The first slice keeps dynamic DNS separate from weights, aliases, backups,
  and drains.
- Added low-cardinality `auth_request` allow/deny/error outcomes to
  `fluxheim_edge_policy_events_total`.

### Fixed

- Moved file-refreshed and DNS-refreshed upstream discovery off blocking Tokio
  executor paths.

### Deferred

- Keep broader typed operator hook points, advanced policy composition,
  stick-table tracking, runtime backend mutation, GeoIP policy, response body
  substitution, TCP stream proxying, and arbitrary Wasm/Lua execution outside
  `1.4.1`.
- Reserve `1.4.2` for proxy runtime module extraction before the next large
  proxy feature. GeoIP/Geo-Context and TCP stream proxying move to later
  `1.4.x` stops.
- Clarify the later GeoIP/Geo-Context plan: the target should use a
  provider-agnostic local MMDB layer for MaxMind GeoIP2/GeoLite2 and CIRCL Geo
  Open datasets, normalized typed country/ASN context, and ordered local
  fallback without built-in remote lookup or database downloading.
- Add an Apple Silicon macOS developer-support stop for local
  `aarch64-apple-darwin` build/check/smoke coverage, Mac-safe dev runtime
  paths, and explicit deferral of production macOS packaging/security support
  while Pingora macOS support remains experimental.

## 1.4.0 - 2026-05-25

### Added

- Added the first production proxy parity edge-policy primitive:
  trusted-proxy-aware IP ACLs through `[vhosts.access]` and
  `[vhosts.routes.access]`, with exact IP/CIDR `allow` and `deny` lists.
- Added opt-in local token-bucket request limiting through
  `[vhosts.rate_limit]` and `[vhosts.routes.rate_limit]`, keyed by the
  trusted-proxy-aware client IP.
- Added opt-in local in-flight request limits through `[vhosts.concurrency]`
  and `[vhosts.routes.concurrency]`.
- Added opt-in gzip response compression behind the `compression-gzip` feature,
  with conservative MIME, size, cookie/auth, range, `no-transform`, and
  `Vary: Accept-Encoding` handling.
- Added `proxy.upstream_weights` for weighted round-robin upstream selection in
  `load-balancer` builds.
- Added `proxy.load_balance.selection` for least-connections, power-of-two,
  weighted source, URI, header, cookie, and consistent-hash upstream selection in
  `load-balancer` builds.
- Added opt-in `proxy.load_balance.passive_health` outlier detection for
  load-balanced upstreams, with bounded consecutive-failure ejection for proxy
  failures and selected 5xx response statuses.
- Added opt-in passive latency ejection with
  `proxy.load_balance.passive_health.max_latency_ms`.
- Added opt-in `proxy.load_balance.retry` redispatch for load-balanced
  connection failures before request forwarding, bounded by retry count and
  safe HTTP method policy.
- Added optional load-balanced retry budgets with `budget_per_window` and
  `budget_window_secs` so redispatch cannot amplify an upstream outage without
  an operator-set cap.
- Extended load-balanced upstream selection, passive health, and retry policy
  to route-level proxy pools, not only vhost-level proxy pools.
- Added load-balanced upstream `backup_upstreams` and `drain_upstreams`
  policies so operators can keep standby origins out of normal rotation and
  stop new traffic to draining origins without removing them from the pool.
- Added opt-in `proxy.load_balance.slow_start` so newly seen or passively
  recovered load-balanced backends can warm up gradually instead of immediately
  receiving their full selection share.
- Added active HTTP load-balancer health checks with path, host,
  expected-status, connection reuse, and port override controls alongside the
  existing TCP/TLS health check mode.
- Added `fluxheim_load_balancer_events_total` to count load-balanced
  selections, unavailable pools, retries, and success/failure outcomes with
  bounded vhost/route labels.
- Extended load-balancer metrics to count passive-health ejection transitions
  without labeling raw upstream addresses.
- Added `proxy.upstream_aliases` as optional safe low-cardinality backend labels
  for load-balancer metrics without exposing raw upstream addresses.
- Added opt-in `compression-zstd` and `compression-brotli` codec features
  alongside gzip, with bounded levels and negotiation preference `br`, `zstd`,
  then `gzip`.
- Added vhost-level compression overrides so operators can keep compression
  disabled globally and enable it only for selected sites.
- Added route-level compression overrides so path prefixes such as
  `/wp-content/uploads/` can opt into or out of compression independently from
  the rest of the vhost.
- Added response `Location` and `Refresh` prefix rewrite rules under
  `headers.response.rewrite` for common `proxy_redirect` /
  `ProxyPassReverse` migrations.
- Added response `Set-Cookie` `Domain=` and `Path=` rewrite rules under
  `headers.response.rewrite.cookie_domain` and
  `headers.response.rewrite.cookie_path`.
- Added route `rewrite_prefix` so a stripped public path prefix can be mapped
  onto a safe upstream path prefix before proxy forwarding.
- Added trusted-proxy-aware client IP, effective cache phase, resolved route
  name, and selected upstream address to structured access log events, with
  `logging.access.include_client_ip`, `logging.access.include_cache_phase`,
  `logging.access.include_route`, and `logging.access.include_upstream`
  controls for redaction-sensitive deployments.
- OTLP trace spans now report the resolved route name instead of a synthetic
  route index label.
- Access logs and OTLP trace spans now report the Fluxheim-applied response
  compression encoding when gzip, zstd, or brotli compression is used.
- Added `fluxheim_response_compressions_total` to count Fluxheim-applied
  response compression by vhost, route scope, and bounded encoding.
- Added `fluxheim_edge_policy_events_total` to count ACL denials, rate-limit
  delays/rejections, and concurrency-limit rejections with bounded labels.
- Added `compression.max_output_bytes` so encoded responses stay bounded even
  when a compressible input is within `max_input_bytes`.
- Added rate-limit delay mode with a bounded `max_delay_ms` budget so vhost and
  route token buckets can smooth short bursts without creating an unbounded
  request queue.
- Added `queue_timeout_ms` to vhost and route concurrency limits so saturated
  policies can wait briefly for an in-flight permit before returning their
  configured rejection status.
- Added listener-level downstream client certificate authentication through
  `[tls.client_auth]` with `off`, `optional`, and `required` modes plus a safe
  CA bundle path. The first implementation wires rustls and OpenSSL/BoringSSL
  listeners and fails closed for s2n until its CA loader can be exposed without
  panic-prone helpers.
- Added downstream TLS/client-certificate request header template variables,
  including `{tls.version}`, `{tls.cipher}`, `{tls.client_cert_sha256}`,
  `{tls.client_cert_serial}`, and `{tls.client_cert_organization}`, so verified
  mTLS identity can be forwarded explicitly to trusted origins.
- Added the same downstream TLS/client-certificate identity values to structured
  access logs as `tls_version`, `tls_cipher`, `tls_client_cert_sha256`,
  `tls_client_cert_serial`, and `tls_client_cert_organization`.
- Added vhost and route access-policy controls for verified downstream client
  certificate fingerprints through `require_client_cert`,
  `allow_client_cert_sha256`, and `deny_client_cert_sha256`.
- Added admin control-plane client-certificate fingerprint hardening for trusted
  TLS/mTLS terminators through `[admin.client_certificate]`.
- Added upstream TLS verification controls for proxy origins:
  `upstream_verify_cert`, `upstream_verify_hostname`, and
  `upstream_alternative_cn`, while keeping certificate and hostname validation
  enabled by default.
- Added proxy upstream custom trust roots and upstream mTLS client certificate
  loading through `upstream_ca_path`, `upstream_client_cert_path`, and
  `upstream_client_key_path`. Rustls, OpenSSL, and BoringSSL are wired; s2n
  fails closed until its upstream PEM loaders can be exposed without
  panic-prone helpers.
- Added opt-in upstream HAProxy PROXY protocol v1 send support through
  `proxy.upstream_proxy_protocol = "v1"`, using the trusted-proxy-aware client
  identity when available and falling back to `PROXY UNKNOWN` when a safe
  TCP4/TCP6 line cannot be formed.
- Added binary PROXY protocol v2 upstream send support through
  `proxy.upstream_proxy_protocol = "v2"`, emitting TCP4/TCP6 frames when Fluxheim
  has same-family source and destination addresses and an empty PROXY/UNSPEC
  frame otherwise.
- Added opt-in listener-side HAProxy PROXY protocol v1 receive support through
  `server.proxy_protocol = "v1"`. It requires `server.trusted_proxies`, rejects
  untrusted direct peers before parsing the header, and restores the PROXY
  source address before downstream TLS and HTTP handling.
- Added listener-side binary PROXY protocol v2 receive support through
  `server.proxy_protocol = "v2"`, with the same trusted-direct-peer gate as v1
  plus bounded TCP4/TCP6 parsing and LOCAL/UNSPEC handling.
- Added upstream HTTP version selection through `proxy.upstream_http_version`
  with `http1`, `http2`, and `http1-and-http2`, plus bounded HTTP/2 stream and
  ping controls for gRPC-capable origins.
- Added route-scoped `[vhosts.routes.grpc]` pass-through policy that requires
  HTTP/2-capable proxy origins and rejects obvious non-gRPC requests before
  forwarding.
- Added upstream connection establishment and keepalive-pool tuning through
  `proxy.upstream_total_connection_timeout_secs` and
  `proxy.upstream_idle_timeout_secs`.
- Added upstream TCP socket tuning for proxy origins, including TCP keepalive,
  Linux user timeout, receive-buffer size, DSCP, and TCP Fast Open controls.
- Added bounded `max_queue` waiters for vhost and route concurrency limits,
  replacing the previous short sleep/retry loop with semaphore-backed wakeups.
- Replaced Fluxheim's direct `rustls-pemfile` usage with
  `rustls-pki-types::pem::PemObject`; the remaining `RUSTSEC-2025-0134`
  warning is transitive through Pingora's rustls stack and documented in
  `SECURITY.md`.

### Security

- Hardened route path rewriting against double-encoded traversal and decoded
  control-byte segments before forwarding to upstreams.
- Rejected request-header append policies that use TLS identity templates so
  spoofed inbound identity headers cannot be forwarded before Fluxheim's
  verified TLS-derived value.
- Switched admin and route/vhost client-certificate fingerprint list checks to
  full-list constant-time-oriented comparisons.
- Added `reject_indeterminate` to vhost and route rate-limit policies so
  operators can reject requests when no trusted-proxy-aware client IP can be
  determined instead of using the shared anonymous bucket.
- Bounded process-global slice-cache fill concurrency keys and abort on a
  poisoned slice-fill lock so high-cardinality cache misses cannot grow that
  map indefinitely.
- Removed the process ID from generated snapshot IDs; uniqueness now comes from
  timestamp plus a process-local sequence without disclosing PID information
  through the authenticated admin API.
- Documented the anonymous shared rate-limit bucket used when no effective
  client IP is available, and warn when admin client-certificate header gates
  are configured on loopback listeners without an enforced terminator boundary.

### Planned

- Move the remaining proxy-operations work into `1.4.1`: dynamic upstream
  discovery, file-watched upstream lists, traffic mirroring, richer structured
  logs, regex/template rewrite policy, local operational sockets, and typed
  hook points.

## 1.3.7 - Production PHP-FPM Completion

Released: 2026-05-23

### Added

- Added managed php-fpm process supervision under the existing `php-fpm`
  feature. External php-fpm remains the default. Managed pools now include a
  watchdog that respawns the php-fpm master after post-start crashes with
  bounded backoff.
- Added a small audited `[vhosts.php.fpm] mode = "managed"` config surface for
  Fluxheim-owned private php-fpm pools, generated pool config, private Unix
  socket paths, bounded worker counts, static/dynamic/ondemand process manager
  modes, max-request recycling, request lifecycle controls, slowlog support,
  output/env toggles, session/upload temp paths, and clear startup/runtime
  diagnostics.
- Extended the local WordPress PHP-FPM smoke test so the same install, login,
  redirect, cookie, and admin-dashboard flow can run against external,
  managed-static, managed-dynamic, managed-ondemand, managed-respawn, all
  managed, or all external plus managed PHP-FPM modes.
- Added a self-contained Wolfi PHP image path that installs `php-8.5-fpm`,
  uses the managed php-fpm container config, and has a smoke test proving
  `/index.php` executes through the Fluxheim-supervised pool.
- Dropped the reserved pure-Rust PHP/phprs track. Managed php-fpm is the
  supported zero-admin PHP direction for the 1.3 line.

### Changed

- Managed php-fpm now starts with a cleared inherited environment and a
  sanitized `PATH`, generates private pool state, and keeps external php-fpm as
  the default deployment mode.
- Managed php-fpm teardown now sends SIGTERM before SIGKILL, detaches blocking
  child cleanup from Tokio worker threads, observes shutdown during respawn
  socket waits, and tracks stable restart windows from the actual successful
  php-fpm socket-ready timestamp.
- The `1.4` roadmap is now the compact production proxy parity line covering
  edge policy/compression, upstream resilience, TLS/protocol parity, and
  discovery/mirroring/operator hooks.

## 1.3.6 - FIPS/ISO Internal Crypto Closure

Released: 2026-05-23

### Added

- Added FIPS/ISO-required internal-crypto guards that fail closed for
  security-sensitive non-TLS cryptography that is not yet routed through the
  selected validated module or externally evidenced service.
- Added validation tests proving FIPS/ISO-required mode rejects managed ACME
  for the intended provider-boundary reason, accepts provider-backed admin
  auth, and rejects local disk-cache encryption, while allowing OpenBao Transit
  cache encryption as an external evidence boundary.
- Added a compliance evidence package template covering release artifacts,
  SBOMs, build commands, cryptographic module evidence, runtime diagnostics,
  scanner output, and Common Criteria-aligned evidence records.
- Added compliance evidence sections to `scripts/release_evidence.sh`,
  including candidate TOE boundary, Security Target-style draft,
  operational-environment assumptions, validation-script identifiers, and
  vulnerability-analysis records.
- Added hot-reload reuse for runtime Pingora cache storage, cache locks, tiered
  storage, and cache predictors so identical cache plans do not allocate a new
  leaked `'static` backend on every authenticated reload.
- Added a release-metadata guard for the `RUSTSEC-2024-0437` suppression so the
  protobuf advisory has to be reviewed when Pingora moves off Prometheus
  `0.13.4`.
- Added a documented numeric-local-loopback-only OTLP exception for
  FIPS/ISO-required mode so operators can export metrics/traces to a local
  collector without making outbound TLS part of Fluxheim's approved
  cryptographic boundary.
- Extended the OpenSSL and rustls FIPS validation scripts with provider-backed
  admin-auth fixtures plus fail-closed fixtures for managed ACME and local
  cache encryption. The managed ACME fixture now checks the specific ACME
  rejection text instead of treating any config-tester failure as evidence.

### Changed

- FIPS/ISO-required mode now prefers externally issued static certificates and
  rejects `[tls.acme] enabled = true` until ACME account key generation, JWS
  account signing, EAB, outbound ACME HTTPS transport, and TLS-ALPN certificate
  generation are routed through validated cryptography or separately evidenced.
- FIPS/ISO-required mode now allows `admin.enabled = true` in
  `tls-openssl-fips` and `tls-rustls-fips` builds because bearer-token HMAC is
  routed through OpenSSL FIPS or AWS-LC FIPS respectively. Non-FIPS builds still
  reject admin in FIPS/ISO-required configs.
- FIPS/ISO-required mode now rejects local cache encryption and requires either
  no cache encryption or `provider = "openbao-transit"` with operator evidence
  for the external OpenBao crypto boundary.
- Added `tls.fips.require_disk_cache_encryption` and
  `tls.iso19790.require_disk_cache_encryption` so operators can promote the
  unencrypted disk-cache warning to a hard config error in stricter
  data-at-rest deployments.
- The compliance evidence package is folded into `1.3.6` so regulated
  operators get the fail-closed gates and the evidence workflow in the same
  release.
- Admin runtime/auth-throttle mutex poisoning now aborts instead of recovering
  potentially inconsistent management state, matching release-mode fail-closed
  behavior in debug/test builds.
- Dynamic admin API JSON responses now serialize through `serde_json::to_vec`
  instead of hand-written `format!` response bodies, preserving the existing
  response schemas while reducing future JSON escaping risk.
- Admin bearer-token authorization now avoids length-check short-circuiting,
  zeroizes the temporary candidate copy used for comparison, and aborts on
  impossible system-clock failures instead of falling back to epoch timestamps.
- Snapshot ID generation now aborts on system-clock failure rather than
  generating `s0-...` identifiers.
- Peer-fill concurrency permit accounting now uses checked arithmetic and
  refuses permits if the counter saturates.
- The `security` feature runtime marker was renamed to
  `security::feature_compiled_in()` so it is not mistaken for an enforcement
  gate.
- The `RUSTSEC-2024-0437` release metadata guard now fails after the scheduled
  manual review date if the advisory exception is still present.

## 1.3.5 - rustls/AWS-LC FIPS Candidate

Released: 2026-05-22

### Added

- Added the rustls/AWS-LC FIPS-capable candidate backend feature:
  `tls-rustls-fips`, with `tls-rustls-iso19790`, `profile-fips-rustls`, and
  `profile-iso19790-rustls` validation/terminology aliases.
- Added provider-aware rustls TLS setup so default rustls builds keep using
  ring while FIPS rustls builds use `rustls::crypto::default_fips_provider()`.
- Added rustls FIPS diagnostics to `fluxheim crypto` and
  `fluxheim-config-tester --crypto`.
- Added `examples/fips-rustls.toml`, `examples/iso19790-rustls.toml`, and
  `scripts/validate-fips-rustls.sh` for local/manual AWS-LC FIPS candidate
  validation.

### Changed

- Split the internal rustls backend feature from the public `tls-rustls`
  provider selection so `tls-rustls` and `tls-rustls-fips` remain mutually
  exclusive public choices.
- Documented that rustls/AWS-LC FIPS candidate builds require the
  `aws-lc-fips-sys` build toolchain, including CMake, Go, and a C compiler.

## 1.3.4 - OpenSSL FIPS-Capable TLS

Released: 2026-05-21

### Added

- Added a standalone FIPS-capable deployment plan covering NIST/CMVP
  references, compliance boundaries, backend-specific OpenSSL and rustls/AWS-LC
  paths, internal crypto blockers, and the post-`1.3.4` roadmap for rustls and
  broader internal-crypto closure.
- Added the `tls.fips.required` fail-closed OpenSSL guard,
  `fluxheim crypto`, and `fluxheim-config-tester --crypto` diagnostics for the
  `1.3.4` OpenSSL FIPS-capable TLS line.
- Added an opt-in `tls-openssl-fips` feature that accepts
  `tls.fips.required` only with `backend = "openssl"` and verifies that the
  OpenSSL FIPS provider can be loaded, queried with `fips=yes`, and selected
  through OpenSSL default properties at runtime.
- Added a small local OpenSSL FIPS support crate that wraps OpenSSL 3 default
  property APIs outside Fluxheim's `#![forbid(unsafe_code)]` crate boundary.
- FIPS-required OpenSSL startup now enables and verifies
  `EVP_default_properties_enable_fips` / `EVP_default_properties_is_fips_enabled`
  before Pingora TLS services are built, and rejects startup if non-FIPS
  algorithms remain available through the default fetch path.
- Patched the vendored `pingora-openssl` compatibility crate to stop forcing
  `openssl/vendored`, allowing OpenSSL builds to link against the operator's
  system OpenSSL provider.
- Added FIPS-capable release evidence instructions for OpenSSL provider
  diagnostics, `tls.fips.required` config-tester checks, and operator evidence
  capture.
- Extended crypto diagnostics to report the OpenSSL configuration and module
  environment visible to the Fluxheim process without hardcoding distro paths.
- Added `profile-fips-openssl` as a narrow proxy/security/OpenSSL-FIPS build
  alias for local and release validation.
- Added `examples/fips-openssl.toml` and a matching
  `fluxheim-config-tester --profile fips-openssl` validation mode.
- Added `scripts/validate-fips-openssl.sh` to build/check the FIPS-capable
  OpenSSL profile, capture provider diagnostics, validate the fixture, and
  optionally require a working provider with `FLUXHEIM_REQUIRE_FIPS_PROVIDER=1`.
- Added fail-closed backend-mismatch and non-FIPS TLS-policy fixtures to the
  OpenSSL FIPS-capable validation script.
- Wired OpenSSL FIPS-capable validation into the optional stable release gate
  with `FLUXHEIM_GATE_FIPS_OPENSSL=1`.
- Added OpenSSL FIPS-capable evidence capture to `scripts/release_evidence.sh`,
  with `--skip-fips` for release lines where it is not relevant.
- Added the OpenSSL FIPS-capable profile to CI and local check coverage so the
  feature alias, config tester fixture, provider diagnostics, and fail-closed
  behavior are exercised before release.
- Documented the `1.3.4` OpenSSL FIPS boundary: Fluxheim proves provider
  availability, enables OpenSSL default FIPS properties for the process-default
  library context, and records the operator evidence still needed for the
  selected module Security Policy.
- Added a mapped OWASP Top 10 2025 baseline document and validation script that
  checks Fluxheim-owned controls for the categories that can be tested in-repo.
- Wired the OWASP Top 10 2025 baseline into stable release gates and release
  evidence capture.

### Changed

- Updated the release runbook for the `1.3.4` release line, corrected the
  local formatting preflight command, and documented explicit OWASP baseline
  evidence capture.

## 1.3.3 - PHP-FPM Hardening And Compatibility

Released: 2026-05-20

### Added

- Started the `1.3.3` PHP-FPM hardening line with opt-in FastCGI
  keep-connection pooling under `[vhosts.php.fpm]`: `keepalive`,
  `pool_max_idle`, and `idle_timeout_secs`.
- Added `[vhosts.php.params]` and `[vhosts.routes.php.params]` for safe custom
  FastCGI parameter injection without allowing overrides of Fluxheim-managed
  CGI variables or inbound `HTTP_*` request-header parameters. Custom parameter
  tables are capped at 128 entries.
- Added `php.fpm_root` for split Fluxheim/php-fpm filesystem layouts so
  Fluxheim can validate scripts under `php.root` while sending php-fpm paths
  under the runtime container root.
- Added `php.resolve_root_symlink` for opt-in final `php.root` symlink
  resolution in current-release/Caddy-style deploy layouts while keeping
  symlinked parent directories rejected.
- Added `php.try_files` with `front-controller`, `wordpress`, and `strict`
  modes for typed PHP front-controller and `try_files $uri =404` behavior.
- Added `php.preset = "wordpress"` to combine WordPress front-controller
  behavior with PHP execution denial for common upload/file directories.
- Added `php.path_info = "split"` as the clear spelling for safe explicit
  `PATH_INFO` splitting, while keeping `strict` as a compatibility alias.
- Added canonical slash redirects for PHP directory indexes so `/dir` redirects
  to `/dir/` before executing `/dir/index.php`.
- Added `php.pass_request_headers` and `php.pass_request_body` switches for
  advanced FastCGI migration control.
- Added `php.stderr_log` and `php.stderr_max_bytes` controls for bounded,
  sanitized php-fpm STDERR logging.
- Added `php.stderr_log_level` so php-fpm STDERR can be logged as `error`,
  `warn`, `info`, or `debug` instead of always using warning severity.
- Added `php.stderr_failure_patterns` for opt-in literal STDERR matching that
  marks a php-fpm response invalid for safe-method retry/failover when
  `php.fpm.retry_invalid_response` is enabled; matching STDERR is logged before
  invalidation when STDERR logging is enabled. Pattern lists are bounded to 32
  entries, with each pattern capped at 512 bytes.
- Added `php.hide_response_headers` for removing selected php-fpm response
  headers before they reach clients; the list is now bounded and rejects
  duplicate header names case-insensitively.
- Stripped hop-by-hop php-fpm response headers, including `Connection`-named
  headers and `Transfer-Encoding`, before Fluxheim frames the client response.
- Added `php.intercept_error_statuses` for opt-in
  `fastcgi_intercept_errors`-style replacement of selected PHP 4xx/5xx
  responses with Fluxheim-generated errors. Intercept status lists are capped
  at the valid 400-599 error-status range.
- Added `[[vhosts.php.error_pages]]` and route-level PHP error pages for
  serving internal static fallback pages when selected PHP statuses are
  intercepted. PHP error-page lists are capped at 64 entries.
- Added `php.deny_path_prefixes` to block php-fpm script execution under
  configured URI prefixes such as WordPress upload directories. PHP execution
  deny prefixes are capped at 128 entries, and `php.allowed_extensions` is
  capped at 16 entries with case-insensitive duplicate rejection.
- Added `php.max_response_header_bytes` to make the php-fpm CGI response
  header cap configurable while keeping the `64KiB` default. Added
  `php.server_port` for explicit CGI `SERVER_PORT` overrides on non-standard
  PHP listener deployments.
- Capped configurable buffered PHP responses at `64MiB` while keeping the
  default `php.max_response_bytes = "64MiB"`; php-fpm STDOUT/STDERR is now
  collected through the configured cap instead of after unbounded buffering.
- Added PHP-specific Prometheus request totals and duration histograms with
  bounded labels through `fluxheim_php_requests_total` and
  `fluxheim_php_request_duration_seconds`, and
  `fluxheim_php_stderr_events_total`, and retry-attempt counts through
  `fluxheim_php_fpm_retries_total`, plus pool visibility through
  `fluxheim_php_fpm_pool_idle_connections` and
  `fluxheim_php_fpm_pool_events_total`; multi-upstream keepalive pools use
  stable indexed pool labels. Added low-cardinality OTLP trace
  attributes for PHP runtime and PHP outcome so Jaeger can distinguish PHP
  handling without script-path labels. PHP request outcomes now distinguish
  connect timeouts, request timeouts, connection errors, configuration errors,
  invalid responses, and intercepted PHP statuses.
- Added cache bypass primitives for path prefixes, exact paths, any non-empty
  query string, and cookie-name prefixes, plus `cache.preset = "wordpress"`
  for common WordPress shared-cache bypasses, including admin, login,
  XML-RPC, cron, app/mail/register, index, and sitemap endpoints. Cache
  bypass, header, status, vary, content-type, extension, and method lists are
  capped to bounded sizes.
- Added `php.ignore_origin_cache_headers` for NGINX-style migrations that need
  Fluxheim to drop PHP-generated `Cache-Control`, `Expires`, and `Pragma`
  before applying response policy.
- Added `php.fpm.tcp_upstreams` for multiple TCP php-fpm backends with
  round-robin selection and safe-method failover on connection failures and
  connect timeouts. Upstream lists are capped at 64 entries and reject
  duplicate authorities.
- Added opt-in php-fpm retry controls with `php.fpm.max_retries`,
  `php.fpm.retry_timeout_secs`, and `php.fpm.retry_methods` for connection
  failures and connect timeouts before
  php-fpm returns a response; request timeouts are not retried. Retry method
  lists are capped at 16 safe methods and now reject non-idempotent methods such
  as `POST`, `PUT`, `PATCH`, and `DELETE`.
- Added opt-in php-fpm retry controls for malformed FastCGI responses and
  selected PHP 5xx responses through `php.fpm.retry_invalid_response` and
  `php.fpm.retry_statuses`, using the same safe-method and retry-window policy.
  Retry status lists are capped at the valid 500-599 server-error range.
- Wired `php.fpm.connect_timeout_secs`, `php.fpm.read_timeout_secs`, and
  `php.fpm.write_timeout_secs` as stricter caps on php-fpm connect and buffered
  FastCGI request phases alongside `php.request_timeout_secs`.
- Added opt-in PHP request-body disk spooling with
  `php.request_body_spool_threshold_bytes` and `php.request_body_spool_dir` so
  large uploads can be replayed to php-fpm and retried without cloning the
  entire request body in memory. Both spool settings are now required together.
  When `php.max_request_body_bytes` is set on the same PHP action, the spool
  threshold must be lower than that body limit. Existing spool directories must
  be directories and must not be group/world writable, and runtime spool
  creation rechecks permissions before writing upload bodies. Runtime spool
  filenames now include CSPRNG entropy to avoid predictable local pre-creation.
- Added PHP-assisted static offload for `X-Accel-Redirect` and `X-Sendfile`.
  Offload targets must resolve under `php.root`, `X-Sendfile` paths are mapped
  from `php.fpm_root` when configured, and Fluxheim refuses to offload files
  with configured PHP script extensions.
- Added PHP `X-Accel-Expires` handling: Fluxheim consumes the internal
  backend header, maps valid TTLs to normal `Cache-Control` and `Expires`
  headers, treats zero or past expiries as `no-store`, and avoids public cache
  directives on responses that set cookies.
- Capped proxy upstream lists, ACME challenge upstream lists, and proxy
  error-page lists at 64 entries, with duplicate upstream rejection.
- Capped configured request/response header mutation lists and maps so
  remove/unset, set/add, and append policies remain bounded.
- Capped listener lists, trusted proxy lists, total vhosts, vhost host aliases,
  and per-vhost route counts so config validation and reload planning stay
  bounded.
- Capped TLS policy allow-lists, global static certificate lists, ACME issuer
  lists, and explicit vhost ACME domain lists so certificate planning remains
  bounded.
- Capped static web `index_files` lists so global, vhost, and route static
  index probing remains bounded.
- Capped `cache.key_parts` to the four supported cache-key fields before
  duplicate and required-path validation.
- Capped configured vhost and route names at 128 bytes so log labels, admin
  responses, and metric dimensions remain bounded.

### Changed

- Added RFC 9110 hardening for proxy and static responses: ACME HTTP-01 405
  responses now include `Allow`, proxied requests and responses append Fluxheim
  `Via`, chunked requests without `Content-Length` are accepted for streaming
  body limits, satisfiable multi-range static requests are served as full
  responses, and Fluxheim-generated text error bodies include `Content-Type`.
- Admin authentication throttling now fails closed with a global lockout when
  the per-source table is full instead of evicting tracked source state.
- Fixed `fluxheim-config-tester --no-runtime-paths` so it skips `server.process`
  runtime path inspection before config loading fails on inaccessible
  `/run/fluxheim` mounts, while still validating non-path process settings.
  Updated the container and production docs to show when to use the tester
  versus full `fluxheim --validate-config` preflight, and refreshed container
  and RPM examples to the current `1.3.3` release line.
- Documented the explicit FastCGI protocol scope for php-fpm: Fluxheim
  supports the one-request-at-a-time `FCGI_RESPONDER` web-serving subset and
  does not support FastCGI multiplexing, authorizer, filter, or management
  roles in `1.3.x`.
- Added PHP application recipes for WordPress, WordPress Multisite, Laravel,
  Symfony, Flarum, MediaWiki, phpBB, XenForo, MyBB, and Discourse-as-proxy,
  clarifying that the reviewed PHP apps fit Fluxheim's generic PHP-FPM
  primitives while flat-root apps still need careful static path exposure until
  generic static deny/allow policy exists.
- Updated the PHP-FPM example to use `php.preset = "wordpress"` and show the
  optional `cache.preset = "wordpress"` shared-cache migration block.
- Removed `php-turbine` from the PHP runtime plan because Turbine-style app
  servers are better handled as reverse-proxy upstreams. The later pure-Rust
  PHP/phprs track has also been dropped from the `1.3.x` plan in favor of
  managed php-fpm.
- Added managed php-fpm process supervision to the future `1.3.x` PHP plan as
  a runtime config mode inside the existing `php-fpm` feature, while keeping
  external php-fpm as the default and rejecting persistent `php-cli` workers as
  the production path for normal PHP applications.
- Hardened PHP-FPM and observability follow-ups from pentest review: bounded
  joined FastCGI header params, added runtime custom-param guards, added a
  default PHP request-body fallback cap, tightened X-Sendfile root checks,
  restricted PHP response header values to ASCII-safe bytes, created PHP spool
  files relative to a verified directory fd on Unix, and added HTTPS-capable
  OTLP/HTTP export with strict 2xx status handling.
- Added private-PKI CA bundle support for OTLP metrics and tracing exporters,
  warn on plaintext OTLP endpoints outside loopback, create PHP body spool
  directories with private Unix permissions, canonicalize existing `php.fpm_root`
  paths while preserving separate-container path mapping, and raise the
  `PHP_ADMIN_VALUE disable_functions` warning to error level.
- Updated the optional `base64-ng` dependency to `1.0.0` for ACME EAB key
  decoding and OpenBao Transit cache encryption encoding.

## 1.3.2 - ACME Operations And Config Tester

Released: 2026-05-18

### Added

- Started the `1.3.2` operational follow-up with a dedicated
  `fluxheim-config-tester` binary for validating mounted configs without
  starting the gateway.
- Added config tester profile validation for `full`, `cache`, `proxy`,
  `web-php`, `development`, and future `load-balancer` release profiles.
- Added config tester modes for runtime-path validation, TLS storage checks,
  ACME target preview, upstream DNS resolution, and explain output.
- Added the dedicated `fluxheim-acme` companion binary with `renew` and
  `targets` commands backed by the existing ACME engine.
- Added a local Unix-domain certificate reload socket so `fluxheim-acme renew`
  can activate renewed certificate handles in the running gateway.
- Added `fluxheim-acme status` and `fluxheim-acme renew --vhost <name>` for
  safer single-target first issuance and renewal operations.
- Added `fluxheim-acme reload` for explicit service-manager or manual
  certificate-handle reload requests.
- Added bounded ACME lifecycle metrics through
  `fluxheim_acme_events_total{event}` for pending, renewed, failed, and reload
  outcomes without exposing domains, certificate paths, or challenge tokens.

### Changed

- Release evidence now builds one unified config-tester artifact instead of
  installing the tester into normal RPMs or runtime images.
- RPMs and runtime images now include `fluxheim-acme` for external ACME
  service/timer and container companion workflows.
- Hardened `fluxheim-acme` certificate reload responses with a bounded socket
  read.
- Kept ACME and cache secret-file intermediates in zeroizing buffers and capped
  ACME secret input files.
- Capped Admin API JSON response and error-message sizes as a defense-in-depth
  guard for authenticated control-plane responses.
- Hardened the certificate reload control socket with private bind/listen
  sequencing and read timeouts.
- Extended Unix `O_NOFOLLOW` coverage across config, snapshot, web,
  runtime-log, ACME, and admin-token path opens.
- Bounded trace-context random ID generation so CSPRNG failures disable tracing
  for the request instead of spinning indefinitely.
- Switched in-memory admin token digests from bare SHA-256 to per-process
  HMAC-SHA256, redacted internal Admin API 500 responses, and made
  indeterminate admin sources count only toward the global throttle budget.

## 1.3.1 - PHP-FPM Runtime Support

Released: 2026-05-16

### Added

- Added the `php-fpm` compile-time module for Fluxheim `1.3.1`, including
  typed `[vhosts.php]` and `[vhosts.routes.php]` config, strict PHP script
  resolution, WordPress-style front-controller dispatch, bounded FastCGI
  request/response handling, and malformed PHP response-header rejection.
- Added PHP runtime feature-policy checks so only one PHP runtime feature can
  be selected in a binary.
- Added `examples/php-fpm.toml` and PHP-FPM build/config documentation.
- Added a hardened browser WordPress login probe for reproducing real browser
  login/admin cookie behavior during gateway testing.

### Changed

- Updated the release line to use `base64-ng 0.8.0`, `aws-lc-rs 1.17.0`,
  `aws-lc-sys 0.41.0`, and `winnow 1.0.3`; `prometheus` remains pinned for
  Pingora compatibility.
- Hardened cache `Vary` request hashing with length-prefixed components instead
  of sentinel delimiters.

### Fixed

- Normalized split `Cookie` headers before proxying upstream and before
  generating PHP-FPM `HTTP_COOKIE`, fixing WordPress browser login flows over
  HTTP/2 and intermediaries that split cookies.
- Cleaned up test/runtime error propagation reported by the final pentest pass.

## 1.3.0 - Shared Ingress And TLS Feature Split

Released: 2026-05-14

### Changed

- Documented the release-artifact ACME default: official RPMs, container
  images, and release tarballs include `acme-client` for full, cache, and proxy
  builds, while raw Cargo profile aliases remain ACME-optional for custom
  offline/static-certificate builds.

### Added

- Started the shared ingress/TLS feature-graph split so TLS backends can be
  compiled without implicitly enabling the full proxy module.
- Added focused profile aliases for the next packaging line:
  `profile-full`, `profile-web-server`, `profile-cache-edge`,
  `profile-proxy-edge`, and `profile-load-balancer-edge`.
- Added CI feature-policy, check, and clippy coverage for the focused
  profiles.
- Added runtime validation that rejects web or cache configuration when the
  corresponding compile-time module is absent.

### Changed

- Container image builds now use focused feature profiles for `full`, `cache`,
  and `proxy` images. The load-balancer image profile remains prepared but is
  gated until the `1.5` load-balancer line unless manually requested.
- Updated the roadmap so `1.3.1+` owns PHP support, `1.4` owns advanced proxy
  parity, `1.5` owns enterprise load-balancer parity, and `1.6` owns shared
  Wasm extensibility.

## 1.2.6 - Slice Cache Range Composition Follow-Up

Released: in progress

### Added

- Added opt-in `[cache.range.slice]`, `[vhosts.cache.range.slice]`, and
  route-scoped slice-cache policy for Varnish-style fixed-slice range
  composition.
- Added normalized slice cache keys so arbitrary client ranges can be served
  from compatible fixed-size cached slices without colliding with complete
  objects or exact `1.2.5` range entries.
- Added bounded missing-slice fill from origin. Fluxheim fetches only normalized
  single-slice `Range` requests, validates `206`, `Content-Range`,
  `Content-Length`, `ETag`/`Last-Modified`, total length, and content type, and
  collapses concurrent fills for the same slice key.
- Added composed responses for bounded ranges, open-ended ranges, suffix
  ranges, and multipart multi-range requests when all required slices are
  fresh and validator-compatible.
- Added end-to-end proxy-cache smoke coverage for slice fill, slice hit,
  open-ended range, suffix range, multipart range composition, and cached
  slice `If-Range` matches.

### Changed

- `range.max_bytes` may exceed `cache.max_object_bytes` when
  `range.slice.enabled = true`; individual `range.slice.size_bytes` values
  remain bounded by `cache.max_object_bytes`.
- Exact admin purges now also remove slice entries for the same indexed path
  when slice caching is enabled.

## 1.2.5 - Bounded Range Cache Follow-Up

Released: in progress

### Added

- Added opt-in `[cache.range]`, `[vhosts.cache.range]`, and route-scoped
  cache range policy for safe bounded single `Range: bytes=start-end` proxy
  requests.
- Added range-specific proxy cache keys so repeated partial downloads can be
  served from cache without colliding with complete-object entries.
- Added range-cache admission checks that only store upstream `206 Partial
  Content` responses when `Content-Range` and `Content-Length` match the
  requested byte window.

### Changed

- Upstream `206 Partial Content` responses are now rejected from normal
  full-object cache admission unless the request is participating in the
  opt-in range-cache path.
- Documented the `1.2.5` large-file cache behavior in the README, config
  reference, cache backend notes, production-readiness notes, and versioning
  plan.

## 1.2.4 - Distributed Cache Peer-Fill Follow-Up

Released: in progress

### Added

- Started the `1.2.4` distributed cache line with `[cache.peer_fill]` policy
  configuration, bounded peer lists, explicit timeouts, fail-open behavior, and
  safe peer-origin validation for future peer-fill runtime support.
- Added a focused `examples/cache-peer-fill.toml` fixture and CI validation for
  the peer-fill configuration shape.
- Added aggregate Prometheus gauges for peer-fill enabled policies, configured
  peers, and maximum configured peer-fill concurrency.
- Added `cache-key` and `cache-lookup` preview fields and fail-closed
  expectation flags for selected peer-fill policy shape.
- Added peer-fill policy coverage to protected admin cache-status JSON.
- Added the first peer-safe runtime primitive for distributed cache fill:
  proxy-cache requests carrying `Cache-Control: only-if-cached` are now served
  from a fresh local cached object or receive `504` without contacting origin.
- Added outbound peer-fill on proxy-cache misses. Fluxheim now asks configured
  peers for `only-if-cached` hits before going to origin, stores valid peer
  hits locally, and respects `fail_open` when no peer can satisfy the request.
- Added bounded policy-level cache activity events for peer-fill hit, miss,
  error, fallback, and fail-closed outcomes.
- Added `scripts/smoke_peer_fill_cache.sh` and wired it into CI/release gates
  to prove node-to-node peer fill, local store after peer hit, and peer-fill
  activity metrics before release. The smoke also verifies fail-closed peer
  misses return `504` without contacting origin and fail-open peer misses fall
  back to origin.
- Enforced `peer_fill.max_concurrent_requests` at runtime per vhost/route cache
  policy so configured peer-fill limits now bound active outbound peer fetches.
- Preserved peer response `Age` during peer-fill admission so a peer hit stores
  only its remaining freshness instead of extending the origin TTL.
- Stored peer-fill hits under the correct `Vary` variance key so subsequent
  local hits preserve negotiated variants.

## 1.2.3 - Optional Cache Encryption Follow-Up

Released: 2026-05-13

### Added

- Started the `1.2.3` optional cache encryption-at-rest line with
  `[cache.disk.encryption]` policy configuration. Encryption remains disabled
  by default and normal deployments do not need OpenBao.
- Added local-key AES-256-GCM encryption for disk cache objects. Local keys can
  be loaded from a safe file path or a systemd/container credential, and
  encrypted cache objects authenticate the configured key id plus combined cache
  key as associated data.
- Added OpenBao Transit runtime encryption for disk cache objects. Fluxheim can
  call OpenBao Transit over HTTPS, load the token from a safe file or
  systemd/container credential, and store only the Transit ciphertext in the
  filesystem or storage-bin cache backend.
- Added optional Podman/OpenBao developer validation with a dev-mode OpenBao
  compose file and an end-to-end smoke script that verifies Transit-backed
  encrypted proxy-cache storage.
- Added focused local-key and OpenBao Transit encrypted cache example configs
  and CI validation for both.
- Added release-gate smoke coverage for local-key encrypted storage-bin cache
  traffic.
- Added `fluxheim cache-keygen` for generating local AES-256-GCM cache
  encryption keys.
- Added cache-encryption operations documentation covering local-key setup,
  OpenBao policy, rotation behavior, and smoke-test commands.

## 1.2.2 - Storage-Bin Disk Cache Follow-Up

Released: 2026-05-13

### Added

- Started the `1.2.2` storage-bin cache line with an explicit
  `cache.disk.backend` selector. The current filesystem backend remains the
  default and `storage-bin` is recognized as the focused slab/bin backend.
- Added the isolated storage-bin cache storage prototype with manifest/bin
  files, durable object index recovery, free-range reuse, LRU eviction parity,
  purge-index synchronization, Pingora `Storage` trait support, and runtime
  backend selection.
- Added storage-bin management parity for runtime stats, activity reset, cache
  inspection, exact purge, indexed hard/soft purge, and stale-object purge so
  the backend has the same operational hooks needed by the filesystem tier.
- Debounced storage-bin index writes after insert, eviction, and purge bursts
  so high-cardinality cache fills do not rewrite the full durable index once per
  object.
- Added storage-bin storage-pressure reporting for allocated bin bytes, reusable
  free bytes, free range count, largest free range, and bin file count in admin
  cache stats and aggregate Prometheus gauges.
- Fixed same-key storage-bin rewrites so revalidation or replacement can reuse
  the previous object's range instead of refusing an otherwise admissible write.
- Added a best-effort storage-bin index flush on clean storage teardown so the
  debounce path reduces write amplification without dropping fresh cache entries
  during normal shutdown.
- Added conservative storage-bin tail reclamation so eviction and purge can
  remove fully-free highest-numbered bin files without moving live objects.
- Added a focused `examples/cache-storage-bin.toml` fixture and CI validation
  for the storage-bin cache backend.

## 1.2.1 - Local Static Cache Follow-Up

Released: 2026-05-12

### Added

- Added the `1.2.1` focused local/static vhost cache follow-up with an explicit
  `local_static` cache-policy opt-in, local cache `MISS`/`HIT`/`Age` headers,
  and cache-key/lookup/exact-purge support for local static objects.

## 1.2.0 - Operations And Cache Completion Pack

Released: 2026-05-12

### Added

- Metrics builds now publish aggregate cache configuration gauges for vhost,
  route, policy, and storage-tier coverage.
- Metrics builds now publish aggregate memory and disk cache storage-pressure
  gauges, including object counts, byte usage, configured budgets, fill ratios,
  and purge-index entry counts.
- Metrics builds now publish bounded cache activity counters for memory and disk
  hits, misses, stores, store refusals, evictions, and purges.
- The local observability smoke now verifies Prometheus cache operation
  histograms plus memory and disk storage-pressure gauges while also checking
  local Prometheus OTLP metrics and Jaeger OTLP traces when available.
- The release smoke suite now verifies proxy cache HIT behavior, cached-hit
  `Age`, conditional `304`, and byte-range `206` behavior end to end.
- Proxy cache revalidation now preserves changed `Last-Modified` metadata from
  origin `304 Not Modified` responses and refuses metadata updates when a
  revalidation response changes `Vary`, keeping existing variant metadata
  intact until full re-keying support is added.
- Disk cache writes now use a v5 object header that records the combined cache
  key, primary key, user tag, cache tags, and path-index metadata, allowing
  Fluxheim to rebuild disk purge indexes after a process restart while
  retaining read compatibility with older v1-v4 objects.
- Cache policies can now set `pass_uncacheable_after` to temporarily bypass the
  cache path for repeated uncacheable responses with the same cache key.
- Cache debug headers now report pass-cache policy bypasses as `BYPASS` with
  reason `cache-pass` when `status_reason_header` is enabled.
- Prometheus cache activity metrics now include bounded policy pass decisions
  as `fluxheim_cache_activity_total{tier="policy",event="pass"}`.
- Prometheus now exposes configured vhost and route cache activity through
  `fluxheim_cache_activity_scope_total{scope,vhost,route,tier,event}`.
- Indexed cache purge endpoints now accept bounded `batches` /
  `x-fluxheim-cache-batches` for incremental large-scope invalidation.
- Stale cache purges now rotate scanned fresh entries on truncated non-dry-run
  batches, allowing bounded background cleanup to reach expired entries behind
  fresh front pages.
- Cache policies can now opt into Pingora's cacheability predictor with
  `[cache.predictor]`, `[vhosts.cache.predictor]`, and
  `[vhosts.routes.cache.predictor]`.
- `fluxheim cache-key` and `fluxheim cache-lookup` now report selected
  cacheability predictor state and can assert it with
  `--expect-cache-predictor-enabled`.
- The proxy cache smoke now enables and asserts vhost/route cacheability
  predictor policy.
- Route-scoped cache runtime stats now appear in the protected admin cache
  status endpoint and activity-reset response.
- `fluxheim cache-lookup` can now assert exact stored response header values
  with `--expect-header "Name: value"`, allowing release smoke tests to prove
  validator changes after proxy cache revalidation.
- Cache activity JSON now includes `miss_ratio_per_mille` alongside
  `hit_ratio_per_mille`.
- Cache activity JSON now includes `store_ratio_per_mille` alongside
  `store_refusal_ratio_per_mille`.
- Cache activity reset responses now include route and vhost cache coverage
  ratios.
- Cache status JSON now includes route and vhost cache coverage ratios.
- Cache status JSON now includes aggregate memory and disk cache tier counts.
- Cache status JSON now includes per-vhost and per-route `storage_tiers`
  counters.
- Cache status and activity-reset JSON now distinguish all configured routes
  from routes with explicit cache policy, including a cache-route coverage
  ratio.
- Cache policies can now emit an optional status response header, such as
  `X-Cache-Status`, for requests that participate in the proxy cache.
- Cache policies can now hide selected upstream response headers before cache
  admission and downstream delivery, enabling tightly scoped static-asset routes
  to strip headers such as `Set-Cookie`.
- Cache policies can now refuse shared cache storage when configured origin
  response headers are present, while still delivering the response normally.
- Cache policies can now refuse shared cache storage when configured origin
  response header values such as `x-app-cache = "private"` are present.
- Cache policies can now bypass lookup and storage when configured request
  headers such as `Cookie` or `Authorization` are present.
- Cache policies can now bypass lookup and storage when configured request
  header values such as `x-preview-mode = "1"` are present.
- Cache policies can now bypass lookup and storage when configured cookie names
  such as `sessionid` or `wordpress_logged_in` are present.
- Cache policies can now bypass lookup and storage when configured cookie
  values such as `preview = "1"` are present.
- Cache policies can now bypass lookup and storage when configured raw query
  parameter names such as `preview` or `token` are present.
- Cache policies can now bypass lookup and storage when configured raw query
  parameter values such as `mode = "private"` are present.
- Cache policies can now add safe request headers such as `Accept-Encoding` to
  the cache variance key when an origin does not emit the needed `Vary` header.
- Cache policies can now set an operator-controlled `key_namespace` to isolate
  new cached objects from older route-cache contents without changing URLs.
- Cache policies can now set `key_parts` to safely customize primary cache keys
  from `method`, `host`, `path`, and `query` without arbitrary interpolation.
- Cache policies can now set `min_uses` to delay shared cache storage until a
  cache key has produced repeated cacheable origin responses.
- Cache policies can now define positive response TTLs by HTTP status, which
  normalizes matching cache-participating origin responses before admission.
- Cache policies can now set `default_status_ttl_secs` as an explicit fallback
  TTL for cache-participating origin statuses not listed in `status_ttls`.
- Configured cache status TTLs now also opt matching non-200 origin responses
  into proxy cache admission; statuses without an explicit or fallback TTL
  remain rejected.
- Cache policies now support `content_types` plus an `extensions` alias for
  `image_extensions`, so route-scoped proxy cache can safely target common
  static assets such as CSS, JavaScript, WebAssembly, fonts, and images.
- Cache policies now support `include_query = false` for tightly matched static
  routes where query parameters should not vary the cache key.
- Cache policies can now explicitly ignore origin `Cache-Control` and `Expires`
  headers before proxy cache admission for tightly scoped static routes.
- Cache request-collapsing locks are now configurable per cache policy through
  `[cache.lock]`, while preserving the previous 30 second defaults.
- Protected cache purge endpoints can now target named route-scoped cache
  policies through `route` or `x-fluxheim-cache-route`.
- Protected cache purge responses now echo the normalized purge identity
  (`host`, `method`, `path`, and optional query) for easier bulk-operation
  auditing.
- Protected single cache purge responses and per-item bulk purge results now
  include aggregate and per-tier `not_purged` booleans.
- Protected bulk cache purge responses now include `purged_ratio_per_mille` so
  operators can quickly see how much of a requested purge batch matched.
- Protected bulk cache purge responses now include `not_purged`, avoiding
  manual subtraction when checking purge misses.
- Protected bulk cache purge responses now also echo the selected `route` and
  cache `scope`, matching single and indexed purge responses.
- Protected bulk cache purge responses now include memory and disk purged
  counts plus per-tier purge ratios.
- Protected indexed cache purge responses now include per-tier
  `memory_purged_ratio_per_mille` and `disk_purged_ratio_per_mille` fields.
- Protected indexed cache purge responses now include aggregate and per-tier
  `not_purged` counts for entries that matched the index but were not removed.
- Protected bulk and indexed cache purge responses now include aggregate and
  per-tier `not_purged_ratio_per_mille` fields for easier dashboarding.
- `server.default_vhost` validation now hints at `include_conf_d = true` or
  directory-based config loading when the named vhost is not loaded.
- Cache policies can now set `stale_if_error_secs` to permit serving stale
  cached objects during upstream errors after normal freshness expires.
- Stale-on-error serving now requires an explicit `stale_if_error_secs` policy
  window instead of serving stale for every upstream error.
- Cache policies can now narrow stale-on-error serving with
  `stale_if_error_on`, covering upstream error classes such as `connect`,
  `timeout`, `read`, `write`, `connection-closed`, `http-status`, `protocol`,
  and `tls`.
- Cache policies can now narrow HTTP-status stale-on-error serving with
  `stale_if_error_statuses`, for example to serve stale only on `500`, `502`,
  `503`, and `504` origin responses.
- Cache policies can now set `stale_while_revalidate_secs` to permit serving
  stale cached objects while Fluxheim revalidates them in the background.
- ACME HTTP-01 client failures now include published challenge URLs after
  challenge material has been written, making failed authorization checks easier
  to debug from production logs.

## 1.1.0 - TLS Policy And Certificate Operations

Released: pending

### Added

- ACME-managed vhost certificate sources now derive safe on-disk certificate
  paths and can satisfy the TLS listener fallback certificate requirement when
  configured on `server.default_vhost`.
- HTTP-01 challenge requests for ACME-managed vhosts can be served locally from
  the managed ACME storage directory when `tls.acme.challenge = "http-01"`.
- TLS-ALPN-01 challenge certificates can now be generated and served by the
  rustls downstream listener when `tls.acme.challenge = "tls-alpn-01"`.
- ACME EAB secret sources can now be loaded through a bounded, redacted,
  zeroized helper for the runtime issuer client.
- ACME-managed certificate files can now be installed through a guarded helper
  that validates PEM shape, writes temporary files, rejects symlinked targets,
  and preserves previous files on validation or staging failures.
- ACME HTTP-01 challenge files can now be installed and removed through the
  managed challenge store with token/value validation and symlink checks.
- ACME account credentials are now stored under safe issuer-derived paths with
  bounded JSON loading, owner-only writes on Unix, and symlink rejection.
- `acme-client` adds live `instant-acme` account bootstrap plus HTTP-01 and
  rustls TLS-ALPN-01 order/finalize support behind an explicit feature gate.
- Google Trust Services production and staging are now built-in ACME issuers,
  with separate default EAB environment variables for each environment.
- Managed ACME certificate expiry is now observed from bounded, symlink-safe PEM
  reads so Fluxheim can distinguish missing, due, and not-yet-due certificates.
- `fluxheim acme-renew` runs due-only renewal once, while
  `fluxheim acme-renew --force-renew` forces every configured ACME vhost.
  The old `--all` alias still works but now prints a deprecation warning.
- Builds with `acme-client` now register a background ACME renewal service for
  configured ACME vhosts. It renews missing or due certificates on the
  configured check interval and refreshes reloadable downstream SNI certificate
  objects after successful renewal.
- Downstream TLS listeners now have explicit policy config for named profiles,
  minimum protocol version, ALPN selection, curve preferences, and cipher suite
  allow-lists. `modern` now means TLS 1.3-only, while the default
  `intermediate` profile preserves the 1.0 TLS 1.2+ / HTTP/1.1+HTTP/2
  compatibility baseline with explicit AEAD ECDHE cipher policy.
- Response HSTS can now be configured as structured policy with `max_age_secs`,
  `include_subdomains`, and `preload` instead of requiring a raw header string.

### Changed

- `1.1.0` is now scoped as TLS policy and ACME certificate operations so normal
  production deployments can avoid external certificate copy scripts.
- Advanced provider-specific and zero-downtime certificate automation moved to
  a later certificate milestone.

## 1.0.0 - Gateway Foundation

Released: 2026-05-08

### Added

- `1.0` gateway migration fixtures and smoke coverage for representative
  multi-site configs, including canonical redirects, app proxy vhosts, custom
  error pages, static aliases, challenge exceptions, and multi-subdomain
  route/proxy layouts.
- Route-level exact, prefix, and fallback matching with proxy, static, and
  redirect actions.
- Route prefix stripping, per-route request body limits, and route-local
  upstream connect/read/send timeout policy.
- Websocket-safe upgrade proxying coverage for `/chat/`-style routes.
- Vhost ACME challenge helper for standard cleartext challenge paths while
  preserving HTTPS redirects for normal traffic.
- Vhost canonical redirect helper for apex/secondary-host redirects that preserve
  the request URI safely.
- Custom upstream error pages with internal static serving.
- Static alias routes with secure optional directory listing and local-time
  timestamp rendering.
- Safe dynamic request-header templates for common proxy migrations.
- SNI certificate selection for the default rustls downstream TLS backend and
  callback-capable downstream TLS backends.
- Native systemd deployment files, sysusers/tmpfiles packaging, and manual
  server preparation helper for compiled binaries.
- Zeroizing admin-token buffers and `subtle`-backed constant-time admin bearer
  token verification.
- SBOM generation and local reproducible-build checks in the stable release
  gate and CI supply-chain evidence.

## 0.5.0 - Basic Sites Preview

Released: 2026-05-06

### Added

- GitHub CI, Dependabot, CodeQL, dependency policy, and release-check scripts.
- Feature preflight validation for mutually exclusive TLS backends and
  zero-retention privacy-mode incompatibilities.
- `profile-*` Cargo feature aliases for common build profiles.
- Dedicated `1.0` core build matrix validation for default, profile, web-only,
  and proxy-only builds.
- Stable release security gate script for local release validation.
- Deep stable-release gate wrapper for release-candidate validation.
- Release-gate report capture helper for local release-note artifacts.
- Stable release-notes template covering gate results, reviewed advisories, and
  container image metadata.
- Production-readiness checklist separating the `1.0` stable-core promise from
  incubator and future modules.
- Vhost config guide explaining TOML `[[vhosts]]` ownership and the recommended
  one-vhost-per-file layout.
- User-friendly header mutation aliases: `remove`/`add` and nested
  `[headers.*.operations]` tables, while keeping `unset`/`set` compatible.
- Config validation rejects ambiguous header additions where the same header is
  defined in more than one `set`, `add`, or `operations.add` table.
- Config validation rejects proxy blocks that define both the compatibility
  `upstream` field and the preferred `upstreams` list.
- Optional `hey` based `1.0` local load-smoke script.
- Raw-socket request-framing smoke for malformed HTTP rejection before release.
- Initial `cargo-fuzz` targets for Host normalization and cache-header parsing.
- Fuzz target compile validation helper for release gates.
- Local `testssl.sh` TLS scan wrapper for scanner-backed release validation.
- `1.0` localhost smoke coverage for HTTP static hosting, HTTP proxying, static
  certificate storage validation, HTTPS static hosting, HTTPS proxying, and
  optional cleartext-to-HTTPS redirect.
- Global `[server.https_redirect]` option with safe Host validation and
  restricted redirect statuses.
- Wolfi, Alpine, SUSE Micro, and Debian runtime Containerfiles.
- Container image publish workflow for GitHub Container Registry and Docker Hub.
- Self-contained packaged default site and config so fresh containers/RPMs
  serve `/srv/fluxheim/index.html` on port `8080` without external assets.
- RPM packaging spec for RHEL/openSUSE-style builds from vendored Cargo
  dependencies.
- Runtime UID/GID build args for container images, defaulting to non-root
  `65532:65532` while allowing deliberate root-runtime images.
- Zero-retention privacy example config for `profile-privacy` builds.

### Changed

- Removed the advanced CodeQL workflow so GitHub CodeQL default setup can own
  code scanning without duplicate SARIF upload failures.
- Updated the optional OpenSSL TLS backend lockfile path to `openssl 0.10.79`
  and `openssl-sys 0.9.115`.
- Centralized temporary test path creation so CodeQL does not treat descriptive
  test labels as filesystem-controlled path input.
- The default build is `proxy`, `web`, `cache`, `tls-rustls`, and `security`.
- Container builds can select both feature set and packaged config.
- CI now separates the stable `1.0` core matrix from incubator-module feature
  checks.
- Container publishing uses variant-suffixed tags such as `v1.0.0-wolfi` and
  `latest-alpine`.
- Roadmap now tracks a future declarative redirect and rewrite engine with
  match-action routing, loop detection, and safe URL handling.
- Release ladder now focuses `1.1` on TLS policy and ACME certificate
  operations before operational and load-balancing modules graduate.
- Process runtime paths now default to `/run/fluxheim` instead of predictable
  files directly under `/tmp`.
- Examples now prefer `upstreams = [...]`; the single `upstream` field remains
  supported for compatibility.

### Security

- Path and header handling are treated as release-gated areas with tests and
  CodeQL scanning.
- Static file serving now rejects same-size file replacement between resolution
  and body read on Unix by checking the opened file handle identity.
- Process PID, upgrade-socket, and process error-log paths are rejected on Unix
  when their nearest existing parent directory is world-writable.
- File logging paths are rejected on Unix when their nearest existing parent
  directory is world-writable.
- Disk cache roots are rejected on Unix when their nearest existing parent
  directory is world-writable.
- Admin token files, configured snapshot stores, and direct snapshot store roots
  are rejected on Unix when they would use a world-writable directory.
- TLS certificate paths, ACME storage paths, and ACME EAB secret file paths are
  rejected on Unix when their nearest existing parent directory is
  world-writable, including in the dedicated TLS storage checker.
- `privacy-mode` rejects access logging and cannot be combined with `cache` or
  `metrics`.
- CodeQL uses the supported Rust `build-mode: none` setup.

### Notes

- This is a preview release for normal static HTML websites and simple
  whole-vhost proxying with static TLS certificates. It is not the `1.0.0`
  gateway release.
- At the `0.5.0` tag, known `1.0.0` gaps included multi-certificate SNI,
  route-level proxy/static/redirect behavior, websocket-safe proxying,
  per-route limits and timeouts, custom upstream error pages, and secure static
  alias/directory listing behavior.

## 0.1.0 - Repository Baseline

### Added

- Initial Fluxheim Rust/Pingora project baseline.
- Modular static web, reverse proxy, cache, TLS, ACME planning, admin snapshot,
  load-balancer, metrics, logging, and privacy-mode foundations.
- EUPL-1.2 license, GitHub-ready README, roadmap, architecture docs, examples,
  and rootless Podman packaging.
- `deny.toml` and audit policy for license/advisory checks.

### Notes

- This is not a production `1.0` release. The stable `1.0` target remains
  static hosting, reverse proxying, vhosts, rustls TLS, secure defaults, and
  local/rootless Podman operation.
