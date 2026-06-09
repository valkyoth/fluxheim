# Changelog

All notable Fluxheim changes should be recorded here before a release tag is
created.

Fluxheim follows semantic versioning once `1.0.0` is released. Before `1.0.0`,
minor versions may still change configuration shape, feature names, and runtime
behavior when the change improves security or project direction.

## 1.5.14 - 2026-06-09

### Changed

- Start the local exec health-check line. The stop line is opt-in, bounded
  command probes for health checks that cannot be represented by TCP/TLS,
  HTTP, gRPC, JSON, or later database protocol probes.
- Add `protocol = "exec"` for load-balancer active health checks with an
  absolute `exec_command`, exact `exec_allowed_commands` allow-list,
  bounded literal argv through `exec_args`, and `exec_timeout_secs`.
- Run exec health checks without a shell, with a cleared inherited
  environment, null stdio, and explicit backend context variables:
  `FLUXHEIM_HEALTH_BACKEND_ADDR`, `FLUXHEIM_HEALTH_BACKEND_HOST`, and
  `FLUXHEIM_HEALTH_BACKEND_PORT`.
- Expose the active health-check protocol in load-balancer runtime status for
  operator visibility without exposing exec command paths or arguments.
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
