# Fluxheim 1.6.31 Release Notes

Fluxheim 1.6.31 starts the cache/PHP native-integration slice of the Pingora
exit work.

## Highlights

- Native HTTP/1 proxy planning now reports cache policy and PHP-FPM gaps with
  explicit blocker reasons instead of folding them into the generic HTTP policy
  bucket.
- Direct native route-proxy construction now fails closed for vhost/route cache
  and PHP-FPM policies until those adapters are implemented, so callers cannot
  bypass the planner and silently drop policy.
- Image/static cache request eligibility and cache-key construction now live in
  the Pingora-independent `fluxheim-cache` crate. The root compatibility module
  only wraps those shared keys into Pingora cache keys while that runtime path
  remains.
- `NativeHttp1Request` now implements the `fluxheim-cache` request-view trait,
  allowing the native proxy to reuse cache bypass, revalidation, range, and
  slice policy helpers without a Pingora request header.
- PHP-FPM response parsing now lives in the Pingora-independent
  `fluxheim-php-fpm` crate and returns plain status/header/body parts. The root
  proxy path only converts those parts into the current runtime response type.
- PHP FastCGI parameter value validation and request-header-to-param-name
  mapping now live in `fluxheim-php-fpm`, giving the native and compatibility
  paths one shared policy for bounded, control-free PHP params.
- PHP `SERVER_NAME` fallback selection now also lives in `fluxheim-php-fpm`,
  keeping host/fallback sanitization shared by native and compatibility paths.
- PHP FastCGI request-header param translation, resolved `HTTP_HOST` insertion,
  `CONTENT_TYPE` value selection, and runtime custom-param filtering now live
  in `fluxheim-php-fpm`; the current proxy path only applies those generated
  pairs to `fastcgi_client::Params`.
- PHP split-container path mapping for `SCRIPT_FILENAME` and safe
  `PATH_TRANSLATED` generation now lives in `fluxheim-php-fpm`, keeping dot
  segment, hidden path, backslash, and control-byte rejection shared.
- PHP request-path to `SCRIPT_NAME`/`PATH_INFO` parsing, allowed-extension
  matching, and deny-prefix checks now live in `fluxheim-php-fpm`; the proxy
  still owns static-file lookup and final execution decisions.
- PHP static-file to script-name mapping and slashless directory-index redirect
  decisions now live in `fluxheim-php-fpm`, sharing root confinement, hidden
  path rejection, and extension checks across native and compatibility paths.
- PHP static-offload target validation now lives in `fluxheim-php-fpm`,
  including X-Accel-Redirect control-byte rejection, X-Sendfile `fpm_root`
  mapping, and PHP-script offload blocking.
- PHP X-Accel-Expires TTL parsing and restrictive origin cache-policy detection
  now live in `fluxheim-php-fpm`, giving native PHP response handling the same
  cache safety rules as the compatibility path.
- PHP response-header stripping policy now lives in `fluxheim-php-fpm`,
  including hop-by-hop headers, `Connection` tokens, configured hidden headers,
  and static-offload internal headers.
- PHP custom error-page/status interception decisions now live in
  `fluxheim-php-fpm`, keeping native and compatibility response handling on one
  status policy.
- Shared PHP response/request policy now pre-reserves bounded `CONTENT_TYPE`
  joins, rejects extensionless static-offload files, ignores invalid
  `Connection` header tokens before response stripping, and asserts ASCII-only
  parser invariants.
- PHP `CONTENT_TYPE` joining now caps and validates during accumulation instead
  of building an oversized intermediate string before rejecting it.
- Pure local-static cache keys now use the explicit `fluxheim-static-v1;`
  prefix, matching the static-cache namespace used by the compatibility cache
  wrapper and making raw key inspection unambiguous.
- Native route-level static web now supports the memory-only
  `cache.local_static` adapter, reusing shared cache admission, bypass,
  revalidation, TTL, status-header, and file-identity key policy.
- Native vhost-level static web now supports the same memory-only
  `cache.local_static` adapter and still falls through to the vhost proxy
  fallback when a static file is not found.
- Native static-web memory cache accounting now includes conservative per-entry
  overhead, cache-key bytes, reason bytes, and response-header bytes before
  admission, preventing small cached objects from undercounting memory use.
- Native static-web memory cache insertion now samples `Instant::now()` once
  for stored/expiry time and avoids running the prune pass inside the initial
  insert lock; pruning also avoids full-table vector allocation and sorting.
- Unsupported native cache shapes still fail closed with explicit cache-policy
  blockers: vhost cache, proxy/image cache, disk cache, and non-static route
  cache remain compatibility-runtime work until their adapters are implemented.
- Native HTTP/1 cutover planning now recognizes the supported static-web
  memory local-static cache adapter, so those routes no longer make an
  otherwise native-ready vhost fallback proxy look unsupported.
- PHP request-body replay/spooling and bounded FastCGI stdout/stderr response
  collection now live in `fluxheim-php-fpm`; the root crate keeps only a thin
  compatibility adapter for the current PHP runtime.
- PHP-FPM keep-alive pool ownership now lives in `fluxheim-php-fpm` behind a
  small metrics callback boundary, so connection reuse, stale idle pruning,
  pool labels, and bounded response collection are owned by the PHP crate.
- Native HTTP/1 upstreams now support configured PROXY protocol v1/v2 send
  through `proxy.upstream_proxy_protocol`, using Fluxheim-owned frame builders
  and writing the header before upstream TLS or HTTP bytes.
- Native upstream PROXY protocol remains connection-scoped: HTTP/1 origin
  pooling is disabled for those upstreams, and native HTTP/2 upstream
  combinations fail closed until multiplexed per-request identity can be
  represented safely.
- Native requests now carry both the direct listener peer/local address and the
  trusted-forwarded effective client address, so upstream PROXY protocol uses
  the same client identity as native ACL/rate-limit/header policy.
- When that native effective client identity comes from forwarded headers,
  upstream PROXY protocol sends source port `0`, the documented unknown-port
  value, because forwarded headers do not include the original client port.
- Native HTTP/1 now has a host router that builds one native route proxy per
  configured vhost and dispatches exact and wildcard Host matches with the same
  default-vhost fallback behavior as the compatibility runtime.
- A native runtime manifest now refuses blocked plans and exports the
  Fluxheim-owned service/listener/background-task graph for blocker-free plans,
  giving the final runner replacement a tested orchestration contract without
  changing production execution yet.
- Native runtime launch-plan validation now rejects duplicate TCP or duplicate
  UDP listener bind intents before reporting the native adapter as the target,
  while still allowing TCP and UDP listeners to share the same address.
- Native runtime launch-plan errors now appear in the cutover evidence report,
  so concrete runner-contract failures are visible even when the high-level
  blocker summary is otherwise ready.
- The native runtime cutover evidence report now includes downstream HTTP/1
  and HTTP/2 launch-policy rows, giving final-runner hardening values a stable
  diffable contract.
- `NativeHttp1Request` now implements the load-balancer request-view trait
  behind the `fluxheim-server/load-balancer` feature, preparing native
  persistence and hash selection to consume native request metadata without a
  Pingora request adapter.
- `SelectedUpstream` now exposes stable address and authority accessors, giving
  native callers a public bridge from Fluxheim-owned load-balancer selection to
  upstream connection setup without reaching into backend internals.
- Selected-upstream metadata now also has public accessors for aliases,
  persistence outcomes, managed affinity cookies, reporters, and permit
  presence, completing the native routing metadata bridge.
- The metrics service now has a concrete native HTTP handler around the
  existing Prometheus response generator, giving the future native runner a
  direct handler for metrics HTTP.
- Root native HTTP/1 proxy construction now applies root response-header policy
  and root compression config before cutover planning marks a root proxy as
  native-ready.
- The native host router can now serve root-only proxy configs without
  `[[vhosts]]`, so the future native runner can instantiate the same root
  proxy shape that the planner reports as native-ready.
- Root static web can now be instantiated by the native host router without
  `[[vhosts]]`, including the supported local-static memory cache mode. Root
  disk/rich cache modes remain explicit native cache blockers.
- The native cutover planner now reports vhost fallback-only static-web, cache,
  and PHP-FPM blockers even when the vhost has no configured upstream proxy,
  matching the native host-router construction path.
- The native cutover planner now also reports route fallback-only static-web,
  cache, and PHP-FPM candidates when a route has no upstream proxy, making
  route-level native blockers visible instead of folding them into the parent
  vhost or fallback proxy summary.
- Native rate-limit delay mode now acquires vhost/route concurrency permits
  before sleeping, so delayed requests still count against configured
  concurrency budgets instead of occupying listener tasks outside those limits.
- Native rate-limit table pruning is now bounded and incremental per shard,
  replacing whole-shard `HashMap::retain` sweeps in the request hot path with a
  small prune queue scan when a shard is full.
- Native rate-limit sharding now hashes the full IPv4/IPv6 client address
  instead of using only the final address byte, reducing attacker-controlled
  hot-shard concentration when many trusted forwarded identities are present.
- Native rate-limit shard selection now uses a per-process random FNV seed and
  routes indeterminate-client buckets through that seeded hash path instead of
  pinning them to shard zero.
- Native rate-limit token refill and expiry pruning now use saturating
  `Instant` arithmetic, avoiding panic surfaces if a bucket timestamp is ever
  observed ahead of the current sample.
- Native static-web filesystem path resolution now rejects residual
  percent-encoding after the initial decode pass, avoiding ambiguous
  double-encoded traversal forms on fallback static serving.
- The native metrics handler can now require a bearer token and compares that
  token with `sanitization` constant-time equality. The current compatibility
  metrics listener still relies on listener binding and network ACLs until the
  final native runner cutover wires token configuration into service creation.
- Documentation now states that native rate-limit delay mode intentionally
  holds vhost/route concurrency permits while sleeping, keeping delayed tasks
  inside the configured concurrency budget instead of allowing unbounded
  sleepers outside the cap.
- Updated `sanitization` to 1.2.2 and `base64-ng` to 1.2.3 across the root,
  server, TLS, and load-balancer crates.
- The remaining normal-profile Pingora dependency exception target is now
  aligned with the roadmap: 1.6.31 is the cache/PHP adapter release, and 1.6.32
  remains the final Pingora-free proof release.

## Test Notes

- Added server-plan tests for root cache, vhost cache, route cache, vhost
  PHP-FPM, and route PHP-FPM native cutover blockers.
- Added route-proxy builder tests proving vhost/route cache and PHP-FPM
  policies are rejected directly until native adapters own those paths.
- Added a live native HTTP/1 proxy test proving safe-method failover skips
  duplicate weighted upstream slots before trying the next unique backend.
- Added live native static-web route and fallback tests for double-encoded
  traversal rejection.
- Added native metrics handler tests for bearer-token rejection and acceptance.
- Added standalone `fluxheim-cache` tests for cache-key construction,
  namespace/query/host normalization, and local-static file identity.
- Added native HTTP/1 tests proving cache request policy helpers work through
  `NativeHttp1Request` for origin-form and absolute-form targets, duplicate
  headers, and range-policy rejection.
- Added standalone `fluxheim-php-fpm` tests for plain PHP response parsing,
  unsafe header rejection, and response/header size limits, then re-ran the
  existing root parser compatibility tests with `php-fpm` enabled.
- Added standalone `fluxheim-php-fpm` tests for FastCGI param value bounds,
  control-byte rejection, and deterministic HTTP header param-name mapping.
- Added standalone and compatibility tests for PHP `SERVER_NAME` fallback
  behavior when the request host is unsafe.
- Added standalone `fluxheim-php-fpm` tests for duplicate request-header
  joining, `Proxy` header blocking, joined-value caps, safe `HTTP_HOST`
  insertion, content-type selection, and runtime custom-param filtering.
- Added standalone `fluxheim-php-fpm` tests for split-container script
  filename mapping and unsafe `PATH_INFO` rejection, plus the existing root
  compatibility test for PHP `fpm_root` mapping.
- Added standalone `fluxheim-php-fpm` tests for direct script detection,
  front-controller fallback, PATH_INFO split mode, unsafe segment rejection,
  allowed-extension matching, and deny-prefix matching.
- Added standalone `fluxheim-php-fpm` tests for static file script-name mapping
  and directory-index redirect decisions, plus existing root compatibility
  coverage for slashless PHP directory indexes.
- Added standalone `fluxheim-php-fpm` tests for PHP static-offload path policy,
  plus root compatibility coverage for X-Accel-Redirect and X-Sendfile
  handling.
- Added standalone `fluxheim-php-fpm` tests for X-Accel-Expires TTL parsing and
  restrictive origin cache-policy detection, plus existing root compatibility
  coverage for absolute-epoch parsing.
- Added standalone `fluxheim-php-fpm` tests for PHP response-header strip lists
  and internal static-offload header names, plus existing root compatibility
  coverage for hidden response headers.
- Added standalone `fluxheim-php-fpm` tests for PHP error-page/status
  interception decisions, plus existing root compatibility coverage for PHP
  custom error pages.
- Extended PHP-FPM tests for extensionless static-offload rejection and invalid
  `Connection` token filtering.
- Added PHP-FPM tests proving `CONTENT_TYPE` rejects control bytes and
  over-limit joined values without retaining the oversized joined result.
- Updated standalone `fluxheim-cache` tests to assert the local-static key
  prefix is `fluxheim-static-v1;`.
- Added live native route static-web tests proving the supported memory
  local-static cache returns `MISS` on the first request and `HIT` on a second
  request through the native listener.
- Added live native vhost static-web tests proving memory local-static cache
  returns `MISS`/`HIT` through the native listener, plus cutover-plan coverage
  for the supported vhost static-cache shape.
- Added native static-web memory-cache tests for conservative cache-entry
  weight accounting and expired/oldest-entry pruning behavior.
- Added route-config tests proving static-web routes accept the supported
  memory local-static cache adapter.
- Added native planning coverage proving static-web memory local-static cache
  routes do not block native HTTP/1 proxy cutover candidates.
- Added standalone `fluxheim-php-fpm` tests for in-memory request-body replay,
  secure spool-file replay/cleanup, and combined FastCGI stdout/stderr response
  size accounting, while keeping root PHP compatibility tests green.
- Added standalone and root compatibility tests proving PHP-FPM keep-alive pool
  labels remain stable after the pool move.
- Added native upstream-client tests proving PROXY protocol v1 and v2 bytes are
  written before HTTP request bytes, plus a live native proxy listener test
  proving listener destination metadata reaches the upstream PROXY line.
- Added native proxy config tests proving HTTP/1 upstream PROXY protocol is
  accepted, origin pooling is disabled for it, and HTTP/2 upstream
  combinations fail closed.
- Added live native host-router tests proving exact Host dispatch, wildcard
  longest-suffix matching, unknown/missing Host fallback, and default-vhost
  config validation.
- Added native runtime manifest tests proving blocked plans return explicit
  blockers and blocker-free multi-service plans expose proxy, admin, metrics,
  stream, UDP, ops-socket, and listener bindings.
- Added native metrics-handler tests proving the Prometheus text response is
  served through the `NativeHttp1Handler` boundary and a live native HTTP/1
  listener.
- Added native metrics-handler tests proving only `GET`/`HEAD /metrics` is
  served, with HEAD returning the Prometheus content length without a body.
- Added native root-proxy tests proving root response headers are stripped,
  set, and appended through the root config constructor, plus planner coverage
  for non-default root response headers.
- Added native host-router tests proving root-only proxy configs are served
  without vhosts and truly empty configs still fail closed.
- Added root static-web native host-router coverage plus planner tests proving
  supported root local-static memory cache is native-ready and unsupported root
  disk cache still fails closed as a cache blocker. The root static-web
  host-router test also proves the native memory cache returns `MISS` then
  `HIT` through a live listener.
- Added native cutover planner tests for vhost fallback-only static web,
  unsupported static-web disk cache, and PHP-FPM so policy blockers remain
  visible without an upstream proxy candidate.
- Added a live native admin listener test proving the authenticated health
  endpoint is served correctly through the native HTTP/1 listener.
- Startup now logs a native runtime manifest preview for blocker-free plans,
  showing the Fluxheim-owned service/listener/background-task graph while the
  compatibility runtime remains active.
- The native runtime cutover evidence report now includes manifest service and
  background-task rows, so CI archives the exact native service graph that the
  final runner will consume.
- Added launch-plan validation tests proving duplicate TCP listener binds keep
  the native target adapter disabled, while TCP and UDP listeners on the same
  address remain valid because they use distinct kernel transports.
- Added cutover-report coverage for native launch-plan error rows, including
  duplicate listener binds.
- Added native launch-policy TSV coverage for representative HTTP/1 and HTTP/2
  hardening values.
- Added feature-gated native request-view tests proving URI keys, repeated
  header values, and Cookie headers are exposed to `fluxheim-load-balancer`.
- Added a feature-gated native server test proving `NativeHttp1Request` drives
  real load-balancer header-hash selection through the shared request-view
  boundary.
- Updated load-balancer selection tests to exercise the new public
  selected-upstream metadata accessors.
- Re-ran targeted tests for native HTTP/1 client encoding, load-balancer
  persistence constant-time comparisons, and TLS secret handling after the
  dependency refresh.
- Re-ran the native runtime cutover evidence gate and the Pingora dependency
  policy gate against the 1.6.31 planning state.
