# Changelog

All notable Fluxheim changes should be recorded here before a release tag is
created.

Fluxheim follows semantic versioning once `1.0.0` is released. Before `1.0.0`,
minor versions may still change configuration shape, feature names, and runtime
behavior when the change improves security or project direction.

## Unreleased

No unreleased changes yet.

## 1.3.2 - ACME Operations And Config Tester

Released: in progress

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

### Changed

- Release evidence now builds separate config-tester artifacts per release
  profile instead of installing the tester into normal RPMs or runtime images.
- RPMs and runtime images now include `fluxheim-acme` for external ACME
  service/timer and container companion workflows.

## 1.3.1 - PHP-FPM Runtime Support

Released: in progress

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

Released: in progress

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
