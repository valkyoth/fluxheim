# Changelog

All notable Fluxheim changes should be recorded here before a release tag is
created.

Fluxheim follows semantic versioning once `1.0.0` is released. Before `1.0.0`,
minor versions may still change configuration shape, feature names, and runtime
behavior when the change improves security or project direction.

## Unreleased

### Added

- Route-scoped cache runtime stats now appear in the protected admin cache
  status endpoint and activity-reset response.
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
