# Fluxheim 1.6.35 Release Notes

Fluxheim 1.6.35 is the first stabilization checkpoint after the Pingora-free
runtime proof release.

This release is intentionally scoped to security cleanup, soak-test evidence,
performance/regression checks, dependency hygiene, and documentation clarity
before the 1.6.36 structural cleanup removes the temporary native proxy shim.

## Highlights

- Keep the normal runtime on the Fluxheim-owned listener, TLS, HTTP/1, HTTP/2,
  WebSocket, cache, load-balancer, admin, metrics, stream, and background
  service paths introduced by the 1.6.34 Pingora-free proof release.
- Start the first-party secret-memory migration pass from direct `zeroize`
  calls toward Fluxheim's `sanitization` crate where the replacement is
  practical and testable.
- Move the legacy root auth subrequest forwarded-header secret container from
  direct `zeroize` wrappers to `sanitization::SecretString`.
- Move native auth-request forwarded and allowed response-header secret
  containers to `sanitization::SecretString`.
- Move native metrics bearer-token storage and transient Authorization header
  candidate buffers to `sanitization` secret containers.
- Move managed load-balancer cookie HMAC key-ring clearing from direct
  `zeroize` calls to `sanitization::SecureSanitize`.
- Move HTTP discovery bearer-token storage and Fluxheim-owned Authorization
  header assembly to `sanitization::SecretString`.
- Move native OpenBao disk-cache encryption token storage to
  `sanitization::SecretString` while preserving the existing OpenBao request
  behavior.
- Align the legacy cache OpenBao token holder with the native cache token
  migration so both cache code paths use `sanitization::SecretString`.
- Move admin bearer-token digest clearing from the `zeroize` derive path to an
  explicit `sanitization::SecureSanitize` drop implementation.
- Update the release checklist to prefer `sanitization::ct` for future
  constant-time secret comparisons, and drop an unused `zeroize` derive feature
  from the load-balancer crate.
- Move native upstream TLS client private-key PEM buffers for both rustls and
  OpenSSL backends to `sanitization::SecretVec`.
- Move stream-proxy upstream TLS client private-key PEM buffers for both rustls
  and OpenSSL backends to `sanitization::SecretVec`.
- Abort if native `auth_request` response-header application cannot access its
  secret container, matching other poisoned security-control locks and avoiding
  a repeated inconsistent 502 path.
- Clear both the admin token digest and stored token length through
  `sanitization::SecureSanitize` during drop.
- Align runtime performance baseline capture with its load-balancer fixture by
  building the `profile-load-balancer` release profile by default.
- Tighten native vhost-level PHP-FPM/static fallback routing so executable PHP,
  PHP directory redirects, denied PHP paths, and fail-closed resolution errors
  stay on the PHP-FPM path, while non-PHP static files can still be served by
  `[vhosts.web]`.
- Carry the native PHP-FPM fallback script-resolution result into the handler
  so vhost PHP/static routing does not resolve the same path twice across a
  deployment race window.
- Make `validate_runtime_config()` run the central structural
  `Config::validate()` checks itself, so standalone runtime validation catches
  cross-field invariants such as peer-fill policy shape before startup.
- Snapshot native disk-cache purge targets before running purge callbacks, so
  stale and indexed maintenance batches no longer hold the global purge
  registry mutex while deleting cache objects.
- Serialize native disk-cache same-key mutations with bounded lock stripes so
  store, purge, and eviction cannot interleave state updates with filesystem
  object removal for the same combined cache key.
- Preserve the client request `Host` as the HTTP/2 upstream `:authority`,
  matching the documented upstream virtual-hosting behavior already used by the
  native HTTP/1 and WebSocket paths.
- Narrow native PHP-FPM fallback fail-closed routing so resolver errors for
  explicit or protected PHP targets still avoid static source exposure, while
  ordinary non-PHP front-controller probe errors defer to static fallback first.
- Harden the WordPress PHP-FPM smoke fixture with explicit private TCP upstream
  opt-in and MariaDB readiness waiting, and verify full native WordPress
  PHP-FPM plus proxy/TLS smoke coverage.
- Fix the release version-bump helper so package versions such as `1.6.35` are
  not interpreted as regex backreferences during automated metadata updates.
- Add `scripts/test_starter.py`, a human-facing selector for the maintained
  live smoke scripts and release gates.
- Add `scripts/check_smoke_images.sh` so maintainers can pull and record the
  configured WordPress, OpenBao, MariaDB, PostgreSQL, and Valkey smoke images.
- Add a privacy-mode live smoke that builds `profile-privacy`, verifies
  client-IP headers are stripped before the upstream, and checks Fluxheim logs
  do not retain the test IP, path, cookie, user-agent, or request ID.
- Extend local and container load-balancer smokes with native
  nginx-compatible Ketama coverage, and extend the container smoke with
  backend failover, recovery, and all-down 503 checks.
- Wire optional deep-gate flags for OpenBao cache encryption, database health
  checks, WordPress, PHP Wolfi, RPM build, privacy mode, and smoke dependency
  image freshness.
- Make the observability smoke self-contained by starting disposable
  Prometheus and Jaeger containers when external URLs are not configured,
  requiring Prometheus scrape plus OTLP metrics ingestion and keeping Jaeger
  trace ingestion opt-in until native span export is implemented.
- Require `cache.peer_fill.shared_secret_file` for non-loopback `http://`
  peer-fill URLs, closing the remaining unauthenticated cross-host plaintext
  peer-fill cache-poisoning configuration.
- Add `cache.peer_fill.shared_secret_file` so peer-fill clusters can require
  response-bound HMAC verification: outbound peer-fill requests include a
  nonce/request signature, peers sign the status, canonical response headers,
  and body digest, and unsigned or tampered peer responses are discarded before
  cache storage.
- Add `scripts/smoke_ports.py` and wire the newer privacy, observability, and
  load-balancer container smokes through the shared randomized localhost port
  allocator instead of repeating ad-hoc allocation snippets.
- Keep dependency, metadata, container, RPM, and smoke-test gates as blocking
  evidence for the stabilization line.

## Compatibility Notes

- No new protocol or extensibility surface is planned for this checkpoint.
- Third-party transitive `zeroize` use inside dependencies such as rustls,
  AWS-LC, and other cryptographic crates remains untouched.
- The 1.6.36 follow-up remains reserved for structural cleanup: deleting the
  temporary native proxy shim, moving remaining DTOs/helpers into owning crates,
  and removing inert Pingora-era root code.

## Verification

- `scripts/validate-release-metadata.sh`
- `scripts/validate-pingora-dependency-policy.sh`
- `scripts/validate-native-runtime-cutover.sh`
- `scripts/capture-runtime-baseline.sh release`
- `scripts/stable_release_gate.sh check`
- `scripts/smoke_privacy_mode.sh`
- `scripts/check_smoke_images.sh`
- `scripts/smoke_load_balancer.sh`
- `scripts/smoke_load_balancer_container.sh`
- `scripts/smoke_openbao_cache_encryption.sh`
- `scripts/smoke_redis_health_check.sh`
- `scripts/smoke_mysql_health_check.sh`
- `scripts/smoke_postgres_health_check.sh`
- `scripts/smoke_observability_local.sh`
- `scripts/smoke_wordpress_php_fpm.sh both`
- `scripts/smoke_wordpress_proxy_tls.sh`
