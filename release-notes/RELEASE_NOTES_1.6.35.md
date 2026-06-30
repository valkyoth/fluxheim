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
- Fail closed if native `auth_request` response-header application cannot
  access its secret container, preventing requests from reaching the upstream
  with silently dropped identity or authorization headers.
- Clear both the admin token digest and stored token length through
  `sanitization::SecureSanitize` during drop.
- Align runtime performance baseline capture with its load-balancer fixture by
  building the `profile-load-balancer` release profile by default.
- Make native vhost-level PHP-FPM take precedence over static web fallback for
  PHP-resolvable paths, preventing `.php` source exposure when a vhost enables
  both `[vhosts.web]` and `[vhosts.php]`.
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
