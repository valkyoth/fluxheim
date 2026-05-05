# Fluxheim Roadmap

This roadmap is the working implementation plan. Keep it current as features
move from design to code.

Release sequencing is defined in [Versioning Plan](docs/versioning-plan.md).
That plan keeps `1.0` intentionally small and promotes larger modules through
later minor releases.

## Current MVP Goal

Fluxheim's first stable release should be a local/rootless-Podman friendly
Pingora static web server and reverse proxy that can safely run small sites and
origin frontends:

- vhost routing with static web serving and single-upstream proxying;
- static/bought-certificate TLS with rustls as the default backend;
- strict header/body limits and basic secure header policy;
- release checks, license checks, and rootless container packaging.

The near-term focus is hardening the already-working baseline rather than
expanding into large research features. ACME runtime, SNI certificate selection,
load balancing, cache, admin snapshots, metrics, Sentinel Mesh/WireGuard,
stale-while-revalidate, and persistent cache indexing remain important, but
they should graduate after the `1.0` stable core according to the versioning
plan.

PHP execution is explicitly post-MVP application-server work. It must stay
disabled by default and compile only through opt-in feature flags because PHP
support changes Fluxheim's threat model from static/proxy serving to dynamic
code execution.

Legacy Perl CGI execution is also post-MVP application-server work. It should
be modeled as a separate opt-in compile feature from PHP, disabled per vhost by
default, and implemented with strict process isolation before it is exposed to
operators.

Legacy HTTP/1.0 and HTTP/0.9 support is future experimental compatibility work
for isolated industrial or research devices only. It must never be compiled into
the default binary and must never run on Fluxheim's normal proxy, cache, admin,
PHP, or CGI paths. The modern protocol direction remains HTTP/1.1, HTTP/2, and
future HTTP/3/QUIC support with strict request parsing.

## Near-Term MVP Hardening

These are realistic additions to implement across the stable core and early
`1.x` releases:

1. **Pingora Process Settings**
   - Map Fluxheim config into Pingora process settings: worker threads,
     daemon mode, PID file, error log, upgrade socket, graceful shutdown
     timeout, upstream keepalive pool size, and max retries.
   - Validate rootless/container-friendly paths and defaults.
   - Extend reload impact classification so process-owned settings require a
     Pingora process upgrade.

2. **Access And Error Logging**
   - Add typed access-log config with secure defaults.
   - Emit structured request logs from the Pingora `logging` hook with method,
     host/vhost, path, status, bytes when available, request id, and latency.
   - Keep log sinks simple at first: stderr/stdout and optional file path.
   - Implement the staged structured logging plan in
     [Logging Architecture](docs/logging-architecture.md).
   - Use `tracing` as the core event system, with JSON output for production
     and `log` compatibility while legacy modules still use `log`.
   - Split log classes into access, error, security, and audit events.
   - Add a bounded async dispatcher so request workers do not perform slow disk
     or network writes directly.
   - Make queue overflow behavior explicit: `drop_new`, `block`, or durable
     `spool`. Do not claim both zero latency and zero data loss without
     durable spooling.
   - Add optional remote TCP/TLS sink with a circuit breaker and stdout/spool
     fallback.
   - Redact secrets by default: authorization headers, cookies, admin tokens,
     ACME/EAB secrets, and configured sensitive fields.

3. **Header Policy**
   - Add configurable upstream forwarding headers:
     `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto`, and
     standardized `Forwarded`.
   - Add configurable response hardening headers for static/proxied responses:
     HSTS, CSP, `X-Content-Type-Options`, frame policy, and referrer policy.
   - Make trusted-proxy handling explicit before accepting client IP headers.

4. **Modern Protocol Focus**
   - Keep normal Fluxheim ingress focused on modern, strictly parsed HTTP:
     HTTP/1.1 and HTTP/2 now, HTTP/3/QUIC as a future security/performance
     milestone.
   - Treat HTTP/3 as separate from legacy support. HTTP/3 needs its own TLS,
     UDP, QUIC, ALPN, certificate, and deployment plan.
   - Do not weaken the normal parser, proxy, cache, admin, PHP, or CGI paths to
     support legacy clients.

5. **Request Body Streaming Limits**
   - Keep current `Content-Length` enforcement.
   - Add streaming byte accounting for chunked/unknown-length bodies so request
     body limits cannot be bypassed.
   - Add focused tests for chunked uploads, oversized streaming bodies, and
     normal uploads.

6. **Load-Balancing Policy Options**
   - Keep round-robin as the stable default.
   - Add explicit config for additional Pingora-supported policies where they
     are available and stable, starting with hash-based selection.
   - Keep smart telemetry and WireGuard routing in Sentinel Mesh as a future
     design until the base load-balancer surface is stronger.

7. **Operator Documentation**
   - Add a concise GitHub-facing project goals document.
   - Add one “production checklist” that states what is MVP-ready and what is
     still experimental.
   - Keep example configs in sync with every new global section.

8. **Zero-Retention Privacy Build Profile**
   - Add a compile-time optional privacy profile for static web serving and
     reverse proxying with no application-level request retention.
   - Architecture and security plan documented in
     [Zero-Retention Privacy Mode](docs/zero-retention-privacy-mode.md).
   - Intended build shape:
     `cargo build --no-default-features --features proxy,web,tls-rustls,privacy-mode`.
   - Privacy mode must disable access logs, remote logs, file logs, per-client
     metrics, disk cache, WAF audit logging, Cloudflare real-IP restoration,
     and any feature that stores or forwards client IPs by default.
   - Fluxheim may still use peer IPs transiently in memory because TCP/TLS
     requires them. The guarantee is no Fluxheim application persistence of
     request logs, IP addresses, cookies, user agents, request IDs, or paths.
   - Privacy mode must not add `X-Forwarded-For`, `Forwarded`, or similar
     client-IP forwarding headers to upstreams. Existing incoming forwarding
     headers should be stripped unless explicitly allowed by a non-privacy
     build.
   - Add release checks proving privacy builds do not compile metrics/logging
     exporters and add tests that request handling does not emit or persist
     client-identifying fields.

## Configuration Model

Fluxheim should support a modern virtual-host configuration model inspired by
Caddy's site blocks and global options, while keeping a strongly typed TOML
format as the first implementation target.

Goals:

- A global server section for process-wide and listener-wide defaults.
- Multiple virtual hosts in one config file.
- Optional config-directory loading, similar to `conf.d`, for local operations.
  Implemented for visible top-level `*.toml` files loaded in sorted order.
- Host/SNI based routing for proxy, static web, cache, TLS, and ACME behavior.
- Clear validation errors before startup.
- No implicit insecure inheritance across vhosts.

Initial TOML shape:

```toml
[server]
listen = ["0.0.0.0:80"]
tls_listen = ["0.0.0.0:443"]
worker_threads = "auto"
graceful_shutdown = "30s"
trusted_proxies = ["10.0.0.0/8", "192.168.0.0/16"]

[server.limits]
max_request_header_bytes = "64KiB"
max_uri_bytes = "8KiB"
max_request_headers = 100
max_request_body_bytes = "16MiB"

[tls]
enabled = true
backend = "rustls"

[tls.acme]
enabled = true
storage = "/var/lib/fluxheim/acme"
contact_email = "admin@example.com"
default_issuer = "letsencrypt"
challenge = "tls-alpn-01"

[[vhosts]]
name = "example.com"
hosts = ["example.com", "www.example.com"]

[vhosts.tls]
enabled = true

[vhosts.tls.acme]
enabled = true

[vhosts.web]
root = "/srv/sites/example"
index_files = ["index.html"]
deny_dotfiles = true

[vhosts.proxy]
upstream = "127.0.0.1:3000"
upstreams = ["127.0.0.1:3000", "127.0.0.1:3001"]

[vhosts.proxy.load_balance]
max_iterations = 256

[vhosts.proxy.load_balance.health_check]
enabled = true
interval_secs = 1
consecutive_success = 1
consecutive_failure = 1
parallel = false

[vhosts.cache]
enabled = true
image_extensions = ["avif", "gif", "jpeg", "jpg", "png", "svg", "webp"]
methods = ["GET", "HEAD"]
max_object_bytes = "32MiB"

[vhosts.cache.memory]
enabled = true
max_size_bytes = "1GiB"

[vhosts.cache.disk]
enabled = false
path = "/var/cache/fluxheim/example.com"
max_size_bytes = "10GiB"
```

Longer-term optional syntax:

```text
{
    listen 0.0.0.0:80 0.0.0.0:443
    acme letsencrypt
}

example.com, www.example.com {
    root /srv/sites/example
    file_server
    reverse_proxy http://127.0.0.1:3000
    cache images
}
```

The Caddyfile-like syntax is a later adapter target. The internal source of
truth should stay a typed Rust config model so tests can validate behavior
without parsing text fixtures for every module.

## Milestones

1. **Proxy Foundation**
   - Typed config loading and validation.
   - Pingora `ProxyHttp` runtime.
   - Plain HTTP upstream support.
   - Optional TLS upstream support.
   - Compile-time Pingora load-balancer module. Implemented with static
     round-robin pools.
   - Pingora TCP health-check config. Implemented in the load-balancer module.
   - Pingora background service registration for periodic load-balancer health
     checks. Implemented.
   - Smart telemetry load balancer over WireGuard. Future design documented in
     [Sentinel Mesh](docs/sentinel-mesh.md).

2. **Static Web**
   - Secure static file resolution.
   - Index files.
   - MIME detection.
   - `GET` and `HEAD` support.
   - Traversal, dotfile, and symlink escape tests.
   - Pingora does not currently provide a ready-made static file server module.
     Continue using Fluxheim's checked file resolver on top of Pingora sessions.
   - Evaluate Pingora `cache`, `connection_filter`, response compression, and
     body filters as web-serving hardening/performance modules.

3. **Virtual Hosts**
   - Add `[[vhosts]]` config. Implemented.
   - Route by `Host` header. Implemented.
   - Route by TLS SNI once downstream TLS lands.
   - Keep backwards-compatible single-site config during migration.
   - Add duplicate host detection. Implemented.
   - Add fallback/default vhost behavior. Implemented with first-vhost fallback.
   - Add explicit configurable default vhost. Implemented.
   - Add wildcard host matching. Implemented for one-label `*.example.com` hosts.

4. **Global Server Settings**
   - Listener defaults. Implemented for TCP listener addresses.
   - Worker/runtime settings.
   - Timeouts.
   - Request header limits. Implemented for URI length, header count, and
     approximate header bytes.
   - Request body limits. Implemented for declared `Content-Length`; streaming
     byte accounting remains.
   - Trusted proxy handling.
   - Access log defaults.

5. **TLS And ACME**
   - Compile-time TLS backend feature selection:
     `tls-rustls`, `tls-openssl`, `tls-boringssl`, or `tls-s2n`.
   - Default to `tls-rustls` for local/rootless portability while documenting
     Pingora's experimental rustls status.
   - Typed global TLS/ACME config. Implemented.
   - Static certificate file config. Implemented.
   - Let's Encrypt issuer config. Implemented.
   - Actalis issuer config with External Account Binding env/file secret
     references. Implemented.
   - Per-vhost certificate policy config. Implemented.
   - ACME renewal queue policy config. Implemented.
   - ACME renewal target discovery and queue scheduling. Implemented for
     config-derived targets and observed certificate expiration times.
   - Reject ambiguous local `renew_after` datetimes. Implemented; use full
     offset datetimes such as `2026-06-01T00:00:00Z`.
   - Safe certificate/key storage permission checks. Implemented for static
     certificates and ACME storage paths.
   - Downstream TLS listener wiring. Implemented for explicit `server.tls_listen`
     addresses with the first global static certificate as the default
     certificate.
   - Config validation for downstream TLS listener prerequisites. Implemented:
     TLS listener addresses require `tls.enabled = true` and a global static
     certificate until ACME/SNI runtime selection lands.
   - Per-vhost/SNI downstream certificate selection.
   - ACME account/order/challenge runtime.
   - Background renewal queue service.
   - Atomic certificate install and rollback on invalid renewed certificates.
   - Runtime certificate/config reload with snapshot swapping for no downtime.
   - Reload impact classification. Implemented for snapshot-safe versus
     process-upgrade changes.
   - CLI reload impact check. Implemented with `--reload-from OLD_CONFIG` and
     `--config NEW_CONFIG`.
   - Durable config snapshot store. Implemented as a versioned on-disk config
     history under an operator-chosen state directory.
   - Snapshot rollback command. Implemented for validated rollback to a chosen
     or previous config snapshot and durable current-pointer update.
   - Admin live rollback. Implemented with `/_fluxheim/rollback?live=true` for
     snapshot-safe targets; process-upgrade targets return a conflict before the
     durable pointer is changed.
   - Self-healing rollback guard. Implemented known-good and pending-validation
     state for snapshot-safe reloads, protected confirm/fail endpoints, and
     fail-closed rollback when the validation window expires.
   - Automatic self-healing watchdog. Implemented as a Pingora background
     service that enforces validation-window expiry without operator traffic.
   - Health-signal self-healing. Implemented protected report endpoint for
     external watchdog success/error signals, with `min_successful_checks` and
     `max_error_rate_per_mille` enforcement.
   - Proxy-integrated self-healing signals. Implemented: during pending
     validation, Fluxheim samples proxy outcomes directly. 2xx/3xx responses
     count as successful checks, while 5xx responses and fatal proxy errors
     count as failed checks and can trigger rollback through the existing
     self-healing guard.
   - Admin/control API for reload, snapshot, rollback, and health state. Planned
     on a localhost-only listener by default, with auth required before remote
     exposure.
   - Admin/control API typed config. Implemented with secure defaults:
     disabled by default, loopback listener, token env/file auth source,
     snapshot store path, and self-healing validation window settings.
   - Admin/control API service. Implemented as a Pingora HTTP service on the
     configured admin listener with unauthenticated local health,
     bearer-token-protected status, snapshot listing, snapshot creation, and
     durable rollback-pointer updates.
   - Admin/control API live reload endpoint. Implemented for the durable current
     snapshot when the reload classifier returns `noop` or `snapshot`; returns
     a conflict for process-upgrade-only changes.

6. **Cache**
   - Typed global and per-vhost cache config. Implemented.
   - Configurable memory and disk cache tier budgets. Implemented in config.
   - Validation that enabled caches declare at least one storage tier.
     Implemented.
   - Cache storage planning for memory object slots and disk paths. Implemented.
   - Image/static eligibility and deterministic cache keys. Implemented.
   - Vhost-aware Pingora cache-key callback. Implemented.
   - Pingora memory backend evaluation. Implemented:
     `pingora-memory-cache 0.8.0` is current and license-compatible, but it is a
     generic count-based cache and needs an HTTP `Storage` adapter.
   - Byte-bounded in-process memory cache tier. Implemented with `moka 0.12.15`,
     verified as latest on 2026-05-05.
   - Runtime vhost memory-cache construction. Implemented.
   - Pingora memory `Storage` adapter. Implemented for complete-object memory
     admission.
   - Pingora `HttpCache` storage admission. Implemented for eligible image
     requests with origin-provided freshness metadata.
   - Request collapsing. Implemented for the memory tier with Pingora
     `CacheLock`.
   - Oversized memory admission refusal. Implemented: objects above
     `cache.max_object_bytes` are not stored.
   - Disk storage. Implemented as a complete-object Pingora `Storage` adapter
     with SHA-256 shard paths, atomic same-directory renames, per-object limits,
     purge, oldest-file eviction, and on-write total-size enforcement.
   - Disk eviction policy. Implemented as scan-based oldest-file eviction.
     Planned: replace scan-based ordering with a persistent LRU/TTL eviction
     index.
   - Multi-tier cache promotion/fallback. Implemented with a tiered Pingora
     storage adapter: memory is L1, disk is L2, misses write to both tiers,
     disk hits promote to memory when they fit, and purge invalidates both.
   - Pingora `Storage` adapter partial streaming admission. Planned with a
     bounded in-progress spool; disabled for memory and disk tiers until
     unknown-size origin responses can be bounded safely.
   - HTTP cache semantics.
   - Stale-while-revalidate.
   - Purge/admin API. Implemented for protected single-key invalidation through
     `POST /_fluxheim/cache/purge` and same-host bulk exact invalidation
     through `POST /_fluxheim/cache/purge-bulk`; tag/prefix purge is planned
     after a cache index lands.
   - Cache admin status. Implemented through protected
     `GET /_fluxheim/cache/status` with aggregate and per-vhost memory/disk
     counters plus hit, miss, store, refused-store, and purge activity.
   - Cache activity reset. Implemented through protected
     `POST /_fluxheim/cache/activity/reset` without clearing cached objects.

7. **Metrics**
   - Compile-time `metrics` module. Implemented.
   - Typed metrics listener config. Implemented with secure defaults:
     disabled by default, loopback listener, and loopback enforcement before
     remote exposure.
   - Pingora Prometheus HTTP service wiring. Implemented.
   - Proxy request outcome counter. Implemented as
     `fluxheim_proxy_requests_total` labeled by vhost, outcome class, and
     status.
   - Reload impact classification. Implemented: metrics listener changes
     require a process upgrade because the service is startup-owned.
   - Additional counters planned: cache operation totals, upstream selection
     totals, load-balancer health transitions, ACME renewal results, and
     self-healing rollback actions.
   - Advanced metrics architecture documented in
     [Metrics Architecture](docs/metrics-architecture.md).
   - Keep Prometheus pull as the safe baseline. Advanced per-vhost buckets,
     remote push, and OTLP export must remain optional add-ons.
   - Planned features:
     - `metrics`: current baseline Prometheus endpoint.
     - `metrics-advanced`: cardinality-safe per-vhost counters and latency
       histograms.
     - `metrics-push`: optional remote exporter.
     - `metrics-otlp`: optional OpenTelemetry/OTLP exporter.
   - Cardinality safety is mandatory: never create metric labels directly from
     arbitrary `Host`, path, query, user-agent, client IP, or request ID values.
     Use configured vhost names and fixed buckets such as `unknown`,
     `invalid_host`, `legacy_unidentified`, and `overflow`.
   - Prefer prebuilt vhost-indexed buckets and atomic counters on the request
     hot path. Evaluate fixed atomic latency buckets first; use `hdrhistogram`
     only with sharded or background aggregation.
   - Remote push exporters must run in background services and must never block
     request workers. Failed pushes keep metrics available locally and expose
     exporter health through Prometheus/admin status.

8. **Future Optional WAF Support**
   - Architecture and security plan documented in
     [WAF Architecture](docs/waf-architecture.md).
   - WAF support must be optional, compile-time gated, and disabled by default.
     Planned features:
     - `waf`: shared WAF config, decision model, audit logging, and native
       lightweight rule engine.
     - `waf-native`: Rust-native signature/anomaly engine using reviewed
       pattern matching crates such as `aho-corasick`.
     - `waf-hyperscan`: optional high-performance regex engine using
       `hyperscan`; Linux-focused and FFI-backed, so not part of defaults.
     - `waf-proxy-wasm`: experimental Proxy-Wasm host path for Coraza/OWASP
       CRS compatibility after a runtime/security audit.
   - Prefer a native MVP first: header/URI checks, body scanning for bounded
     content types, anomaly scoring, per-vhost enablement, dry-run mode, and
     audit events. Coraza/Proxy-Wasm is a future compatibility engine, not the
     initial default.
   - WAF hooks should run early in Pingora request handling: inspect method,
     URI, normalized headers, cookies, and client metadata before upstream
     selection; inspect request bodies only under explicit size and content-type
     limits.
   - Body scanning must be conditional and bounded: do not scan arbitrary large
     uploads, binary content, or streaming bodies beyond `max_scan_bytes`.
     Default action for oversized bodies should be configurable per vhost:
     `skip`, `deny`, or `score`.
   - Enforce cardinality and privacy rules: WAF metrics/logs must not store raw
     secrets, complete cookies, authorization headers, full request bodies, or
     attacker-controlled metric labels. Audit logs should include rule IDs,
     phase, action, score, vhost, and request ID only after redaction.
   - Fail mode must be explicit per vhost: `fail_closed` for high-security
     deployments, `fail_open` only when availability is more important and the
     risk is documented in config validation warnings.
   - Add tests for header blocks, body blocks, anomaly thresholds, dry-run
     behavior, redaction, max body scan limits, malformed input, reload of WAF
     rules through snapshots, and default builds proving WAF is absent unless
     explicitly compiled.

9. **Future Optional Cloudflare Origin Support**
   - Architecture and security plan documented in
     [Cloudflare Origin Support](docs/cloudflare-origin-support.md).
   - Cloudflare support must be optional, compile-time gated, and disabled by
     default. Planned features:
     - `cloudflare`: shared config, trusted IP ranges, header restoration, and
       Cloudflare-aware logging context.
     - `cloudflare-api`: Cloudflare API client, IP range refresh, and Origin CA
       certificate automation.
     - `cloudflare-origin-ca`: CSR generation and Cloudflare Origin CA
       certificate lifecycle.
     - `cloudflare-aop`: Authenticated Origin Pulls client certificate
       verification configuration and reload support.
   - Implement trust-boundary support first: accept `CF-Connecting-IP`,
     `CF-Ray`, `CF-IPCountry`, and related headers only when the direct peer IP
     matches validated Cloudflare IP ranges or mTLS AOP succeeds. Never trust
     Cloudflare headers from arbitrary clients.
   - Cloudflare IP ranges should be loaded from pinned config at startup and
     optionally refreshed by a background service from Cloudflare's official IP
     API. Refresh failures must keep the last valid range set and expose
     health through admin/metrics.
   - Cloudflare Origin CA automation is feasible but must be separate from
     Let's Encrypt/ACME: generate a local private key and CSR, call the
     Cloudflare Origin CA API, persist the cert/key atomically with strict file
     permissions, and reload TLS without downtime only through the existing
     certificate reload/snapshot model.
   - Authenticated Origin Pulls must distinguish global AOP from stricter
     zone-level/per-hostname AOP. Global AOP proves traffic came from the
     Cloudflare network, not from the user's specific account; prefer
     zone-level or per-hostname AOP for high-security deployments.
   - API tokens must be least-privilege, never logged, loaded from secrets/env
     paths rather than config snapshots by default, and redacted in all admin,
     log, and error output.
   - Add tests for spoofed Cloudflare headers from non-Cloudflare peers, IP
     range refresh failure, stale range fallback, Ray ID logging, real-IP
     restoration, token redaction, Origin CA CSR validation, and default builds
     proving Cloudflare support is absent unless explicitly compiled.

10. **Zero-Retention Privacy Mode Compatibility**
   - Architecture and security plan documented in
     [Zero-Retention Privacy Mode](docs/zero-retention-privacy-mode.md).
   - Privacy mode is not a normal runtime toggle. It should be a compile-time
     profile so logging/metrics/exporter code paths can be excluded from the
     binary.
   - Planned feature:
     - `privacy-mode`: static web plus reverse proxy operation with
       no application-level request retention.
   - Planned incompatible features:
     `metrics`, `metrics-advanced`, `metrics-push`, `metrics-otlp`,
     `logging-remote`, `logging-file`, `logging-spool`, `waf`,
     `waf-native`, `waf-hyperscan`, `waf-proxy-wasm`, `cloudflare`,
     `cloudflare-api`, `cloudflare-origin-ca`, `cloudflare-aop`, `php-*`,
     `perl-cgi-*`, `legacy-http-*`, and disk cache features.
   - Privacy builds must not persist client IPs, request paths, user agents,
     cookies, request IDs, or per-client counters. Startup/config errors may
     still be emitted without request metadata.
   - Reverse proxy behavior must strip inbound `X-Forwarded-For`, `Forwarded`,
     `X-Real-IP`, and similar headers, and must not synthesize new real-IP
     headers for upstreams.
   - Document the boundary clearly: Fluxheim can avoid storing client data, but
     the OS, container runtime, firewall, Cloudflare/CDN, and upstream
     applications can still log traffic unless configured separately.

11. **Future PHP Runtime Support**
   - Architecture and security plan documented in
     [PHP Runtime Support](docs/php-runtime-support.md).
   - PHP must be optional and compile-time gated. Planned mutually exclusive
     features:
     - `php-turbine`: preferred future integration target if Turbine exposes an
       auditable Rust/library interface with compatible licensing and maintained
       security posture.
     - `php-phprs`: experimental pure-Rust PHP interpreter path for research and
       compatibility tests, not production WordPress/Laravel hosting until the
       interpreter matures.
     - `php-fpm`: backwards-compatible FastCGI bridge to php-fpm over Unix or
       TCP sockets.
   - Add `compile_error!` guards so only one PHP runtime feature can be selected
     in a binary.
   - Add typed PHP config per vhost: enabled runtime, document root, index file,
     allowed extensions, socket/upstream, request timeout, body limit override,
     environment allow-list, and path-info policy.
   - Security baseline before any PHP implementation:
     canonicalize `SCRIPT_FILENAME`, reject traversal/symlink escapes, never
     serve `.php` source as static fallback, deny dotfiles by default, enforce
     strict CGI param allow-list, scrub inherited environment, enforce request
     body limits, add execution timeouts, and log STDERR safely without leaking
     secrets.
   - `php-fpm` bridge plan:
     use `fastcgi-client 0.11.1` or a reviewed equivalent, map Pingora requests
     to FastCGI params, support Unix sockets first, parse CGI response headers
     strictly, and include integration tests against a rootless php-fpm
     container.
   - `php-turbine` plan:
     first evaluate whether Turbine is available as a Rust library or only as a
     standalone/container runtime. If only standalone, integrate as a managed
     upstream/sidecar instead of embedding it into Fluxheim. If embeddable,
     require a license/security audit and isolate unsafe PHP SAPI/FFI surfaces.
   - `php-phprs` plan:
     keep behind `php-phprs-experimental` docs and CI checks only; do not mark
     production-ready until PHP language/framework compatibility and security
     behavior are proven.
   - PHP runtime changes should be process-upgrade changes, not snapshot-only
     reloads, until each runtime proves safe reload semantics.

12. **Future Perl CGI Support**
   - Architecture and security plan documented in
     [Perl CGI Support](docs/perl-cgi-support.md).
   - Perl CGI must be optional and compile-time gated. Planned features:
     `perl-cgi` for the module, `perl-cgi-cegla` for the `cegla`/Tokio CGI
     implementation, and optional Linux-only sandbox hardening features such as
     `perl-cgi-landlock`.
   - Use current `cegla-cgi 0.2.3` / `tokio-cegla 0.2.3` only after a normal
     license/security review. Both are MIT. `rlimit 0.11.0` is the planned
     Unix resource-limit helper, and `landlock 0.4.4` is the optional Linux
     path sandbox helper.
   - Add typed per-vhost CGI config: enabled flag, script root, allowed
     extensions, interpreter path, index names, request timeout, max body
     override, max stdout/header bytes, uid/gid policy, working directory,
     environment allow-list, and sandbox profile.
   - Security baseline before any CGI implementation:
     canonicalize script paths, reject traversal/symlink escapes, deny dotfiles,
     never execute writable-by-group/world scripts, never serve CGI source as
     static fallback, scrub inherited environment, pass only strict RFC 3875 CGI
     variables, enforce body limits for streaming requests, set execution
     timeouts, cap stdout/stderr, parse CGI headers strictly, and kill process
     groups on timeout or client cancellation.
   - Process isolation plan:
     prefer an external low-privilege `perl` interpreter; use `uid`/`gid` where
     available, `rlimit` for CPU/memory/file/process limits, optional Landlock
     for Linux path restrictions, and rootless container boundaries for
     deployment. Do not rely on chroot unless the process has the privileges and
     operational model to support it safely.
   - CGI runtime changes should be process-upgrade changes until process pool,
     sandbox, and per-vhost policy reload semantics are proven safe.

13. **Future Legacy Static HTTP Support**
   - Architecture and security plan documented in
     [Legacy Static HTTP Support](docs/legacy-static-http.md).
   - Legacy protocol support must be compile-time gated, disabled by default,
     and separate from normal listeners. Planned features:
     `legacy-http-static`, `legacy-http10-static`, and
     `legacy-http09-static`.
   - No legacy feature may be included in the default feature set. Release
     checks should include a guard that fails if any legacy HTTP feature is
     accidentally pulled in by `default`.
   - HTTP/1.0 compatibility is allowed only for static file serving on an
     explicitly configured legacy listener and default legacy vhost. It must
     reject `Transfer-Encoding`, `Upgrade`, ambiguous `Content-Length`, request
     bodies unless explicitly allowed for static-safe methods, and persistent
     connections. It must force `Connection: close`.
   - HTTP/0.9 compatibility is allowed only on a dedicated raw TCP listener,
     separate from Pingora's normal HTTP service. It may only support one-line
     `GET /path` static file reads. No headers, no status-sensitive behavior,
     no TLS, no proxy, no cache, no admin, no PHP, no CGI, and no directory
     listings.
   - Legacy requests must use the existing static resolver's canonical path
     security model and must never fall through to proxy/cache/admin/dynamic
     handlers.
   - Add explicit request-smuggling tests for HTTP/1.0 framing, upgrade
     headers, transfer-encoding misuse, multiple content-length values,
     malformed HTTP/0.9 lines, traversal, and attempts to reach non-static
     routes.

14. **Future HTTP/3 And QUIC**
   - HTTP/3 is the modern protocol direction, not a legacy-compatibility
     feature.
   - Plan as a separate future milestone after MVP hardening: evaluate Pingora
     or ecosystem QUIC support, TLS/ALPN handling, UDP listener ownership,
     rootless Podman networking constraints, certificate reload interaction,
     metrics, and zero-downtime process upgrades.
   - HTTP/3 must preserve the same security posture as HTTP/1.1/HTTP/2:
     strict parsing, no downgrade shortcuts, no legacy protocol fallback on
     modern listeners, and the same vhost/cache/admin isolation rules.

15. **Operational Packaging**
   - Rootless Podman image. Implemented with a pinned Rust 1.95.0 builder and
     non-root runtime user.
   - Rootless Podman smoke script. Implemented for image build, packaged config
     validation, and runtime UID verification.
   - Release/security checklist. Implemented in
     [Release Checklist](docs/release-checklist.md), with a wrapper script for
     local release gates.
   - Hardware-specific local build documentation. Implemented with
     `target-cpu=native` guidance.
   - Example configs for local, reverse-proxy, static-site, and mixed modes.
   - Release/security checklist.
   - Rootless userspace WireGuard evaluation for Sentinel Mesh.
