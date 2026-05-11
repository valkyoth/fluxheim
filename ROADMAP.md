# Fluxheim Roadmap

This roadmap is the working implementation plan. Keep it current as features
move from design to code.

Release sequencing is defined in [Versioning Plan](docs/versioning-plan.md).
That plan treats `0.5.x` as the basic-sites preview and `1.0.0` as the first
gateway-ready release for Fluxheim's representative real multi-site configs.
Larger modules still graduate through later minor releases.

## Current Release Goal

Fluxheim `1.0.0` is the first gateway-ready baseline: static sites, SNI-backed
TLS vhosts, route redirects, location-style proxying, websocket-safe proxy
headers, directory listing, static aliases, cleartext ACME challenge
exceptions, default HTTP service packaging, and native systemd deployment.

The active `1.1.0` focus is TLS policy hardening plus ACME runtime issuance and
renewal for Let's Encrypt and Actalis, so deployments do not depend on manual
certificate copy scripts. The target surface is explicit safe TLS profiles,
minimum protocol version controls, ALPN controls, backend validation, scanner
gates, HTTP-01 issuance, Actalis EAB support, renewal scheduling, safe storage,
and failure behavior that keeps the last valid certificate serving.

Advanced load balancing, admin snapshots, metrics, Sentinel Mesh/WireGuard,
stale-while-revalidate, persistent cache indexing, and advanced certificate
automation remain important, but they should graduate in later minor releases
according to the versioning plan.
In-process Linux seccomp/Landlock sandboxing is also post-`1.0` work: the
stable `1.0` boundary is hardened systemd/container deployment, while
kernel-enforced in-process sandboxing should remain an optional compile-time
module until path and syscall policies are proven across native and container
deployments.

Operational and admin tooling follows once the public TLS and certificate
lifecycle surface is configurable and tested.

Future differentiating features should lean into infrastructure problems that
are hard to solve safely with external glue: cluster-wide state, identity-aware
routing, AI-aware request controls, traffic mirroring, and encrypted
inter-node transport. These are not `1.0` items. Each one needs an explicit
compile-time feature, a documented threat model, redaction/privacy rules, and
failure-mode tests before it can move from research to beta.

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
     Initial safe numeric mapping is implemented through `[server.process]`
     for `daemon`, `error_log`, `pid_file`, `upgrade_sock`, `threads`,
     `listener_tasks_per_fd`, `work_stealing`, `upstream_keepalive_pool_size`,
     `max_retries`, `grace_period_seconds`, and
     `graceful_shutdown_timeout_seconds`.
   - Validate rootless/container-friendly paths and defaults. Implemented for
     PID file, upgrade socket, and optional error log by reusing Fluxheim's
     symlink/traversal runtime-path validation.
   - Extend reload impact classification so process-owned settings require a
     Pingora process upgrade. Implemented for `[server.process]`.

2. **Access And Error Logging**
   - Add typed access-log config with secure defaults. Initial
     `logging.access.enabled` support is implemented.
   - Apply `logging.level` and `logging.format` during startup through
     `env_logger`, while still letting `RUST_LOG` override the configured
     default filter. Runtime log level/format changes require a process
     upgrade.
   - Add typed stream sink selection for OS/container logs. Implemented as
     `logging.target = "stderr" | "stdout"`; changes require a process
     upgrade.
   - Add an optional local file sink with explicit append/truncate behavior,
     safe path validation, no final symlink following on Linux, and
     `privacy-mode` rejection. Implemented as `[logging.file]`.
   - Emit structured request logs from the Pingora `logging` hook with method,
     optional host, vhost, optional query-free path, status, request ID, request body
     bytes seen, response body bytes seen, low-cardinality status class, error flag, and latency. Initial
     stdout/stderr-compatible JSON event emission is implemented through the
     existing `log` stack and is compiled out in `privacy-mode`.
   - Allow operators to suppress raw request hosts and paths while keeping
     access logs enabled. Implemented as `logging.access.include_host` and
     `logging.access.include_path`.
   - Broaden response byte accounting if later response paths bypass Pingora's
     response body filter or static file accounting.
   - Keep log sinks simple at first: stderr/stdout and optional file path.
     Implemented for stderr/stdout plus `[logging.file]`; async/remote sinks
     remain future work.
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
   - Add optional OpenTelemetry tracing as a separate observability module.
     Architecture and security plan documented in
     [OpenTelemetry Tracing](docs/opentelemetry-tracing.md).
   - Tracing must be compile-time gated and disabled by default. Planned
     features:
     - `otel-tracing`: W3C Trace Context propagation, trace-log correlation,
       and internal request spans.
     - `otel-otlp`: optional OTLP exporter to a local collector.
   - Start with propagation-only support: extract valid `traceparent`, generate
     a trace ID when absent, inject context into upstream requests, and include
     trace IDs in structured logs when logging is enabled.
   - Add spans after propagation is stable: vhost routing, request filtering,
     auth request, cache lookup/store, upstream selection/connect/response,
     static file reads, and future body filters.
   - Add sampling before export is marked beta: probabilistic sampling for
     normal traffic, optional all-`5xx` sampling, and latency-aware sampling for
     slow requests.
   - OTLP export must run through bounded background queues, expose exporter
     health, redact attributes, and never block request workers when the
     collector is down.
   - Tracing attributes must be low-cardinality and redacted: use vhost, route,
     status class, cache tier, upstream pool, and policy names; avoid raw
     queries, cookies, authorization values, bodies, and arbitrary path labels.
   - `privacy-mode` should reject tracing/export features unless a future
     strictly propagation-only privacy design is written and tested.

3. **Header Policy**
   - Add configurable upstream forwarding headers:
     `X-Forwarded-For`, `X-Forwarded-Host`, `X-Forwarded-Proto`, and
     standardized `Forwarded`. Implemented globally for proxied requests
     through `[headers.request]`; spoofable inbound client-IP headers are
     stripped by default, Fluxheim replaces `X-Forwarded-For` from the observed
     peer address, and RFC `Forwarded` remains opt-in.
   - Add configurable response hardening headers for static/proxied responses:
     HSTS, CSP, `X-Content-Type-Options`, frame policy, and referrer policy.
     Implemented globally for proxied and static responses through
     `[headers.response]`; HSTS and CSP are opt-in, while `nosniff`, frame
     denial, and `no-referrer` are defaulted.
   - Add generic header mutation blocks for both request and response stages:
     `unset`, `set`, and `append`. Implemented globally under
     `[headers.request]` and `[headers.response]` so operators can hide version
     headers such as `Server`/`X-Powered-By`, add CORS/cache headers, append
     `Vary`/`Set-Cookie`, or set proxy marker headers.
   - Add per-vhost header overlays. Implemented under
     `[vhosts.headers.request]` and `[vhosts.headers.response]`; vhosts inherit
     global headers and can override booleans/modes or add more
     `unset`/`set`/`append` mutations.
   - Make trusted-proxy handling explicit before accepting client IP headers.
     Implemented as `server.trusted_proxies`; append mode preserves inbound
     `X-Forwarded-For` only when the direct peer matches a configured IP/CIDR.
   - Grow trusted-proxy handling into a typed client identity layer after the
     `1.0` route core is stable. Fluxheim should keep separate values for the
     direct socket peer, verified proxy hop, restored client IP, and original
     forwarding chain instead of destructively overwriting one address field.
   - Future real-client identity features should include recursive
     `X-Forwarded-For` traversal with `max_hops`, provider-managed trusted
     range sets, Proxy Protocol v2 support, and optional IP context enrichment
     such as Geo/ASN/threat metadata loaded from local databases. All of this
     must be fail-closed around trust boundaries and incompatible with
     `privacy-mode` unless a non-retaining design is written and tested.

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
     body limits cannot be bypassed. Implemented in Pingora's
     `request_body_filter`; every proxied body chunk is counted against
     `server.limits.max_request_body_bytes` and over-limit streams fail with
     `413`.
   - Add focused tests for chunked uploads, oversized streaming bodies, and
     normal uploads. Initial pure limit-counter tests cover exact-limit,
     over-limit, and saturating counter behavior; end-to-end upload tests
     remain future work.

5a. **Proxy Response Buffering**
   - Add proxy response buffering and backpressure controls for migrations that
     currently rely on gateway buffer knobs for WordPress and app backends.
     The design should expose bounded per-connection response buffer
     count/size equivalents, clear defaults, streaming behavior when disabled,
     and tests proving slow clients cannot exhaust worker memory.

6. **Load-Balancing Policy Options**
   - Keep round-robin as the stable default.
   - Add explicit config for additional Pingora-supported policies where they
     are available and stable, starting with hash-based selection.
   - Keep smart telemetry and WireGuard routing in Sentinel Mesh as a future
     design until the base load-balancer surface is stronger.

7. **Operator Documentation**
   - Add a concise GitHub-facing project goals document.
   - Add one “production checklist” that states what is MVP-ready and what is
     still experimental. Implemented in
     [Production Readiness](docs/production-readiness.md).
   - Keep example configs in sync with every new global section.
   - Improve config diagnostics for real multi-file deployments: `conf.d`
     parse errors should include the source file path, validation errors should
     include vhost and route context where possible, and common TOML table-shape
     mistakes should get actionable hints.
   - Add production container migration docs from the `1.1` gateway cutover:
     direct `podman run --rm` config validation and ACME commands, an
     HTTP-only first-issuance sequence for HTTP-01, explicit notes that
     Fluxheim must serve public port 80 during validation, container secret
     mount examples for EAB files, and safer optional error-page mount paths
     such as `/var/lib/fluxheim/errors` instead of nested paths below a
     read-only image directory.
   - Improve ACME command output for production runs: report per-target
     `skipped`, `renewed`, and `failed` status, include domain/order context
     on issuer failures, and print the HTTP-01 challenge path/URL when an
     authorization fails. Implemented for target statuses, per-target
     success/failure lines, due-only status messaging, and HTTP-01 URL context
     after challenge files are published. Planned: richer issuer
     authorization/order context when the client library exposes it cleanly.
   - Add native systemd deployment support before `1.0.0`: a hardened
     `fluxheim.service`, optional environment file, tmpfiles/sysusers
     guidance, documented install paths, config validation before start, and
     graceful `SIGTERM`/reload behavior for manually compiled binaries.
   - Treat the packaged systemd unit as the stable `1.0` host sandbox:
     non-root runtime user, no ambient capabilities, no-new-privileges, strict
     filesystem protection, private temporary/device namespaces, limited
     address families, namespace restrictions, and a conservative syscall
     filter.

8. **Zero-Retention Privacy Build Profile**
   - Add a compile-time optional privacy profile for static web serving and
     reverse proxying with no application-level request retention. Initial
     `privacy-mode` feature is implemented and covered by the release check
     script.
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
     client-IP forwarding headers to upstreams. Implemented for the proxy
     request header policy: incoming forwarding headers are stripped even if
     config asks to synthesize forwarding headers.
   - Add release checks proving privacy builds do not compile metrics/logging
     exporters and add tests that request handling does not emit or persist
     client-identifying fields. Initial compile/test coverage exists for
     `proxy,web,tls-rustls,privacy-mode`; exporter absence checks remain future
     work once logging exporters exist.

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

[headers.request]
enabled = true
strip_inbound_client_ip_headers = true
x_forwarded_for = "replace"
x_forwarded_host = true
x_forwarded_proto = true
forwarded = false
unset = ["x-powered-by"]

[headers.request.set]
x-proxy-by = "Fluxheim"

[headers.request.append]
via = "fluxheim"

[headers.response]
enabled = true
strict_transport_security = "max-age=31536000; includeSubDomains"
content_security_policy = "default-src 'self'"
x_content_type_options = "nosniff"
x_frame_options = "DENY"
referrer_policy = "no-referrer"
unset = ["server", "x-powered-by"]

[headers.response.set]
cache-control = "public, max-age=60"

[headers.response.append]
vary = ["Accept-Encoding"]

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
   - Static `ETag`, `If-None-Match`, `If-Modified-Since`, and single
     `Range`/`Content-Range` response planning. Implemented.
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
     certificate or a default-vhost static/ACME certificate source.
   - Per-vhost/SNI downstream certificate selection. Implemented for the
     default rustls backend and callback-capable TLS backends.
  - ACME account/order/challenge runtime. Implemented as one-shot and
    background `acme-client` paths for HTTP-01.
  - Background renewal queue service. Implemented for due-only checks on the
    configured renewal interval.
  - Runtime certificate adoption after renewal. Implemented for reloadable
    downstream SNI resolvers/callbacks.
  - Production ACME companion mode. Planned for the operations pack: keep the
    integrated background worker for simple installs, but add a `fluxheim-acme`
    command/binary plus `fluxheim-acme.service` and `fluxheim-acme.timer` for
    production renewals. The companion should run as the Fluxheim runtime user,
    reuse the same ACME engine, share only the ACME storage directory, and let
    the main webserver focus on serving traffic, HTTP-01 challenge files, and
    reloading certificate handles.
   - Atomic certificate install and rollback on invalid renewed certificates.
     Implemented for the managed ACME install helper.
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
   - Full cache-header semantics. Planned as a required cache-pack hardening
     track before cache is called complete:
     - response headers: `Cache-Control`, `Expires`, `ETag`,
       `Last-Modified`, `Vary`, `Age`, and `Accept-Ranges`;
     - request headers: `If-Match`, `If-Unmodified-Since`, `If-None-Match`,
       `If-Modified-Since`, `Cache-Control`, `Pragma`, `Range`, and
       `If-Range`;
     - static responses should honor conditional requests, forced
       revalidation, range validation, explicit no-store/no-cache policy, and
       operator-configured browser/CDN headers. Implemented for static
       `If-Match`, `If-Unmodified-Since`, `If-None-Match`,
       `If-Modified-Since`, request `Cache-Control`, `Pragma`, single
       `Range`, and `If-Range`;
     - proxied cache responses should preserve origin validators and freshness
       metadata, emit correct `Age` behavior on hits, respect request
       revalidation controls, and avoid caching when origin/client directives
       forbid it. Implemented conservatively for request `Cache-Control:
       no-cache`, `Cache-Control: no-store`, `Cache-Control: max-age=0`, and
       `Pragma: no-cache` by bypassing Fluxheim cache admission until full
       proxy revalidation is implemented. Implemented for origin response
       `Cache-Control: no-store`, `private`, `no-cache`, `max-age=0`, and
       `s-maxage=0` by refusing shared image-cache admission until full proxy
       revalidation is implemented. Pingora's cache pipeline already
       injects `Age` for stored-response hits and applies downstream
       conditional/range handling when cache is enabled; Fluxheim tests still
       need an end-to-end cached-hit assertion around those Pingora behaviors;
     - `Vary` must be part of the cache-key strategy before content
       negotiation, compression, image filtering, or media variants are marked
       stable. Implemented for Pingora cache variance: repeated `Vary` headers
       are normalized, request variant headers are hashed into the variance
       key, and `Vary: *`, malformed, oversized, or excessive `Vary` headers
       are rejected from cache admission. Sensitive `Vary` fields such as
       `Cookie`, `Authorization`, and `Proxy-Authorization` are also rejected
       to avoid per-user cache variants;
     - `Set-Cookie` responses must not be stored in the shared image cache.
       Implemented: cache admission rejects responses carrying `Set-Cookie`;
     - proxied image-cache admission should validate the origin response, not
       only the request path. Implemented: shared image-cache admission is
       limited to `200 OK` responses with an `image/*` `Content-Type`, and
       rejects missing/non-image content types, redirects, and errors;
     - CDN-facing headers should be user-configurable through header policy and
       documented examples, not hardcoded globally.
   - Request collapsing. Implemented for memory, disk, and tiered cache
     policies with Pingora `CacheLock`; cache-lock coverage is exposed in
     metrics/admin status so stampede-protection gaps are visible.
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
   - Pingora `Storage` adapter partial streaming admission. Implemented for
     disk-only cache admission with bounded same-root temporary files and an
     atomic final object write. Memory and tiered production adapters still
     keep Pingora partial-write support disabled until their in-progress object
     accounting is proven.
   - Route-scoped reverse-proxy cache policy for production gateway migrations.
     Needed for Forgejo-style static path caching such as
     `/avatars`, `/repo-avatars`, `/assets`, and `/img`, with explicit path
     matchers, operator-controlled cache keys, status-specific TTLs,
     stale-on-error behavior, cache-lock request collapsing, optional
     `X-Cache-Status` style response headers, and carefully gated controls for
     ignoring upstream freshness headers or hiding `Set-Cookie` on cacheable
     static routes. This must remain opt-in per route and must not weaken the
     default refusal to store personalized responses.
   - Full reverse-proxy cache policy parity. Planned:
     - cache-key templates are implemented as constrained `key_parts` using
       safe request fields rather than arbitrary string interpolation;
     - `min_uses` style delayed admission before storing a response.
       Implemented with a bounded short-lived admission counter per cache key;
     - status-specific TTL rules, including `any` fallback TTL. Implemented
       through typed `status_ttls` and `default_status_ttl_secs` policy;
     - explicit request-side bypass rules and response-side no-store rules
       based on bounded header, cookie, and query predicates. Implemented for
       header-presence and exact header-value request bypass, raw
       query-parameter and exact query-value request bypass, cookie-name and
       exact cookie-value request bypass, plus response header-presence and
       exact header-value no-store controls;
     - stale serving controls for origin error and updating are implemented
       through explicit `stale_if_error_secs` and
       `stale_while_revalidate_secs` windows, with `stale_if_error_on` for
       connect, timeout, read, write, connection-closed, HTTP status, protocol,
       TLS, and other upstream error classes, plus
       `stale_if_error_statuses` for selected 5xx origin statuses;
     - optional cache-status response headers for production debugging;
     - route-local controls for ignoring upstream freshness headers and hiding
       `Set-Cookie`, allowed only when the route is explicitly marked static or
       otherwise personalized-content safe;
     - bounded cache-key indexing for memory and disk tiers is implemented as
       the foundation for broader invalidation. Indexed vhost/route scope
       purge, path-prefix purge, tag purge, wildcard path-pattern purge, and
       stale purge are implemented through the admin API. A background stale
       disk purger is implemented through `[cache_purger]`;
     - startup cache-index loading rebuilds the bounded purge index from stored
       v5 disk object metadata. Planned: make this rebuild incremental so very
       large disk caches do not block gateway startup;
     - byte-range/slice caching for large immutable files, with explicit
       warnings that the source object must not change during slice fill.
   - Dedicated cache-server feature track inspired by Varnish/Vinyl-style
     accelerators. Planned:
     - richer cache policy phases for receive, hash, hit, miss, backend
       response, deliver, and synthetic responses without exposing unsafe
       arbitrary code by default;
     - object metadata fields for TTL, grace, keep, hit-for-pass/pass, tags,
       surrogate keys, and variant identities;
     - health-aware stale/grace behavior where stale objects can be served
       differently for healthy versus unhealthy origins;
     - ban/tag invalidation with asynchronous evaluation and bounded memory use;
     - first-class cache observability: per-route hit/miss/pass/bypass/stale
       counters, storage pressure, eviction reasons, origin fetch outcomes,
       and structured cache decision logs;
     - live administration for cache policy reload, purge/ban operations,
       storage inspection, and safe config activation through the existing
       admin/snapshot model;
     - extension points for optional policy modules or WASM filters after the
       stable typed policy language is complete.
   - HTTP cache semantics.
   - Stale-while-revalidate.
   - Purge/admin API. Implemented for protected single-key invalidation through
     `POST /_fluxheim/cache/purge`, same-host bulk invalidation through
     `POST /_fluxheim/cache/purge-bulk`, indexed scope purge, path-prefix
     purge, tag purge, wildcard path-pattern purge, and stale purge. Purge
     removes all stored `Vary` variants for the selected primary cache identity
     in memory and disk tiers. Indexed purge endpoints support vhost and route
     scopes, bounded batch limits, hard purge, and soft purge where applicable.
   - Cache admin status. Implemented through protected
     `GET /_fluxheim/cache/status` with aggregate and per-vhost memory/disk
     counters plus hit, miss, store, refused-store, and purge activity.
   - Cache activity reset. Implemented through protected
     `POST /_fluxheim/cache/activity/reset` without clearing cached objects.

6a. **Future Optional Compression**
   - Architecture and security plan documented in
     [Compression](docs/compression.md).
   - Compression must be optional, compile-time gated, and disabled by default
     until body-filter resource limits and cache-variant behavior are proven.
   - Planned features:
     - `compression`: shared config, negotiation, eligibility checks, and
       response body filter integration.
     - `compression-zstd`: Zstandard response encoding for modern dynamic or
       streaming responses.
     - `compression-brotli`: Brotli response encoding for eligible static web
       assets.
     - `compression-gzip`: gzip compatibility fallback for older clients.
   - Prefer Zstandard and Brotli where clients support them. Gzip should be a
     fallback, not the default preferred encoding.
   - Do not compress already-compressed formats, `no-transform` responses,
     unsafe personalized responses, or range responses until a range-aware
     design exists.
   - Compression variants must integrate with cache keys and
     `Vary: Accept-Encoding`, including policy-version isolation.
   - Expensive compression must use bounded worker pools or blocking-task
     offload so request workers do not stall.
   - Add tests for negotiation, excluded MIME types, cache isolation,
     disconnect cancellation, resource limits, side-channel-sensitive response
     exclusions, and default/privacy builds proving compression is absent.

7. **Future Optional Image Filter**
   - Architecture and security plan documented in
     [Image Filter](docs/image-filter.md).
   - Image filtering must be optional, compile-time gated, and disabled by
     default. Planned features:
     - `image-filter`: shared config, eligibility checks, metadata reporting,
       transform pipeline, and cache-key integration.
     - `image-filter-webp`: WebP output/input support after codec review.
     - `image-filter-avif`: AVIF output/input support as beta after codec
       performance and maintenance review.
   - Initial transformations:
     validate image type, report metadata, resize, crop, rotate by
     `90`/`180`/`270`, strip metadata by default, and set bounded JPEG/WebP
     quality.
   - Supported input formats should start with JPEG, PNG, GIF, and WebP. GIF
     animation handling must be explicit: reject, first frame only, or preserve
     only when the selected codec safely supports animation.
   - The module must enforce hard resource limits before and during decode:
     input bytes, decoded pixels, output bytes, width/height, timeout, and
     per-vhost/global transform concurrency.
   - Transform policies must be explicit per vhost or route. Do not process
     admin, metrics, ACME, PHP, CGI, legacy HTTP, or arbitrary binary
     responses.
   - Transformed variants need cache isolation by vhost, source identity,
     policy version, dimensions, crop/rotate settings, output format, quality,
     and normalized `Accept` bucket.
   - Prefer WebP only when the client advertises support and the vhost policy
     allows it. AVIF remains beta until resource use and codec maintenance are
     proven.
   - Security baseline:
     strip EXIF/GPS/comment metadata by default, reject malformed/oversized
     files safely, do not log image bytes or sensitive source URLs, keep FFI
     codecs behind separate feature flags, and require license/advisory review
     for codec dependencies.
   - Exit criteria before beta:
     unsupported-format tests, decode-bomb tests, output-dimension tests,
     metadata stripping tests, WebP negotiation tests, cache-key isolation
     tests, timeout/concurrency tests, and default/privacy build absence
     checks.

8. **Metrics**
   - Compile-time `metrics` module. Implemented.
   - Typed metrics listener config. Implemented with secure defaults:
     disabled by default, loopback listener, and loopback enforcement before
     remote exposure.
   - Pingora Prometheus HTTP service wiring. Implemented.
   - Proxy request outcome counter. Implemented as
     `fluxheim_proxy_requests_total` labeled by vhost, fixed method bucket,
     outcome class, and fixed status class.
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

9. **Future Optional WAF Support**
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

10. **Future Optional Cloudflare Origin Support**
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

10a. **Future Trusted Client Identity Layer**
   - Generalize provider-specific real-IP restoration into a reusable trust
     layer that can support local load balancers, private platform gateways,
     Cloudflare, and future provider packs without duplicating header parsing.
   - Planned config shape:
     `trusted_client_ip` profiles with explicit `from` CIDRs, selected header
     names, `recursive`, `max_hops`, and optional provider references.
   - Keep identity non-destructive: request context should expose direct peer
     IP, trusted proxy chain, restored client IP, and provider metadata
     separately.
   - Provider-managed ranges may refresh in background with last-known-good
     fallback, bounded file/API sizes, signature/checksum support where
     available, and clear health reporting.
   - Proxy Protocol v2 support should be an explicit listener option because it
     changes connection framing. TLV metadata must be allow-listed and bounded.
   - Optional Geo/ASN/threat enrichment should load local databases at startup
     or snapshot reload, use bounded lookups, and never add raw client IP labels
     to high-cardinality metrics.

11. **Zero-Retention Privacy Mode Compatibility**
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
     `logging-remote`, `logging-spool`, `waf`,
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

12. **Future PHP Runtime Support**
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

13. **Future Perl CGI Support**
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

14. **Future Legacy Static HTTP Support**
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

15. **Future HTTP/3 And QUIC**
   - HTTP/3 is the modern protocol direction, not a legacy-compatibility
     feature.
   - Keep it outside `1.0.0`. HTTP/3 changes Fluxheim's listener model from
     TCP/TLS-only ingress to a dual TCP plus UDP service. It should land first
     as an opt-in `http3` or `http3-experimental` compile feature after the
     gateway core and TLS policy surface are stable.
   - Plan as a separate future milestone after MVP hardening: evaluate whether
     a supported Pingora HTTP/3 server API can be reused before falling back to
     direct ecosystem QUIC integration. The milestone must cover TLS/ALPN
     handling, UDP listener ownership, rootless Podman networking constraints,
     certificate reload interaction, metrics, graceful shutdown, and
     zero-downtime process upgrades.
   - Do not treat `Alt-Svc` as the implementation. Advertising HTTP/3 is easy;
     Fluxheim must only emit `Alt-Svc` from listeners/vhosts where the UDP
     QUIC service is actually configured and healthy, with the advertised port
     matching the deployed UDP mapping.
   - Start with a conservative config surface:
     `enabled`, `listen`, `advertise_alt_svc`, `max_concurrent_streams`,
     `idle_timeout`, and `enable_0rtt = false`. 0-RTT must remain disabled
     until Fluxheim has explicit replay-safe route policy for idempotent
     traffic.
   - First implementation target should be minimal GET/HEAD traffic through the
     existing vhost and route policy model. Full parity needs request body
     streaming, upload limits, static serving, proxying, cache behavior,
     access/error logs, dynamic headers, and certificate selection to behave
     consistently with HTTP/1.1 and HTTP/2.
   - The core engineering risk is not memory pinning or one buffer choice; it
     is correctly integrating QUIC connection state, UDP socket batching,
     connection IDs, anti-amplification limits, congestion behavior, stream
     timeouts, and request/response mapping into Fluxheim's existing policy
     pipeline without creating a second independent server path.
   - Release validation must include HTTP/3 interop and resilience checks:
     client tests with HTTP/3-capable tooling, browser discovery through
     `Alt-Svc`, UDP firewall/container mapping tests, packet loss/reordering
     tests, malformed frame handling, load tests, and request-smuggling-style
     boundary tests for mixed HTTP/1.1, HTTP/2, and HTTP/3 deployments.
   - HTTP/3 must preserve the same security posture as HTTP/1.1/HTTP/2:
     strict parsing, no downgrade shortcuts, no legacy protocol fallback on
     modern listeners, and the same vhost/cache/admin isolation rules.

16. **Future Advanced TLS Privacy And Post-Quantum Work**
   - Track post-quantum hybrid key exchange as a dedicated TLS backend
     milestone, not as a string-only config promise. The first target is
     `X25519MLKEM768` once the default downstream TLS backend can enforce it
     through a stable crypto provider.
   - Evaluate ML-DSA/PQC certificate chain handling as part of certificate
     parsing, storage, scan, and handshake-size testing. Larger certificate
     chains must be tested against initial congestion window behavior and
     mobile networks before being advertised as production-ready.
   - Add Encrypted Client Hello only when the TLS backend, DNS publishing flow,
     key rotation model, and operational docs are all in place. ECH changes
     certificate/SNI visibility and needs explicit failure-mode tests.
   - Track RFC 8879 TLS certificate compression separately from response
     compression. Zstandard certificate compression is interesting for PQC
     chain sizes, but it must be supported by the chosen TLS stack and tested
     with real browsers before release.
   - Do not build OCSP stapling unless a concrete modern deployment need
     appears; ACME automation, short-lived certificates, and browser revocation
     mechanisms are higher-priority.

17. **Future Optional Host Sandbox**
   - Plan as an optional compile-time module after the `1.0` native systemd
     and container deployment boundaries are stable.
   - Planned feature flags:
     - `host-sandbox`: shared config, lifecycle hook, and operator docs.
     - `host-sandbox-seccomp`: Linux syscall filtering after initialization.
     - `host-sandbox-landlock`: Linux filesystem path restrictions after
       config, certificates, listeners, state, cache, and log paths are opened
       or validated.
   - Scope:
     bind listeners, load config/certificates, prepare runtime directories,
     then install irreversible restrictions that deny process creation,
     executable loading, and access to paths outside the configured roots.
   - Do not compile this into default builds until it is proven across native
     systemd, rootless Podman, and normal static/proxy workloads. Operators
     with unusual logging, certificate reload, cache, or content paths must
     have explicit allow-list config.
   - WASM is a separate future plugin sandbox. Do not require Fluxheim itself
     to run inside Wasmtime; use systemd/container policy for `1.0` and
     optional seccomp/Landlock for later host hardening.
   - Exit criteria before beta:
     tests for denied `execve`/process creation, denied unapproved path access,
     normal static/proxy traffic after sandbox installation, reload behavior,
     report-only diagnostics, and release checks proving sandbox code is absent
     from default and privacy builds.

17. **Future Cluster-Native State**
   - Plan as an optional compile-time module after the load-balancer,
     metrics, admin, and security profiles are stable.
   - Goal: let multiple Fluxheim nodes coordinate selected security and routing
     state without requiring an external database for the first useful cases.
   - Planned features:
     - `cluster-state`: shared config, node identity, peer discovery, local
       persistence, admin/metrics visibility, and compatibility checks.
     - `cluster-gossip`: lightweight eventually consistent distribution for
       blocklists, allowlists, health summaries, and coarse counters.
     - `cluster-consensus`: stronger Raft-style coordination for state that
       must not diverge, such as global rate-limit leases or active leader
       ownership.
   - Start with safe eventually consistent data: blocklists, drain state,
     backend health hints, and low-risk counters. Do not start with billing,
     authentication decisions, or hard quotas that require exact consistency.
   - Global rate limiting should be designed as a separate capability on top of
     cluster state. It needs explicit consistency semantics:
     `local_only`, `eventual`, or `strict`.
   - Security baseline:
     every node must have a stable identity, authenticated peer transport,
     replay protection, bounded message sizes, version negotiation, and
     fail-closed behavior for strict policies.
   - Privacy baseline:
     replicated state must never contain raw paths, queries, authorization
     headers, cookies, user agents, or client IPs unless an operator explicitly
     enables a non-privacy profile and the field is documented.
   - Exit criteria before beta:
     split-brain tests, clock-skew tests, peer restart tests, message fuzzing,
     downgrade/version mismatch tests, and release checks proving cluster code
     is absent from default and privacy builds.

18. **Future External Authorization And Identity-Aware Routing**
   - Architecture and security plan for external authorization requests is
     documented in [External Authorization Request](docs/auth-request.md).
   - Architecture and security plan for signed URL grants is documented in
     [Secure Links](docs/secure-links.md).
   - Plan as optional `auth-request` and `identity` module families after
     stable admin, logging redaction, TLS, and header policy are mature.
   - Goal: let Fluxheim ask a trusted authorization service for an access
     decision, and later verify user or service identity at the edge and route
     or annotate requests based on explicit policy rather than blindly trusting
     inbound headers.
   - Planned features:
     - `auth-request`: per-vhost/per-route external authorization probe before
       static serving or proxying.
     - `auth-zone`: global deny-by-default authorization coverage with
       explicit route/path exclusions, so protected deployments do not depend
       on every route remembering to opt in.
     - `auth-hook-uds` and `auth-hook-grpc`: low-latency persistent
       authorization hooks over Unix domain sockets or gRPC for deployments
       that do not want per-request HTTP overhead.
     - `identity-oidc`: OIDC discovery, JWKS fetch/cache, JWT verification,
       issuer/audience validation, and key rotation.
     - `identity-oauth2`: OAuth2 token introspection for providers that require
       online validation.
     - `identity-policy`: per-vhost route decisions based on verified claims,
       groups, roles, tenant IDs, or subscription tier.
     - `secure-links`: signed URL grants for static, proxy, download, and media
       routes, using modern HMAC or Ed25519 verification instead of weak
       digest-only schemes.
     - `secure-links-replay`: optional token replay/usage accounting when an
       explicit state backend is available.
   - Authorization decision contract:
     `2xx` from the auth service allows the original request, `401` and `403`
     deny with controlled response handling, and every other status is an auth
     service error.
   - External auth must be fail-closed by default. `fail_open` should require
     explicit per-vhost config and emit a security event.
   - Auth probes should be header-only by default. Body forwarding requires
     explicit opt-in, small body caps, content-type allow-lists, redaction, and
     independent timeout budgets.
   - Headers copied to the auth service, copied from the auth service to the
     upstream, or copied to the client must be allow-listed. Fluxheim must strip
     spoofable identity and forwarding headers before making decisions.
   - Optional auth-decision caching must be isolated by vhost, route, method,
     identity/session fingerprint, and policy version. Positive and negative
     TTLs must be separate and bounded.
   - Header injection must be deny-by-default and namespaced. Fluxheim should
     strip inbound identity headers before adding verified replacement headers.
   - Local JWT verification should be preferred when possible. External
     authorization is for session/policy decisions that cannot be verified
     locally or need live revocation.
   - Secure links should validate signed claims such as expiry, path, method,
     audience, entitlement tier, and optional token ID before cache lookup,
     static serving, proxying, or media transformation.
   - Identity state should be stored in the request context after verification
     so later phases can map verified claims to upstream headers, route
     decisions, logs, and metrics without reparsing tokens.
   - Denial handling should support browser and API clients separately:
     configured login redirects with a safe return destination for browser
     requests, and JSON `401`/`403` responses for AJAX/API clients when
     configured.
   - Security baseline:
     auth backend TLS verification by default, optional mTLS, strict auth
     backend response-size limits, loop prevention, strict
     issuer/audience/expiry checks, algorithm allow-lists, bounded token sizes,
     JWKS cache pinning rules, stale-key behavior, clock-skew limits, no raw
     token logging, and explicit failure modes.
   - Routing examples:
     route verified admin users to an admin upstream pool, route paid tiers to
     stronger backend pools, or deny requests before proxying when claims do
     not match per-vhost policy.
   - Exit criteria before beta:
     auth allow/deny/error tests, timeout tests, response-size tests,
     challenge-header allow-list tests, JWT confusion tests,
     expired/revoked token tests, key rotation tests, spoofed identity-header
     tests, signed-link expiry/path/method/audience tests, token redaction
     tests, recursive-auth rejection, and privacy-mode incompatibility guards.

19. **Future Declarative Redirect And Rewrite Engine**
   - Goal: provide a safe match-action pipeline for redirects and internal
     request rewrites without procedural phase ordering.
   - Global HTTPS redirect is part of the stable core. The future engine should
     expand this into per-vhost and per-route policies.
   - Planned matcher model:
     named matchers for host, path, method, header, query, source network,
     protocol, and verified identity claims when identity modules are enabled.
   - Planned actions:
     external redirect, internal path rewrite, query merge/strip, route stop,
     route continue, and controlled synthetic responses.
   - Safety baseline:
     redirect destinations must be parsed and validated, host-derived redirects
     must reject unsafe Host headers, rewrite targets must stay origin-form
     unless explicitly configured as redirects, and internal rewrite cycles
     must be rejected during config validation.
   - Performance baseline:
     compile path matchers into tries where practical, compile multiple regex
     rules into grouped matchers, bound pattern count and pattern size, and
     reject catastrophic or unsupported patterns at config load.
   - WASM integration:
     complex rewrite decisions may later call a sandboxed WASM policy hook, but
     only after the WASM host has fuel, wall-time, memory, host-call, and
     failure-mode limits.

20. **Future AI Gateway**
   - Plan as an optional compile-time module family after metrics, WAF, cache,
     and identity foundations exist.
   - Goal: make Fluxheim understand AI API traffic enough to control cost,
     protect backends, and safely reuse responses where operators opt in.
   - Planned features:
     - `ai-gateway`: shared request classification, provider/upstream config,
       model routing, and safety hooks.
     - `ai-rate-limit`: token-aware rate limits such as tokens per minute,
       output-token budget, and per-tenant quotas.
     - `ai-semantic-cache`: opt-in semantic cache for deterministic or
       cache-approved prompts using vector similarity with strict privacy
       boundaries.
     - `ai-prompt-guard`: prompt-injection and data-exfiltration scoring,
       preferably integrated with the future WAF decision model.
   - Start realistic:
     implement provider-agnostic request size limits, model allow-lists, API
     key redaction, per-vhost model routing, and token accounting for responses
     where providers return usage metadata. Token estimation is useful as a
     fallback but must be labeled approximate.
   - Semantic caching is high risk and must be opt-in per vhost and per route.
     It must never cache prompts or responses containing secrets, personal
     data, authorization material, cookies, file uploads, tool outputs, or
     tenant-private context unless an operator provides an explicit safe policy.
   - Security baseline:
     redact prompts by default in logs, cap body sizes before inspection,
     isolate cache entries by vhost/tenant/model/policy version, and expose
     clear cache-hit explanations for audit without storing sensitive payloads
     in normal logs.
   - Exit criteria before beta:
     token-budget tests, provider metadata parsing tests, redaction tests,
     semantic-cache isolation tests, jailbreak/prompt-guard dry-run tests, and
     default/privacy build absence checks.

21. **Future Traffic Mirroring**
   - Plan as an optional compile-time `traffic-mirror` module after reverse
     proxy, load balancing, metrics, privacy profiles, and request body
     streaming limits are stable.
   - Goal: safely shadow a bounded portion of production traffic to a test or
     analysis upstream while the live client receives only the primary
     response.
   - Planned features:
     - per-vhost and per-route mirror rules;
     - percentage, header, identity-claim, and method based sampling;
     - request body size caps and body redaction/transformation policies;
     - mirror timeout budgets that cannot affect the primary request;
     - mirror result metrics without storing sensitive request data.
   - Never mirror by default. The operator must explicitly opt in and choose
     what fields may be copied. Unsafe methods such as `POST`, `PUT`, `PATCH`,
     and `DELETE` require a stronger explicit config than idempotent requests.
   - Security baseline:
     strip credentials by default, remove cookies unless allow-listed, cap body
     copies, block mirrored admin paths, and forbid mirroring in
     `privacy-mode`.
   - Exit criteria before beta:
     primary-response isolation tests, cancellation tests, timeout tests,
     redaction tests, sampling distribution tests, and proof that mirror
     failures never change the client response.

22. **Future Sentinel Mesh Graduation**
   - Keep the current Sentinel Mesh design as a research track until the
     load-balancer, TLS reload, admin, metrics, and cluster-state foundations
     are mature.
   - Goal: encrypted node-to-node and edge-to-backend transport with smart
     routing based on verified telemetry.
   - Planned features:
     - `sentinel-mesh`: high-level mesh config, node identity, route policy,
       admin/metrics visibility, and health state.
     - `sentinel-wireguard-userspace`: optional userspace WireGuard transport
       evaluation for rootless deployments.
     - `sentinel-telemetry`: signed backend load/health reports over the
       encrypted channel.
   - The first implementation should not try to be a full service mesh. Start
     with gateway-to-backend tunnels and smart load balancing for small
     clusters.
   - Security baseline:
     authenticated peers, key rotation, replay protection, route allow-lists,
     no plaintext fallback unless explicitly configured, and clear behavior
     when tunnel health diverges from backend HTTP health.
   - Exit criteria before beta:
     tunnel restart tests, wrong-peer tests, stale telemetry tests, failover
     tests, rootless Podman smoke coverage, and default/privacy build absence
     checks.

23. **Future Programmable Media Edge**
   - Architecture and security plan documented in
     [Programmable Media Edge](docs/programmable-media-edge.md).
   - Video-aware delivery must be optional, compile-time gated, and disabled by
     default. Planned features:
     - `media-edge`: shared media config, policy model, parser limits, route
       integration, and metrics hooks.
     - `media-hls`: HLS manifest parser/rewrite support.
     - `media-dash`: DASH manifest parser/rewrite support after XML parser
       review.
     - `media-ssai`: dynamic manifest stitching with a trusted decision
       service.
     - `media-watermark`: forensic watermarking research track.
     - `media-transmux`: edge transmuxing/packaging research track.
   - Start with manifest intelligence, not video decoding:
     parse HLS/DASH manifests, validate segment URLs, rewrite safe segment
     routes, enforce manifest limits, and expose media metrics.
   - Add segment-aware cache/routing only after cache indexing and range
     behavior are strong enough. Cache keys must isolate vhost, asset ID,
     representation, byte range, sequence, encryption key ID, tenant/entitlement
     policy, and media policy version.
   - Dynamic stitching should operate at manifest level first. Any ad or
     personalization decision service needs strict timeouts, fail behavior,
     redaction, and no raw user-profile logging.
   - WASM media policy plugins are future-only and require a sandbox with CPU,
     memory, wall-time, outbound-network, and host-call limits.
   - Forensic watermarking should begin with safer manifest or timed-metadata
     markers. Segment-level or bitstream-level watermarking requires reviewed
     TS/fMP4 parsers, codec/container compatibility tests, fuzzing, and a
     legal/privacy policy for user-identifying marks.
   - Edge transmuxing is research. The first scope should be container
     packaging/remuxing only, not arbitrary video transcoding, GPU scheduling,
     or frame processing.
   - Security baseline:
     reject oversized/recursive/escaping manifests, never cache media keys or
     authorization tokens, never mix personalized segments across users or
     tenants, redact personalized URLs, keep DRM license flows out of scope
     until separately modeled, and forbid media-edge in `privacy-mode` by
     default.
   - Exit criteria before beta:
     manifest parser tests, manifest fuzzing, segment URL normalization tests,
     media cache-key isolation tests, ad-stitch timeout/fallback tests,
     redaction tests, metrics cardinality tests, and default/privacy build
     absence checks.

24. **Future WASM Extensibility**
   - Architecture and security plan documented in
     [WASM Extensibility](docs/wasm-extensibility.md).
   - WASM support must be optional, compile-time gated, and disabled by
     default. Planned features:
     - `wasm`: shared runtime config, plugin loading, limits, host-call policy,
       and lifecycle integration.
     - `wasm-proxy-abi`: proxy-oriented ABI compatibility path.
     - `wasm-wasi`: explicit WASI capability support for narrowly scoped
       policy plugins.
   - Current crate candidates checked on 2026-05-05:
     `wasmtime 44.0.1`, `wasmtime-wasi 44.0.1`, and `proxy-wasm 0.2.4`.
   - Start with request/response header hooks and access-control decisions.
     Do not expose body mutation, filesystem, outbound network, process
     spawning, cache internals, or admin APIs in the first stage.
   - Use a reviewed proxy-oriented ABI where practical, but expose only the
     subset Fluxheim can implement safely. Unsupported host calls must fail
     deterministically.
   - Every plugin needs strict resource limits:
     module size, compiled artifact size, linear memory, fuel/instruction
     budget, wall-time, log bytes, header mutations, synthetic response size,
     and per-vhost concurrency.
   - WASI capabilities must be disabled by default. Filesystem, network,
     clocks, randomness, environment variables, and process state require
     explicit grants and should remain unavailable for normal header/access
     plugins.
   - Security baseline:
     reject symlinked plugin files/parents, hash loaded modules, version the
     host ABI, redact secrets from host calls, prevent plugins from directly
     controlling cache keys/routing/TLS verification, isolate traps/timeouts,
     and reject WASM in `privacy-mode` by default.
   - Exit criteria before beta:
     ABI compatibility tests, header mutation tests, deny/synthetic response
     tests, unsupported host-call tests, fuel/timeout/trap tests, capability
     denial tests, redaction tests, plugin path hardening tests, and
     default/privacy build absence checks.

24. **Operational Packaging**
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
