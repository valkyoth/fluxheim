# Versioning Plan

Fluxheim should use SemVer, but with a conservative interpretation: a feature is
not considered stable just because it compiles. A feature becomes stable only
after it has docs, config validation, tests, release checks, and a clear
security boundary.

The main lesson from the roadmap is to avoid shipping one giant 1.0. The
`0.5.x` line is the basic-sites preview: static HTML, vhosts, static TLS,
containers, and simple whole-vhost proxying. Version `1.0.0` should be the
first stable gateway release that can migrate Fluxheim's own representative
multi-site configs without losing core behavior. Larger modules then graduate
in later minor releases.

## Versioning Rules

- `0.x`: incubator releases. Config shape and behavior may still change.
- `1.0.x`: stable core bugfixes only.
- `1.x.0`: add stable, production-supported modules without breaking existing
  1.x configs.
- `2.0.0`: allowed only for breaking config/API behavior or major threat-model
  changes that cannot be feature-gated safely.

Security fixes should be backported to the latest stable minor when practical.

Every public release must pass the matching release security and stability gate
in `docs/release-checklist.md`. Preview releases may document known gaps, but
must still pass dependency, license, static/proxy smoke, and container checks
for the behavior they claim. Stable `1.0.x` runs the full gate against route
routing, static hosting, reverse proxying, TLS, cache policy, headers, and
container delivery; later minors must add the same dependency, fuzzing, DAST,
load, TLS, and malicious-input coverage for every newly stable module.

## Stability Levels

Every module should carry one of these labels in docs and examples:

- `stable`: supported for production use.
- `beta`: usable by operators who can tolerate config/behavior changes.
- `experimental`: compile-time opt-in only, not production-supported.
- `research`: architecture documented, not implemented or not recommended for
  real deployments.

Default builds should include only stable modules.

## Release Ladder

### 0.1 - Repository And Safety Baseline

Goal: make the project buildable and auditable.

Scope:

- Rust toolchain pin.
- EUPL-1.2 license.
- `deny.toml`.
- `cargo fmt`, `cargo clippy`, `cargo test`, `cargo deny`, and `cargo audit`
  release gates.
- Basic config parsing.
- GitHub-ready README, security policy, and examples.

Exit criteria:

- `scripts/release_checks.sh` passes.
- License/advisory policy is documented.
- Rootless Podman build path is documented, even if not final.

### 0.2 - Static Web Beta

Goal: serve small static websites safely.

Scope:

- Static file serving.
- Canonical path resolution.
- Index files.
- Dotfile denial.
- Content type detection.
- Basic vhost routing.
- Config directory loading.

Exit criteria:

- Traversal tests pass.
- Static-only reduced build compiles.
- Example static site config validates.

### 0.3 - Reverse Proxy Beta

Goal: proxy one upstream per vhost safely.

Scope:

- Pingora reverse proxy.
- Plain HTTP and TLS-to-upstream support.
- Host/vhost routing.
- Request size limits.
- Basic upstream header policy.
- Static certificate TLS for downstream listeners.

Exit criteria:

- Proxy-only reduced build compiles.
- Upstream TLS and plain upstream tests pass.
- Request-body limit tests cover `Content-Length` and streaming bodies.

### 0.4 - Operational Beta

Goal: make local/rootless operation repeatable.

Scope:

- Rootless Podman image.
- Hardware-specific local build docs.
- Example configs for static, proxy, and mixed use.
- Process setting validation.
- Basic structured error output.

Exit criteria:

- Podman smoke passes.
- Release checklist is complete.
- Config validation errors are clear enough for GitHub users.

### 0.5 - Basic Sites Preview

Goal: publish a truthful preview release for simple real websites.

Scope:

- Basic vhost routing by Host header.
- Static HTML/CSS/JS/image/font serving from one safe web root per vhost.
- Static TLS certificates with rustls as the default backend.
- Global cleartext-to-HTTPS redirect.
- Simple whole-vhost reverse proxying to one upstream.
- Header policy, request limits, static cache headers, ETag/conditional
  request handling, and byte ranges.
- Rootless Podman/container examples and shutdown behavior.
- GitHub CI, dependency/license checks, CodeQL, release notes, and docs.

Known gaps:

- Multiple downstream certificates selected by SNI.
- Path/location routing.
- Per-route redirects, proxy/static actions, body limits, and timeouts.
- Websocket-specific upgrade handling.
- Custom upstream error pages.
- Static aliases and directory listing.
- Dynamic DNS re-resolution and upstream failure policy.

Exit criteria:

- `scripts/stable_release_gate.sh check` or an equivalent documented preview
  gate passes.
- `scripts/smoke_1_0_core.sh` passes for the basic static/proxy/TLS behavior
  it currently covers.
- Release notes clearly say this is not the `1.0.0` gateway release.
- The version is tagged as `v0.5.0`.

### 1.0 - Gateway Core

Goal: a stable Fluxheim release that can migrate the representative real
multi-site gateway configs without requiring another front server.

The target configs include:

- apex plus `www` redirect hosts;
- cleartext ACME challenge exception paths plus HTTPS redirect for everything
  else;
- multiple TLS certificates on the same listener;
- whole-host proxy apps;
- `/chat/` websocket-capable proxy routes with prefix stripping;
- per-host and per-route body-size limits;
- per-route upstream connect/read/send timeouts;
- custom `502` fallback pages;
- static alias-style repository paths, index files, and directory listing.

Stable scope:

- Static web hosting.
- Reverse proxy.
- Cache module compiled in by default, with runtime cache disabled unless the
  operator configures a storage tier.
- Vhost routing.
- Caddy-inspired TOML config and `conf.d` loading.
- Static/bought certificate support.
- Rustls as the default TLS backend.
- Default downstream certificate support in the default rustls build.
- SNI certificate selection for multiple configured downstream certificates in
  the default rustls build and callback-capable TLS backends.
- Optional OpenSSL and s2n TLS builds when they pass the release matrix.
- Optional BoringSSL TLS builds on builders with `libclang` available for
  bindgen.
- TLS listener cipher/protocol policy follows the selected Pingora TLS backend
  defaults in `1.0`; user-configurable TLS policy is not stable until a later
  release.
- Secure header policy.
- Optional global cleartext-to-HTTPS redirect.
- Declarative route layer with exact, prefix, and fallback matching.
- Route actions for proxy, static serving, and redirects.
- Safe route URL rewriting, including prefix stripping for proxy backends.
- Per-route request body limits.
- Per-route upstream connect/read/send timeout policy.
- Websocket-safe upgrade proxying with tests.
- Custom upstream error pages with internal-only static serving.
- Static aliases and directory listing with traversal, symlink, dotfile, and
  generated-output tests.
- Request header/body limits.
- Container DNS names that work reliably for Podman deployments, with either
  safe startup resolution or documented/implemented re-resolution behavior.
- Rootless Podman runtime.
- Native systemd deployment support for manually compiled binaries:
  `fluxheim.service`, optional environment file, tmpfiles/sysusers guidance,
  config validation before start, hardened service defaults, and documented
  graceful stop/reload behavior. The packaged unit is the stable `1.0` host
  sandbox: non-root runtime user, no ambient capabilities, no-new-privileges,
  strict filesystem protection, limited address families, namespace
  restrictions, and a conservative syscall filter.
- Explicit trusted proxy CIDR handling for forwarded client-IP headers. The
  richer trusted-client identity layer remains a later milestone.
- Release/security checks.

Not in 1.0 stable scope:

- Load balancing.
- ACME runtime issuance.
- Admin snapshots/rollback.
- Prometheus metrics.
- Advanced logging pipelines.
- Full rewrite scripting or WASM extension hooks.
- WAF.
- Cloudflare automation.
- PHP/CGI.
- Legacy HTTP.
- Sentinel Mesh/WireGuard.
- In-process seccomp or Landlock sandboxing.

Exit criteria:

- Default 1.0 binary contains only stable core modules.
- `--no-default-features --features web` works.
- `--no-default-features --features proxy` works.
- Static+proxy+TLS mixed config has integration coverage through the stable
  gateway smoke suite.
- A fixture set equivalent to the six representative gateway configs validates
  and passes local smoke tests.
- SNI selector tests prove each configured host maps to the intended
  certificate, and the stable gateway smoke suite verifies rustls SNI by
  checking the certificate served for a vhost-specific TLS handshake.
- Route tests prove ACME challenge exceptions, `www` redirects, `/chat/`
  prefix stripping, websocket upgrade proxying, error-page fallback, and static
  alias/directory-listing behavior.
- No known `cargo audit` advisory without documented exception.
- `cargo deny check` passes.
- The 1.0 security and stability launch gate in `docs/release-checklist.md`
  has been run and recorded. This includes dependency checks, CodeQL/CI,
  malformed request framing tests, header scrubbing checks, local load testing,
  TLS scanning, and a deployment-side DAST pass.
- Fuzz targets exist or have been run for Fluxheim-owned parser and policy
  logic that can affect request routing, filesystem access, redirects, cache
  keys, or cache-header decisions.

### 1.1 - TLS Policy And Certificate Operations

Goal: expose explicit TLS policy without making insecure combinations easy, and
make normal ACME certificate issuance and renewal practical for production
deployments without external copy scripts.

Stable scope:

- Named TLS policy profiles such as `modern` and `compat`, with `modern` as the
  TLS 1.3-only profile and `intermediate` as the default compatibility profile.
- Minimum protocol version config, bounded to safe values.
- ALPN policy for HTTP/1.1 and future HTTP/2/HTTP/3 work.
- Downstream curve preferences and cipher-suite allow-lists for rustls,
  OpenSSL, and BoringSSL where the selected backend exposes enforceable
  listener controls.
- Structured HSTS response policy.
- Per-backend validation that rejects cipher or protocol settings unsupported
  by the selected TLS backend.
- ACME runtime issuance for Let's Encrypt, Actalis, and Google Trust Services.
- HTTP-01 and rustls TLS-ALPN-01 challenge handling for configured vhosts.
- External Account Binding support for Actalis and Google Trust Services.
- Safe ACME storage under a configured state directory, with private-key and
  certificate permission validation.
- Renewal queue with a user-chosen renew-before window.
- Renewal failures must not drop active traffic or remove the last valid
  certificate.
- Own/bought static certificates remain fully supported.

Beta scope:

- Separate upstream TLS policy if upstream transport needs different
  compatibility than public downstream listeners.
- Zero-downtime dynamic certificate reload for reloadable downstream SNI
  resolvers/callbacks.
- Post-quantum hybrid groups, Encrypted Client Hello, TLS certificate
  compression, and HTTP/3/QUIC remain later milestones until the selected TLS
  and QUIC backends expose stable server APIs and release-grade interop tests.

Exit criteria:

- Config validation rejects weak protocol versions and empty/unknown cipher
  lists.
- `testssl.sh` scans are recorded for every stable TLS backend in the release
  matrix.
- TLS policy changes are classified correctly as reload-safe or requiring a
  process restart.
- ACME issuance and renewal tests cover issuer selection, EAB secret loading,
  challenge routing, systemd/container secret-file deployment, storage
  permissions, failed renewal, and keeping the previous valid certificate.
- Release notes clearly state whether certificate reload is automatic,
  restart-based, or deploy-hook based in `1.1.0`.

### 1.2 - Operations And Cache Completion Pack

Goal: add safe operational visibility, controlled reload tooling, and finish
the production cache platform already started during the 1.2 gateway migration
work.

Stable scope:

- Access/error logging with redaction.
- Private admin API on loopback by default.
- Config snapshots.
- Dry-run reload validation.
- Rollback.
- Basic self-healing rollback.
- Better config diagnostics for production operators: include source file paths
  for `conf.d` parse errors, vhost/route context for validation errors where
  available, and actionable hints for common table-shape mistakes. Static web
  root validation now reports whether the failing path belongs to global web
  config, a vhost, a route, or a proxy error-page web block.
- Production container migration docs and helpers:
  - document the first-issuance sequence for HTTP-01, including the requirement
    that Fluxheim is the process serving public port 80 before ACME validation;
  - provide direct `podman run --rm` validation and ACME examples for operators
    whose compose provider handles one-shot commands poorly;
  - avoid example mounts that require creating nested mountpoints inside
    read-only image paths, and prefer stable paths such as
    `/var/lib/fluxheim/errors` for optional mounted error pages;
  - document container secret mounts for EAB files without relabel suffixes
    when the host tree is already labeled for container access.
- Prometheus metrics baseline on loopback by default.
- Strict host-routing mode for hardened deployments: missing or invalid host
  identity returns `400`, unknown hosts return `421`, default-vhost fallback
  remains available for compatibility, and rejections are visible through
  low-cardinality metrics plus security logs.
- Built-in admin authentication brute-force throttling with bounded per-source
  and global failure windows, progressive lockouts, and metrics/security-log
  events for failed or throttled control-plane access.
- Authenticated admin health checks by default. Unauthenticated health is an
  explicit loopback-only compatibility mode, and health probes can use an empty
  `204` response to reduce control-plane fingerprinting.
- Remote admin transport must fail closed: non-loopback admin listeners require
  an explicit `trusted_tls_terminator` declaration until Fluxheim has
  first-class admin TLS/mTLS support.
- Observability changes should be designed as paired surfaces where practical:
  Prometheus metrics for aggregate dashboards and OpenTelemetry
  traces/attributes/events for request-path diagnosis. Cache observability in
  particular should expose the same low-cardinality vhost, route, tier, status,
  and reason concepts across admin JSON, Prometheus, and OpenTelemetry.
- Proxy response buffering and streaming/backpressure controls for production
  gateway migrations, including configurable response buffer count/size
  equivalents, bounded memory budgets per connection, safe streaming behavior
  when buffering is disabled, and tests proving slow clients cannot exhaust
  worker memory. Initial 1.2 work exposes downstream write timeout and minimum
  send-rate controls for proxied responses; full configurable response-buffer
  count/size remains a follow-up if Pingora exposes a stable hook for it.
- Route-scoped cache policies for selective production caches, such as
  repository avatar/assets paths, where only one proxy route should use a cache
  tier while the rest of the vhost remains uncached.
- Cache completion work promoted into 1.2:
  - `1.2` is the stable cache-completion release. The main cache safety and
    operations concerns are now in the current development line: the documented
    proxied `304 Not Modified` metadata merge edge, very large disk-cache
    loader/purger pacing and visibility, cache-debug/release-gate coverage,
    and production validation for stampede protection. Remaining work before
    tagging `1.2` should be release-candidate validation and narrow polish, not
    new cache architecture. Larger cache architecture extensions are split into
    focused `1.2.x` releases below so each follow-up has one clear job;
  - disk-only cache admission now streams body chunks into a bounded temp file
    under the cache root before atomically committing the final object, so the
    disk tier no longer buffers the full response body in memory during
    admission. Startup also cleans stale Fluxheim-owned temp files after a
    conservative age threshold while preserving fresh active-writer temps.
    Reader-visible partial writes are not a 1.2 stable blocker and should move
    through a later focused cache follow-up if production testing proves it
    necessary;
  - broader persistent cache index coverage for older disk object formats and
    future metadata migrations; new v5 disk objects rebuild purge metadata
    across process restarts with combined-key, primary-key, user-tag,
    cache-tag, and path-index metadata. Startup now merges the disk index
    checkpoint with a full deterministic shard scan so files outside a stale or
    truncated checkpoint cannot become eviction orphans, removes corrupt or
    unindexable `.fhc` objects, and enforces the disk-size budget before
    serving traffic. Disk index checkpoint writes now merge existing root
    entries so separate vhost and route cache policies sharing a disk root
    cannot erase each other's restart purge metadata state, and regression
    coverage asserts insert bursts are checkpointed by the debounced background
    writer instead of synchronously per object. The memory and disk fast purge
    indexes no longer use an unrelated FIFO cap; memory eviction notifications
    remove evicted objects from the fast index, and purges still scan live
    object metadata as the source of truth;
  - background or broader incremental disk purge/cleanup for very large purge
    scopes; indexed purge endpoints now accept bounded `batches` so operators
    can advance large scope, prefix, and wildcard purges without removing
    request limits, and `purge-stale` now provides bounded operator-triggered
    cleanup for expired indexed entries with dry-run mode and conservative
    batching for production safety checks. `[cache_purger]` now adds an
    opt-in process-wide background stale disk cleanup loop that uses the same
    indexed primitive per vhost and route cache. Truncated non-dry-run
    stale purges rotate scanned fresh entries to the back of the purge index,
    so batched stale cleanup can advance through fresh front pages and reach
    expired entries later in the same vhost or route bucket. Prometheus
    counters report background purger outcomes and scanned/stale/purged entry
    counts, and duration histograms report bounded per-tick cleanup time, so
    operators can see when cleanup is truncated, slow, or falling behind;
  - cache warmer/preload command or admin workflow for release deploys;
    `fluxheim cache-warm` now warms explicit paths through a running local HTTP
    listener so vhost, route, cache-key, and admission policy stay identical to
    production traffic;
  - richer cache-tag policy controls on top of the initial exact-match
    `Surrogate-Key` / `Cache-Tag` / `X-Cache-Tags` indexed purge support;
    cache policies can now configure or disable trusted tag headers with
    `tag_headers`;
  - soft purge, where indexed scope, prefix, tag, and wildcard purge can mark
    objects stale and keep bodies available for revalidation instead of removing
    them immediately;
  - broader hit-for-pass/pass-cache policy coverage; `pass_uncacheable_after`
    now provides opt-in bounded pass decisions for repeated uncacheable cache
    keys;
  - broader cache-header regressions beyond the current proxy cache HIT `Age`,
    conditional `304`/`200` validator match and mismatch behavior from `ETag`
    and `Last-Modified`, byte-range `206`, ETag/date `If-Range` match/mismatch
    behavior, HEAD probes that do not poison cached GET bodies,
    validator-based upstream revalidation from origin `304`, stale-object
    refresh from origin `200`,
    stale-while-revalidate serving during a background refresh,
    stale-if-error serving after an upstream connection failure, cache-lock
    request collapsing for concurrent misses, `Vary` variant isolation, disk
    HIT after restart, client refresh revalidation for `Cache-Control:
    no-cache`, `Cache-Control: max-age=0`, and `Pragma: no-cache`, and the
    bounded `Cache-Control: no-store` request-bypass reason in release smoke;
  - full validator-based upstream revalidation edge-case coverage for proxied
    cache responses, including explicit behavior when origins change `Vary`,
    `ETag`, `Last-Modified`, or freshness headers during revalidation. 1.2 now
    preserves changed `Last-Modified` values from origin `304 Not Modified`
    responses and protects changed `Vary` values by refusing the revalidation
    metadata update until variance re-keying can move into the Pingora path;
  - large-object range behavior is handled by explicit opt-in bounded
    range-cache policy in `1.2.5`: safe single `bytes=start-end` requests get a
    range-specific cache key and only matching upstream `206` metadata is
    admitted. A larger reader-visible multi-slice composition design can move
    to the later media-edge line if production needs it;
  - cache manager/loader hardening beyond the current startup purge-index
    rebuild and stale purger: full deterministic startup scans now prevent
    checkpoint orphans, startup enforces the disk-size budget before serving,
    stale cleanup is bounded and observable, and aggregate pressure gauges show
    whether memory or disk caches are approaching their budgets. Additional
    configurable incremental loader/purger pacing can move to a later patch if
    production scale testing shows startup scans or cleanup ticks need more
    shaping;
  - invalidation maturity beyond exact purge and wildcard/prefix/tag purge:
    evaluate whether stored metadata predicates are needed for the 1.2 stable
    baseline. If they are not required for production safety, keep them out of
    1.2 and reserve any Varnish-style policy expressiveness for the later Wasm
    cache hook release;
  - cache object inspection and debug tooling for production incidents,
    including object metadata lookup, freshness state, stored headers,
    purge-index membership, and dry-run invalidation output without dumping
    sensitive request data by default. `fluxheim cache-key` now provides safe
    cache-key preview by selecting the effective vhost/route policy and
    printing key hashes without contacting upstreams. `fluxheim cache-lookup`
    now adds the first object metadata lookup by checking selected memory/disk
    tiers and reporting status, size, freshness state, stale-serving
    eligibility, cache tags, and stored header names without reading cached
    bodies to stdout or dumping header values.
    Lookup output also reports purge-index membership so operators can tell
    whether indexed scope, prefix, tag, wildcard, and stale purges can reach an
    object without a full scan. `cache-key` and `cache-lookup` report the
    selected cache-lock state, wait timeout, cacheability predictor state, and
    memory/disk tier availability so operators can verify stampede-protection,
    predictor, and storage policy for the exact vhost or route that a request
    matches. `cache-key` can also fail
    closed with `--expect-eligible`, `--expect-cache-lock-enabled`,
    `--expect-cache-lock-wait-timeout-secs`,
    `--expect-cache-predictor-enabled`, `--expect-memory-tier-enabled`,
    `--expect-disk-tier-enabled`, and `--expect-storage-tiers`, plus
    `--expect-scope`, `--expect-vhost`,
    `--expect-route`, `--expect-namespace`, `--expect-key-namespace`, and
    `--expect-user-tag`, so deploy scripts can assert cache policy layout,
    selected vhost/route, internal namespace, and cache isolation boundary
    before warming objects. Both commands can include bounded safe request
    headers such as `Accept-Language` and `Accept-Encoding`, so operators can
    debug negotiated `Vary` variants without contacting upstreams.
    `cache-lookup` can fail closed for deploy
    checks with `--require-object`, `--expect-tier`, `--expect-status`,
    `--expect-body-bytes`, `--expect-fresh-ttl-secs`, `--expect-cache-tag`,
    `--expect-header-name`, `--expect-header "Name: value"`,
    `--expect-cache-lock-enabled`,
    `--expect-cache-lock-wait-timeout-secs`,
    `--expect-cache-predictor-enabled`,
    `--expect-memory-tier-enabled`, `--expect-disk-tier-enabled`,
    `--expect-storage-tiers`, `--expect-scope`, `--expect-vhost`,
    `--expect-route`, `--expect-namespace`, `--expect-key-namespace`,
    `--expect-user-tag`,
    `--expect-serve-stale-if-error`, `--expect-serve-stale-while-revalidate`,
    `--expect-purge-indexed`, and
    `--expect-freshness-state fresh|stale|expired`, so scripts can assert that
    warm objects exist, preserved expected response metadata and freshness
    policy, are purge-index reachable, and are in an acceptable serving state
    without contacting upstreams;
  - cache warm/import/export workflows for deploys and repository mirrors,
    including clear failure accounting and no hidden best-effort misses.
    `cache-warm` now treats only 2xx/3xx responses as successful by default
    and requires explicit `--allow-status` opt-in for deliberate negative-cache
    warm targets such as configured 404 TTLs. It can also require expected
    cache-status header values so warm scripts fail when traffic bypasses the
    selected cache policy unexpectedly, can repeat each target with a
    cache-status sequence such as `MISS,HIT`, can warm negotiated variants with
    bounded safe request headers, now has smoke coverage for input-file dry-run
    validation, input-file warming, and deliberate 404 negative-cache warming,
    caps input files before parsing, and can dry-run target parsing without
    sending requests to a running server;
  - cache observability through both Prometheus and OpenTelemetry, including
    per-vhost/per-route/tier hit, miss, stale, bypass, store, refusal, eviction,
    purge, and storage-pressure signals. Prometheus now exposes configured
    vhost/route scoped cache activity counters, purge counters, cache-lock
    coverage, aggregate memory/disk storage-pressure gauges, and policy-level
    pass/bypass/stale/revalidate decisions without cache keys, hosts, or paths.
    `otel-tracing` now provides W3C `traceparent`
    propagation and access-log trace ID correlation, `otel-otlp` now provides
    initial local OTLP/HTTP trace export, and `metrics-otlp` now provides
    local OTLP/HTTP metrics export for Prometheus/collector receivers with
    bounded exporter success/failure counters and histograms. Richer
    OpenTelemetry internal spans, sampling, and trace/event coverage remain
    planned.
- Production ACME companion operating mode:
  - Keep the `1.1` in-process ACME background worker for simple single-binary
    installs.
  - Add a dedicated `fluxheim-acme` binary or subprogram mode as the production
    companion interface while keeping `fluxheim acme-init` and
    `fluxheim acme-renew` compatibility for simple/manual workflows.
  - Ship `fluxheim-acme.service` as a one-shot unit and
    `fluxheim-acme.timer` for scheduled renewal. The main `fluxheim.service`
    remains the traffic-serving webserver and should not spawn long-lived child
    processes itself.
  - Run the companion service as the same runtime user as Fluxheim by default,
    using systemd credentials or container secrets for EAB material. Prefer
    `key_id_credential` and `hmac_key_credential` config fields so the same
    TOML works under the web service, ACME service, and container secrets.
  - Share only the configured ACME storage directory with the webserver. The
    webserver continues to serve HTTP-01 challenge files and exposes only a
    local protected certificate-reload control path for the companion after
    files change.
  - Add an explicit `tls.acme.automation = "background" | "external"` config
    knob so production installs can prefer the service/timer model without
    losing the simple integrated mode.
  - Improve renewal command output so each target reports `skipped`, `renewed`,
    or `failed`; failures should include the domain/order context and, for
    HTTP-01 authorization failures, the challenge URL/path that the CA could
    not validate.
  - Make first issuance clearer: missing certificate files should be reported
    as due targets in normal due-only renewal output, while forced renewal
    remains documented as a rate-limit-sensitive recovery/testing command.

Exit criteria:

- Admin and metrics listeners fail validation when exposed remotely without
  explicit opt-in.
- Snapshot and rollback tests pass.
- Logs redact secrets by default.
- Metrics labels are cardinality-safe.
- Cache metrics and OpenTelemetry attributes are cardinality-safe and never use
  raw path, query, cookie, authorization, or cache-key values by default.
- ACME CLI output is actionable for partial-success production runs and does
  not require operators to infer which target failed from issuer-level errors.
- Container migration docs include a validated HTTP-only first-issuance flow,
  HTTPS enablement flow, and SNI verification checklist.

### 1.3.0 - Shared Ingress And TLS Feature Split

Goal: make Fluxheim's module boundaries honest before PHP, advanced proxy, and
load-balancer features add more code on top. TLS, ACME, admin/config
validation, metrics, and runtime ingress are shared capabilities; static web,
cache, reverse proxy, and load balancing should not be pulled into focused
builds unless the operator selected them.

Stable scope:

- Introduce an explicit shared ingress/runtime feature boundary.
- Make `tls`, `tls-rustls`, `tls-openssl`, `tls-boringssl`, `tls-s2n`, `acme`,
  and `acme-client` depend on shared ingress/TLS primitives rather than
  implicitly selecting the generic `proxy` feature.
- Keep exactly one TLS backend selectable at a time.
- Keep ACME certificate loading and renewal usable for every TLS-capable
  focused profile.
- Split profile aliases into honest deployment profiles:
  - `profile-full`;
  - `profile-web-server`;
  - `profile-cache-edge`;
  - `profile-proxy-edge`;
  - `profile-load-balancer-edge`;
  - `profile-observability`;
  - `profile-privacy`.
- Keep compatibility aliases for older profile names where practical, but mark
  them transitional.
- Update container image profiles to follow the focused model:
  - `full`;
  - `cache`;
  - `proxy`.
- The `cache` image is TLS/ACME-capable but does not compile local static
  webserver behavior unless `web` is selected.
- The `proxy` image is TLS/ACME-capable but does not compile static web, cache,
  or load-balancer behavior unless selected.
- The `profile-web-server` and `profile-load-balancer-edge` feature aliases
  compile and validate, but official web-only and load-balancer images are not
  published as normal `1.3.0` tag outputs.
- The load-balancer image profile is prepared and manually dispatchable for
  pre-`1.5` testing, but normal tag publishing skips it until the `1.5`
  load-balancer line.
- Config validation must produce clear disabled-module errors such as
  "web module not compiled", "cache module not compiled", or
  "load-balancer module not compiled".
- CI must build and test the focused profiles and prove unrelated modules are
  absent from the feature set.
- Release docs and image tags must explain the difference between the published
  `full`, `cache`, and `proxy` images plus the prepared-but-gated
  `load-balancer` image profile.

Exit criteria:

- `cargo check --no-default-features --features profile-web-server`
  succeeds.
- `cargo check --no-default-features --features profile-cache-edge`
  succeeds.
- `cargo check --no-default-features --features profile-proxy-edge`
  succeeds.
- `cargo check --no-default-features --features profile-load-balancer-edge`
  succeeds.
- TLS/ACME config validates in each TLS-capable focused profile.
- Static web config is rejected cleanly when `web` is not compiled.
- Cache config is rejected cleanly when `cache` is not compiled.
- Load-balancer config is rejected cleanly when `load-balancer` is not
  compiled.
- Image workflow publishes focused images from the new profile names.

### 1.3.1 - PHP Application Server

Goal: add production-compatible PHP support without making PHP part of the
default Fluxheim threat model. The stable `1.3.1` target is a `php-fpm`
FastCGI bridge for WordPress-style, front-controller, and legacy PHP
deployments. Embedded Rust PHP integrations remain follow-up `1.3.x` work
behind separate compile-time features.

Stable scope for `1.3.1`:

- Compile-time `php` base module and `php-fpm` runtime module.
- `php` remains absent from default, cache, privacy, and normal proxy builds.
- Per-vhost and per-route PHP enablement.
- PHP-FPM over Unix socket and explicit TCP endpoints.
- `index.php` and WordPress-style front-controller support.
- Safe `.php` script resolution under a configured PHP root.
- Static fallback must never serve PHP source when PHP is enabled and a PHP
  route fails.
- Strict CGI/FastCGI param allow-list, including `SCRIPT_FILENAME`,
  `SCRIPT_NAME`, `DOCUMENT_ROOT`, `REQUEST_METHOD`, `QUERY_STRING`,
  `REQUEST_URI`, `SERVER_NAME`, `SERVER_PORT`, and `SERVER_PROTOCOL`.
- `PATH_INFO` disabled by default, with strict opt-in split rules.
- Request body limits, configurable response byte limits, streaming body
  accounting, connect/read/write timeouts, and response header byte limits.
- Strict parsing of PHP-generated status and headers.
- Sanitized, size-limited PHP STDERR logging and PHP metrics.
- WordPress and minimal PHP-FPM example configs.
- Browser-validated WordPress install, login, admin, plugin, and theme flows
  for direct PHP-FPM serving and reverse-proxy gateway deployments.
- Split `Cookie` header normalization for proxy upstreams and PHP-FPM
  `HTTP_COOKIE`.

### 1.3.2 - ACME Companion Agent And Config Tester

Goal: make adding ACME-backed vhosts operationally smooth for existing
multi-site gateways. A new vhost should be able to enter a pending certificate
state, complete HTTP-01 issuance, and activate HTTPS without taking already
serving vhosts down and without requiring operators to manually run a second
restart after issuance. The same release should also make failed container
startup easier to diagnose by shipping a small release-page config tester that
can validate mounted configs even when the gateway container itself will not
start.

Stable scope for `1.3.2`:

- Ship a dedicated `fluxheim-acme` companion binary or subprogram mode for
  ACME lifecycle work.
- Keep `fluxheim` focused on serving traffic, challenge paths, and certificate
  handles; keep `fluxheim-acme` focused on account state, issuance, renewal
  scheduling, EAB secret access, and certificate installation.
- Add a local-only control channel, preferably a runtime-user owned Unix
  socket, that lets the ACME companion request certificate reloads from the
  running gateway after files are installed.
- Keep the control API small and non-general-purpose:
  - renew all due targets;
  - renew one vhost/target;
  - report target status;
  - request certificate-handle reload;
  - expose health/status for service managers.
- Do not let the companion silently rewrite production config in the first
  stable version. Assisted config generation can be a later command that writes
  reviewed snippets or snapshots.
- Preserve pending managed ACME certificate startup behavior for reloadable SNI
  TLS backends, while keeping static certificate paths fail-closed.
- Integrate with packaged systemd units and containers so external
  `fluxheim-acme.service`/timer-style renewals can activate certs in the
  running gateway without a full process restart.
- Document first-issuance flows for native systemd, rootless Podman, and the
  one-shot/manual CLI case.
- Publish a tiny `fluxheim-config-tester` release asset for every official
  release profile, but do not install it into normal RPMs or runtime images by
  default.
- The tester must reuse Fluxheim's real config and runtime validation code
  rather than maintaining a separate parser.
- The tester must validate against the selected target profile, for example
  `full`, `cache`, `proxy`, `web-php`, or future `load-balancer`, so operators
  do not get false positives from a broader binary than the image they run.
- Initial tester modes should cover config validation, runtime-path validation,
  TLS/ACME storage checks, ACME target preview, upstream resolution checks, and
  an `--explain` output mode that includes vhost/route/module context for
  filesystem, DNS, and disabled-module failures.

Implementation status:

- Initial `fluxheim-config-tester` binary target added.
- Initial profile validation, runtime-path validation, TLS storage checks, ACME
  target preview, upstream DNS resolution, and `--explain` output added.
- Initial `fluxheim-acme` companion binary with `renew` and `targets` commands
  added.
- Local Unix-domain certificate reload socket added for companion-driven
  certificate-handle reloads.
- `fluxheim-acme status` and `fluxheim-acme renew --vhost <name>` added for
  target status reporting and single-target renewal.
- `fluxheim-acme reload` added for explicit local certificate reload requests
  through the companion control path.
- Bounded ACME lifecycle metric `fluxheim_acme_events_total{event}` added for
  pending, renewed, failed, and reload outcomes.
- Release evidence packaging for separate config-tester artifacts started.

Exit criteria:

- Adding a new ACME vhost with missing cert files does not break existing TLS
  vhosts.
- HTTP-01 validation can complete while the new SNI certificate is pending.
- Successful companion-driven issuance reloads the running gateway certificate
  resolver/callback without restarting the process.
- Failed issuance leaves existing certificates and vhosts serving.
- The local control channel is unavailable remotely by default and protected by
  filesystem permissions or an equivalent local secret.
- Logs and metrics expose `pending`, `renewed`, `failed`, and `reload_failed`
  states without leaking EAB material, account keys, or ACME token secrets.
- A downloaded `fluxheim-config-tester` can validate the same mounted config
  paths/operators use for Podman/systemd and report actionable context when the
  main gateway container cannot start.
- Tester release assets are produced for the official release profiles and are
  documented as diagnostics-only tools, not runtime dependencies.

Follow-up `1.3.x` FIPS-capable TLS build plan:

- Add an explicit FIPS-capable compile/profile line without claiming that
  Fluxheim itself is a validated cryptographic module. The release wording must
  say "FIPS-capable build using a validated cryptographic module" and must
  point operators to the selected module certificate, security policy, platform
  limits, and install procedure.
- Treat the compliance documents as release requirements, not optional
  references:
  - FIPS PUB 140-3 defines the cryptographic module security requirements.
  - The current FIPS 140-3 Implementation Guidance defines how labs and
    vendors interpret those requirements for modern software modules.
  - NIST SP 800-52 Rev. 2 defines the TLS versions, cipher suites, key sizes,
    and curves that a web server profile may allow.
  - The chosen module's CMVP Security Policy is the binding installation and
    invocation guide. Fluxheim documentation must point operators at the exact
    certificate/security-policy boundary used for the selected backend.
- Fluxheim's responsibility in a FIPS-required build is enforcement and
  evidence: validate only FIPS-approved TLS versions/ciphers/curves, trigger
  or verify the selected backend's FIPS mode exactly as its Security Policy
  requires, expose backend/provider evidence in diagnostics, and fail closed
  when the provider cannot prove approved operation. Fluxheim must not ship
  home-grown cryptography or describe itself as FIPS compliant merely because
  a feature flag was enabled.
- Add backend-specific feature gates rather than one vague `fips` switch:
  - `tls-rustls-fips`: rustls backend using rustls' `fips` feature and the
    AWS-LC FIPS provider path. This requires replacing current ring-specific
    rustls helpers with provider-aware helpers, installing
    `rustls::crypto::default_fips_provider()` at startup, and failing startup
    if generated `ServerConfig` / `ClientConfig` objects do not report FIPS
    status where rustls exposes that check. The feature should route builds to
    the AWS-LC FIPS crate path, document the CMake, Go, and C compiler build
    requirements, and explicitly construct rustls server/client configs from
    provider suites permitted by NIST SP 800-52 Rev. 2.
  - `tls-openssl-fips`: OpenSSL backend built and linked against OpenSSL 3.x
    with a validated FIPS provider. Operators remain responsible for installing
    the validated provider and running the provider setup expected by the
    module Security Policy, such as `openssl-fipsinstall` where applicable.
    Fluxheim should support an operator-supplied OpenSSL config path or
    environment contract, require provider/config diagnostics, and fail closed
    when FIPS-required mode cannot prove the FIPS provider/default properties
    are active.
  - `tls-boringssl-fips`: research-only until Fluxheim can prove it is linked
    to a BoringCrypto validated module stream, can query the module/version, and
    can document the exact CMVP certificate/security-policy boundary. Normal
    BoringSSL must not be described as FIPS validated.
  - `tls-s2n-fips`: research-only until the s2n/Pingora integration can prove
    s2n was built with FIPS-capable AWS-LC, expose `s2n_get_fips_mode`, and
    restrict configured s2n security policies to FIPS-approved cryptography.
- Add a high-level `fips-required` compile feature or config guard only after
  backend-specific checks exist. When enabled, non-FIPS TLS backends, non-FIPS
  cipher/curve choices, non-FIPS ACME/account crypto paths, and incompatible
  dependencies must fail validation instead of silently downgrading.
- Inventory internal cryptography before publishing FIPS profiles. Any
  security-sensitive operation outside TLS, including random request/session
  identifiers, admin token MACs, ACME/account signing, cache encryption,
  password hashing, CSRF/session/JWT support, and future plugin signing, must
  either route through the selected validated backend or be disabled/rejected in
  FIPS-required builds. Pure RustCrypto, ring, or other non-validated fallback
  paths cannot remain reachable for those operations in a FIPS-required binary.
- Add `profile-fips-rustls` and optionally `profile-fips-openssl` once CI can
  build them reproducibly. These profiles should be separate from default,
  cache, proxy, PHP, and load-balancer profiles so non-FIPS operators do not
  inherit large FIPS build dependencies.
- Add release evidence:
  - compile logs and lockfile for the selected backend;
  - runtime `--version --crypto` or equivalent output showing backend, provider,
    FIPS-required setting, and module/version evidence where available;
  - config-tester checks that prove a FIPS-required config fails with a
    non-FIPS backend or missing provider;
  - docs explaining that FIPS compliance also depends on OS/container base,
    provider installation, module integrity data, runtime configuration, and the
    operator's deployment environment.
- Keep FIPS support incompatible with any backend or feature where we cannot
  prove the cryptographic boundary. "Compiled with a FIPS-capable dependency"
  is not enough for release claims.

Follow-up `1.3.x` PHP runtime plan:

- `1.3.3`: php-fpm hardening and production compatibility fixes.
  - Connection pooling to php-fpm with idle pruning.
  - `fastcgi_keep_conn`-style reuse where the selected client/runtime can
    safely keep FastCGI connections open between requests, with stale-connection
    detection and a clear fallback to one request per connection.
  - True streaming request and response bodies.
  - Chunked upload disk-spooling so large uploads do not require full RAM
    buffering before php-fpm receives `CONTENT_LENGTH`.
  - Custom FastCGI params in config. Implemented as validated
    `[vhosts.php.params]` / `[vhosts.routes.php.params]` tables that cannot
    override Fluxheim-managed CGI parameters.
  - Path mapping for separate Fluxheim/php-fpm container filesystem roots.
    Implemented as `php.fpm_root` for FastCGI `DOCUMENT_ROOT`,
    `SCRIPT_FILENAME`, and `PATH_TRANSLATED` mapping.
  - Caddy-style PHP root override and optional root-symlink resolution for
    split container layouts, while keeping Fluxheim's symlink escape checks.
  - NGINX/Caddy-style `try_files` PHP presets for common apps:
    static-file first, directory index, front-controller fallback, and explicit
    `=404` behavior for sites that must not route everything through
    `index.php`.
    Implemented as `php.try_files = "front-controller"`, `"wordpress"`, or
    `"strict"`.
  - Configurable `PATH_INFO` splitting model compatible with Caddy's `split`
    and NGINX's `fastcgi_split_path_info`, but expressed as safe typed config
    rather than arbitrary regex by default.
    Implemented as `php.path_info = "disabled"` or `"split"`; `"strict"` is
    retained as a compatibility alias for `"split"`.
  - Canonical directory slash redirect when `{path}/index.php` exists and the
    app expects `/dir/` semantics.
    Implemented as a `308` redirect before executing directory `index.php`
    scripts.
  - `fastcgi_pass_request_headers` / `fastcgi_pass_request_body` equivalents
    as explicit advanced switches, defaulting to today's safe allow-list.
    Implemented as `php.pass_request_headers` and `php.pass_request_body`, both
    defaulting to `true`; disabled body pass-through still drains and limits the
    downstream body.
  - Configurable CGI response-header limits.
    Implemented as `php.max_response_header_bytes`, defaulting to `64KiB`.
  - `X-Accel-Redirect` / `X-Sendfile` support for PHP-assisted static
    offload, plus internal-only target validation, `X-Accel-Expires` handling
    where it maps to Fluxheim cache metadata, and response-header stripping so
    backend control headers are not leaked to clients.
  - `fastcgi_intercept_errors`-style integration with Fluxheim error pages for
    selected PHP statuses, keeping normal PHP responses untouched by default.
    Initial generic interception implemented as `php.intercept_error_statuses`;
    static fallback pages are supported with `[[vhosts.php.error_pages]]` and
    `[[vhosts.routes.php.error_pages]]`.
  - PHP response-header policy controls matching common NGINX migrations:
    hide/pass selected backend headers, ignore selected cache-control headers,
    and reject conflicting `Content-Length` / transfer headers.
    Initial hide controls implemented as `php.hide_response_headers`; hop-by-hop
    PHP response headers are stripped by default.
  - STDERR handling options: capture/log, truncate, severity mapping for 4xx/5xx
    responses, and optional fatal-error match that marks a response invalid for
    retry/failover.
    Initial controls implemented as `php.stderr_log` and
    `php.stderr_max_bytes`.
  - php-fpm upstream load balancing and failover.
  - FPM upstream retry policy aligned with NGINX/Apache/Caddy behavior:
    connect error, timeout, invalid header, selected 5xx statuses, max tries,
    total retry timeout, and retry-safe method matching.
  - FPM upstream TLS and Unix/TCP socket controls should remain explicit; Unix
    sockets keep strict path/permission validation and TCP supports DNS refresh
    when the proxy resolver work lands.
  - PHP-specific Prometheus metrics for bounded request totals and durations.
    Implemented as `fluxheim_php_requests_total` and
    `fluxheim_php_request_duration_seconds`; deeper pool, timeout, and STDERR
    counters remain planned.
  - FastCGI cache-specific convenience config on top of Fluxheim's cache
    engine.
  - FastCGI cache semantics compatible with common NGINX deployments:
    cache key presets, status-based TTLs, `Cache-Control`/`Expires`/
    `Set-Cookie`/`Vary` admission behavior, bypass/no-cache conditions,
    cache lock, stale-on-error/timeout, background refresh where available, and
    authenticated purge integration.
  - WordPress-focused migration presets for `wp-admin`, `wp-login.php`,
    `xmlrpc.php`, sitemap/feed exclusions, logged-in/commenter cookie bypass,
    Super Cache/W3TC static-file fallbacks, and denial of PHP execution under
    uploads/files-style directories.
    Initial execution denial implemented as `php.deny_path_prefixes`.
  - FastCGI multiplexing, authorizer, and filter-role review. These are not
    required for normal PHP-FPM web serving, but should be documented
    explicitly as unsupported or implemented if enterprise users need them.
- `1.3.4`: embedded Rust PHP/Turbine-style integration if the source, license,
  API, isolation, reload, and concurrency model pass review.
- `1.3.5`: pure-Rust PHP interpreter experiment behind `php-phprs`, beta or
  test-only until compatibility and maintenance are proven.

Compile-time feature shape stays:

```toml
php = []
php-fpm = ["php", "dep:fastcgi-client"]
php-turbine = ["php"]
php-phprs = ["php", "dep:phprs"]
```

Only one PHP runtime feature may be selected in one binary. Add compile-time
guards for incompatible runtime combinations.

Exit criteria:

- `--features web,php-fpm` release build passes.
- Default, cache, privacy, and load-balancer profiles prove PHP is absent
  unless explicitly selected.
- PHP source files are never served as static fallback.
- Traversal, symlink escape, missing script, directory script, malformed
  FastCGI response, timeout, oversized body, and STDERR-size tests pass.
- WordPress-style front-controller routing, login/admin cookies, plugin/theme
  install/update/delete flows, and common cache-plugin bypass patterns are smoke
  tested against php-fpm.
- Config validation makes unsafe PHP roots, sockets, and runtime combinations
  actionable.

### 1.4 - Advanced Proxy

Feature-graph prerequisite:

- `1.4` proxy images should compile the HTTP proxy and shared ingress/TLS
  surface without static web, local static cache, or load-balancer code unless
  explicitly selected.

Goal: make Fluxheim's HTTP and stream proxy layer migration-friendly for
HAProxy and NGINX operators before expanding the load-balancer surface. This
release should cover reverse-proxy behavior, connection management,
backpressure, buffering, protocol bridging, and operator visibility that apply
even when a route targets one upstream.

Stable scope:

- Compile-time proxy surface stays modular; advanced proxy capabilities remain
  available through explicit `proxy` subfeatures where they add dependencies
  or attack surface.
- New proxy dependencies must be deliberate and profile-gated. Prefer small
  in-tree policy implementations for bounded Fluxheim-specific behavior such
  as queue policy, rewrite validation, typed variables, and overload decisions;
  keep mature protocol/TLS/runtime crates for transport machinery unless a
  later dependency-reduction milestone proves an in-tree replacement safer.
- Per-vhost and per-route upstream connection controls:
  - max in-flight requests/connections for a route or upstream target;
  - bounded request queue with queue timeout, max depth, overflow action, and
    low-cardinality queue metrics;
  - optional priority classes derived from safe request attributes such as
    route, method, authenticated policy result, or configured header allow-list;
  - async backpressure so slow or saturated upstreams do not force unbounded
    buffering inside Fluxheim.
- Upstream keepalive and connection-pool tuning beyond the existing global
  pool size:
  - per-route pool limits;
  - idle timeout;
  - maximum reuse count or lifetime;
  - clear behavior when upstream closes an idle pooled connection.
- NGINX-style proxy buffering controls:
  - request buffering on/off;
  - response buffering on/off;
  - header buffer size and response body buffer limits;
  - spill-to-disk policy if implemented, with safe temp-path validation and
    privacy-mode rejection;
  - streaming passthrough mode for long-lived or large responses.
- Safer large-payload proxying:
  - explicit memory budget per proxied stream;
  - cancellation on downstream disconnect;
  - bounded body-copy buffers;
  - documented zero-copy strategy. Kernel zero-copy should be pursued only
    where the Rust/Pingora/Tokio stack can expose it safely; otherwise the
    stable goal is bounded-copy streaming, not unsafe shortcuts.
- Protocol translation:
  - client HTTP/2 to upstream HTTP/1.1 controls;
  - client HTTP/1.1 to upstream HTTP/2 where Pingora support is stable;
  - future HTTP/3 ingress may map to HTTP/1.1 or HTTP/2 upstreams, but QUIC
    itself remains a separate protocol milestone.
- WebSocket and upgrade handling parity with explicit timeout and header
  behavior.
- gRPC/gRPC-Web proxy compatibility where it fits Fluxheim's HTTP/2 stack,
  including body-size, timeout, and status/trailer handling.
- NGINX-style request mirroring for HTTP routes with strict limits:
  - mirror body on/off;
  - mirror timeout;
  - no effect on primary response;
  - low-cardinality metrics for mirror success/failure.
- External auth request integration may stay in the existing auth-request
  design, but `1.4` should make it proxy-route complete: timeout, header
  forwarding, allowed response headers, deny status, and metrics.
- PROXY protocol support:
  - accept Proxy Protocol v1/v2 on configured listeners;
  - send Proxy Protocol to upstreams on configured routes;
  - validate trust boundaries before restoring client identity.
- TCP stream proxy foundation:
  - compile-time feature separate from HTTP proxy if needed;
  - safe listener and upstream config;
  - byte counters, idle timeout, connect timeout, and max connection limits;
  - no HTTP header/cache/admin behavior on stream routes.
- UDP proxy foundation if it can be bounded safely:
  - session table with TTL and max entries;
  - per-source and global rate/byte limits;
  - explicit DNS/gaming/IoT examples only after smoke tests;
  - no claim of load balancing until the `1.5` load-balancer line owns
    multi-upstream UDP policy.
- Richer proxy variables for logging, headers, and future Wasm inputs:
  - upstream connect time, first-byte time, response time, selected target,
    retry count, queue time, TLS protocol/cipher, request ID, vhost, route,
    cache phase, and protocol.
  - variables must be bounded, typed, redacted where needed, and forbidden from
    creating high-cardinality metric labels by default.
- Variable-based structured logging:
  - configured log fields from a typed allow-list;
  - JSON output and existing access-log privacy controls;
  - no raw query/cookie/authorization values unless explicitly enabled.
- Local operational socket:
  - Unix-domain socket for fast local status and counters, similar in spirit to
    HAProxy's stats socket;
  - root/service-owner permissions, strict path validation, no network bind by
    default;
  - read-only status first, with any mutating commands deferred or separately
    authorized.
- Regex-based request/response header and URI rewrite rules using Rust's
  memory-safe regex engine:
  - route-scoped allow-list of operations;
  - replacement output length limits;
  - deterministic failure behavior;
  - no arbitrary code execution.
- Apache/NGINX/Caddy migration-oriented proxy knobs:
  - `ProxyPreserveHost` / Caddy default-host behavior as explicit host policy;
  - `ProxyPassReverse`/`proxy_redirect`-style `Location` and `Refresh` rewrite
    rules;
  - `ProxyPassReverseCookieDomain`, `ProxyPassReverseCookiePath`, and
    NGINX-style cookie flag/domain/path rewrites;
  - `proxy_set_header` / Caddy `header_up` and `header_down` parity including
    set, append, unset, wildcard unset, and bounded regex replacement;
  - pass/drop request headers and request body switches for migration cases;
  - method and URI rewrite before upstream dispatch;
  - response interception hooks for selected statuses and headers;
  - upstream TLS controls: SNI override, trust roots, mTLS client cert, protocol
    and cipher policy where supported, and explicit insecure-skip-verify
    rejection or audit warning;
  - upstream DNS refresh for container/service-name targets so Fluxheim can
    start when optional backends are temporarily absent and recover when they
    appear.

Out of scope for `1.4`:

- Load-balancer pool algorithms, active health checks, backup/drain/slow-start,
  redispatch, and sticky sessions. Those belong to `1.5`.
- Direct Server Return as a stable HTTP proxy feature. DSR is a layer-4/network
  topology feature and should be evaluated in the `1.5` load-balancer or later
  stream-proxy line after Linux routing, source-address, and observability
  constraints are documented.
- Cache engine work already completed in `1.2.x`, except where proxy buffering
  and streaming behavior must integrate correctly with cache admission.

Exit criteria:

- HAProxy/NGINX migration fixtures cover queue limits, queue timeout,
  backpressure, request/response buffering, upstream keepalive, WebSocket,
  gRPC, request mirroring, PROXY protocol receive/send, external auth request,
  variable logging, and TCP stream proxy basics.
- Memory usage remains bounded under slow client, slow upstream, large upload,
  large download, and upstream stall tests.
- Queue, pool, buffering, mirror, stream, and protocol-translation metrics are
  available when metrics are enabled and stay low-cardinality.
- Privacy-mode rejects incompatible logging, temp-file buffering, stream
  identity restoration, or payload-retaining features.
- Config validation catches unsafe temp paths, impossible queue settings,
  invalid regex rewrites, unsupported protocol combinations, and unsafe PROXY
  protocol trust boundaries.

### 1.5 - Load Balancer

Feature-graph prerequisite:

- `1.5` load-balancer images should compile load-balancer, shared ingress/TLS,
  ACME, metrics, and security modules without static web, local static cache,
  or generic single-upstream reverse-proxy-only code unless explicitly
  selected. The load balancer may reuse shared proxy transport abstractions
  internally, but the public feature name and image profile must not pull in
  unrelated webserver behavior.

Goal: graduate Fluxheim's load balancer to an enterprise-grade traffic
management layer. The target is HAProxy/nginx migration parity plus the
operator primitives people expect from F5 BIG-IP LTM: rich pool metadata,
health/performance monitors, persistence, adaptive recovery behavior, and
programmable traffic decisions. Palo Alto-style security expectations should be
represented as clear policy integration points around the load balancer, not as
a claim that Fluxheim is a full next-generation firewall in `1.5`.

Stable scope:

- Compile-time `load-balancer` module.
- Load-balancer additions should minimize dependency surface while preserving
  migration parity. Selection algorithms, persistence tables, circuit state,
  and policy evaluation are good candidates for in-tree Fluxheim
  implementations; protocol, TLS, async runtime, and cryptographic machinery
  should remain on reviewed mature crates until a far-future transport/core
  replacement line exists.
- Named upstream pools that can be selected globally, per vhost, or per route,
  so one vhost can proxy normal app traffic and route-specific traffic to
  different backend sets.
- Separate L4 and L7 load-balancing modes:
  - HTTP/1.1 and HTTP/2 request-aware pools;
  - gRPC-aware HTTP/2 pools where trailers/status handling is preserved;
  - TCP stream pools built on the `1.4` stream-proxy foundation;
  - UDP session pools only if the `1.4` UDP proxy foundation proves bounded
    and observable;
  - HTTP/3/QUIC remains a later protocol milestone unless the QUIC ingress
    stack is already stable before `1.5`.
- Multiple upstreams per pool with safe address validation and per-upstream
  metadata: name, address, weight, backup, disabled/down, drain/maintenance,
  max in-flight requests or connections, max queue, priority group, manual
  resume, warm-up/slow-start after recovery, administrative tags, and optional
  per-upstream TLS/SNI settings.
- Weighted round-robin stable default.
- Selection policies needed for common HAProxy/nginx/F5 migrations and Pingora
  parity:
  - weighted round-robin;
  - least-connections / least-in-flight;
  - least-time / EWMA latency-aware selection when metrics are trustworthy;
  - power-of-two-choices for lower herd effects than naive least-connections;
  - source-IP hash;
  - generic hash by a bounded key template such as host, path, header, or
    request ID;
  - consistent hash / Ketama for cache-stateful upstreams;
  - bounded-load consistent hashing so overloaded nodes can be skipped without
    remapping the whole ring;
  - random where it is useful for large homogeneous pools;
  - priority-group selection for F5-style preferred/fallback groups.
- Session persistence:
  - cookie persistence with signed/opaque cookies;
  - source-address persistence with TTL and table-size limits;
  - header-based persistence from a configured allow-list;
  - TLS session/client-certificate persistence only after privacy/security
    review;
  - persistence must be visible, bounded, purgeable, and incompatible with
    privacy-mode unless a no-retention policy is configured.
- Active health checks:
  - TCP connect checks;
  - TLS handshake checks with SNI and verification controls;
  - HTTP checks with method, path, expected status range, expected response
    header/body substring, Host header, and upstream TLS/SNI where configured;
  - HTTP/2 and gRPC health checks where protocol support is stable;
  - UDP checks only with explicit send/expect patterns and timeout limits;
  - interval, timeout, consecutive success/failure thresholds, initial state,
    jitter, parallel check controls, manual resume, and per-pool/per-member
    overrides.
- Adaptive health/performance monitors:
  - track latency, error rate, queue time, and in-flight load;
  - support optional adaptive thresholds for least-time and circuit breakers;
  - make every automatic ejection explainable through admin status and logs.
- Passive health observation from real proxy traffic: connection failures,
  upstream timeout/error classes, selected HTTP status classes, bounded
  error-limit windows, and configurable actions such as mark-down,
  fast-recheck, temporary ejection, or circuit-open state.
- Circuit breaking and adaptive concurrency:
  - per-pool and per-member circuit state;
  - half-open probe limits;
  - cooldown windows;
  - optional adaptive concurrency inspired by queue/latency feedback, with
    minimum/maximum bounds and metrics.
- Retry and redispatch controls:
  - bounded retries for connection failures and selected HTTP status codes;
  - redispatch to a different healthy upstream after configured retry counts;
  - method/body safety so non-idempotent or streaming requests are not retried
    unless explicitly allowed.
- Upstream TLS/SNI and certificate verification controls aligned with the
  existing proxy TLS surface.
- Client mTLS and upstream mTLS policy integration:
  - route/pool decisions can use verified client-certificate attributes only
    from the typed identity layer;
  - upstream client certificates are configured through safe secret paths or
    future secret-store providers;
  - mTLS failures emit security events without exposing certificate secrets.
- Per-upstream and per-pool timeout/keepalive controls, including connect,
  read, send, idle keepalive, and reuse-pool sizing.
- Request queuing and overload behavior should integrate with the `1.4`
  advanced proxy queue/backpressure layer:
  - per-pool and per-member queue size;
  - priority groups/classes;
  - queue timeout;
  - shed/503/backup-pool overflow actions;
  - queue-time metrics and logs.
- Clear all-nodes-down behavior with configurable fail status, optional static
  error page integration, and no accidental fallback to an unrelated pool.
- Dynamic runtime operations:
  - admin/API ability to drain, disable, enable, force-down, or manually resume
    a pool member when admin is enabled;
  - safe persistence of dynamic state only after the config/snapshot model is
    clear;
  - no unauthenticated or plaintext remote mutation.
- Security and policy integrations:
  - edge rate limits per vhost/route/pool/member using token-bucket or
    leaky-bucket algorithms;
  - reputation/Geo/IP-set decisions as inputs from the future trusted-client
    identity layer, never from untrusted headers;
  - TLS fingerprint signals such as JA3/JA4-like fingerprints if rustls/boring
    expose enough ClientHello detail safely;
  - WAF-lite/body inspection stays a separate WAF module, but load-balancer
    routing should be able to consume an allow/deny/risk decision from WAF,
    auth-request, or future Wasm policy.
- Programmability:
  - `1.5` defines stable load-balancer hook points and typed context for future
    iRules-like Wasm policy;
  - actual Wasm execution belongs to the shared `1.6` runtime so Fluxheim does
    not grow one-off scripting engines;
  - hooks should cover pool selection, persistence-key choice, request deny,
    header mutation, mirror/shadow target choice, and circuit/policy metadata.
- Load-balancer observability:
  - Prometheus and OpenTelemetry counters/histograms for selected upstream,
    health transitions, retries, redispatches, ejections, all-down responses,
    in-flight requests, queue time, selected algorithm, circuit state,
    persistence hits/misses, slow-start state, and latency;
  - admin status for each pool/upstream with health state, active traffic,
    queue depth, last error, last transition, circuit state, persistence table
    size, and drain/maintenance state;
  - optional local Unix-socket status from the `1.4` proxy operations layer.
- Runtime/reload behavior:
  - config validation catches duplicate upstream names, invalid weights,
    impossible thresholds, and unsafe hash/header keys;
  - graceful reload keeps serving with the old pool until the new pool is
    validated;
  - health-check background services, persistence tables, and dynamic pool
    state are included in reload impact classification.
- Migration docs mapping common HAProxy and nginx upstream concepts to Fluxheim
  config, plus F5-style monitors, persistence, priority groups, and iRules
  equivalents to Fluxheim config or future Wasm hooks.

Beta scope:

- Dynamic service discovery beyond static config and normal DNS resolution,
  using Pingora's service-discovery interface when it can be tested reliably.
- Weighted random two-choice as a distributed-load-balancer policy.
- Direct Server Return / transparent proxying after Linux routing, source
  address, NAT/SNAT, and observability constraints are documented and tested.
- Cross-node persistence-table replication.
- Global server load balancing (GSLB) / DNS-based traffic steering.
- Deep packet inspection and App-ID-like classification. This is a security
  platform feature, not a basic load-balancer feature; treat it as WAF/security
  policy integration unless a separate design exists.
- Live traffic visualizer UI. Metrics and admin API are stable first; a UI can
  layer on top later.

Exit criteria:

- `--features proxy,load-balancer` release build passes.
- Health check transitions are tested.
- Failover, retry, redispatch, all-down, backup, priority group, drain,
  manual-resume, slow-start, circuit breaking, adaptive health, persistence,
  and queue-overflow behavior are documented and smoke tested.
- Load-balancer metrics are available when `metrics` is enabled.
- OpenTelemetry attributes use low-cardinality pool/upstream names only and do
  not expose raw URLs, headers, cookies, or request bodies.
- HAProxy/nginx migration fixtures cover weighted round-robin, backup servers,
  least-connections, hash/consistent-hash routing, health-check failure,
  redispatch, and all-down behavior.
- F5-style migration fixtures cover monitor-driven down/up transitions,
  priority groups, persistence, manual drain/resume, slow-start, and
  iRules-equivalent hook-point documentation.
- Security integration tests prove rate limits, mTLS identity inputs, and
  reputation/Geo/IP-set decisions fail closed at trust boundaries.

### Cache Maturity Follow-Ups

Goal: add controlled image/static caching.

Status: mostly promoted into the 1.2 Operations And Cache Completion Pack. Keep
this section as the cache maturity checklist and move completed items upward as
they land.

Current implementation status:

- Implemented in the current 1.2 development line:
  - memory, disk, and tiered memory+disk Pingora cache storage;
  - route-scoped cache policies for selective production paths such as
    repository avatars/assets;
  - method, extension, content-type, query participation, cache-key namespace,
    and cache-key-part controls;
  - positive and negative status TTLs, optional origin freshness override,
    `stale-if-error`, and `stale-while-revalidate` windows;
  - configurable cache locks for request collapsing across memory, disk, and
    tiered cache policies;
  - shared-cache safety controls for `Set-Cookie`, request bypass headers,
    request bypass cookies, request bypass query parameters, response-header
    hiding, origin `Cache-Control`/`Expires` override, explicit `Vary`
    request-header keys, and unsafe/sensitive `Vary` rejection. Full proxy
    smoke coverage now verifies configured request-header, header-value,
    cookie-name, cookie-value, query-param, and query-value bypasses expose the
    expected bounded `BYPASS` reasons and do not poison an existing public GET
    object;
  - optional cache-status and cache-status-reason response headers;
  - protected admin cache status, activity reset, single purge, bulk purge,
    indexed scope purge, prefix purge, tag purge, wildcard purge, stale purge,
    soft purge, and bounded purge batching endpoints;
  - per-vhost and per-route admin status for storage tiers, storage pressure,
    purge metadata coverage, activity counters, hit/miss/store/refusal/eviction
    ratios, configured route count, cache-policy route count, and cache-route
    coverage ratio;
  - live-object purge metadata indexes for memory and disk tiers;
  - process-wide opt-in background stale disk purger;
  - `fluxheim cache-warm` path warming through the normal local listener with
    2xx/3xx success accounting and explicit `--allow-status` overrides for
    deliberate negative-cache warming, plus optional cache-status header
    expectations, per-target repeat sequences, dry-run target validation, and
    bounded summary counts for response statuses, cache-status values, and
    failure reasons;
  - Prometheus cache activity metrics and initial OTLP metrics export.
    Prometheus also reports cache-lock-enabled policy count so request
    collapsing coverage is visible without high-cardinality labels. Cache admin
    status responses expose per-policy cache-lock wait timeouts, and
    Prometheus reports the maximum configured cache-lock wait timeout as a
    low-cardinality gauge. The
    policy-level pass/bypass/stale counters show configured scoped cache
    decisions without exposing request-specific labels. The proxy cache smoke
    suite now asserts bounded Prometheus purge counters and cache activity
    counters for disk hits, scoped purge events, policy bypasses, and allowed
    stale serving, while the local observability smoke asserts cache policy
    gauges and request-collapsing lock timeout gauges.
  - Pingora cache primitives already used directly or through adapters:
    `Storage`, `HandleHit`, `HandleMiss`, `CacheLock`, cache phase/reason
    reporting, variance keys for `Vary`, stale metadata, and bounded
    forced-freshness through `ForcedFreshness::ForceExpired` when operators
    opt in with `allow_client_cache_refresh` and clients send refresh headers
    such as `Cache-Control: no-cache`, `max-age=0`, or `Pragma: no-cache`.
    Pingora's cacheability predictor is now available as an explicit opt-in
    policy through
    `[cache.predictor]`, `[vhosts.cache.predictor]`, and
    `[vhosts.routes.cache.predictor]`, with Fluxheim custom policy reasons
    skipped so configured bypass/refusal counters remain authoritative.
    Direct `CachePut`-style preload is useful but can land after
    the loopback `cache-warm` path because it is an operator convenience, not
    a correctness prerequisite. `HttpCacheDigest` lock/lookup timing is now
    exposed as Prometheus histograms, included in OTLP metrics export, and
    attached to OTLP request trace spans together with the bounded cache phase.

Stable scope for declaring the cache pack complete:

- Memory cache with global and per-vhost size limits.
- Disk cache with global and per-vhost directory/size limits.
- Tiered memory+disk cache.
- Full cache-header semantics for static and proxied cacheable responses:
  `Cache-Control`, `Expires`, `ETag`, `Last-Modified`, `Vary`, `Age`,
  `Accept-Ranges`, `If-None-Match`, `If-Modified-Since`, request
  `Cache-Control`, `Pragma`, `Range`, and `If-Range`.
- User-configurable browser/CDN cache headers through global and per-vhost
  header policy.
- Route-scoped reverse-proxy cache policy for common gateway migrations,
  including path matchers for static upstream paths, operator-controlled cache
  keys, positive/negative status TTLs, stale-on-error behavior, cache-lock
  request collapsing, upstream `Cache-Control`/`Expires` override controls,
  response-header hiding for `Set-Cookie`, and optional cache-status response
  headers.
- Protected purge/status endpoints if admin module is enabled.
- Cache activity counters.
- Background/incremental cache cleanup with bounded work per tick and clear
  pressure metrics.
- Cache warm and metadata/debug commands suitable for release deploys and
  production incident response.
- Proxy cache HIT `Age`, conditional `304`/`200` validator match and mismatch
  behavior from `ETag` and `Last-Modified`, byte-range `206`, ETag/date
  `If-Range` match/mismatch behavior, cache-status HIT headers on cached
  conditional/range responses, HEAD probes that do not poison cached GET
  bodies, `Vary` variant isolation,
  stale-while-revalidate serving during background refresh,
  stale-if-error serving after upstream failure, cache-lock request collapsing
  for concurrent misses, disk HIT after restart, client refresh revalidation,
  and no-store request-bypass reason behavior are covered end to end. Admin
  exact/bulk purge, stale dry-run, tag purge, prefix purge, wildcard purge, and
  route-scoped purge are smoke tested against real cached objects after
  restart, with bounded Prometheus purge counters asserted for every protected
  purge shape in that smoke path.
- Proxied cache revalidation refreshes metadata safely when origins return
  `304 Not Modified`. Freshness metadata, `ETag`, and changed `Last-Modified`
  values are covered in the current smoke suite. Changed `Vary` values on 304
  are detected and treated as a refused revalidation metadata update so
  existing variant metadata is preserved; full changed-`Vary` re-keying remains
  a Pingora-path follow-up.
- `scripts/stable_release_gate.sh` runs the promoted proxy-cache and local
  observability smoke suites before a `1.2` stable release.

Focused cache-only follow-up releases after 1.2:

- `1.2.1`: opt-in local/static vhost caching. This release has one job: make
  Fluxheim's cache model consistent for operators who expect local `[vhosts.web]`
  and route-scoped web actions to participate in the same cache controls as
  proxied content. The local static-file cache supports whole-vhost and
  route-scoped web actions, prefers memory caching first to avoid duplicating
  local files on disk, keys by request identity plus canonical static file
  identity metadata, keeps the existing symlink/traversal protections, and
  exposes optional static cache-status and `Age` headers.
- `1.2.2`: optional slab/bin disk storage backend for large, high-churn caches.
  This release has one job: evaluate and, if safe, add a storage-bin backend
  that pre-allocates large data files, stores objects in fixed-size or classed
  extents, maintains a durable free map and object index, supports crash
  recovery and compaction, and exposes fragmentation/space-amplification
  metrics. The filesystem object backend stays the portable default until slab
  storage proves safer and faster in production tests. The `1.2.2` line adds
  the `cache.disk.backend = "storage-bin"` runtime backend after the allocator,
  durable index, recovery path, and operational hooks are in place.
- `1.2.3`: optional cache encryption at rest. This release has one job: add an
  opt-in cache encryption layer for disk cache objects, with key metadata
  designed alongside the storage-bin format. The default remains unencrypted and
  does not require OpenBao. The first implemented provider is a local file or
  systemd/container credential key source for small deployments. The OpenBao
  Transit provider supports regulated deployments that need centralized key
  custody, key versioning, and rotation while storing only Transit ciphertext in
  the cache backend. The cache object format records key id/version, nonce or
  Transit ciphertext marker, ciphertext length, and authenticated-data scope so
  objects cannot be swapped between cache keys. The release includes validated
  local-key and OpenBao example configs, local-key release-gate smoke coverage,
  and an optional Podman/OpenBao Transit smoke path.
- `1.2.4`: distributed cache metadata and peer-fill. This release has one job:
  implement the first safe multi-node cache coherence model for clustered
  deployments, including peer-fill limits, failure behavior, metrics, and clear
  isolation between vhosts/routes. The release adds the `[cache.peer_fill]`
  config contract with bounded peer lists, explicit timeouts, fail-open
  behavior, and safe peer-origin validation. It also adds the safe
  `Cache-Control: only-if-cached` local-cache response path so peer fill can ask
  another node for a fresh cached object without causing that node to contact
  origin. Outbound peer-fill uses that path on local proxy-cache misses, stores
  valid peer hits locally, applies `fail_open` to decide whether a peer miss
  falls back to origin, preserves peer `Age`, stores `Vary` variants correctly,
  and is covered by a local multi-node smoke test.
- `1.2.5`: focused bounded range-cache follow-up for large proxy-cache objects.
  This release adds opt-in caching for safe single `Range: bytes=start-end`
  proxy requests, stores range responses under range-specific cache keys, and
  admits only matching upstream `206` responses with correct `Content-Range`
  and `Content-Length`. It also rejects unkeyed upstream `206` responses from
  the full-object cache so partial responses cannot poison complete-object
  entries.
- `1.2.6`: focused fixed-slice range-cache follow-up. This release adds
  opt-in slice composition for large proxy-cache objects, including bounded,
  open-ended, suffix, and multipart byte-range responses from fresh compatible
  slices, plus bounded missing-slice fill and per-slice request collapsing.

Cross-cutting packaging follow-up for the next suitable `1.2.x` or `1.3`
release: add proper manual pages for native deployments, including
`fluxheim(8)`, `fluxheim.toml(5)`, ACME, cache, snapshot, reload/rollback, and
config-validation workflows. The RPM should install the generated/static man
pages into the distro manpath and the package checks should verify they are
present.

Exit criteria:

- Cache cannot exceed configured memory/disk budgets.
- Cache keys are collision-resistant and vhost-isolated.
- Operators can explicitly decide whether the query string participates in
  route-scoped static cache keys.
- Operators can set a cache key namespace per cache policy to intentionally
  isolate old and new route-cache contents without URL changes.
- Cache request-collapsing lock enablement and timeouts are configurable per
  cache policy. This is the cache-stampede protection path: one request for an
  uncached or expired key gets the origin writer permit while matching readers
  wait for the fill up to the configured timeout.
- Protected cache purge endpoints can target route-scoped cache policies by
  route name.
- Protected cache purge responses identify each requested host/method/path/query
  alongside the selected vhost/route and per-tier result, so production bulk
  purges are auditable.
- Cache respects method/content-type policy and request/response cache
  directives.
- `Vary` handling is tested before negotiated variants are stable. Implemented
  initially with Pingora cache variance keys and unsafe/sensitive `Vary`
  rejection.
- Shared cache admission refuses `Set-Cookie` responses.
- Route-scoped proxy cache cannot leak personalized responses: upstream
  `Set-Cookie` stripping and cache-header override controls require explicit
  config, are tested only on matched paths, and are documented with Forgejo-like
  static asset examples before being called stable.
- Route-scoped proxy cache can bypass lookup and storage when configured
  request headers such as `Cookie` or `Authorization` are present.
- Route-scoped proxy cache can explicitly include safe request headers such as
  `Accept-Encoding` in the cache variance key when the origin omits `Vary`.
- Origin `Cache-Control`/`Expires` override controls are explicit opt-ins and
  remain scoped to matched cache routes.
- Route-scoped proxy cache can opt into `stale-if-error` windows so stored
  static objects may be served during upstream failures after normal freshness
  expires.
- Route-scoped proxy cache can opt into `stale-while-revalidate` windows so
  stored static objects may be served while Fluxheim revalidates them in the
  background.
- Proxied static-cache admission stores `200 OK` origin responses only when
  both the request extension and response media type match cache policy;
  non-200 statuses are admitted only when explicitly listed in cache
  `status_ttls`.
- Cache hits emit correct validator/freshness behavior, including `Age` where
  Fluxheim serves from cache. Pingora provides the cache-hit `Age`,
  conditional, and range hooks; Fluxheim's smoke suite covers proxy cache HIT
  `Age`, conditional `304`/`200` validator match and mismatch behavior from
  `ETag` and `Last-Modified`, byte-range `206`, ETag/date `If-Range`
  match/mismatch behavior, cache-status HIT headers on cached conditional/range
  responses, HEAD probes that do not poison cached GET bodies, `Vary` variant
  isolation,
  stale-while-revalidate serving during background refresh, stale-if-error
  serving after upstream failure, cache-lock request collapsing for concurrent
  misses, disk HIT after restart, admin exact/bulk purge, stale dry-run, vhost
  prefix/tag/wildcard purge, route-scoped purge against real cached objects, and
  Prometheus purge counters for each protected purge shape, plus
  `Cache-Control`/`Pragma` refresh and bypass reason headers.
- HEAD requests intentionally bypass cache storage with the bounded
  `method-head` reason in `1.2`; full HEAD-to-GET cache parity is deferred to
  beta/future compatibility work.
- Purge endpoints require admin protection and remove all stored `Vary`
  variants for the selected cache identity.

### 1.6 - WASM Extensibility

Goal: add one shared sandboxed extension runtime for nginx-Lua-style operator
logic and VCL-like cache policy decisions, instead of creating separate
partial extension systems for cache, proxy, WAF, or media features.

Stable scope:

- Compile-time `wasm` module.
- Plugin loading from approved directories with strict path, ownership, and
  symlink validation.
- Wasmtime-based sandbox evaluation after license/advisory review.
- Request header hook.
- Response header hook.
- Access-control hook returning allow, deny, or continue.
- Cache-policy hooks inspired by VCL, but designed as a constrained Rust/Wasm
  ABI rather than an embedded language:
  - lookup/admission hook for bypass, pass, continue, or deny decisions;
  - safe cache-key component hook with typed inputs and explicit
    low-cardinality output limits;
  - `put_object`/store-admission hook for response-header inspection,
    TTL override, tag assignment, and header mutation;
  - invalidation hook for metadata predicates after the declarative 1.2 ban
    model is proven;
  - all cache hooks must be bounded by fuel, wall time, memory, output size,
    and deterministic failure behavior.
- Strict module, memory, fuel, wall-time, log, mutation, synthetic response,
  and concurrency limits.
- Plugin hashing and admin/metrics visibility when those modules are enabled.

Beta scope:

- Compile-time `wasm-proxy-abi` compatibility path.
- Per-vhost and per-route plugin chains.
- WASM-powered policy hooks for media, auth, WAF, or logging redaction.

Experimental scope:

- `wasm-wasi` with explicit capability grants.
- Streaming body hooks.

Exit criteria:

- WASM features are absent from default and privacy builds.
- Symlinked plugin files and symlinked parents are rejected.
- Unsupported ABI and host calls fail deterministically.
- Fuel exhaustion, timeout, trap, and plugin panic behavior is tested.
- Plugins cannot access bodies, filesystem, network, env, admin APIs, cache
  internals, or secrets without explicit capability grants.
- Plugins cannot directly control routing destinations or upstream TLS
  verification. Cache-key influence is allowed only through the constrained
  cache hook ABI with typed inputs, configured output limits, and explicit
  operator opt-in per vhost or route.

### 1.7 - Compression Pack

Goal: add safe, opt-in response compression without blocking request workers or
breaking cache correctness.

Stable scope:

- Compile-time `compression` module.
- `zstd` and `br` negotiation where client support and route policy allow it.
- `gzip` compatibility fallback.
- Conservative MIME/content eligibility rules.
- `Vary: Accept-Encoding` handling and cache-key isolation.
- Resource limits for input size, buffered size, level, and concurrency.
- Bounded offload for expensive compression work.

Beta scope:

- Precompressed static asset discovery.
- Hardware or CPU-specific acceleration.
- Shared dictionary compression if standards and client support are mature.

Exit criteria:

- Compressed and identity variants are cache-isolated.
- Already-compressed formats and `Cache-Control: no-transform` responses are
  not compressed.
- Personalized/sensitive responses are excluded by default.
- Downstream disconnects cancel or stop compression work.
- Default and `privacy-mode` builds prove compression is absent.

### 1.8 - Media Transform Pack

Goal: add safe, opt-in image transformation for static and proxied image
responses.

Stable scope:

- Compile-time `image-filter` module.
- Per-vhost/per-route image transform policies.
- Image validation and metadata reporting.
- Resize, crop, and rotate by fixed safe angles.
- JPEG/PNG/GIF/WebP input support after codec review.
- JPEG/PNG/WebP output support after codec review.
- Metadata stripping by default.
- Hard limits for input bytes, decoded pixels, output bytes, dimensions,
  timeout, and concurrency.
- Transform cache-key isolation when `cache` is enabled.

Beta scope:

- AVIF input/output.
- Sharpen/blur/grayscale transforms.
- Animated image preservation.

Exit criteria:

- Default builds do not include image filtering.
- Codec dependencies pass license and advisory policy.
- Decode-bomb, malformed-image, timeout, and concurrency tests pass.
- Transformed variants are isolated by vhost, source, transform policy, output
  format, dimensions, quality, and `Accept` bucket.
- `privacy-mode` rejects incompatible transform/cache combinations.

### 1.9 - Advanced Certificate Automation

Goal: extend the `1.1` certificate lifecycle with provider-specific and
zero-downtime automation that is too broad for the first ACME release.

Stable scope:

- Zero-downtime certificate reload through the runtime/snapshot model if it was
  not promoted in `1.1`.
- DNS-01 support for wildcard certificates if a safe provider interface exists.
- Certificate deployment hooks for external secret stores.

Beta scope:

- Cloudflare Origin CA automation behind `cloudflare-origin-ca`.
- Additional ACME providers with non-standard account or challenge behavior.

Exit criteria:

- Renewal failure does not drop active traffic.
- Private key storage permissions are validated.
- Tests cover renewal scheduling and reload classification.

### 1.10 - Privacy And Security Profiles

Goal: provide explicit security/privacy build profiles.

Stable scope:

- `privacy-mode` zero-retention build profile.
- Compile-time incompatibility guards.
- No access logs, request metrics, disk cache, WAF audit logs, or client-IP
  forwarding in privacy builds.
- Hardened filesystem trust checks inspect sensitive path ownership and write
  permissions consistently across config, TLS, ACME, admin token, snapshot,
  process, log, and cache paths. POSIX ACL inspection is tracked here as the
  next strict-profile hardening step after mode-bit enforcement.

Beta scope:

- Native WAF header/body scoring behind `waf-native`.

Exit criteria:

- Privacy build proves metrics/logging exporters are absent.
- Forwarded IP headers are stripped in privacy mode.
- WAF is dry-run capable and redacts secrets before beta promotion.

### 1.11 - Cloudflare Origin Pack

Goal: support Cloudflare as a verified trusted peer.

Stable scope:

- Trusted Cloudflare IP range loading.
- Safe real-IP restoration only after trust validation.
- Ray ID log correlation.
- Optional IP range refresh with last-known-good fallback.
- Integration with the future trusted-client identity layer when that layer
  exists, while still keeping Cloudflare support compile-time optional.

Beta scope:

- AOP/mTLS automation.
- Origin CA automation if not stabilized in `1.9`.

Exit criteria:

- Spoofed `CF-*` headers from non-Cloudflare peers are ignored.
- API tokens are never logged.
- AOP mode clearly distinguishes global, zone-level, and per-hostname trust.

### 1.12 - Trusted Client Identity Layer

Goal: make restored client identity safe, auditable, and reusable across load
balancers, private gateways, and provider packs.

Stable scope:

- Typed request identity context with separate direct peer IP, trusted proxy
  chain, restored client IP, and provider metadata.
- Explicit trusted-client profiles with CIDRs, selected headers, recursive
  chain traversal, and `max_hops`.
- Last-untrusted-hop selection for multi-proxy `X-Forwarded-For` chains.
- Config validation for ambiguous or unsafe trust policies.

Beta scope:

- Provider-managed trusted ranges with background refresh and last-known-good
  fallback.
- Proxy Protocol v2 listener support with bounded TLV metadata allow-lists.
- Optional local Geo/ASN/threat metadata enrichment.

Exit criteria:

- Spoofed forwarded headers from untrusted peers are ignored.
- Malformed or oversized forwarding chains are rejected or ignored safely.
- Direct peer, restored client IP, and chain metadata remain separately
  inspectable in tests.
- Provider range refresh failure keeps the last valid set and reports health.
- Proxy Protocol v2 framing is tested independently from normal HTTP
  listeners.
- Privacy builds reject real-client restoration and IP enrichment unless a
  no-retention design is implemented.

### 1.13 - Advanced Metrics And Logging

Goal: add richer observability without hurting the request path.

Stable scope:

- Advanced per-vhost metrics buckets.
- Cache/LB/admin/security counters.
- Bounded async logging dispatcher.
- Optional local file sink.
- Compile-time `otel-tracing` module.
- W3C Trace Context propagation.
- Trace-log correlation through structured log fields.
- Low-cardinality internal spans for vhost routing, request filtering, cache,
  upstream selection, upstream connect/response, and static file serving.
- Head-based probabilistic sampling.

Beta scope:

- Remote logging sink with circuit breaker.
- Production-grade `metrics-otlp` and `otel-otlp` exporter health, TLS/gRPC
  transport, histogram export, and collector failure metrics on top of the
  initial local HTTP exporters.
- Latency-aware and status-aware trace sampling.

Exit criteria:

- Remote sink failure never blocks request workers.
- Cardinality attack tests pass.
- Queue overflow behavior is explicit and tested.
- Malformed trace context is rejected or ignored without reflection.
- Trace IDs are propagated to upstreams and correlated in logs.
- Collector failure never blocks request workers.
- Sensitive span attributes are redacted.
- OpenTelemetry features are absent from default and privacy builds.

### 1.14 - Traffic Policy And Safety Pack

Goal: add declarative redirect/rewrite policy plus controlled release-safety
tools for operators who need to test new backends without changing
client-visible responses.

Stable scope:

- Declarative redirect rules for common permanent and temporary redirects.
- Declarative request rewrite rules with named matchers.
- Path-template rewrites without raw string concatenation.
- Config-load loop detection for internal rewrites.
- Per-vhost traffic mirroring for idempotent requests.
- Percentage-based sampling.
- Mirror timeout budgets isolated from the primary request.
- Mirror result counters when `metrics` is enabled.

Beta scope:

- Multi-pattern matcher compilation for large rule sets.
- Query-parameter merge, strip, and allow-list policies.
- WASM hook for complex rewrite decisions after the WASM sandbox is stable.
- Body redaction/transformation policies.
- Identity-claim based sampling if `identity` is enabled.
- Mirroring of non-idempotent methods with explicit operator opt-in.

Exit criteria:

- Rewrite cycles are rejected at config load.
- Redirect destinations are validated to prevent open redirects.
- Matcher tests cover host, path, method, header, and query conditions.
- Mirror failures never alter the live client response.
- Credentials and cookies are stripped unless explicitly allow-listed.
- Mirroring is incompatible with `privacy-mode`.
- Tests cover cancellation, timeout, sampling, and redaction behavior.

### 1.15 - External Authorization And Identity-Aware Routing

Goal: enforce access decisions through a trusted authorization service first,
then add native identity verification and claim-aware routing.

Stable scope:

- Compile-time `auth-request` module.
- Per-vhost/per-route authorization probes.
- Global auth zones that protect a vhost by default with explicit route/path
  exclusions.
- Decision handling: allow on `2xx`, deny on `401`/`403`, and treat every other
  auth service status as an error.
- Fail-closed default with explicit `fail_open` opt-in.
- Header allow-lists for auth request metadata, auth response headers copied to
  upstreams, and challenge headers copied to clients.
- Auth backend timeouts and response-size limits.
- HTTPS and Unix-domain-socket auth hooks.
- Compile-time `identity-oidc` module.
- OIDC discovery and JWKS caching.
- JWT issuer, audience, expiry, and algorithm validation.
- Per-vhost claim-based allow/deny/routing policy.
- Verified header injection after stripping spoofable inbound identity headers.
- Configured browser login redirects and API/AJAX denial responses.
- Compile-time `secure-links` module for signed URL grants.
- HMAC and Ed25519 verification for signed route access.
- Expiry, path, method, audience, and route-claim validation.
- Redaction for secure-link tokens in logs and errors.

Beta scope:

- Optional auth-decision caching with bounded positive/negative TTLs.
- Auth backend mTLS.
- gRPC authorization hooks.
- OAuth2 token introspection.
- Tenant/subscription-tier based upstream pool selection.
- Replay/usage controls for signed links when an explicit state backend is
  available.

Exit criteria:

- Auth requests are absent from default builds and incompatible with
  `privacy-mode`.
- Auth loops are rejected by config validation.
- `2xx`, `401`, `403`, error-status, timeout, and response-size behavior are
  tested.
- Spoofable identity and forwarding headers are stripped before auth decisions.
- Raw tokens are never logged.
- Token and JWKS sizes are bounded.
- Key rotation and stale-key behavior are tested.
- Spoofed identity headers are stripped before verified replacements are added.
- Global auth zones are tested so protected vhosts cannot accidentally expose a
  route through missing per-route auth config.
- Browser redirect return destinations are normalized and validated.
- Signed links reject expired, malformed, wrong-path, wrong-method, and
  wrong-audience tokens.
- Signed-link tokens and decoded claims are redacted from logs and errors.

### 1.16 - Cluster State

Goal: let Fluxheim nodes share selected operational and security state without
requiring external infrastructure for the first useful cases.

Stable scope:

- Compile-time `cluster-state` module.
- Authenticated peer identity and transport.
- Version negotiation.
- Gossip-style replication for low-risk state such as blocklists, drain state,
  backend health hints, and coarse counters.
- Admin/metrics visibility into cluster health.

Beta scope:

- Strict global rate-limit leases.
- Consensus-backed state for policies that cannot safely diverge.

Exit criteria:

- State replication never appears in default or privacy builds.
- Split-brain, clock-skew, restart, and downgrade tests pass.
- Replicated state avoids raw paths, queries, cookies, authorization headers,
  user agents, and client IPs unless an explicit non-privacy policy allows it.
- Global rate limits document whether they are `local_only`, `eventual`, or
  `strict`.

### 1.17 - AI Gateway

Goal: add AI-aware proxy controls for cost, safety, and cacheability where
operators explicitly opt in.

Stable scope:

- Compile-time `ai-gateway` module.
- Model allow-lists and per-vhost model routing.
- Provider API key redaction.
- Request/body limits for AI routes.
- Token accounting from provider usage metadata where available.

Beta scope:

- Token-estimation fallback for providers without usage metadata.
- Token-per-minute and tenant quota enforcement.
- Prompt-guard dry-run scoring.

Experimental scope:

- Semantic response caching through vector similarity.

Exit criteria:

- Prompt and response logging is redacted by default.
- Cache entries are isolated by vhost, tenant, model, and policy version.
- Semantic caching is opt-in per route and refuses sensitive/private contexts by
  default.
- Tests cover token budgets, provider metadata parsing, redaction, cache
  isolation, and default/privacy build absence.

### 1.18 - Sentinel Mesh

Goal: graduate the encrypted gateway-to-backend tunnel design into a supported
small-cluster routing module.

Stable scope:

- Compile-time `sentinel-mesh` module.
- Authenticated node identity.
- Encrypted gateway-to-backend transport policy.
- Signed backend health/load telemetry.
- Smart load-balancer selection from verified telemetry.

Beta scope:

- Userspace WireGuard transport for rootless deployments.
- Multi-datacenter route policy.

Exit criteria:

- Wrong-peer, stale-telemetry, tunnel-restart, and failover tests pass.
- No plaintext fallback exists unless explicitly configured.
- Rootless Podman smoke coverage exists for the supported transport.
- Mesh code is absent from default and privacy builds.

### 1.19 - Optional Host Sandbox Module

Goal: provide an opt-in in-process Linux sandbox for deployments that cannot
rely only on systemd or container runtime policy.

Research scope:

- Compile-time `host-sandbox` module family, disabled by default.
- Linux-only subfeatures such as `host-sandbox-seccomp` and
  `host-sandbox-landlock`.
- Apply the sandbox only after config parsing, certificate loading, listener
  binding, and runtime directory setup are complete.
- Deny process creation and executable loading after initialization:
  `execve`, `execveat`, `fork`, `vfork`, and `clone` variants that create new
  processes.
- Landlock path policy for approved config, content, cache, log, runtime, and
  state roots.
- Compatibility mode for rootless containers and native systemd deployments.

Exit criteria:

- Sandbox features are absent from default builds until promoted and tested.
- A failed sandbox install must fail closed unless the operator explicitly
  configures report-only mode for testing.
- Tests cover normal static/proxy serving, denied process execution, denied
  unapproved path access, reload behavior, and container/native differences.
- Documentation states that systemd/container sandboxing remains the stable
  `1.0` boundary; in-process seccomp/Landlock is an additional hardening layer,
  not a replacement for least-privilege deployment.

### 2.0 - Remaining Dynamic Runtime Boundary

Goal: add non-PHP dynamic runtime features only after a deliberate major
boundary. PHP has moved into the `1.3.x` line because FastCGI/PHP-FPM support
is the highest-priority adoption blocker, but other process-execution runtimes
still need a separate threat-model boundary.

Candidate scope:

- Perl CGI with process isolation.

Reason for 2.0:

Arbitrary CGI and other process-launch runtimes change Fluxheim from a
proxy/static/PHP-FPM gateway into a broader application execution host. That is
a larger threat-model change than cache, load balancing, or certificate
automation.

Exit criteria:

- Runtime modules are compile-time optional and disabled by default.
- Process isolation is tested.
- Source files are never served as static fallback.
- Rootless Podman examples exist for every runtime.

### 1.9 - Crypto RPC Edge

Goal: add a compile-time optional crypto RPC edge family for blockchain-aware
JSON-RPC/WebSocket proxying, safe POST-body caching, and node-health-aware
routing. Ethereum/EVM should be the first concrete implementation because it has
the strongest dApp fit and a comparatively standard HTTP/WebSocket JSON-RPC
surface. Bitcoin, Cardano, and XRPL should be documented as later chain-specific
modules, not forced into the Ethereum policy model.

This is a future module family after the web, PHP, proxy, load-balancer, and
WASM foundations have enough stability to support chain-specific edge gateways
without weakening the default build.

Shared family shape:

```toml
chain-edge-core = ["proxy", "cache", "dep:serde_json", "dep:sha2"]
eth = ["chain-edge-core"]
eth-verify = ["eth"] # future proof-verification/co-processing review
btc = ["chain-edge-core"] # future review
ada = ["chain-edge-core"] # future review
xrpl = ["chain-edge-core"] # future review
```

`chain-edge-core` should contain only bounded shared primitives: JSON-RPC
parsing, batch limits, method policy dispatch, cache-key helpers, upstream
health snapshots, retry safety classification, redacted logging/tracing helpers,
and WebSocket sticky-routing primitives. It must not contain chain-specific
method allow-lists or finality rules.

First implementation feature shape:

```toml
eth = ["proxy", "cache", "dep:serde_json", "dep:sha2"]
eth-ens = ["eth"] # future review; exact dependencies intentionally undecided
eth-verify = ["eth"] # future proof-verification/co-processing review
profile-ethereum-rpc = ["proxy", "cache", "eth", "tls-rustls", "security"]
```

The first implementation should focus on native Ethereum JSON-RPC proxy/cache
behavior. ENS routing is documented for later review as `eth-ens`, but should
not block or expand the initial `eth` scope.

Stable Ethereum `eth` scope:

- HTTP JSON-RPC `POST` pass-through with bounded body, response, method, and
  batch limits.
- JSON-RPC 2.0 single-call and batch classifier.
- Chain-id verification with `eth_chainId` before serving traffic.
- Health probes using `eth_blockNumber`, `eth_syncing`, and finalized/safe
  block data when available.
- Upstream ejection or de-prioritization for syncing nodes, stale nodes, chain
  mismatch, repeated transport failures, and selected read-only JSON-RPC error
  classes.
- Conservative retry only for read-only calls; no default retry for
  transaction submission or signing/account methods.
- Native cache-key generation for Ethereum JSON-RPC POST requests.
- Cache admission only for whitelisted immutable/finality-safe methods.
- Cache integration with existing memory/disk cache backends and cache metrics.
- Multi-provider upstream routing so applications are not dependent on one
  centralized RPC provider. Operators should be able to mix local nodes,
  community nodes, and hosted providers, with explicit failover and optional
  quorum/compare modes for high-value reads.
- Censorship-resistance controls that can detect repeated provider-side
  denials, lag, or method-specific failures and move read traffic to healthier
  upstreams without client-side code changes.
- Redacted logging and tracing that records method and policy decisions but not
  full params or responses by default.
- Privacy-preserving RPC modes should be researched as a separate beta track:
  request metadata minimization, no body/param logging, optional cache-only
  answers for immutable data, client IP/header stripping before upstream, and
  future relay/blind-query designs. Fluxheim must not claim full verifiable
  anonymization until the design can prove the gateway cannot link requester,
  query, and response.

Initial cacheable method candidates:

- `eth_getBlockByHash`;
- `eth_getBlockByNumber` for explicit old block numbers, `safe`, or
  `finalized`;
- `eth_getBlockTransactionCountByHash`;
- `eth_getBlockTransactionCountByNumber` under the same block-number policy;
- `eth_getTransactionByHash` with conservative TTL/negative-cache controls;
- `eth_getTransactionReceipt`, with long TTL only after the containing block is
  known finalized;
- `eth_getLogs` only for bounded ranges entirely finalized or older than the
  configured finality depth.

Do not cache in the initial stable module:

- `latest` or `pending` requests unless a later explicit short-TTL policy is
  designed;
- `eth_sendRawTransaction`, signing methods, account methods, txpool/debug/admin
  namespaces, or any method with side effects;
- `eth_call`, `eth_estimateGas`, fee methods, or gas-price methods until a
  method-specific block-tag/TTL policy exists;
- WebSocket subscriptions.

Beta scope:

- WebSocket pass-through with sticky upstream selection.
- `eth_subscribe` health-aware placement for new sessions.
- Hosted-provider fallback with quota-aware routing.
- Quorum reads for selected immutable methods, comparing responses from two or
  more upstreams before caching or returning high-assurance data.
- Privacy-preserving relay mode for JSON-RPC reads after a threat-model review.
- Proof-verification co-processing behind `eth-verify`, including
  `eth_getProof`/Merkle-Patricia proof checks, light-client header validation,
  and later ZK proof verification where mature libraries exist.
- More method-specific cache policies after production traces prove safe
  behavior.

Future `eth-verify` review:

- Verify selected blockchain-derived data at the edge before returning or
  caching it.
- Use account/storage proofs, transaction/receipt inclusion checks, or
  Helios-style light-client state instead of trusting a single RPC provider.
- Keep proof engines behind a separate compile-time feature because trie,
  consensus, precompile, and ZK dependencies are too heavy for a normal RPC
  cache/proxy build.
- Bound proof bytes, trie depth, verification time, worker concurrency, and
  cache metadata size.
- Fail closed for protected methods when proof verification fails, checkpoints
  are stale, or the provider response does not match the verified state root.
- Treat privacy as a separate design problem: proof requests can reveal the
  account, storage key, or contract state being queried unless combined with a
  stronger relay/blinding design.

Future `eth-ens` review:

- Resolve ENS registry/resolver records through Ethereum RPC.
- Read and decode resolver `contenthash()` records.
- Proxy or redirect IPFS/Arweave content through configured gateways.
- Cache resolver/contenthash answers with block/finality awareness.
- Explicitly document browser and TLS limitations: browsers do not normally
  resolve raw `.eth` names through DNS, public ACME does not issue for raw
  `.eth`, and Fluxheim can route `.eth` hosts only when traffic reaches it with
  that Host header or through a gateway-domain pattern.

Future `btc` review:

- Bitcoin Core JSON-RPC proxy/cache for selected chain methods.
- Confirmation-depth-based cache safety instead of Ethereum `finalized`/`safe`
  tags.
- Candidate cached methods: `getblockhash`, `getblock`, `getblockheader`, and
  carefully gated `getrawtransaction`.
- Wallet, mining, raw transaction submission, and node/admin methods denied by
  default or explicitly pass-through only.
- Pruned-node and `txindex` behavior documented before any cache claims.

Future `ada` review:

- Cardano support should likely target Ogmios first, or explicitly choose a
  higher-level provider API after review.
- Chain points, slots, epochs, rollbacks, and UTXO-state cache invalidation
  require Cardano-specific policy.
- Cache candidates include known-point block queries, transaction lookup,
  stable epoch protocol parameters, and selected UTXO queries tied to a known
  point.

Future `xrpl` review:

- XRPL HTTP JSON-RPC/WebSocket proxy/cache with ledger-aware routing.
- Validated ledger queries can be cache candidates; current/open ledger queries
  and subscriptions are not cacheable by default.
- Transaction submission stays non-retry/non-cache by default.
- Health probes should track validated ledger progress and full-history node
  behavior.

Exit criteria:

- Default, PHP, static-site, cache-edge, proxy-edge, privacy, and
  load-balancer builds prove crypto RPC modules are absent unless selected.
- `--features eth` and `profile-ethereum-rpc` release builds pass.
- Malformed JSON, oversized batches, unknown methods, cache-key limits, and
  oversized upstream responses are tested.
- `latest`, `pending`, side-effect, account, signing, debug/admin, and
  transaction-submission methods are not cached by default.
- Finalized/old-block responses are cached with deterministic cache keys and
  purge-compatible metadata.
- Chain-id mismatch and syncing/stale upstreams are rejected or ejected before
  serving normal traffic.
- Metrics avoid account, transaction, block, contract, calldata, and ENS-name
  label cardinality.
- Documentation includes Geth, Erigon, Reth, and hosted-provider examples.
- Documentation includes a decentralization and privacy threat model explaining
  what Fluxheim can protect, what it cannot protect, and why "verifiably
  anonymized" RPC needs more than ordinary reverse proxying.
- Later chain modules must ship their own method-safety matrix, finality model,
  health probes, and cache-admission tests before stable release.
- `eth-verify` cannot be promoted until default and `eth`-only builds prove
  verification dependencies are absent, malformed proofs fail safely, stale
  light-client checkpoints fail closed, and verified cache entries record the
  verified block/state-root context.

Detailed design lives in [Crypto RPC Edge](crypto-rpc-edge.md).

### Future - Dependency Reduction And Sovereign Core

Goal: after the main web, cache, PHP, proxy, load-balancer, and extension
surfaces are stable, reduce long-term dependency risk by moving bounded
Fluxheim-specific logic in-tree and hiding large external engines behind
Fluxheim-owned interfaces.

This is a far-future hardening track, not a reason to delay feature parity.
During `1.4` and `1.5`, new code should still be designed with this direction
in mind: keep dependency additions feature-gated, avoid exposing third-party
types in Fluxheim's public config/runtime boundaries, and prefer small local
implementations where the behavior is narrow and security-reviewable.

Good candidates:

- load-balancer selection algorithms and persistence tables;
- queue, overload, and circuit-breaker policy;
- cache indexing helpers and bounded metadata structures;
- header, rewrite, and variable evaluation helpers;
- release/build helper scripts where shell/Python dependencies can shrink.

Poor candidates until much later:

- TLS and cryptographic primitives;
- HTTP/2, HTTP/3, QUIC, and complex protocol state machines;
- async runtime internals;
- compression codecs and media/container parsers;
- mature parser libraries where replacement bugs would become security bugs.

Exit criteria before replacing a mature dependency:

- the replacement has fuzz/property tests where applicable;
- security behavior is documented and covered by malformed-input tests;
- performance and memory bounds match or improve the previous implementation;
- release notes explain the dependency removal and migration risk;
- the old implementation remains available behind a temporary feature gate when
  rollback risk is high.

### 2.1 - Programmable Media Edge

Goal: add media-aware manifest, segment, and personalization features only
after the cache, identity, metrics, and traffic-safety modules are mature.

Stable scope:

- Compile-time `media-edge` module.
- HLS manifest parser and safe rewrite engine.
- Segment URL normalization and escape rejection.
- Manifest size, segment count, variant count, and recursion limits.
- Segment-aware cache-key design for HLS/VOD and live-window policies.
- Media metrics with cardinality-safe labels.

Beta scope:

- DASH manifest parser after XML parser review.
- Dynamic manifest stitching through a trusted decision service.
- WASM policy plugins inside a strict sandbox.

Research scope:

- Forensic watermarking.
- TS/fMP4 segment mutation.
- Edge transmuxing and packaging.

Exit criteria:

- Media features are absent from default and privacy builds.
- Manifest parser fuzzing passes before beta.
- Segment cache keys isolate vhost, asset, representation, range, sequence,
  key ID, tenant/entitlement policy, and media policy version.
- Personalized URLs, tokens, entitlement claims, media keys, and raw manifests
  are redacted from logs.
- Stitched manifest failures cannot affect non-media routes.
- Any segment or bitstream mutation has parser fuzzing, codec/container
  compatibility tests, and a documented legal/privacy policy.

### Experimental-Only Tracks

These should not be promised in a stable minor until proven:

- HTTP/3/QUIC, including UDP listener ownership, `Alt-Svc` advertisement,
  replay-safe 0-RTT policy, and parity with the normal vhost/proxy/cache
  pipeline.
- Legacy HTTP/1.0 and HTTP/0.9 static listeners.
- Coraza/Proxy-Wasm WAF compatibility.
- Pure Rust PHP interpreter experiments.
- Strict cluster consensus for hard global quotas.
- Semantic AI response caching.
- Forensic video watermarking.
- Edge transmuxing and packaging.
- WASI capability plugins.
- Streaming body mutation through WASM.

## What Changes In Cargo Defaults

The `0.5` and `1.0` default feature set is intentionally narrowed to core
modules only:

```toml
default = ["proxy", "web", "cache", "tls-rustls", "security"]
```

Modules such as `load-balancer`, `acme`, `metrics`, `admin`,
`privacy-mode`, `image-filter`, `media-edge`, `wasm`, `waf`, `cloudflare`,
PHP, CGI, and legacy HTTP should be selected explicitly until their target
release graduates them.

The `1.3.0` feature graph starts splitting shared ingress/TLS from feature
families that happen to use it. `tls-rustls` no longer selects the full proxy
module by itself, and focused cache/proxy image profiles no longer compile
local static web serving. The current shared building blocks are:

```toml
ingress = ["dep:pingora", "dep:tokio", "dep:bytes", "dep:http"]
proxy = ["ingress", ...]
web = [...]
cache = [...]
load-balancer = ["proxy", ...] # transitional until the 1.5 load-balancer line
tls = ["ingress", "dep:rustix"]
tls-rustls = ["tls", "pingora/rustls", "dep:rustls", "rustls/ring"]
tls-rustls-fips = ["tls", "pingora/rustls", "dep:rustls", "rustls/fips"] # planned; provider-aware AWS-LC FIPS path
fips-required = [] # planned guard after backend/provider checks and internal crypto routing exist
acme = ["tls", ...]
```

The contract should not change: TLS and ACME are ingress capabilities, not
webserver capabilities. FIPS-capable TLS features should follow the same rule:
they are backend-specific ingress capabilities and must not pull in unrelated
web/cache/proxy/load-balancer behavior.

Grouped builds should be exposed as Cargo feature aliases, not a custom
`--group` flag. The initial profile aliases are `profile-core`,
`profile-static-site`, `profile-reverse-proxy`, `profile-cache-server`,
`profile-load-balancer`, `profile-observability`, and `profile-privacy`.

The first focused profile aliases are:

- `profile-web-server`: static/local web serving with TLS. In the initial
  `1.3.0` split this still selects the shared proxy runtime because static
  serving has not yet been separated from that ingress service.
- `profile-cache-edge`: cache server with TLS/ACME and proxy-cache transport,
  but no local static webserver behavior unless `web` is also selected.
- `profile-proxy-edge`: reverse proxy with TLS/ACME and advanced proxy
  controls, but no static web/cache/LB unless selected.
- `profile-load-balancer-edge`: load balancer with TLS/ACME and observability,
  but no static web/cache or single-upstream proxy extras unless selected.
- `profile-full`: convenience all-in profile for operators who want one binary
  with every stable production module.

Container image profiles follow the same names where the release line publishes
them:

- `full`: all stable production modules.
- `cache`: focused cache edge, TLS-capable, no local webserver by default.
- `proxy`: focused reverse proxy, TLS-capable.
- `load-balancer`: focused load balancer, TLS-capable; prepared and manually
  dispatchable in `1.3.0`, normally published once the `1.5` line promotes the
  runtime behavior.

The `profile-web-server` feature alias exists for native/custom builds. A
separate official web-only image can be added with the PHP line if it becomes
useful for operators.

Each focused image must have CI checks proving that unrelated modules are
absent from the binary feature set. Runtime config validation should reject
disabled module config with actionable errors such as "web module not compiled"
or "load-balancer module not compiled".

Package scripts that accept a raw `--features` value should run
`scripts/validate-features.sh` before Cargo. This catches unsupported feature
combinations, especially multiple TLS backends, before dependency compilation
reaches Pingora.

## Git Tags

Use signed annotated tags. This repository should have SSH signing configured
locally with `gpg.format=ssh`, `user.signingkey`, and `tag.gpgSign=true`; verify
with `git config --local --get tag.gpgSign`.

```bash
git tag -s v0.5.0 -m "Fluxheim 0.5.0"
git tag -v v0.5.0
git push origin v0.5.0

git tag -s v1.0.0 -m "Fluxheim 1.0.0"
git tag -v v1.0.0
git push origin v1.0.0
```

Patch releases should normally contain fixes only. The `1.2.x` cache line is
the exception while the cache server is being completed as a focused sequence:

- `v0.5.1`: security or bug fixes for the basic-sites preview.
- `v1.0.1`: security or bug fixes for stable core.
- `v1.1.1`: fixes for TLS policy hardening.
- `v1.2.1`: focused opt-in local static-file caching for whole vhosts or
  matched web routes.
- `v1.2.2`: focused slab/bin cache storage backend, if it proves safe enough
  after `1.2`.
- `v1.2.3`: focused optional cache encryption at rest with local-key support
  and OpenBao Transit provider support.
- `v1.2.4`: focused distributed cache metadata and peer-fill release.
- `v1.2.5`: focused bounded range-cache follow-up for large proxy-cache
  objects before `1.3`.
- `v1.2.6`: focused fixed-slice range-cache composition follow-up before
  `1.3`.
- `v1.3.1`: `php-fpm` FastCGI bridge.
- `v1.3.2`: ACME companion agent, zero-downtime first-issuance activation, and
  release-page config tester binaries.
- `v1.3.3`: focused php-fpm hardening and compatibility fixes.
- `v1.3.4`: embedded Rust PHP/Turbine-style integration if review passes.
- `v1.3.5`: pure-Rust PHP interpreter experiment behind `php-phprs`.
- `v1.4.1`: fixes for advanced proxy parity.
- `v1.5.1`: fixes for load balancer.
- `v1.6.1`: fixes for the shared Wasm extensibility runtime.

## Changelog Shape

Every release should include:

- stable features added;
- beta/experimental features included but not supported as stable;
- security fixes;
- dependency updates;
- migration notes;
- known limitations;
- exact release check command output summary.
