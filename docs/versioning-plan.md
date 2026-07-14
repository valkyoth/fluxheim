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
- Optional OpenSSL TLS builds when they pass the release matrix. BoringSSL and
  s2n were removed from the supported matrix in `1.5.4`.
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
- Downstream curve preferences and cipher-suite allow-lists for rustls and
  OpenSSL where the selected backend exposes enforceable listener controls.
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
    operations concerns are now in the 1.2 release line: the documented
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
- Make `tls`, `tls-rustls`, `tls-rustls-fips`, `tls-openssl`,
  `tls-openssl-fips`, `acme`, and `acme-client` depend on shared ingress/TLS
  primitives rather than implicitly selecting the generic `proxy` feature.
- Remove the incomplete/low-value `tls-boringssl` and `tls-s2n` backends from
  the future supported matrix. Rustls remains the default go-to backend; OpenSSL
  remains supported for operators who need OpenSSL integration or OpenSSL FIPS
  evidence.
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

The standalone operator and implementation reference is
[FIPS-Capable Deployments](fips.md). The `1.3.4` line completes the OpenSSL
FIPS-capable TLS path: terminology guardrails, compliance-boundary
documentation, crypto inventory, backend diagnostics, fail-closed TLS-policy
validation, OpenSSL provider proof, OpenSSL default FIPS property enablement,
and release evidence. Broader FIPS-required deployment readiness should remain
staged after `1.3.4`: rustls/AWS-LC FIPS after provider-aware rustls helpers
exist, and internal crypto closure before any broad FIPS-required profile is
recommended for production.

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
    AWS-LC FIPS provider path. The `1.3.5` candidate replaces ring-specific
    rustls helpers with provider-aware helpers, installs/passes
    `rustls::crypto::default_fips_provider()`, and fails startup if a
    FIPS-required generated `ServerConfig` does not report FIPS status. The
    feature routes builds to the AWS-LC FIPS crate path, documents the CMake,
    Go, and C compiler build requirements, and constrains configured rustls
    suites/groups through the Fluxheim FIPS TLS policy.
  - `tls-openssl-fips`: OpenSSL backend built and linked against OpenSSL 3.x
    with a validated FIPS provider. Operators remain responsible for installing
    the validated provider and running the provider setup expected by the
    module Security Policy, such as `openssl-fipsinstall` where applicable.
    Fluxheim should support an operator-supplied OpenSSL config path or
    environment contract, require provider/config diagnostics, and fail closed
    when FIPS-required mode cannot prove the FIPS provider/default properties
    are active. The `1.3.4` path proves provider availability with an explicit
    `fips=yes` fetch, enables OpenSSL default FIPS properties through a small
    local support crate, verifies those properties, and checks that a non-FIPS
    cipher is rejected through the default fetch path.
  - BoringSSL and s2n are not supported FIPS/ISO paths. The supported TLS
    matrix is rustls, rustls/AWS-LC FIPS, OpenSSL, and OpenSSL FIPS.
- Keep `tls.fips.required` as the high-level config guard and require
  backend-specific proof features underneath it. When enabled, non-FIPS TLS
  backends, non-FIPS cipher/curve choices, non-FIPS ACME/account crypto paths,
  and incompatible dependencies must fail validation instead of silently
  downgrading.
- Inventory internal cryptography before publishing FIPS profiles. Any
  security-sensitive operation outside TLS, including random request/session
  identifiers, admin token MACs, ACME/account signing, cache encryption,
  password hashing, CSRF/session/JWT support, and future plugin signing, must
  either route through the selected validated backend or be disabled/rejected in
  FIPS-required builds. Pure RustCrypto, ring, or other non-validated fallback
  paths cannot remain reachable for those operations in a FIPS-required binary.
- Add narrow FIPS/ISO profile aliases separately from default, cache, PHP, and
  load-balancer profiles so non-FIPS operators do not inherit OpenSSL or AWS-LC
  FIPS build/provider requirements. `profile-fips-openssl` and
  `profile-iso19790-openssl` ship with the `1.3.4` OpenSSL path;
  `tls-rustls-iso19790`, `profile-fips-rustls`, and
  `profile-iso19790-rustls` are part of the `1.3.5` rustls/AWS-LC candidate.
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

Post-`1.3.4` implementation ladder:

- `1.3.5`: rustls/AWS-LC FIPS candidate. Refactor current ring-specific rustls
  helpers into provider-aware helpers, use rustls' AWS-LC FIPS provider path,
  verify rustls FIPS status on provider/server configs, add rustls FIPS/ISO
  profiles and examples, and document AWS-LC FIPS build requirements and CMVP
  Security Policy evidence.
- `1.3.6`: internal crypto closure and compliance evidence package. Classify
  ACME, EAB, admin tokens,
  request IDs, temp names, cache encryption, OpenBao Transit, OTLP HTTPS, and
  future signing/session features as validated-backend-routed, externally
  evidenced, non-security-sensitive, or disabled in FIPS-required builds. The
  implementation routes admin bearer-token HMAC through OpenSSL FIPS or AWS-LC
  FIPS in the matching FIPS builds, rejects managed ACME, local cache
  encryption, and remote/HTTPS OTLP in FIPS/ISO-required configs, while
  allowing OpenBao Transit cache encryption only through local numeric loopback
  HTTP as an external evidence boundary and documenting request IDs/temp names
  as non-secret operational identifiers. Publish a repeatable release evidence
  template with SBOM notes, build command, module certificate, Security Policy,
  provider config, runtime crypto diagnostics, and scanner output checklist.
  Include Common Criteria evidence alignment from
  `common-criteria-roadmap.md`: candidate TOE boundary, Security Target-style
  draft, security-relevant interfaces, operational-environment assumptions,
  validation-script identifiers, and vulnerability-analysis records. This is
  an actionable evidence track, not a Common Criteria certification or EAL
  claim.

Follow-up `1.3.x` PHP runtime plan:

- `1.3.3`: php-fpm hardening and production compatibility fixes.
  - Connection pooling to php-fpm with idle pruning.
  - `fastcgi_keep_conn`-style reuse where the selected client/runtime can
    safely keep FastCGI connections open between requests, with stale-connection
    detection and a clear fallback to one request per connection.
  - True streaming request and response bodies. Request-body disk replay is in
    place for large PHP bodies; direct downstream-to-FastCGI and
    FastCGI-to-client streaming remain future work.
  - Chunked upload disk-spooling so large uploads do not require full RAM
    buffering before php-fpm receives `CONTENT_LENGTH`. Implemented with
    `php.request_body_spool_threshold_bytes` and
    `php.request_body_spool_dir`.
  - Custom FastCGI params in config. Implemented as validated
    `[vhosts.php.params]` / `[vhosts.routes.php.params]` tables that cannot
    override Fluxheim-managed CGI parameters.
  - Path mapping for separate Fluxheim/php-fpm container filesystem roots.
    Implemented as `php.fpm_root` for FastCGI `DOCUMENT_ROOT`,
    `SCRIPT_FILENAME`, and `PATH_TRANSLATED` mapping.
  - Caddy-style PHP root override and optional root-symlink resolution for
    split container layouts, while keeping Fluxheim's symlink escape checks.
    Implemented with `php.fpm_root` and default-off
    `php.resolve_root_symlink` for final-root symlinks.
  - NGINX/Caddy-style `try_files` PHP presets for common apps:
    static-file first, directory index, front-controller fallback, and explicit
    `=404` behavior for sites that must not route everything through
    `index.php`.
    Implemented as `php.try_files = "front-controller"`, `"wordpress"`, or
    `"strict"`.
    WordPress PHP-side migration defaults are also available as
    `php.preset = "wordpress"`, which combines WordPress front-controller
    behavior with deny prefixes for common upload/file execution paths.
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
    offload. Implemented with targets constrained under `php.root`,
    `X-Sendfile` mapped from `php.fpm_root` for split containers, and PHP
    script extensions refused as offload targets. `X-Accel-Expires` is
    initially implemented for PHP responses by stripping the backend control
    header, mapping valid TTLs to normal cache headers, treating zero or past
    expiries as `no-store`, and keeping cookie responses private.
  - `fastcgi_intercept_errors`-style integration with Fluxheim error pages for
    selected PHP statuses, keeping normal PHP responses untouched by default.
    Initial generic interception implemented as `php.intercept_error_statuses`;
    static fallback pages are supported with `[[vhosts.php.error_pages]]` and
    `[[vhosts.routes.php.error_pages]]`.
  - Retry policy for connection failures and connect timeouts before PHP returns
    a response. Implemented as `php.fpm.max_retries` and
    `php.fpm.retry_methods`, with `php.fpm.retry_timeout_secs` as an optional
    per-request retry window, defaulting to no retries and excluding request
    timeouts to avoid duplicated side effects. Broader status and invalid-header
    retry controls are opt-in as `php.fpm.retry_invalid_response` and
    `php.fpm.retry_statuses`. With `tcp_upstreams`, Fluxheim tries
    enough endpoints to cover the configured list for safe methods even when
    `max_retries = 0`.
  - PHP response-header policy controls matching common NGINX migrations:
    hide/pass selected backend headers, ignore selected cache-control headers,
    and reject conflicting `Content-Length` / transfer headers.
    Initial hide controls implemented as `php.hide_response_headers`;
    `php.ignore_origin_cache_headers` removes PHP-generated `Cache-Control`,
    `Expires`, and `Pragma`; hop-by-hop PHP response headers are stripped by
    default.
  - STDERR handling options: capture/log, truncate, severity mapping for 4xx/5xx
    responses, and optional fatal-error match that marks a response invalid for
    retry/failover.
    Initial controls implemented as `php.stderr_log`, `php.stderr_log_level`,
    `php.stderr_max_bytes`, and `php.stderr_failure_patterns` for opt-in
    invalid-response handling.
  - Initial php-fpm TCP upstream list and failover. Implemented as
    `php.fpm.tcp_upstreams` with round-robin selection and safe-method
    failover on connection failures and connect timeouts.
  - FPM upstream retry policy aligned with NGINX/Apache/Caddy behavior:
    connect error, timeout, invalid header, selected 5xx statuses, max tries,
    total retry timeout, and retry-safe method matching.
    Implemented for connection errors, connect timeouts, malformed FastCGI
    responses, and configured 5xx statuses; request timeouts stay non-retryable.
  - FPM upstream TLS and Unix/TCP socket controls should remain explicit; Unix
    sockets keep strict path/permission validation and TCP supports DNS refresh
    when the proxy resolver work lands.
  - PHP-specific Prometheus metrics for bounded request totals and durations.
    Multi-upstream keepalive pools use stable indexed pool labels.
    Implemented as `fluxheim_php_requests_total` and
    `fluxheim_php_request_duration_seconds`,
    `fluxheim_php_stderr_events_total`,
    `fluxheim_php_fpm_retries_total`,
    `fluxheim_php_fpm_pool_idle_connections`, and
    `fluxheim_php_fpm_pool_events_total`. OTLP request spans include
    low-cardinality `fluxheim.php.runtime` and `fluxheim.php.outcome`
    attributes for PHP-handled requests when `otel-otlp` is enabled.
  - FastCGI cache-specific convenience config on top of Fluxheim's cache
    engine.
  - FastCGI cache semantics compatible with common NGINX deployments:
    cache key presets, status-based TTLs, any-query bypass for WordPress-style
    dynamic URLs, `Cache-Control`/`Expires`/
    `Set-Cookie`/`Vary` admission behavior, bypass/no-cache conditions,
    cache lock, stale-on-error/timeout, background refresh where available, and
    authenticated purge integration.
  - WordPress-focused migration presets for `wp-admin`, `wp-login.php`,
    `xmlrpc.php`, sitemap/feed exclusions, logged-in/commenter cookie bypass,
    and denial of PHP execution under uploads/files-style directories.
    Initial execution denial implemented as `php.deny_path_prefixes`.
    Super Cache/W3TC static-file fallbacks remain future work and need typed
    static-file probing rather than rewrite-string interpolation.
  - Flat-root PHP applications such as classic forum/wiki packages expose a
    separate web/static concern: they often need arbitrary private directory
    denial while still serving selected static asset directories. This is not a
    PHP-FPM protocol gap; track a generic static `deny_path_prefixes` /
    allow-list policy before recommending broad static roots for those apps.
  - FastCGI multiplexing, authorizer, and filter-role review. Documented as
    unsupported for `1.3.x`; Fluxheim supports the normal one-request-at-a-time
    `FCGI_RESPONDER` PHP-FPM web-serving subset.
- `1.3.4`: OpenSSL FIPS-capable TLS build path, fail-closed provider
  validation for FIPS-required configs, runtime crypto diagnostics, and
  release-gate evidence for FIPS-capable builds.
- `1.3.7`: managed php-fpm mode under the existing `php-fpm` feature.
  This should be a runtime config choice, not a separate `php-fpm-managed`
  Cargo feature, because it still uses the same FastCGI bridge and security
  model. The target operator experience is `mode = "managed"` plus a small
  worker count, where Fluxheim generates a minimal private php-fpm config,
  creates a Fluxheim-owned Unix socket, starts php-fpm in foreground mode,
  supervises restarts, enforces max-request recycling, and shuts workers down
  cleanly during reload or gateway shutdown.
  - Keep `mode = "external"` as the default and fully supported behavior.
  - Managed mode must use the system php-fpm binary, not a long-lived
    `php-cli` stdin/stdout worker protocol, for production apps. Persistent
    CLI workers do not provide the request isolation expected by WordPress,
    Laravel, Symfony, phpBB, XenForo, MediaWiki, and similar applications.
  - The generated pool config exposes only a small, auditable subset: binary
    path, private socket directory, static/dynamic/ondemand process manager
    mode, worker count, dynamic spare/start sizing, ondemand idle timeout,
    listen backlog, max requests per worker, request terminate timeout,
    slowlog controls, private socket owner/group/mode, worker stdout/stderr
    decoration, `clear_env`,
    session-save and upload-temp directories, and optional user/group where
    safe.
  - A managed php-fpm watchdog should respawn the php-fpm master after
    post-start crashes with bounded backoff, while reload/shutdown paths must
    terminate the old master gracefully without blocking async worker threads.
  - The generated socket, config, pid, logs, and temporary directories must use
    the same safe-path ownership, symlink, and writable-parent checks used by
    ACME/cache/runtime paths.
  - On validation, Fluxheim should fail clearly when php-fpm is missing,
    incompatible, or cannot write to its managed directories, and should
    distinguish process-start failure from FastCGI request failure in logs,
    metrics, and config-tester output.
  - Future php-cgi support can be evaluated separately for tiny deployments,
    but it should not block managed php-fpm because php-cgi process-per-request
    behavior is a different performance and compatibility tradeoff.
- Pure-Rust PHP/phprs is no longer planned for the 1.3 line. Managed php-fpm
  covers the zero-admin PHP deployment goal while preserving normal php-fpm
  compatibility and isolation.
- `1.3.6` completed the admin API JSON cleanup: dynamic admin responses now
  serialize through `serde_json::to_vec` instead of hand-written `format!`
  bodies, while retaining the existing response schemas and response-size
  safety limit.
- Turbine-style PHP app servers are not Fluxheim runtime targets. Treat them as
  HTTP upstreams that Fluxheim can reverse-proxy to unless a future project
  exposes a small, auditable library API with a clearly safer boundary than
  reverse proxying.

Compile-time feature shape stays:

```toml
php = []
php-fpm = ["php", "dep:fastcgi-client"]
```

Managed php-fpm is not a separate runtime feature; it belongs behind
`php-fpm` because it changes process lifecycle, not the request protocol.

Exit criteria:

- `--features web,php-fpm` release build passes.
- Default, cache, privacy, and load-balancer profiles prove PHP is absent
  unless explicitly selected.
- PHP source files are never served as static fallback.
- Traversal, symlink escape, missing script, directory script, malformed
  FastCGI response, timeout, oversized body, and STDERR-size tests pass.
- WordPress-style front-controller routing, login/admin cookies, plugin/theme
  install/update/delete flows, and common cache-plugin bypass patterns are smoke
  tested against php-fpm. For `1.3.7`, the local WordPress smoke must pass in
  `external`, all managed process-manager modes, and `managed-respawn` mode.
- Config validation makes unsafe PHP roots, sockets, and runtime combinations
  actionable.

### 1.4 - Production Proxy Parity

Feature-graph prerequisite:

- `1.4` proxy images should compile the HTTP proxy and shared ingress/TLS
  surface without static web, local static cache, or load-balancer code unless
  explicitly selected.

Goal: make Fluxheim's proxy layer migration-friendly for NGINX, HAProxy, Envoy,
and Caddy operators. This line should close the operational gaps that matter
most before adding a new major feature family: rate limiting, IP ACLs,
compression, upstream selection, passive health/outlier detection, mTLS/client
certificate authentication, PROXY protocol, gRPC-safe HTTP/2 handling, traffic
mirroring, dynamic upstream discovery, buffering/streaming controls, rewrite
policy, and local operational visibility.

Current parity estimate after the `1.4.0` proxy baseline:

- Fluxheim is roughly 75-80% of the way to NGINX OSS parity for common
  HTTP/HTTPS reverse-proxy, static-file, PHP-FPM, and edge-cache deployments.
  The largest adoption blocker is regex routing with capture-aware rewrites;
  `auth_request`-style external authorization is the next common migration
  blocker.
- Fluxheim is roughly 60-65% of the way to HAProxy parity for HTTP load
  balancing. The remaining major gaps are TCP stream mode, stick-table-style
  multidimensional tracking, runtime backend mutation/drain commands, and
  composable ACL expressions.
- Fluxheim is already ahead of the reference proxies in regulated-deployment
  ergonomics: Rust memory safety, native OTLP, FIPS/ISO-capable TLS build
  paths, BREACH-safe compression defaults, and config snapshot/self-healing
  controls.

Reference parity map:

| Capability | Reference behavior | Fluxheim 1.4 target |
| --- | --- | --- |
| Rate and connection limiting | NGINX `limit_req`/`limit_conn`, HAProxy stick-table counters, Envoy local/global rate limit filters | Local per-vhost/per-route token bucket and concurrency limits first; external/global service later only if needed |
| IP ACLs | NGINX `allow`/`deny`, HAProxy ACL rules, Envoy RBAC | Ordered CIDR allow/deny at listener, vhost, and route scopes with trusted-proxy-aware client IP |
| Compression | NGINX/HAProxy compression, Envoy compressor, Caddy `encode` | Opt-in gzip/zstd/brotli negotiation with MIME/size rules, resource caps, and cache-safe `Vary: Accept-Encoding` |
| Load balancing | NGINX RR/least_conn/ip_hash/hash, HAProxy algorithms/stick tables, Envoy policies | Weighted round-robin, weighted least-connections, power-of-two, source/header/cookie hash, bounded sticky sessions |
| Passive health/outlier detection | Envoy outlier ejection, HAProxy observed errors, Caddy passive health | Per-upstream failure, timeout, 5xx, and latency counters with temporary ejection and circuit-open state |
| mTLS/client auth | NGINX `ssl_verify_client`, HAProxy `verify required`, Envoy TLS validation context | Listener-level required/optional client cert verification, CA bundle validation, identity variables, and route/admin policy use |
| PROXY protocol | NGINX/HAProxy/Envoy listener and upstream support | Accept v1/v2 only from trusted peers; optionally send v1/v2 upstream |
| gRPC | Envoy first-class gRPC/trailers, NGINX `grpc_pass` | Preserve HTTP/2 trailers/status/body limits/timeouts; no transcoding in 1.4 |
| HTTP/3/QUIC | NGINX/Caddy/Envoy support | Track as Fluxheim-owned `1.9` protocol milestone using Rust `quinn`/`h3` after the `1.8` macOS/Windows production-parity line is stable |
| Traffic mirroring | NGINX `mirror`, Envoy shadowing | First slice: safe bodyless shadow requests with deterministic sampling, timeout budgets, allow-listed headers, and no effect on primary response; body mirroring/redaction later |
| Dynamic discovery | Envoy xDS, Caddy dynamic upstreams, DNS/service integrations | DNS refresh and file-watched upstream lists first; xDS/Kubernetes/Consul later |
| Regex routing and rewrites | NGINX `location ~`, named captures, `rewrite`; HAProxy regex ACLs | Rust `regex`-based route matchers, capture variables, and bounded rewrite/header templates |
| External auth subrequest | NGINX `auth_request`, OAuth2 proxy patterns, Envoy external authz | Route/vhost auth subrequest policy with bounded header forwarding, timeout, response handling, and metrics |
| Response and URI rewrites | NGINX `proxy_redirect`, Apache `ProxyPassReverse`, NGINX `proxy_cookie_domain`/`proxy_cookie_path`, NGINX `rewrite`/HAProxy path replace | Bounded `Location`, `Refresh`, `Set-Cookie` domain/path rewrites, route `strip_prefix`/`rewrite_prefix`, then regex/template rewrite policy |
| Geo policy | NGINX GeoIP2 module, HAProxy maps/ACLs | Optional `geoip` feature using provider-agnostic MMDB readers for MaxMind GeoIP2/GeoLite2 and European CIRCL Geo Open datasets, with country/ASN variables, ACLs, and route selection |
| TCP stream proxy | NGINX stream, HAProxy TCP mode | Separate stream feature with byte-copy proxying, TLS passthrough/SNI sniffing later, TCP metrics, and no HTTP semantics |
| Apple Silicon macOS development | NGINX/Homebrew developer workflows | Developer-build and smoke-test support for `aarch64-apple-darwin`; not a production/FIPS support claim while Pingora macOS remains experimental |
| Extension hooks | NGINX/HAProxy Lua, Envoy Wasm | Typed policy inputs and hook points in 1.4; actual shared Wasm runtime moves to 1.7 after the Pingora exit |

Release shape:

- `1.4.0` - production proxy parity baseline:
  - edge policy and compression:
  - local request-rate token bucket with burst, nodelay/delay modes, and
    configurable rejection status;
  - per-route, per-vhost, and per-listener connection limits and bounded queues;
  - ordered CIDR allow/deny policy with trusted-proxy integration;
  - response compression feature with gzip compatibility, zstd/brotli where
    supported, MIME/size allow-lists, concurrency and memory limits,
    privacy-mode rejection, and cache-safe `Vary` behavior.
  - response `Location` and `Refresh` prefix rewrite rules are implemented
    under `headers.response.rewrite` for common `proxy_redirect` /
    `ProxyPassReverse` migrations. `Set-Cookie` `Domain=` and `Path=` rewrites
    are implemented under the same response rewrite policy. Route
    `rewrite_prefix` is implemented for bounded public-prefix to upstream-prefix
    URI mapping after `strip_prefix`; regex/template URI rewrites remain later
    1.4 work.
  - upstream selection and resilience:
  - named upstream pools and per-route pool selection;
  - weighted round-robin, weighted least-connections, power-of-two choices, source hash,
    URI hash, header hash, and cookie stickiness;
  - retry/redispatch controls, retry budgets, idempotency-aware defaults, backup
    servers, drain, and slow-start;
  - passive health/outlier detection with consecutive failure, 5xx, timeout,
    and latency ejection; active HTTP health checks may land here if they fit;
  - Prometheus now counts load-balanced selections, unavailable pools, retries,
    and selected upstream success/failure outcomes through bounded vhost/route
    labels. It also counts passive-health ejection transitions.
    `proxy.upstream_aliases` now provides optional safe low-cardinality backend
    labels for operator-facing metrics; richer per-backend health transition
    metrics remain later work.
  - TLS, identity, and protocol parity:
  - listener-level mTLS/client certificate auth with `off`, `optional`, and
    `required` modes plus safe CA file handling for rustls and OpenSSL is
    implemented. Verified downstream TLS/client
    certificate identity can now be forwarded through explicit request header
    templates such as `{tls.client_cert_sha256}` and is included in structured
    access logs through bounded `tls_*` fields. Vhost and route access policies
    can require a verified client certificate or allow/deny specific
    certificate SHA-256 fingerprints. The admin control plane can also require
    or allow/deny SHA-256 client-certificate fingerprints supplied by a trusted
    TLS/mTLS terminator through `[admin.client_certificate]`. BoringSSL and s2n
    are not supported Fluxheim TLS backends;
  - upstream TLS controls: SNI override, trust roots, upstream mTLS client cert,
    protocol/cipher policy where supported, and auditable insecure-skip-verify
    behavior. SNI override already existed; certificate verification, hostname
    verification, alternative-CN controls, custom upstream trust roots, and
    upstream mTLS client certificates are implemented for rustls and OpenSSL.
    BoringSSL and s2n were removed in `1.5.4`; remaining work is per-upstream
    protocol/cipher policy;
  - PROXY protocol v1/v2 accept/send with explicit trust boundaries. Listener
    v1/v2 receive is implemented through `server.proxy_protocol` with mandatory
    trusted-peer gating, and upstream v1/v2 send is implemented through
    `proxy.upstream_proxy_protocol`. v2 support is conservative TCP4/TCP6 plus
    LOCAL/UNSPEC only; TLV interpretation remains future work;
  - gRPC-safe HTTP/2 proxying for trailers, status, timeouts, body limits, and
    streaming behavior. Upstream HTTP version selection is implemented through
    `proxy.upstream_http_version` with `http1`, `http2`, and
    `http1-and-http2`, plus bounded h2 stream and ping controls. Route-scoped
    `[vhosts.routes.grpc]` policy now validates gRPC pass-through routes by
    requiring an HTTP/2-capable proxy action and rejecting obvious non-gRPC
    requests before forwarding. Remaining work is explicit end-to-end h2
    trailer/status fixture coverage. gRPC-Web/JSON transcoding remains out of
    scope unless a mature crate or small adapter is justified.
- `1.4.1` - HTTP migration blockers and proxy operations:
  - stop line: ship only HTTP reverse-proxy migration blockers and read-only
    operational visibility. Do not add GeoIP policy, advanced ACL expression
    evaluation, stick-table tracking, runtime backend mutation, response body
    substitution, TCP stream proxying, UDP proxying, HTTP/3, gRPC
    transcoding, or arbitrary Wasm/Lua execution in `1.4.1`;
  - regex path routing using Rust's `regex` crate. The first slice is bounded
    route matching: exact routes first, then prefix routes, then configured
    regex routes in documented order. Regex size limits and config-time
    compilation failures are required; untrusted catastrophic-backtracking
    behavior is avoided by the Rust regex engine design. Regex routing must be
    disabled by default behind an explicit global config opt-in such as
    `server.regex_enabled = true`; config validation must reject route regexes,
    capture-aware rewrites, and regex-backed templates unless that global opt-in
    is set. This keeps accidental high-cardinality or overly broad regex policy
    out of normal prefix/exact-route deployments;
  - named and numbered regex captures exposed as bounded typed variables for
    request-header templates and path-only `rewrite_template` routes in the
    first slice. Structured logs and future typed hooks remain follow-up work.
    Capture variables must not become metric labels by default;
  - method-based route matching through `methods = ["GET", "HEAD"]`, with
    config-time validation, so read/write routing can be expressed without Lua
    or duplicated vhosts. The first slice treats method lists as route match
    conditions rather than deny policies: a method mismatch keeps searching
    later routes or fallback;
  - WebSocket and generic HTTP/1.1 upgrade parity: first slice is explicit
    `proxy.websocket = true` upgrade policy on HTTP/1 upstream routes, strict
    hop-by-hop upgrade header forwarding, and forced cache bypass for upgraded
    connections. Remaining coverage should focus on end-to-end `101 Switching
    Protocols` fixtures and long-lived timeout behavior;
  - `auth_request`-style external authorization for proxy actions. The first
    slice makes one bounded `GET` subrequest before forwarding, sends only
    configured request headers, enforces connect/read/body limits, treats 2xx as
    allow, returns bounded 4xx/5xx auth denials, copies allow-listed auth
    response headers into the upstream request, and constrains FIPS/ISO-required
    deployments to numeric local `http://` auth sidecars until outbound TLS
    client evidence is provider-aligned. Low-cardinality decision metrics are
    recorded through edge-policy events; richer deny/error policy remains later
    work;
  - DNS-refreshing upstreams for container/service-name targets. First slice is
    `upstream_dns_refresh_secs` for load-balancer builds, resolved by Pingora
    service discovery and deliberately kept separate from weights, aliases,
    backups, and drains until backend metadata has a stable dynamic format;
  - file-watched upstream lists for service discovery without full config
    reload. First slice is `upstreams_file` for load-balancer builds: one
    `host:port` or `ip:port` authority per line, safe file handling, bounded
    refresh intervals, and no weights/aliases/backup/drain line metadata yet;
  - traffic mirroring/shadowing: first slice is an optional `traffic-mirror`
    feature for safe bodyless methods only, deterministic per-mille sampling,
    allow-listed request headers, timeout budgets, bounded response draining,
    FIPS/ISO local-sidecar enforcement, and low-cardinality mirror outcomes via
    edge-policy metrics. Body mirroring, redaction/transformation policies, and
    header/identity-claim sampling remain later work;
  - custom proxy error pages at vhost/route scope, loaded from safe filesystem
    paths and used by fail-to-proxy/error-response paths;
  - richer typed proxy variables and structured JSON access logs. Structured
    access logs already include trusted-proxy-aware client IP, effective cache
    phase, resolved vhost, route identity, and selected upstream address; OTLP
    spans also use the resolved route identity; access logs also include
    selected upstream aliases and retry counts for load-balanced requests, and
    OTLP spans record Fluxheim-applied response compression encoding while
    Prometheus metrics count applied compression by bounded encoding;
  - route-scoped regex/template rewrite policy. `Location`, `Refresh`, and
    `Set-Cookie` response rewrites are already implemented through the
    inherited response-header policy path, route `rewrite_prefix` handles
    simple upstream path-prefix mapping, and regex routes can use bounded
    path-only `rewrite_template` capture expansion. Do not add nginx-style
    sequential rewrite loops or `if` blocks in `1.4.1`;
  - local Unix operational socket: first slice is `[admin.ops_socket]`, a
    read-only Unix-domain HTTP endpoint for status, cache status, snapshots, and
    health checks with owner/group-only socket permissions. Pool, queue,
    rate-limit, circuit, and mirror-specific detail can be added without
    exposing mutating commands;
  - typed hook points for future Wasm/Lua-like policy without executing plugins
    in 1.4.
- `1.4.2` - proxy module split and maintenance architecture:
  - stop line: no new operator-facing proxy feature surface unless required to
    preserve behavior during extraction. Keep config compatibility, keep public
    metrics/logs stable, and pass the existing `1.4.1` smoke and security
    matrix before moving on;
  - split the large HTTP proxy runtime into focused domains before adding more
    proxy surface. Completed first-pass extractions: access logging,
    compression, auth subrequests, traffic mirroring, edge policy, route
    policy, outbound PROXY protocol framing, and `php_fpm` slices for
    managed-process lifecycle, request-body spooling, FastCGI endpoint/pool
    transport, timeout/retry classification, and CGI response parsing. The
    first `proxy_cache` slices cover request-side cache identity, bypass,
    revalidation, response admission, `Vary` helpers, bounded range-cache
    request/key/admission policy, and fixed-slice range planning. Freshness,
    status-header, stale-serving, and response-header mutation policy also live
    in `proxy_cache`. Cache admin/API request and result DTOs live in
    `cache_api` so admin response shapes are no longer stranded in `proxy.rs`.
    Remaining domains: high-level PHP request/session orchestration, stateful
    proxy cache runtime/storage, slice object assembly, and the remaining proxy
    core orchestration;
  - keep `FluxProxy` and the Pingora `ProxyHttp` lifecycle as the orchestration
    layer while extracting domain logic behind small, testable APIs;
  - move tests with their domains where practical, and keep the existing
    behavior tests as regression coverage for the extraction;
  - preserve feature-gated builds so default/no-default/profile builds continue
    proving that optional domains compile in and out cleanly;
  - source-boundary rule going forward: new product domains should start in
    their own module once they have independent validation, tests, metrics,
    external dependencies, or security policy. `proxy.rs` should remain the
    Pingora lifecycle and request/response orchestration layer; `config.rs`
    may keep the serde-facing config surface, but substantial feature-specific
    validation and helper logic should move into focused config/domain modules;
  - non-proxy split candidates to track after the active proxy extraction:
    `config.rs` can be separated by admin, TLS/compliance, proxy/routing,
    cache, PHP, and ACME validation domains; `cache.rs` can separate storage
    registries, disk/storage-bin backends, encryption/OpenBao transit, purge
    indexing, and cache-key policy; `admin.rs` can separate auth/throttle,
    JSON/status responses, local ops socket, self-healing, and cache purge
    endpoints; `cli.rs` can separate cache inspection/warmup commands from
    top-level command dispatch. These are maintenance refactors, not release
    blockers unless touched by a feature;
- `1.4.3` - config module split and maintenance architecture:
  - stop line: no new operator-facing config features, no config migration, and
    no behavior changes unless required to preserve existing validation during
    extraction. Keep `crate::config::*` public paths stable for callers;
  - split the largest remaining source file into focused domains before adding
    GeoIP or other policy features. Start with config source loading and safe
    TOML file discovery, then move domain validation in conservative slices;
  - target slices: `config_loader` for path-safe config source discovery and
    bounded TOML reads; `config_admin`; `config_tls`; `config_proxy`;
    `config_cache`; `config_php`; `config_acme`; and shared
    `config_validation` helpers where cross-domain validators are genuinely
    shared;
  - keep `src/config.rs` as the serde-facing facade and re-export layer at
    first. Do not force downstream modules to chase new paths during the split;
  - move tests with their domain only when the moved code no longer needs large
    private fixtures from `config.rs`. Otherwise keep behavior tests in place
    until the domain boundary is stable;
  - preserve feature-gated builds so optional domains compile in and out
    exactly as they did in 1.4.2;
  - document every intentionally deferred split candidate at release time so
    the config split does not become an unbounded refactor.
- `1.4.4` - Apple Silicon macOS developer support:
  - stop line: Level 1 support only. Make Fluxheim build and run for local
    development on `aarch64-apple-darwin` with documented dev configs and one
    smoke gate. Do not claim macOS production support, FIPS evidence, launchd
    packaging, Homebrew distribution, notarized binaries, or parity with the
    Linux release gates in `1.4.4`;
  - add a macOS CI or documented manual gate for the development profile:
    `cargo check --locked --no-default-features --features web --lib`,
    `profile-static-site`, `profile-reverse-proxy`, `profile-full`, and
    `profile-development` for `fluxheim` and `fluxheim-acme`;
  - add macOS developer examples that keep runtime state under project-local
    or `/tmp` paths instead of Linux service paths: run sockets, pid files,
    admin snapshots, ACME storage, disk cache, access/file logs, and PHP-FPM
    socket directories must all be writable by an unprivileged Mac user;
  - add one runtime smoke test on an Apple Silicon runner or local M-series
    machine for static serving, reverse proxying, disk cache with a Mac-safe
    path, structured logs, and managed PHP-FPM when Homebrew PHP is available;
  - audit native dependency behavior on macOS, especially `ring`,
    `aws-lc-sys`, `zstd-sys`, `libz-ng-sys`, optional OpenSSL TLS backends,
    and PHP-FPM process management. Prefer feature/profile fixes
    that avoid compiling unused native dependencies for developer builds;
  - document required local prerequisites such as Xcode Command Line Tools,
    Rust target/toolchain, CMake when selected features need it, and optional
    Homebrew PHP-FPM for managed PHP development tests;
  - document release artifacts by normalized target labels:
    `aarch64-macos` for Apple Silicon Macs, `x86_64-macos` for Intel Macs,
    `aarch64-linux` for Linux ARM64, and `x86_64-linux` for the main Linux
    x86_64 build. Do not publish one ambiguous "ARM" artifact, and do not use
    machine-local `target-cpu=native` tuning for public release binaries;
  - keep Linux as the production support baseline. macOS support is for
    contributor development and local site testing until Pingora's macOS
    support is no longer experimental and Fluxheim has regular macOS smoke
    coverage.
- `1.4.5` - bounded Geo-Context and advanced HTTP policy foundation:
  - stop line: ship local GeoIP/Geo-Context and bounded HTTP policy only. Do
    not add TCP stream listeners, TLS passthrough SNI routing, UDP proxying,
    HTTP/3, gRPC transcoding, xDS/Kubernetes/Consul control planes, global
    distributed rate-limit services, arbitrary Wasm/Lua execution, built-in
    GeoIP database downloading, remote GeoIP lookup fallbacks, or impossible
    travel/anomaly engines in `1.4.5`;
  - optional `geoip` Cargo feature as a bounded Geo-Context foundation, not a
    broad programmable geo engine. Implement a provider-agnostic MMDB layer:
    the hot-path should ask a typed `GeoProvider`/`GeoDatabase` abstraction for
    `lookup(ip)` and receive Fluxheim's normalized `GeoContext`, not provider
    structs. Initial supported local providers are MaxMind GeoIP2/GeoLite2
    country/ASN databases and European CIRCL Geo Open datasets when supplied in
    MMDB-compatible form. Use the same `maxminddb` reader path for both, and
    fail closed with a clear runtime error if an incompatible MMDB is supplied;
  - GeoIP config should support an ordered local database list such as
    `[[geoip.databases]] provider = "maxmind"` and
    `provider = "circl-geo-open"` with `path = "..."`, plus an explicit
    `fallback_enabled` switch. Fallback means "try the next local MMDB when the
    primary has no usable country/ASN result", not remote lookup or silent
    best-effort compliance bypass;
  - load database files with the same safe path rules used for other
    operator-supplied files, and reload by atomically swapping an `Arc` on
    config reload. Do not make database downloading/updating part of the proxy
    process in `1.4.5`; document a systemd timer/sidecar pattern that downloads
    MaxMind/CIRCL files, verifies checksums or signatures where the provider
    publishes them, writes atomically, and then triggers Fluxheim reload;
  - implement GeoIP as its own `geoip`/`geo_context` module from the start,
    with only thin hooks in config, proxy policy, and access logs first.
    Metrics and tracing are follow-up work only if they stay bounded. Do not
    add GeoIP lookup or policy logic directly to `proxy.rs` or grow
    `config.rs` with large database-management helpers;
  - expose GeoIP as typed request context, not spoofable inbound headers.
    Initial normalized fields are country ISO code and ASN. Provider/source
    diagnostics, city, latitude, and longitude stay out of the first stable
    surface unless an operator explicitly enables them later because they are
    more privacy-sensitive;
  - use the typed geo context in vhost/route access policy and structured
    access logs first. Request-header templates, OTLP span attributes, and
    metric labels are follow-up work only if they remain bounded and useful;
    never emit city, IP, or raw organization strings as default metric labels;
  - privacy-mode behavior: either reject GeoIP entirely or restrict it to
    policy-only country/ASN evaluation with no logs, trace attributes, headers,
    or persisted request context. Decide before implementation and test both
    compile-time and config-time behavior;
  - defer built-in GeoIP auto-downloaders, ETag/Last-Modified URL polling, L1
    lookup caches, remote sidecar lookup fallbacks, adaptive rate-limit
    weighting, programmable rhai/Wasm geo logic, and impossible-travel
    detection to `1.5` or `1.6` after the typed context and policy model are
    stable;
  - advanced ACL composition, stick-table-style local tracking, runtime backend
    management, NGINX `map`-style variables, and bounded response body
    substitution remain in this policy line only if the config split is already
    complete and the stop line remains realistic. Otherwise move them to `1.5`.
- `1.4.6` - TCP stream proxy foundation:
  - stop line: ship L4 TCP stream proxy basics only. Do not add UDP proxying,
    DNS-specific UDP load balancing, generic L7 policy on stream routes,
    HTTP cache/compression/auth/PHP behavior on stream routes, xDS/Kubernetes
    service discovery, or Wasm/Lua stream filters in `1.4.6`;
  - compile-time feature separate from HTTP proxy if needed;
  - port/listener-based stream routing to one or more upstreams, reusing the
    load-balancer selection and health primitives only where they are transport
    neutral and do not pull HTTP policy into stream routes;
  - bidirectional Tokio byte copy with half-close handling, connect timeout,
    max connection lifetime, per-direction byte caps/accounting, max connection
    limits, and graceful drain behavior;
  - upstream PROXY protocol send where configured, and route-local
    listener-side PROXY protocol receive only behind trusted peer rules;
  - upstream TLS and upstream mTLS are allowed only if they reuse the same safe
    certificate/key loading model as HTTP upstream TLS without expanding the
    stop line; otherwise keep them for a later stream hardening release;
  - TLS passthrough SNI routing only as a later subfeature after a bounded
    ClientHello parser and preread buffer limits are tested. SNI passthrough
    must forward the original bytes unmodified after peeking;
  - no HTTP headers, cache, auth subrequest, compression, or PHP behavior on
    stream routes.
- `1.4.7` - TCP stream hardening:
  - stop line: harden the `1.4.6` TCP stream proxy foundation only. Do not add
    UDP proxying, TLS passthrough SNI routing, xDS/Kubernetes/Consul discovery,
    or Wasm/Lua stream filters in `1.4.7`;
  - implement true per-read stream idle timeout on top of the manual copy loop,
    while keeping `max_connection_secs` as a separate lifetime cap;
  - add stream upstream TLS and upstream mTLS where it can reuse the existing
    safe certificate/key loading and upstream TLS evidence model. If this
    expands into a new trust-store or provider model, defer it to `1.5`;
  - move only transport-neutral load-balancer policy to stream routes:
    connection limits, upstream weights/backup/drain state, and health state are
    candidates; HTTP request/response policy, cache, compression, auth
    subrequests, PHP, header mutation, and body policy stay out of stream
    routes;
  - expand stream smoke/security tests for half-close behavior, byte caps,
    idle timeout, upstream TLS/mTLS, PROXY receive/send combinations, and
    metrics labels.
- Future macOS production support:
  - track as a later release line after `1.4.x`, not as spillover from the
    developer-support milestone. Production macOS requires regular macOS CI,
    runtime smoke coverage, packaging policy, launchd service files, signed or
    notarized binary decisions, Homebrew formula maintenance, and a security
    review of APFS, macOS ACLs, symlink behavior, Unix sockets, process
    supervision, and certificate/key storage;
  - do not include FIPS/ISO-19790 claims in macOS production support unless a
    separate provider-specific evidence package exists for macOS. The current
    compliance evidence remains Linux/operator-environment focused.

Version discipline for the rest of `1.4.x`:

- A version is releasable when every item above its stop line is either
  implemented, explicitly documented as deferred, or removed from that version
  before the release candidate. Do not keep adding adjacent parity requests to
  the active version after that point.
- Security fixes, correctness fixes, test coverage, docs, and release evidence
  may still land inside the active version. New feature families must move to
  the next planned version unless they are required to make an already-in-scope
  item safe.
- If a pentest uncovers a design gap in a not-yet-started feature family, record
  it under the future version instead of expanding the current release.

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
    low-cardinality queue metrics. Prometheus now counts concurrency-limit
    rejections through bounded edge-policy labels; queue wait/depth histograms
    remain later work;
  - optional priority classes derived from safe request attributes such as
    route, method, authenticated policy result, or configured header allow-list;
  - async backpressure so slow or saturated upstreams do not force unbounded
    buffering inside Fluxheim.
- Local rate limiting and overload controls:
  - token bucket per client IP, route, vhost, header, authenticated identity, or
    configured variable;
  - burst, delay/nodelay, dry-run, and custom rejection status/body;
  - bounded state tables with TTL and eviction behavior;
  - low-cardinality metrics only by default. Prometheus now counts rate-limit
    delay and rejection decisions through bounded edge-policy labels.
- IP filtering and route ACLs:
  - ordered allow/deny CIDR lists;
  - trusted-proxy-aware source IP selection;
  - Prometheus now counts ACL denials through bounded edge-policy labels;
  - explicit behavior for missing/invalid forwarded identity;
  - route/vhost/listener inheritance and clear deny status.
- Response compression:
  - gzip compatibility path plus zstd/brotli when dependencies and browser
    behavior justify them;
  - content-type and minimum-size eligibility;
  - resource caps for CPU, memory, and concurrent compression jobs;
  - cache-key isolation and `Vary: Accept-Encoding` correctness;
  - disabled in privacy mode unless the policy proves no extra retention.
- Upstream keepalive and connection-pool tuning beyond the existing global
  pool size:
  - upstream idle timeout is implemented through
    `proxy.upstream_idle_timeout_secs`;
  - total connection establishment timeout is implemented through
    `proxy.upstream_total_connection_timeout_secs`;
  - upstream TCP keepalive, Linux user timeout, receive-buffer size, DSCP, and
    TCP Fast Open socket controls are implemented through `proxy.upstream_tcp_*`,
    `proxy.upstream_tcp_recv_buffer_bytes`, `proxy.upstream_dscp`, and
    `proxy.upstream_tcp_fast_open`;
  - remaining work: per-route pool limits, maximum reuse count or lifetime, and
    clear behavior documentation when an upstream closes an idle pooled
    connection.
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
- Advanced upstream selection and resilience:
  - weighted round-robin;
  - least-connections for uneven PHP/app request durations;
  - source/header/cookie/URI hash;
  - sticky sessions with bounded state and safe cookie defaults;
  - retry/redispatch budgets, backup/drain/slow-start state;
  - passive health/outlier detection and circuit-breaker state based on
    connection errors, timeouts, selected response-status classes, and latency.
- Client mTLS and certificate-derived identity:
  - listener-level client-auth mode first because TLS verification happens
    before normal HTTP routing;
  - optional SNI/vhost-specific behavior only after backend support is proven;
  - expose verified subject, SAN, serial, issuer, and fingerprint as typed
    variables after redaction rules;
  - safe use for admin endpoint hardening, route ACLs, upstream headers, and
    Cloudflare Authenticated Origin Pulls.
- NGINX-style request mirroring for HTTP routes with strict limits:
  - mirror body on/off;
  - mirror timeout;
  - no effect on primary response;
  - low-cardinality metrics for mirror success/failure.
- External auth request integration may stay in the existing auth-request
  design, but `1.4` should make it proxy-route complete: timeout, header
  forwarding, allowed response headers, deny status, and metrics.
- PROXY protocol support:
  - accept Proxy Protocol v1/v2 on configured listeners. Listener v1/v2 receive
    is implemented through `server.proxy_protocol` with trusted peer gating;
  - send Proxy Protocol to upstreams on configured routes. Upstream v1/v2 send
    is implemented through `proxy.upstream_proxy_protocol`;
  - validate trust boundaries before restoring client identity.
- Dynamic service discovery:
  - DNS refresh for upstream hostnames with TTL/refresh controls;
  - file-watched upstream lists for container/service-name environments;
  - strict validation before replacing an active pool;
  - later xDS/Kubernetes/Consul support only after the local discovery model is
    stable.
- TCP stream proxy foundation is tracked as `1.4.6`, not as part of the HTTP
  proxy runtime. It should reuse listener/TLS/load-balancer building blocks
  where possible but remain a separate stream feature with no HTTP semantics.
- UDP proxying is deliberately deferred. Pingora does not provide UDP support,
  and raw UDP forwarding needs a session/NAT table, affinity model, and
  protocol-specific health semantics. Do not build it until a concrete DNS,
  syslog, DTLS, gaming, or IoT requirement justifies the extra surface.
  When scheduled, make it a separate future version with a concrete target:
  generic UDP session forwarding, DNS UDP load balancing, syslog UDP
  forwarding, QUIC passthrough, or game-server UDP proxying. Each target needs
  explicit session TTLs, affinity, packet/byte/drop metrics, amplification
  controls, and protocol-appropriate health checks.
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
  - first slice implemented as `[admin.ops_socket]`, a Unix-domain HTTP socket
    for fast local status, cache status, snapshots, and health checks;
  - root/service-owner or dedicated-group permissions, strict path validation,
    no network bind by default;
  - mutating commands remain deferred or separately authorized.
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

- Direct Server Return as a stable HTTP proxy feature. DSR is a layer-4/network
  topology feature and should be evaluated in the `1.5` load-balancer or later
  stream-proxy line after Linux routing, source-address, and observability
  constraints are documented.
- Full Envoy-style global rate-limit service, xDS control plane, Kubernetes
  controller, Consul integration, gRPC-Web transcoding, gRPC-JSON transcoding,
  and HTTP/3/QUIC are tracked as later work. HTTP/3/QUIC is now planned as a
  Fluxheim-owned `1.8` protocol milestone after the `1.6` Pingora-free runtime
  is stable, using reviewed Rust QUIC/HTTP3 ecosystem crates rather than
  waiting on a proxy-framework API.
- Arbitrary Lua/Wasm script execution. `1.4` should define typed hook points and
  bounded policy surfaces; the shared Wasm runtime moves to a separate `1.7`
  line. NGINX rewrite-module-style `if` conditions should be evaluated there
  as sandboxed policy hooks rather than copied into TOML as a second ad-hoc
  language. TCP stream Wasm/Lua-style filters also belong to the shared Wasm
  line, not `1.4.7`: they require a sandbox ABI, fuel/time/memory limits,
  stream mutation limits, and a clear security model for long-lived L4
  connections.
- HTTP/2 server push should be skipped permanently unless the browser ecosystem
  reverses course; mainstream clients removed or never enabled it, so it is not
  a useful parity target.
- Cache engine work already completed in `1.2.x`, except where proxy buffering
  and streaming behavior must integrate correctly with cache admission.

Exit criteria:

- HAProxy/NGINX migration fixtures cover queue limits, queue timeout,
  backpressure, local rate limits, connection limits, IP ACLs, compression,
  request/response buffering, upstream keepalive, advanced selection policies,
  passive health/outlier ejection, mTLS client-auth, WebSocket, gRPC, regex
  routing, method routing, request mirroring, PROXY protocol receive/send,
  external auth request, variable logging, advanced ACL composition, GeoIP
  policy when compiled, runtime backend drain/disable/enable, and TCP stream
  proxy basics.
- Memory usage remains bounded under slow client, slow upstream, large upload,
  large download, compressed-response, rate-limit abuse, and upstream stall
  tests.
- Queue, pool, rate-limit, ACL, compression, circuit, mTLS, buffering, mirror,
  stream, and protocol-translation metrics are available when metrics are
  enabled and stay low-cardinality.
- Privacy-mode rejects incompatible logging, temp-file buffering, stream
  identity restoration, compression, mirroring, or payload-retaining features.
- Config validation catches unsafe temp paths, impossible queue settings,
  impossible rate-limit tables, invalid ACLs, unsafe compression/cache
  combinations, invalid regex rewrites, unsupported protocol combinations,
  unsafe client-cert CA paths, and unsafe PROXY protocol trust boundaries.

### 1.5 - Load Balancer

Feature-graph prerequisite:

- `1.5` load-balancer images should compile load-balancer, shared ingress/TLS,
  ACME, metrics, and security modules without static web, local static cache,
  or generic single-upstream reverse-proxy-only code unless explicitly
  selected. The load balancer may reuse shared proxy transport abstractions
  internally, but the public feature name and image profile must not pull in
  unrelated webserver behavior.
- `1.5.0` promotes the `profile-load-balancer-edge` image profile to the normal
  load-balancer release artifact line.
  The official focused load-balancer image should remain TLS/ACME/metrics
  capable and omit static web, local static cache, PHP-FPM, and generic
  webserver behavior unless the operator selects a broader profile.

Goal: stabilize the `1.4` proxy, stream, and edge-policy primitives for larger
enterprise estates. Since `1.4` owns the common single-node parity features,
`1.5` focuses on operational scale: runtime pool mutation, multi-instance
state, deeper active/adaptive health policy, admin workflows, migration tooling,
and F5-style estate management. Palo Alto-style security expectations should be
represented as clear policy integration points around the load balancer, not as
a claim that Fluxheim is a full next-generation firewall in `1.5`.

`1.5.0` stop line:

- Build an F5 LTM / HAProxy / Envoy-class HTTP/TCP load-balancer control plane,
  not a complete BIG-IP replacement. UDP proxying and GSLB/DNS traffic
  steering are later `1.5.x` tracks after the HTTP/TCP control plane is stable.
  WAF/ASM, SSL VPN, NAT appliance behavior, firewalling, and
  iRules-compatible scripting are separate future module families.
- Prefer bounded, observable policy over magic automation. Every adaptive or
  dynamic decision must have admin status, metrics, audit logs, and clear
  fallback behavior.
- Do not spill into the `1.7` Wasm runtime. `1.5` may define typed hook points
  and migration language for iRules-style behavior, but actual sandboxed
  policy execution belongs to the shared Wasm line.

Stable scope:

- Compile-time `load-balancer` module remains the place for estate-scale
  features that go beyond one Fluxheim instance's normal proxy routing.
- The `1.5.x` modularization line should keep Pingora in the build graph and
  focus on crate boundaries, Fluxheim-owned internal interfaces, feature
  mapping, and parity tests. It should not carry hard Pingora-removal gates.
  Cache, load-balancer, stream, background-task, HTTP/error, web, PHP-FPM, and
  ACME work in this line should prepare clean adapters and focused crates so
  the `1.6.x` runtime line can remove Pingora layer by layer.
- Fluxheim-owned modules should standardize on the Rust `http` crate for
  request/response/status/header types and a Fluxheim-owned `FluxError` /
  `FluxResult` taxonomy instead of propagating Pingora HTTP wrappers and
  `pingora::Error` through internal APIs. Keep narrow adapters at Pingora
  HTTP proxy boundaries until a later HTTP runtime replacement line exists.
- The `1.5.5` HTTP/error boundary line deliberately stops before broad
  runtime rewrites. Any leftover plain `io::Result` / Pingora adapter use in
  PHP-FPM process lifecycle, PHP request-body spool files, stream data-path
  copy/connect/shutdown helpers, upstream TLS material loading, and
  load-balancer factory/background wiring should move with the future native
  PHP/HTTP-runtime, stream-runtime, TLS/server-runtime, and load-balancer-core
  milestones below rather than being chipped away as unbounded cleanup.
- The stream proxy should become Fluxheim-native before the load-balancer
  substrate work. Its tunnel, PROXY protocol framing, connection limits, byte
  caps, idle/lifetime limits, and metrics are already Fluxheim-owned; the
  remaining Pingora pieces are listener entrypoint, stream abstraction, and
  upstream TLS connector wiring.
- The `1.5.0` maintenance split keeps health checks, backend state,
  persistence, selection algorithms, backend policy/status, and file/DNS
  discovery in separate `src/load_balancer/*` modules. Future load-balancer
  work should extend those domains or create a new focused module instead of
  growing the parent orchestration file.
- The `1.5.x` line should keep load-balancer logic moving into
  `crates/fluxheim-load-balancer` with Fluxheim-owned backend snapshots,
  discovery traits, readiness state, health-check scheduling, and runtime
  policy interfaces. Removing `pingora-load-balancing` from compilation is a
  `1.6.x` responsibility, not a `1.5.x` release gate.
- Background tasks use the `1.5.12` Fluxheim adapter for Fluxheim-owned work:
  cache metrics, stale purging, ACME renewal, admin watchdog, load-balancer
  refresh loops, and future discovery workers see Fluxheim shutdown/readiness
  handles rather than Pingora `GenBackgroundService`, `background_service()`,
  raw `ShutdownWatch`, or `ServiceReadyNotifier` types. Keep
  `ServiceWithDependents` only as the outer Pingora server-registration
  adapter until the later server-bootstrap line.
- Cache storage has a `FluxCacheStorage` interface owned by Fluxheim so memory,
  disk, encrypted disk, tiered storage, predictors, stale policy, purge/index
  behavior, and admission tests are no longer coupled to Pingora's `Storage` /
  `HandleHit` / `HandleMiss` session types. The Pingora HTTP proxy path keeps a
  narrow adapter while cache internals become independently testable.
- Server bootstrap, listener ownership, and TLS listener configuration remain
  a later major dependency-reduction line, not a `1.5` goal. Pingora's worker
  setup, signal handling, hot-restart file-descriptor passing, service
  orchestration, `TlsSettings`, SNI resolver hooks, mTLS, ALPN, and OCSP
  wiring are valuable but also the part where Fluxheim has already needed
  vendor patches. Replacing them requires a dedicated server-runtime milestone
  with bare-metal and cloud-native deployment models considered separately.
- Replacing Pingora `ProxyHttp` and `Session` is the final HTTP core
  dependency-reduction line and should be treated as a major release-sized
  project. Fluxheim's routing, access control, header policy, cache,
  compression, PHP-FPM, GeoIP, mirroring, auth-request, and logging currently
  hang from Pingora's callback lifecycle. A future `hyper`-style
  `async fn(Request<Body>) -> Response<Body>` core may make that flow more
  linear and testable, but it must not be mixed with smaller subsystem
  refactors.
- Runtime pool and member state through a local authenticated control plane:
  drain, disable, force-down, enable/normal, manual resume, persistence-table
  clear, configured-member runtime weight overrides, and load-balancer-only
  runtime status without full process restart. Runtime weight controls are
  available for round-robin and least-* selectors where the selector can apply
  a bounded overlay directly. Runtime add/remove-member, runtime metadata
  updates, and runtime weight mutation for hash/ring/Maglev/power-of-two
  selectors remain future control-plane work because they need either an atomic
  backend-set swap or selector-specific table/ring semantics.
- Persisted pool state for operator actions and reload survival remains later
  `1.5.x` work, with safe snapshot/write semantics and audit events.
- Cluster-aware state sharing for selected tables where single-node behavior is
  insufficient:
  - load-balancer-managed cookie/sticky-session tables, including explicit
    cookie mirroring for active-active HA setups where a request may land on a
    different Fluxheim node after failover or normal balancing;
  - application-cookie persistence tables when operators choose to mirror the
    affinity decision rather than relying only on the application cookie value;
  - rate-limit counters if local-only limits prove insufficient;
  - passive health/circuit state only where sharing is safe and bounded;
  - runtime drain/disable/forced-down overrides so HA peers do not route to a
    member another node has administratively removed.
  Retry budgets, queue counters, and high-churn telemetry should stay local
  unless a later design proves that replication is bounded and operationally
  useful.
- Named upstream pools can be selected globally, per vhost, or per route, so one
  vhost can proxy normal app traffic and route-specific traffic to different
  backend sets.
- Separate L4 and L7 load-balancing modes:
  - HTTP/1.1 and HTTP/2 request-aware pools;
  - gRPC-aware HTTP/2 pools where trailers/status handling is preserved;
  - TCP stream pools built on the `1.4` stream-proxy foundation;
  - TLS passthrough SNI routing only after a bounded ClientHello parser,
    preread buffer cap, malformed-handshake behavior, and unmodified byte replay
    are proven;
  - UDP session pools only after a concrete post-`1.4` requirement proves raw
    UDP forwarding can be bounded and observable. Treat this as a `1.5.x`
    follow-up transport track, not part of the `1.5.0` stop line;
  - xDS/Kubernetes/Consul discovery only after local DNS/file discovery and
    runtime backend mutation are stable. Treat this as a control-plane feature,
    not a quick stream-proxy add-on;
  - HTTP/3/QUIC remains a later protocol milestone targeted at `1.9`, after
    the Fluxheim-owned Pingora-free server/listener/TLS and HTTP runtime
    boundaries and the `1.8` macOS/Windows production-parity line are stable.
- Multiple upstreams per pool with safe address validation and per-upstream
  metadata: name, address, weight, backup, disabled/down, drain/maintenance,
  max in-flight requests or connections, max queue, priority group, manual
  resume, warm-up/slow-start after recovery, locality/failure-domain tags,
  administrative tags, optional external load-score metadata, and optional
  per-upstream TLS/SNI settings.
- `1.4` selection algorithms remain the single-node default. `1.5` adds
  operational controls around them: priority groups, maintenance mode,
  runtime member-state changes, runtime weight overrides for supported
  selectors, pool-level policy templates, and migration tools that translate
  common HAProxy/nginx pool definitions into Fluxheim config. Runtime
  add/remove-member and selector-specific weight changes for hash/ring/Maglev
  policies remain later control-plane slices.
  - weighted least-connections / ratio least-connections for heterogeneous
    backends;
  - least-time / EWMA latency-aware selection from observed upstream request
    latency;
  - consistent hash / Ketama for cache-stateful upstreams;
  - Maglev hashing for stable large-pool distribution where table size and
    memory cost are bounded;
  - bounded-load consistent hashing so overloaded nodes can be skipped without
    remapping the whole ring;
  - least-sessions selection where a bounded persistence/session table exists;
  - priority-group selection for F5-style preferred/fallback groups;
  - locality-aware preferred selection so same-zone or same-site backends can
    be tried before remote failure domains.
- Session persistence:
  - `1.5.0` request-cookie persistence consumes an application or upstream
    cookie selected by configuration; load-balancer-managed cookie insertion is
    a later `1.5.x` persistence slice;
  - load-balancer-managed cookie persistence with signed/opaque `Set-Cookie`
    insertion on the first eligible response, configurable `Secure`,
    `HttpOnly`, `SameSite`, `Path`, `Domain`, and `Max-Age` attributes,
    key-rotation behavior, backend identity privacy, and explicit interaction
    with compression/cache/header policies;
  - source-address persistence with TTL and table-size limits;
  - header-based persistence from a configured allow-list;
  - TLS session/client-certificate persistence only after privacy/security
    review;
  - persistence must be visible, bounded, purgeable, and incompatible with
    privacy-mode unless a no-retention policy is configured.
  - persistence dump/restore for reload and restart survival is later `1.5.x`
    work. The file format must be versioned, size-limited, atomically written,
    auditable, and safe to ignore on corruption rather than poisoning a pool.
- Active health checks:
  - TCP connect checks;
  - TLS handshake checks with SNI and verification controls;
  - HTTP checks with method, path, expected status range, expected response
    header/body substring, Host header, and upstream TLS/SNI where configured;
  - HTTP health-check request headers, including support for authenticated
    health endpoints through explicitly configured low-sensitivity headers.
    Header names and values must be validated, redacted in logs/status where
    needed, and excluded from high-cardinality metric labels;
  - HTTP/2 and gRPC health checks using the standard gRPC Health Checking
    Protocol, with optional service name, strict message-size limits, no
    general protobuf parser requirement for the first slice, and response
    status mapped into normal active-health state;
  - structured JSON response checks for common health bodies, using bounded
    `serde_json` parsing and simple exact field-path comparisons before any
    JSONPath-like language is considered;
  - weighted degraded health responses where a trusted health endpoint can
    return a bounded effective-weight signal such as `X-Health-Weight`. This is
    a health-derived overlay separate from configured weight and runtime
    operator overrides, must be visible in status/audit, and must automatically
    clear when the backend returns to normal;
  - local exec/command checks are an opt-in `1.5.14` monitor slice for cases
    not representable by TCP/TLS, HTTP, gRPC, or JSON checks. They must use
    absolute allow-listed paths, no shell, no ambient environment injection,
    strict timeout/output limits, redaction, and compile/config gates because
    they introduce process execution;
  - protocol-aware database/service monitors for common load-balanced services
    such as Redis `PING`, PostgreSQL startup/auth-safe readiness, MySQL
    handshake/readiness, SMTP, LDAP, and custom send/expect checks are a later
    `1.5.x` monitor slice, with strict timeout/body-size bounds and no
    unbounded script execution;
  - authenticated agent checks may be added later for applications that can
    report local overload, reduced capacity, or drain state more accurately
    than protocol probes;
  - UDP checks only in the later UDP follow-up, with explicit send/expect
    patterns and timeout limits;
  - interval, timeout, consecutive success/failure thresholds, initial state,
    jitter, parallel check controls, manual resume, and per-pool/per-member
    overrides.
- Adaptive health/performance monitors:
  - track latency, error rate, queue time, and in-flight load;
  - support optional adaptive thresholds for least-time and circuit breakers;
  - support trusted external load-score inputs only through authenticated,
    audited, bounded control-plane paths or explicitly configured health-check
    response fields;
  - make every automatic ejection explainable through admin status and logs.
- Passive health observation from real proxy traffic: connection failures,
  upstream timeout/error classes, selected HTTP status classes, bounded
  error-limit windows, and configurable actions such as mark-down,
  fast-recheck, temporary ejection, or circuit-open state.
- Circuit breaking and adaptive concurrency:
  - per-pool and per-member circuit state;
  - named open/half-open/closed state that maps existing passive ejection,
    max-in-flight saturation, pending-request queue pressure, retry budget
    exhaustion, and cooldown behavior into operator-visible breaker reasons;
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
  - actual Wasm execution belongs to the shared `1.7` runtime so Fluxheim does
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

- Fluxheim-native HTTP/error type boundary replacement for Pingora wrapper
  types in Fluxheim-owned modules. Use Rust `http` crate request, response,
  status, method, URI, and header types where practical, and replace
  `pingora::{Error, ErrorType}` propagation with a `thiserror`-backed
  Fluxheim error taxonomy carrying explicit context. Keep Pingora adapters at
  `ProxyHttp`, service, and transport edges.
- Fluxheim-native load-balancer substrate replacement for the remaining
  Pingora LB pieces: `Backend`, `Backends`, `LoadBalancer<S>`,
  `ServiceDiscovery`, static discovery, readiness maps, health-check wiring,
  and background service lifecycle. Preserve existing config/admin behavior and
  keep Pingora for the HTTP proxy core.
- Fluxheim-native stream-proxy runtime replacement for the remaining Pingora
  stream pieces: `ServerApp`, `protocols::Stream`, and `TransportConnector`.
  Preserve existing stream config, route selection, PROXY protocol, byte/idle
  limits, metrics, upstream TLS/mTLS behavior, and smoke coverage while using a
  direct Tokio listener loop and explicit TLS connector.
- Fluxheim-native background task registry replacement for Fluxheim-owned
  background work. The `1.5.12` adapter removes task implementations from
  Pingora `GenBackgroundService`, direct `background_service()` registration,
  raw `ShutdownWatch`, and `ServiceReadyNotifier` handling by using a Tokio
  watch-based shutdown handle and one-shot readiness callback. Keep
  `ServiceWithDependents` only as the outer server-registration adapter until
  the later server-bootstrap line; preserve graceful shutdown behavior and keep
  task metrics/status visible.
- Fluxheim-owned cache interface decoupling for Pingora cache `Storage`,
  `HandleHit`, and `HandleMiss` semantics. Preserve existing cache behavior and
  add an adapter for the Pingora HTTP path rather than rewriting the cache
  implementation. `1.6.2` has moved cache key identity, serialized object
  envelopes, cache-tag helpers, disk index types, native cache storage traits,
  plaintext disk object header sizing/encoding/parsing, and storage-bin
  layout/manifest/free-map helpers into `fluxheim-cache`; encrypted disk-object
  handling and storage-bin safe file opening remain in the root adapter until
  the native HTTP/cache cutover.
- `1.6` server-runtime ownership work: replace Pingora `Server`, listener/TLS
  setup, hot-restart fd passing where retained, service registration, signal
  handling, and TLS resolver hooks with a Fluxheim-owned Tokio server
  bootstrap. Preserve bare-metal hot restart only if its operational value
  justifies the complexity; cloud-native deployments may accept a simpler
  listener model.
- `1.6` HTTP runtime replacement work: replace Pingora `ProxyHttp` and
  `Session` with a Fluxheim-owned HTTP core built around standard `http` types
  and an async request/response pipeline. Treat this as the largest
  dependency-reduction project, with migration fixtures proving that cache,
  compression, PHP-FPM, GeoIP, mirroring, auth-request, rate limits, access
  policy, observability, and failure paths behave the same.
- Dynamic service discovery beyond static config and normal DNS resolution,
  using Fluxheim's native discovery interface after the backend-set model is no
  longer coupled to Pingora's load-balancing crate.
- Runtime add/remove-member and runtime metadata-update operations after the
  backend-set swap design is proven across priority-group, locality,
  persistence, health, and queue policy. Runtime weight changes for
  hash/ring/Maglev/power-of-two selectors stay here until their table,
  sampling, and remap semantics are explicitly designed.
- Load-balancer-managed cookie insertion and sticky-session cookie mirroring
  for HA pairs or active-active Fluxheim clusters. This must include signed or
  opaque cookie values, rotation, table-size/TTL limits, peer authentication,
  replay handling, fail-open/fail-closed choices, and clear cache/compression
  interactions before being promoted to stable scope.
- Persistence table dump/restore so source, header, application-cookie, and
  load-balancer-managed cookie affinity can survive reloads and controlled
  restarts without unbounded disk growth.
- HA state replication for runtime member overrides, selected sticky-session
  tables, and optionally passive-health/circuit state. The first design should
  prefer a small authenticated peer protocol over ad hoc shared files, and it
  must document split-brain, peer loss, replay, and bounded-memory behavior.
- Weighted random two-choice as a distributed-load-balancer policy.
- Dynamic ratio / external load-score selection when the score source, trust
  boundary, expiration, replay behavior, and audit trail are proven.
- UDP proxying as a separate `1.5.x` transport follow-up, with each target
  scoped separately: DNS UDP load balancing, syslog UDP forwarding, QUIC
  pass-through, or game-server UDP proxying. Do not build a generic UDP catchall
  without session table, affinity, timeout, health-check, metrics, and
  rootless/container-network semantics.
- Direct Server Return / transparent proxying after Linux routing, source
  address, NAT/SNAT, and observability constraints are documented and tested.
- Cross-node persistence-table replication.
- Global server load balancing (GSLB) / DNS-based traffic steering as a
  separate `1.5.x` control-plane follow-up after local pool health and runtime
  backend mutation are stable. Scope must include DNS answer policy, regional
  failover, TTL behavior, health propagation delay, DNSSEC/evidence
  requirements where relevant, and clear non-goals for authoritative DNS
  features Fluxheim does not own.
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

- Implemented in the 1.2 release line:
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

### 1.6 - Pingora Exit

Goal: remove Pingora from Fluxheim's normal build graph by the end of the
`1.6.x` line. No default, full, cache, proxy, PHP, load-balancer, or release
container build should compile `pingora`, `pingora-core`, `pingora-proxy`,
`pingora-cache`, `pingora-load-balancing`, `pingora-runtime`,
`pingora-rustls`, or vendored Pingora source after the final `1.6.x` release.

This replaces the previous plan to put Wasm in `1.6`. The reason is security
and operational control: Pingora is currently inside Fluxheim's HTTP, listener,
TLS, and proxy runtime security boundary. Reported upstream vulnerabilities and
slow upstream response time make this dependency-reduction work higher priority
than adding a new extensibility feature. Wasm moves to `1.7`.

The work must remain incremental. Each minor release should remove one layer,
preserve operator-facing behavior, and add parity tests before deleting the old
adapter. When cleanup naturally exposes a subsystem boundary, split it into a
focused workspace crate instead of growing the root `fluxheim`
binary/orchestration crate. Good target crates include `fluxheim-server`,
`fluxheim-runtime`, `fluxheim-proxy`, `fluxheim-cache`, `fluxheim-web`,
`fluxheim-php-fpm`, `fluxheim-snapshot`, `fluxheim-acme`,
`fluxheim-headers`/`fluxheim-http-policy`, `fluxheim-protocol`, and other
narrow helper crates. Keep `proxy.rs`, `runtime.rs`, and `admin.rs` as late
extractions: proxy and runtime move only when the native HTTP/server runtime is
ready, and admin moves only after domain crates expose stable APIs so the admin
crate does not become a circular dependency hub.

The 1.6 line also adopts two security-engineering policies learned from the
smaller Aesynx and Skrifheim workspace models:

- [Fluxheim Modularity Policy](modularity-policy.md): large files and unclear
  crate boundaries are security review risk. New Rust implementation files
  should target 300 lines and stay under 500 lines. Existing large files get a
  staged exception inventory and split plan instead of an immediate blocking
  gate.
- [Runtime Facts And Policy Proofs](runtime-facts-and-policy-proofs.md):
  Fluxheim should become more aware of its own runtime decisions through typed,
  bounded, redacted facts and small policy-proof objects. This is not a
  database in the request path; it is a safer internal decision shape for logs,
  metrics, traces, admin status, future Wasm hooks, and pentest review.

Pre-planning dependency map:

| Current Pingora surface | Replacement direction | Notes |
| --- | --- | --- |
| `pingora-load-balancing` backend containers, health service wiring, and background service traits | `fluxheim-load-balancer` owns `FluxBackend`, backend snapshots, discovery, health checks, persistence, runtime state, and Tokio update tasks | Selection logic is already Fluxheim-owned. Finish removing Pingora background/listen/shutdown traits from this crate before touching the HTTP proxy core. |
| `pingora-cache` `Storage`, `CacheKey`, metadata, hit/miss, and adapter types | `fluxheim-cache` owns `FluxCacheStorage`, `FluxCacheKey`, metadata, hit/miss/admission/stale/purge interfaces | The existing disk/index/encryption/eviction code is already Fluxheim logic. Keep a temporary adapter only while the old proxy runtime exists. |
| `pingora::server::Server`, service registration, shutdown watch, and listener bootstrap | `fluxheim-server` / `fluxheim-runtime` built on `tokio`, `tokio::signal`, `JoinHandle`/task registry, watch channels, and a cancellation token such as `tokio-util::sync::CancellationToken` | Keep signal behavior, graceful shutdown, readiness, log rotation, and any retained hot-restart behavior covered by smoke tests before removal. |
| Pingora TCP stream service and transport connector wrappers | direct `tokio::net::TcpListener`, `tokio::net::TcpStream`, existing PROXY protocol framing, `tokio-rustls`, and `tokio-openssl` | Stream proxy data path is already mostly Tokio copy loops, limits, counters, and timers. This is the lowest-risk runtime cutover. |
| Pingora TLS listener configuration and peer abstractions | Fluxheim listener/peer structs backed by `rustls`/`tokio-rustls` and OpenSSL/`tokio-openssl` only | Do not reintroduce s2n or BoringSSL. Preserve SNI, mTLS/client auth, ALPN, OCSP where supported, FIPS/ISO evidence, and cert reload semantics. |
| `pingora::http` wrappers and `pingora::{Error, ErrorType}` | standard `http` types, `bytes`, `http-body`/`http-body-util`, and `fluxheim-common`/`fluxheim-runtime` error taxonomy | Keep conversion shims until the HTTP proxy runtime is fully replaced. New internal APIs should not add fresh Pingora types. |
| Pingora `ProxyHttp` and `Session` callback lifecycle | `fluxheim-proxy` async request pipeline using standard `http` request/response parts, bounded body streams, Fluxheim route/cache/auth/mirror/PHP modules, and explicit upstream connectors | This is the largest migration. Build it beside the old path first, run fixture parity, then cut over profile by profile. |
| Pingora HTTP/1.1 and HTTP/2 connection handling | Evaluate `hyper`/`hyper-util` for HTTP/1.1 and HTTP/2 serving/client pools, with direct `h2` use where Fluxheim needs lower-level limits | Do not cut over until header count, body read, response write lifetime, flow-control, reset, and timeout controls are testable. If an upstream crate does not expose a required safety hook, add a Fluxheim boundary or postpone that protocol mode. |

Replacement rules for 1.6:

- Prefer standard Rust ecosystem crates that Fluxheim already uses or can test
  directly: `tokio`, `http`, `bytes`, `rustls`, `tokio-rustls`, `openssl`,
  `tokio-openssl`, `thiserror`, and focused protocol crates such as
  `hyper`/`hyper-util`/`h2` only after a security-hook review.
- New crates must be owned by a domain boundary first, not added directly to
  `proxy.rs` or `runtime.rs`. The root `fluxheim` crate should mostly wire
  config, feature flags, and binaries together.
- Use the Pingora-exit line to finish the larger crate boundaries before
  starting new `1.7+` feature families. `fluxheim-snapshot`,
  `fluxheim-acme`, `fluxheim-headers`/`fluxheim-http-policy`, and
  `fluxheim-protocol` should move when their dependency direction is clean.
  `fluxheim-proxy`, `fluxheim-runtime`, and a possible `fluxheim-admin` should
  remain later steps because they currently coordinate many other domains.
- Feature mapping must stay explicit: root features such as `proxy`, `cache`,
  `load-balancer`, `stream-proxy`, `php-fpm`, `tls-rustls`, and `tls-openssl`
  map to matching sub-crate features. Avoid hidden default features that pull
  Pingora back into the graph.
- New substantial code should follow the 300-line target / 500-line hard target
  from the modularity policy. If an existing large legacy file must be touched,
  avoid making it larger unless the same release records an exception update or
  a split step.
- New security-sensitive decisions should prefer typed decision/proof structs
  over ad hoc booleans and string reasons where practical. The proof model may
  start small, but the direction should be consistent: bounded reason enums,
  explicit policy epochs, redaction classification, and deterministic
  allow/deny/redact/defer outcomes.
- Every cutover release gets a dependency gate that knows which Pingora crate
  should already be gone. By the final 1.6 release, all official profile
  `cargo tree` runs and container builds must fail if any Pingora crate appears.
- The old and new paths may coexist only behind temporary internal feature
  gates during migration. They must not both ship as long-term supported
  runtimes.

Planned `1.6.x` sequence:

The remaining `1.6.x` entries are implementation checkpoints, not mandatory
public tags. To keep external pentest and release costs sustainable, continue
committing checkpoint work through the final Pingora-removal proof, then publish
the combined Pingora-exit result as the next `1.6.29` release and keep `1.6.30`
available for the stabilization/security-only follow-up.

- `v1.6.0`: Pingora-exit foundation. Freeze current HTTP/proxy/cache/LB
  behavior into golden tests, migration fixtures, smoke scripts, packet-level
  HTTP fixtures, cache fixtures, TLS fixtures, and release gates. Add
  dependency-graph checks that can fail the release once a target Pingora crate
  is expected to be gone. Add repeatable runtime baseline tooling before any
  replacement runtime ships: first capture locked dependency trees, per-profile
  Pingora dependency presence, release metadata, and default release-binary
  size; then extend the same evidence format to startup time, memory,
  file-descriptor use, idle connection cost, loopback HTTP/1.1 latency,
  keep-alive throughput, cache HIT/MISS latency, load-balancer selection cost,
  TLS handshake cost for rustls and OpenSSL where available, and representative
  container image size. Save machine-readable output under
  `target/release-evidence/runtime-baseline/` during release gates and keep the
  benchmark method, command lines, environment assumptions, and accepted
  comparison rules in a tracked documentation file such as
  `docs/runtime-baseline.md`. Add the first `fluxheim-runtime` /
  `fluxheim-server` traits and keep runtime behavior unchanged. Also record the
  extraction dependency graph in `docs/extraction-dependency-graph.md` for the
  remaining large root modules:
  `snapshot.rs`, `acme.rs`, `headers.rs`, `proxy_protocol.rs`,
  `trace_context.rs`, `runtime.rs`, `proxy.rs`, and `admin.rs`, so later
  cutovers are ordered by dependencies rather than file size.
  Add the first report-only modularity gate: list non-generated Rust files over
  500 lines, create a legacy exception inventory with split targets, and fail
  only for new oversized files or legacy files that grow without an exception
  update. Add the initial runtime-fact and policy-proof design inventory:
  fact kinds, decision kinds, bounded reason enums, policy epoch terminology,
  redaction/visibility levels, and the first candidate subsystems to adopt
  proof-shaped decisions.
- `v1.6.1`: load-balancer independence. Remove `pingora-load-balancing` from
  normal builds. Replace remaining
  Pingora background/listen/shutdown service traits in
  `fluxheim-load-balancer` with Fluxheim/Tokio task handles. Add a
  load-balancer-only `cargo tree` gate proving `pingora-load-balancing` is not
  compiled. Committed work includes the active dependency cut, native backend
  sets and TCP health-check adapter, focused load-balancer container runtime
  smoke, the first `fluxheim-load-balancer` API/runtime DTO split, and moving
  the Pingora `ServiceWithDependents` adapter from the load-balancer crate to
  the root runtime boundary. Request-key extraction now uses a
  Fluxheim-owned `LoadBalancerRequestView` so Pingora request headers are
  adapted only at the root proxy boundary. The remaining Pingora HTTP
  health-check connector is carried into the HTTP/runtime cutover.
- `v1.6.2`: cache independence. Move cache interfaces into `fluxheim-cache`
  and replace remaining Pingora cache key/meta/hit/miss/admission adapter
  usage where the cache domain itself can be made transport-neutral. Keep a
  temporary compatibility adapter only for the old HTTP runtime. The current
  Pingora facade still requires `pingora/cache` while the legacy proxy runtime
  imports `pingora::cache`; keep that exception explicit and track final
  `pingora-cache` compile removal under the native HTTP/runtime cutover.
  Committed work includes cache key identity, serialized object envelopes,
  disk index entries, disk index management, a crate-owned
  `FluxCacheStorage`/hit/miss interface, and native-interface adapters for
  memory, filesystem disk, storage-bin disk, disk-backend, and tiered cache
  storage.
- `v1.6.3`: stream runtime cutover. Move TCP stream proxying to
  `fluxheim-stream` or `fluxheim-proxy` using direct Tokio listeners and
  connectors, including upstream TLS/mTLS through rustls and OpenSSL.
  Committed work includes `fluxheim-stream`, stream upstream selection,
  source allow/deny policy, trusted PROXY source parsing, DNS-rebinding guard
  decisions, copied-byte accounting, byte-limited copy-loop timeout handling,
  and PROXY protocol parsing/writing. Keep the root stream adapter as the
  temporary Pingora service-registration boundary until background/runtime
  supervision is replaced, and keep stream smoke tests for source ACL, SNI
  verification, PROXY protocol, limits, and timeout behavior.
- `v1.6.4`: background runtime cutover. Replace Pingora background service
  wiring with Fluxheim-owned Tokio task supervision, cancellation, readiness,
  and shutdown handling for cache metrics, ACME renewal, stale purging,
  admin/self-healing work, discovery refresh loops, and load-balancer updates.
  Committed work includes moving the shared Fluxheim shutdown, readiness,
  background-task trait, and background-service handle into `fluxheim-runtime`,
  replacing the root implementation with a narrow Pingora registration adapter,
  and making the load-balancer crate reuse the same runtime primitives. It
  also moves admin self-healing snapshot runtime state, pending validation,
  validation metrics, health-signal outcomes, and expiry/error-rate rollback
  decisions into `fluxheim-snapshot`.
  This is the right point to move durable config snapshot IDs, metadata, store
  validation, listing, rollback file operations, and known-good state helpers
  into `fluxheim-snapshot`, with the root admin/runtime modules left as API
  adapters until their own boundaries are ready.
- `v1.6.5`: HTTP/error, protocol, and header-policy boundary cleanup. Finish
  standard Rust `http` type usage and Fluxheim-owned error taxonomy at internal
  boundaries. Move proxy protocol framing, HTTP type adapters, path-safety
  helpers not already in `fluxheim-common`, and other small protocol helpers
  into `fluxheim-protocol` where that does not create a dependency cycle. Start
  `fluxheim-headers` or `fluxheim-http-policy` for hop-by-hop stripping,
  trusted forwarded-header normalization, route/header mutation helpers, and
  related tests, but keep proxy-session-specific application in the root proxy
  adapter until the native HTTP runtime exists. Keep only narrow compatibility
  shims where a not-yet-replaced outer runtime still needs them. Add a
  lint/search gate that blocks new internal `pingora::http` and
  `pingora::Error` usage outside adapters.
- `v1.6.6`: listener/TLS abstraction. Introduce `fluxheim-tls` for
  Fluxheim-owned downstream TLS listener planning, certificate selection, SNI
  matching, ALPN/cipher policy, TLS provider setup, and FIPS runtime checks.
  Keep Pingora listeners active only as the old adapter while parity tests run.
  Move ACME order/account/certificate installation, renewal scheduling inputs,
  filesystem safety helpers, and certificate-install rollback logic behind
  `fluxheim-acme` APIs once the native listener/server cutover can consume them
  without depending on the old Pingora runtime.
- `v1.6.7`: server bootstrap planning boundary. Build the Fluxheim-owned
  `ServerPlan` surface for process settings, listener inventory, service
  intent, background-task intent, downstream HTTP/2 policy, PROXY protocol
  listener policy, and admin/private Unix socket planning while keeping the
  active Pingora runtime as an explicit compatibility adapter.
- `v1.6.8`: native server/listener continuation and HTTP/1.1 runtime preview
  foundations. Start with a Fluxheim-owned bounded HTTP/1.0/HTTP/1.1
  request-head parser and server-plan HTTP/1 limits, continue removing Pingora
  server/listener glue, then add the Fluxheim-owned HTTP/1.1 proxy pipeline
  beside the old path using standard `http` types, bounded body streams,
  explicit downstream/upstream timeouts, and existing route/policy modules.
  Keep it behind an internal migration feature until fixture parity is green.
- `v1.6.9`: native HTTP/1.1 runtime continuation and static-serving parity.
  Add the Fluxheim-owned HTTP/1.1 connection/listener runtime over Tokio IO,
  map `[server.limits]` into the native HTTP/1 policy, and prove static file
  serving, HEAD framing, directory listings, fixed-length bodies, chunked
  bodies, keep-alive, explicit close, and shutdown behavior with real socket
  tests. Keep the active production proxy/cache/PHP listener on the Pingora
  compatibility adapter until full route and upstream parity is green.
- `v1.6.10`: native HTTP/1.1 upstream/proxy foundation. Add the
  Fluxheim-owned bounded upstream HTTP/1 client, plain static-upstream proxy
  handler, and `ServerPlan` eligibility inventory for native proxy candidates.
  Keep the production default on the Pingora compatibility adapter until route
  matching, request/response header policy, access policy, rate/concurrency
  limits, retries, compression, auth-request, traffic mirroring, PHP-FPM, ACME
  challenge routing, GeoIP, cache interaction, observability, and
  admin-visible failure semantics are all implemented and smoke-tested on the
  native path. The eligibility gate must fail closed for unsupported policy
  layers, dynamic discovery, load balancing, upstream TLS, upstream PROXY
  protocol, HTTP/2 upstreams, and websocket upgrade. Connection pooling remains
  deferred performance parity until the upstream connector/pooling work in
  `v1.6.13`.
- `v1.6.11`: native HTTP/2 runtime preview. Add HTTP/2 serving/proxying through
  the selected Rust stack only after validating request-boundary limits,
  response-flow-control lifetime limits, slow-body protection, stream resets,
  trailer behavior, gRPC pass-through, HPACK/header-count controls where
  available, and mixed HTTP/1.1+HTTP/2 fixtures. Start with an explicit
  `fluxheim-server` preview gate that records every required safety hook and
  keeps native HTTP/2 cutover blocked until the missing hooks are implemented
  and covered by parity fixtures.
- `v1.6.12`: native HTTP/2 runtime hardening. Promote the preview into a
  reusable `fluxheim-server` HTTP/2 connection primitive with Fluxheim-owned
  request/response types, explicit response-write lifetime, bounded response
  DATA capacity handling, and request/response trailer parity. Keep production
  HTTP/2 cutover blocked until the remaining pre-routing HPACK/header-count
  allocation proof is implemented or the protocol mode has an equally strong
  Fluxheim-owned boundary.
- `v1.6.13`: native HTTP/1.1 upstream connector and pooling parity. Replace the
  simple static-upstream HTTP/1.1 connector/pool path with Fluxheim-owned
  connectors, bounded connection reuse, request/response timeout handling,
  connection accounting, privacy-mode-safe observability, and focused smoke
  tests. Keep Pingora as the production proxy fallback for unsupported policy
  layers, HTTP/2 upstreams, upstream TLS/mTLS, dynamic discovery, and complex
  retry/failover behavior.
- `v1.6.14`: native upstream TLS/mTLS, SNI, CA verification, and conservative
  static failover parity. Extend the Fluxheim-owned upstream connector to cover
  rustls/OpenSSL TLS, client certificates, explicit SNI, per-route CA bundles,
  plain static upstream lists with safe-method ordered failover, conservative
  retry decisions, and admin-visible failure reasons. Keep DNS/file/runtime
  discovery and advanced load-balancer policy behind eligibility gates until
  the native path can prove it never silently downgrades verification, routing,
  or health semantics.
- `v1.6.15`: native HTTP/2 upstream/client parity and remaining HTTP/2 safety
  hooks. Add Fluxheim-owned HTTP/2 upstream request handling, stream reset and
  trailer behavior, gRPC pass-through fixtures, response-flow-control lifetime
  checks, and any remaining HPACK/header-count allocation boundary needed
  before production HTTP/2 cutover. If a crate does not expose a required
  safety hook, keep that protocol mode gated off rather than forcing cutover.
- `v1.6.16`: native proxy cutover for simple proxy, cache, static, and PHP
  paths. Move the first production-eligible profiles to the Fluxheim-owned
  request pipeline only where route matching, request/response header policy,
  access policy, rate/concurrency limits, compression, auth-request, traffic
  mirroring, PHP-FPM, ACME challenge routing, GeoIP, cache interaction,
  observability, and admin-visible failure semantics are all explicitly
  supported or fail closed. Preserve the Pingora compatibility adapter for any
  profile or feature combination still outside the native eligibility matrix.
- `v1.6.17`: remove the last direct Pingora dependency from the
  `fluxheim-load-balancer` crate. Replace the Pingora HTTP health-check client
  with Fluxheim-owned HTTP/1 and h2/gRPC probes, keep TCP/Redis/MySQL/Postgres
  checks native, and add real listener-backed tests proving HTTP/1 and gRPC
  health checks still work. Release gates must prove `cargo tree -p
  fluxheim-load-balancer` has no Pingora crates. The root compatibility runtime
  may still pull Pingora transitively until the next native HTTP cutover step.
- `v1.6.18`: expand the native cutover to every official profile and remove
  `pingora-proxy`, `pingora-cache`, `pingora-pool`, `pingora-lru`,
  `pingora-timeout`, Pingora HTTP/error wrapper dependencies, and other
  proxy/cache/pool transitive Pingora crates from normal builds. Release gates
  must prove default, full, cache, proxy, PHP, load-balancer, FIPS, macOS
  developer, and release-image profiles no longer compile those crates.
  Split the now-native load-balancer health-check implementation by protocol
  once the 1.6.17 behavior has settled, so TCP/TLS, HTTP/1, gRPC/h2, Redis,
  MySQL, PostgreSQL, exec, and shared validators are reviewable independently.
  After proxy, cache, load-balancer, snapshot, ACME, header-policy, and
  protocol crates have stable APIs, reduce `admin.rs` to endpoint routing and
  auth glue or move it into `fluxheim-admin` if the dependency graph stays
  one-way. Do not let admin own domain state; it should call domain APIs and
  serialize responses.
- `v1.6.19`: isolate the remaining Pingora compatibility runtime behind an
  explicit Cargo feature boundary and prove native TLS-only web builds do not
  pull Pingora through TLS feature forwarding. Do not claim this as the final
  runtime cutover; root proxy/admin/metrics/listener compatibility removal is
  a behavior change and belongs in the next slice.
- `v1.6.20`: make the production runtime cutover contract explicit and keep the
  remaining compatibility adapter behind measured blockers instead of forcing an
  unsafe flip. This slice must keep the native TLS/listener work Pingora-free,
  preserve the native HTTP/1 and HTTP/2 proof tests, record which production
  services still require compatibility glue, and split any newly touched
  runtime code toward the 500-line modularity target. Dependency policy targets
  move to the final proof release only with matching release notes explaining
  the remaining blockers.
- `v1.6.21`: add and test the Fluxheim-owned Tokio background supervisor and
  shutdown token that will replace Pingora background-service orchestration for
  internal tasks. Certificate reload, ACME renewal, cache stale purge, cache
  metrics, OTLP export, and load-balancer refresh tasks already implement the
  Fluxheim task trait; keep the production Pingora adapter while the main
  server shutdown source still comes from Pingora, and wire those tasks to the
  native supervisor during the `1.6.22`-`1.6.24` runtime/listener cutover.
- `v1.6.22`: move metrics/admin/ops HTTP serving onto Fluxheim-native HTTP
  handlers. Admin must stay auth-first and should expose the same response
  shape as the compatibility path. Release gates need localhost smoke coverage
  for admin health/status, metrics scrape, and ops socket behavior.
- `v1.6.23`: cut stream and UDP proxy service startup over to Fluxheim-native
  listeners and shutdown handling. Keep the existing stream/UDP data paths but
  remove Pingora service registration from those services. Soak tests should
  cover stream byte limits, connection caps, downstream PROXY protocol, UDP
  session expiry, passive health, and per-source rate limits.
- `v1.6.24`: finish the native HTTP/2 downstream parity proof and make the
  representative native-runtime cutover report blocker-free for the simple
  HTTP/1 + HTTP/2 + admin + metrics + stream + UDP config. Keep the remaining
  Pingora runtime/listener/TLS adapter crates in normal builds until the next
  checkpoint so the final deletion is reviewed as a focused dependency-removal
  change.
- `v1.6.25`: harden the Pingora-exit evidence before final deletion. Add
  per-proxy native HTTP/1 candidate rows to the runtime cutover report so
  cache, web, PHP, auth, traffic mirror, rewrite, compression, and advanced
  load-balancer blockers are visible per configured scope. Add the first native
  HTTP/1 route-proxy execution primitive for ordinary exact, prefix, and
  fallback proxy routes, including method filters, longest-prefix selection,
  prefix rewrite/strip, query preservation, and safe-path validation. Re-scope
  the dependency exception target to the final deletion release rather than
  pretending the rich proxy path can be removed without finishing those parity
  slices.
- `v1.6.26`: move the remaining native policy execution closer to parity for
  ordinary proxy configs. Add native route redirect actions with safe `{uri}`,
  `{path}`, and `{query}` expansion, and enforce route-level request body
  limits before forwarding. Apply route-level response header overlays for
  supported native route-proxy responses. Keep request-header mutation,
  response-header rewrites, access policy, forwarded-header handling, and
  compression hooks targeted for follow-up slices with native request/response
  tests.
- `v1.6.27`: start moving rich proxy integrations onto native adapters by
  landing route-level native static web serving. Reuse `fluxheim-web` for
  ETags, conditional requests, ranges, `HEAD`, directory listings, and
  symlink-safe path planning, with real native HTTP/1 listener tests. Also move
  explicit route request-header unset/set/append mutations into the native route
  proxy while keeping forwarded-client-IP ownership shortcuts on the
  compatibility path. Add native default round-robin and static weighted
  round-robin selection for multiple static upstreams while keeping
  health-aware, persistence, priority-group, backup/drain, dynamic discovery,
  and hash-based load-balancer policies on the compatibility path. Move
  route-level response rewrite rules for `Location`, `Refresh`, and
  `Set-Cookie` onto the native route response policy through
  `fluxheim-headers`.
  Keep cache lookup/fill/stale paths, PHP-FPM routing, auth-request, traffic
  mirror, and compression targeted for the next compatibility-removal slices.
- `v1.6.28`: continue the native rich-proxy parity work instead of forcing an
  unsafe final deletion. Move route-level response compression onto the native
  HTTP/1 route proxy through `fluxheim-compression`, with gzip/brotli/zstd
  feature mapping and live native listener tests. Move `proxy.error_pages`
  onto the native HTTP/1 proxy by serving configured static fallback pages
  through `fluxheim-web` on 502/504 failures. Keep inherited global/vhost
  compression, cache lookup/fill/stale, PHP-FPM, auth-request, traffic mirror,
  forwarded-client-IP ownership shortcuts, dynamic discovery, health-aware
  load-balancing, persistence, priority/backup/drain, and hash-based selection
  on the compatibility path until each has native parity tests.
- `v1.6.29`: move inherited global/vhost compression and root/vhost/route
  header policy onto the native HTTP/1 proxy and route proxy. Prove plain proxy
  compression, inherited route compression, request-header mutation,
  response-header mutation, standard response security headers, and safe
  forwarded-header ownership modes with live native listener tests. Support
  `X-Forwarded-For = off`, `X-Forwarded-For = replace`, `X-Real-IP`,
  `X-Forwarded-Host`, `X-Forwarded-Proto`, RFC `Forwarded`, and trusted-chain
  `X-Forwarded-For = append` on the native path. Move vhost redirect fallback
  routes and explicit ACME HTTP-01 upstream challenge routes into native
  route-proxy construction and the cutover inventory, preserving the
  compatibility route order. Move regex route matching and path-only
  `rewrite_template` capture expansion onto the native route proxy with live
  tests for safe capture encoding and unsafe rewritten-path rejection. Move
  IP/CIDR vhost and route access allow/deny policy onto the native route proxy
  with live tests for direct-peer denial and trusted forwarded-chain client
  restoration. Move vhost and route concurrency limits onto the native route
  proxy, including immediate reject and bounded queue timeout behavior. Move
  vhost and route local rate limiting onto the native route proxy, including
  token-bucket rejection and delay-mode admission. Move per-proxy downstream
  response write timeout, total response timeout, and minimum send-rate policy
  onto native HTTP/1 proxy responses. Move
  `proxy.upstream_total_connection_timeout_secs` onto native upstream
  establishment. Move `proxy.upstream_tcp_recv_buffer_bytes` and
  `proxy.upstream_dscp` plus the upstream TCP keepalive triple onto native
  upstream socket creation, and move `proxy.upstream_tcp_user_timeout_ms` on
  targets that expose `TCP_USER_TIMEOUT`. Move
  `proxy.downstream_read_timeout_secs` onto native HTTP/1 request-body parsing
  after route/proxy selection. Move route-scoped `[vhosts.routes.grpc]`
  request validation onto the native route proxy. Add native request-context
  slots for TLS client identity and Geo context, populate TLS identity from
  native rustls/OpenSSL listener handshakes, let handlers attach Geo context,
  and teach the native route-proxy access evaluator to consume those typed
  facts so cert/Geo access policy no longer blocks the native HTTP/1 cutover
  inventory.
  Move safe-method traffic mirroring onto the native HTTP/1 proxy when the
  `traffic-mirror` feature is compiled. Move `proxy.auth_request` onto the
  native HTTP/1 proxy when the `auth-request` server feature is compiled.
  Finish the remaining native HTTP policy blockers that do not need cache, PHP,
  dynamic discovery, or load-balancer state: wire runtime TLS client identity
  into native request context for vhost and route certificate access policy,
  wire Geo country/ASN context into native request context for vhost and route
  Geo access policy, move managed local ACME HTTP-01 challenge serving onto the
  native path, and either implement upstream TCP Fast Open safely or document it
  as an explicitly unsupported native blocker. Add live native listener tests
  for each path and keep cache, PHP-FPM, dynamic discovery, load-balancer state,
  upstream TCP Fast Open, and upstream HTTP/2 explicitly reported as
  compatibility blockers until they have native parity tests.
- `v1.6.30`: move plaintext native upstream HTTP/2 forwarding into the native
  HTTP/1 proxy path. Support `proxy.upstream_http_version = "http2"` for h2c/
  prior-knowledge origins, map `proxy.read_timeout_secs`,
  `proxy.send_timeout_secs`, and `proxy.upstream_h2_max_streams` onto the native
  H2 policy, keep a Tokio connection-driver task per pooled h2 connection,
  reserve stream capacity with `proxy.upstream_h2_max_streams`, fail closed on
  invalid programmatic stream limits, bound the H2 handshake, invalidate stale
  pooled handles on h2 errors, and retry safe methods once after a pre-response
  pooled-handle failure. Add live proxy tests proving downstream HTTP/1 requests
  forward to in-process plaintext and TLS/ALPN H2 origins, reuse one upstream H2
  connection, emit configured H2 keepalive pings, reconnect after upstream
  GOAWAY, preserve static ordered and weighted upstream selection while using
  H2 transport, negotiate TLS `http1-and-http2` fallback through ALPN, and add
  an explicitly disabled-by-default `proxy.upstream_h2c_upgrade` compatibility
  mode for plaintext `http1-and-http2` origins that support HTTP/1.1 h2c
  Upgrade. Keep advanced health-aware/dynamic load-balancer state on the
  `v1.6.32` native load-balancer cutover instead of mixing it into this
  upstream transport slice.
- `v1.6.31`: move the native runtime dispatch, HTTP/1 upstream transport, host
  routing, admin/metrics/stream/UDP service registration, and proxy listener
  TLS/PROXY-protocol paths far enough that a representative full runtime can
  run under the Fluxheim-owned supervisor. Keep rich proxy cache, PHP-FPM, and
  WebSocket/upgrade gates explicit until their native adapters can prove full
  request/response parity.
- `v1.6.32`: finish native load-balancer compatibility and keep the native
  runtime launch evidence honest. This release closes the proxy gates that need
  shared runtime/load-balancer state: dynamic discovery, health-aware selection,
  persistence, priority groups, locality, backup/drain/disabled policy,
  max-in-flight, aliases/tags, static weight parity, and native service
  supervision for load-balancer refresh tasks. Static ordered/weighted pools,
  active health checks, static advanced load-balancer policy, and dynamic
  discovery may run natively only when the native proxy and refresh task share
  the same `UpstreamLoadBalancer` state. File/HTTP/DNS discovery must clone
  vetted upstream transport policy onto selected dynamic authorities instead of
  trusting unbounded per-request transport configuration. Add a Fluxheim-owned
  nginx/Ketama-compatible consistent hash selection mode for operators
  migrating from nginx or Pingora Ketama behavior. Keep the existing rendezvous
  consistent-hash and bounded-load consistent modes as the default Fluxheim
  algorithms, but document that the compatibility mode is for matching
  nginx-style request-to-backend mapping. Do not depend on `pingora-ketama`;
  implement and test the ring behavior in Fluxheim with parser, static-ring
  rejection, and runtime mutation tests. Complete the current native PHP-FPM
  route work: request-to-FastCGI parameter planning, PHP stdout-to-native
  response planning, safe static script resolution, request-body staging,
  bounded FastCGI execution, external and managed php-fpm route actions, and
  PHP custom error pages. Convert the downstream HTTP/2 preview into production
  native listener dispatch with TLS ALPN `h2` selection, multi-stream proxy
  handling, request/response trailer preservation, and fail-closed behavior for
  unsupported upgrade semantics. Keep proxy-cache parity as the explicit
  remaining compatibility blocker. This release should be pentested and shipped
  before starting the final cache work so cache findings are attributable to
  the next focused slice.
- `v1.6.33`: close the final native proxy-cache parity gates. Cache work must
  cover lookup/fill/stale, Vary/Range/conditional semantics, cache status and
  reason headers, no-store/private/Set-Cookie admission protection,
  cache-control overrides, HEAD bypass behavior, stale-if-error and
  stale-while-revalidate, peer-fill guardrails, purge visibility, and
  root/vhost/route cache policy readiness only after the native adapter owns
  the full request/response/cache-key path. Add focused unit tests plus live
  native listener smoke tests proving `MISS` followed by `HIT`, stale serving,
  Vary isolation, auth-before-cache ordering, range/slice behavior where
  supported, and disk/memory/tier behavior. Do not remove Pingora in this
  release unless the cache smoke and pentest pass cleanly; the goal is cache
  parity, not simultaneous dependency deletion.
  - Current checkpoint: native HTTP/1 proxy memory-cache lookup/fill is wired
    for ordinary single-upstream GET responses. It reuses `fluxheim-cache`
    request/response policy helpers, emits configured cache status/reason
    headers, preserves HEAD bypass behavior, isolates origin/configured Vary
    variants in memory, serves configured `stale_if_error_secs` entries on
    upstream errors/statuses, enforces `cache.origin_protection` fill budgets,
    serves bounded single `Range` requests from fresh cached full objects,
    supports native load-balanced upstream pools for the same memory-cache
    subset, supports `cache.min_uses`, `cache.pass_uncacheable_after`, and
    opt-in `[cache.predictor]` cache-pass decisions through bounded
    Fluxheim-owned counters, serves `stale_while_revalidate_secs` objects with
    bounded background refresh, supports `[cache.lock]` same-key request
    collapsing for concurrent memory-cache misses, supports memory-tier
    `[cache.range.slice]` fixed-slice range composition, supports peer-fill
    over HTTPS and loopback-or-opt-in HTTP, supports unencrypted, local-key
    encrypted, and OpenBao Transit encrypted filesystem and storage-bin disk
    cache plus memory+disk tiering, and has live native listener `MISS` then
    `HIT`, collapsed-fill `HIT`, slice-fill then slice `HIT`, multipart slice
    composition, filesystem disk persistence, encrypted filesystem disk
    persistence, storage-bin persistence, encrypted storage-bin persistence,
    OpenBao storage-bin validation/hit decrypt coverage, memory refill from
    disk, `PEER-HIT` then `HIT`, and stale-refresh tests. Storage-bin file-set,
    manifest, index, bin allocation, free-map recovery, and native index I/O
    now live behind the `fluxheim-cache`/native adapter boundary.
- `v1.6.34`: remove the final Pingora runtime/listener/TLS adapter crates from
  normal builds after proxy-cache parity is proven. The native WebSocket
  baseline already covers strict `Upgrade: websocket` requests on forced HTTP/1
  static upstream routes with shared 101 validation, prebuffer preservation,
  and a bounded bidirectional tunnel; native load-balanced WebSocket pools
  select one upstream at upgrade time and pin the tunnel to that backend.
  Remaining upgrade work should cover generic token-based HTTP/1 upgrades only
  if there is a real operator need and HTTP/2 WebSocket semantics separately
  from hop-by-hop HTTP/1 upgrades. This release is the final Pingora-free proof
  release: `cargo tree`, release containers, RPM builds, source builds, and
  focused artifacts must all prove no normal Fluxheim build compiles vendored
  Pingora code.
- `v1.6.35`: stabilization/security-only release for the Pingora-free runtime
  before adding new extensibility or protocol surface. This release should
  prioritize pentest cleanup, performance regression checks, memory/FD leak
  checks, long-running soak tests, runtime-baseline comparisons, and
  documentation clarity. It should also run the first-party secret-memory
  migration from direct `zeroize` APIs to the Fluxheim `sanitization` crate
  where practical, using crate-scoped patches and tests. Keep third-party
  transitive `zeroize` use inside crates such as rustls/AWS-LC untouched, and
  avoid mixing this secret-container migration into the runtime cutover slices.
  Expand release evidence after the Pingora removal by making optional live
  smokes easy to run through a single test starter, adding a smoke dependency
  image freshness check for WordPress/OpenBao/database images, and proving
  privacy mode, nginx-compatible Ketama, load-balancer container
  failover/recovery/all-down behavior, database health checks, OpenBao cache
  encryption, and WordPress PHP-FPM/proxy-TLS behavior with real local or
  containerized services. Close the peer-fill MITM cache-poisoning gap in this
  stabilization release by adding a `cache.peer_fill.shared_secret_file`
  response-bound HMAC mode: outbound peer-fill requests carry a nonce/request
  signature, peers sign status/canonical headers/body digest, and receivers
  discard unsigned or tampered peer responses before cache storage. Require that
  shared secret for non-loopback `http://` peer-fill URLs so cross-host
  plaintext peer fill cannot remain silently unauthenticated.
- `v1.6.36`: post-cutover structural cleanup release before the `1.7` Wasm
  line. Turn the temporary native proxy boundary into proper crate APIs by moving
  any still-needed DTOs/helpers out of `src/native_proxy.rs` and into
  their owning crates, updating root callers to import `fluxheim-server`,
  `fluxheim-cache`, `fluxheim-load-balancer`, and related crate APIs directly,
  then deleting the shim. Delete disabled Pingora-era root modules and inert
  `cfg(any())` compatibility code once no normal or test profile references
  them. Keep this release behavior-preserving and cleanup-only except for
  fixes found by pentest/CI.

  Required cleanup outcomes:

  - Remove `src/native_proxy.rs` or reduce it to an empty deleted
    compatibility boundary with all still-used request/cache/admin DTOs moved
    into their owning crates.
  - Remove dead Pingora-era root modules and adapters that are no longer
    compiled by any supported profile, including old proxy/cache/web/listener
    compatibility surfaces where tests prove the native replacement owns the
    behavior.
  - Replace root imports of old `crate::proxy::*` compatibility symbols with
    direct imports from `fluxheim-server`, `fluxheim-cache`,
    `fluxheim-load-balancer`, `fluxheim-headers`, or other owning crates.
  - Move cache-preview route matching onto the same precompiled native route
    selection structures used by the serving path. The temporary shim currently
    compiles regex routes on demand for authenticated admin cache-preview
    calls; this is bounded and off the hot path, but deleting the shim should
    remove that duplicate matcher entirely.
  - Keep peer-fill authenticity follow-ups behavior-preserving: improve secret
    source ergonomics, add optional certificate pinning/mTLS-specific examples,
    and retain live tamper tests proving forged peer-fill responses are
    discarded.
  - Add a true ACME live-issuance smoke against a disposable local ACME CA such
    as Pebble or another bounded test CA. Existing `1.6.35` coverage validates
    native TLS planning, managed certificate loading, ACME storage safety, and
    renewal logic, but it does not yet perform a complete HTTP-01/TLS-ALPN-01
    issuance cycle against a live CA in one script.
  - Keep `scripts/validate-pingora-dependency-policy.sh check`,
    `scripts/validate-modularity-policy.sh check`, release containers, RPM,
    and representative smoke tests as blocking evidence for the cleanup.

- `v1.6.37`: final pre-Wasm crate-boundary cleanup release. Use this release to
  finish the obvious post-Pingora crate moves that make future work easier,
  while keeping runtime behavior stable and avoiding a giant `1.6.36` release.
  New substantial code after this line should default to a focused workspace
  crate or an existing domain crate, with the root `fluxheim` crate acting as
  binary/orchestration glue.

  Primary extraction targets:

  - Start `fluxheim-acme` as a workspace crate and move ACME account, order,
    challenge, renewal, certificate install, and certificate observation logic
    into it. Keep `src/bin/fluxheim-acme.rs`, CLI commands, runtime
    orchestration, and the root `src/acme.rs` compatibility re-export as thin
    root wiring until the remaining binary glue can move behind stable crate
    APIs.
  - Move observability helpers still living in root `metrics`, `metrics_otlp`,
    `otel_otlp`, `otlp_http`, and `trace_context` into
    `fluxheim-observability` where this does not change exported metric names,
    log schemas, trace context behavior, or CodeQL path-safety annotations. The
    root modules should remain only as registry/exporter/runtime adapters.
  - Move remaining root header-policy helpers into `fluxheim-headers` without
    changing privacy-mode gates, trusted-proxy semantics, hop-by-hop stripping,
    or forwarding-header behavior. Header security tests must move with the
    logic.
  - Continue reducing `src/native_proxy.rs` and root cache/admin DTO shims by
    moving stable request/result/policy types into `fluxheim-server`,
    `fluxheim-cache`, `fluxheim-load-balancer`, or `fluxheim-headers`. Delete
    root compatibility wrappers once callers use the owning crates directly.
  - Review `src/tls.rs`, `src/upstream_tls.rs`, and `src/stream_tls.rs` for
    small remaining TLS helper moves into `fluxheim-tls` or `fluxheim-stream`.
    Do this only when dependency direction stays domain-crate-only and the root
    runtime remains the orchestrator.
  - Split obvious CLI/config-tester subcommand helpers into smaller root modules
    when it reduces coupling for release/testing workflows. Do not create a
    separate CLI crate unless the dependency graph is clean and the binary
    wiring stays straightforward.

  Deliberate deferrals:

  - Do not attempt a single mechanical `fluxheim-proxy` extraction. Native HTTP
    proxy logic still spans `fluxheim-server` routing, upstream clients, cache,
    PHP/static route adapters, WebSocket, HTTP/2, and admin-visible runtime
    handles. Extract stable DTOs and policy/result types first; move route
    proxy/upstream-client pieces behind a future `fluxheim-proxy` crate only
    after tests prove no circular dependency back to `fluxheim-server`,
    `fluxheim-cache`, or root admin code.
  - Do not move `src/admin.rs` into `fluxheim-admin` yet unless the dependency
    graph has clearly inverted. Admin depends on nearly every domain; it should
    move only after cache, ACME, load-balancer, metrics, TLS, runtime, and
    snapshot crates expose stable request/result APIs.
  - Do not create tiny crates merely to move lines around. Prefer stronger
    existing domain crates and smaller root modules when the extraction does
    not reduce coupling or review risk.

  Required evidence:

  - `scripts/validate-modularity-policy.sh check` remains green or any new
    exception has a documented split target.
  - `cargo test --locked --workspace` and focused crate tests cover every moved
    policy or DTO boundary.
  - Release metadata, RPM, container, native-runtime, Pingora dependency, and
    Pingora boundary gates remain green.
  - Existing smoke tests for ACME/TLS planning, observability, headers,
    cache/admin status, and native proxy behavior still pass without config
    changes.
  - The release notes explicitly list moved crates/modules so reviewers and
    pentest can focus on dependency-boundary and behavior-preservation checks.

Stable exit criteria:

- `cargo tree` for every supported official profile contains no Pingora crate.
- Release containers, RPM builds, source builds, and focused artifacts compile
  without vendored Pingora code.
- `fluxheim-config-tester --runtime-cutover` reports no blockers for the
  representative config, and every real compatibility gate in
  `NativeHttp1ProxyConfigError`, `root_policy_supported`,
  `vhost_policy_supported`, `route_policy_supported`, and the native runtime
  summary has either native support, a parity test, or a deliberately documented
  removal/behavior-change note.
- `1.6.0` baseline evidence exists before runtime cutovers begin, and later
  `1.6.x` runtime releases compare against it. Regressions in latency, memory,
  startup time, binary size, connection cost, cache hit path, TLS handshake
  cost, or container size must be fixed, explicitly accepted in release notes,
  or justified as a security-driven tradeoff.
- HTTP/1.1 and HTTP/2 behavior, routing, upstream selection, cache semantics,
  compression, PHP-FPM, ACME, GeoIP, traffic mirroring, auth-request,
  rate/concurrency limits, header policy, observability, admin-visible failure
  semantics, and migration fixtures remain compatible unless a release note
  explicitly documents a security-driven behavior change.
- Runtime adapters are deleted only after tests prove the new path. Prefer more
  tests over reviewer memory: golden fixtures, malicious-input fixtures,
  protocol-boundary fixtures, cache freshness/range/Vary/conditional fixtures,
  TLS/SNI/mTLS fixtures, load-balancer persistence/health/failover fixtures,
  PHP-FPM fixtures, admin/status fixtures, and smoke/container tests should
  grow with every cutover.
- TLS support remains limited to rustls/rustls-FIPS and OpenSSL/OpenSSL-FIPS,
  with SNI, mTLS/client-auth, ALPN, OCSP where supported, and release evidence
  preserved.
- The root `fluxheim` crate remains orchestration glue; large runtime domains
  live in focused workspace crates.
- New or split Rust implementation files stay under the modularity policy's
  500-line hard target unless documented as a temporary exception with a split
  plan. Legacy oversized files have an actively shrinking exception inventory.
- Security-sensitive decision paths increasingly return typed policy proofs or
  runtime facts that are bounded, redacted, and safe for logs/metrics/traces or
  explicitly marked internal-only.
- Pingora-removal work does not add Wasm, HTTP/3/QUIC, UDP/GSLB, WAF, or
  VPN/firewall appliance behavior.

### 1.7 - WASM Extensibility

Goal: add one shared sandboxed extension runtime for nginx-Lua-style operator
logic and VCL-like cache policy decisions, instead of creating separate
partial extension systems for cache, proxy, WAF, or media features.

The practical target is to cover the operational jobs commonly solved with F5
iRules, nginx Lua/OpenResty, HAProxy Lua/SPOE, and VCL-style cache logic:
conditional routing, pool selection, persistence-key choice, access decisions,
synthetic responses, header mutation, mirror/shadow target choice,
logging/redaction, and bounded cache policy. This is not syntax compatibility
with iRules or Lua. Fluxheim should expose typed, versioned host calls with
strict resource limits instead of embedding a general scripting language into
the proxy or load-balancer hot path.

Stable scope:

- `v1.7.0`: compile-time `wasm`, `wasm-proxy-abi`, and `wasm-wasi` feature
  gates, with the Wasm feature family absent from default builds and rejected
  by `privacy-mode`.
- `v1.7.0`: `fluxheim-wasm` workspace crate foundation with plugin loading
  from approved directories, strict absolute-path validation, regular-file and
  symlink-parent rejection, module-size limits, and SHA-256 recording.
- `v1.7.0`: Wasmtime-based sandbox evaluation with fuel, memory,
  table/instance, and wall-time limits plus a real Wasm smoke script that
  verifies successful execution and trapped infinite-loop behavior.
- `v1.7.0`: typed plugin manifest boundary with plugin name, path, ABI, phase,
  fail-mode, and sandbox-limit validation. Preview ABIs require explicit
  allowance, duplicate phases are rejected, and `fail_open` is rejected for
  security decision phases.
- `v1.7.1`: wire the manifest boundary into Fluxheim config validation and add
  the first live native HTTP/1 access-control hooks. Cover plugin registry,
  per-vhost/per-route attachment validation, host-call namespace,
  deterministic error taxonomy, fail-open/fail-closed behavior, admin-visible
  configured plugin hashes, accepted/rejected registry fixtures,
  F5-iRules-style conditional allow/deny behavior through the first preview
  access ABI, and non-overridable built-in Fluxheim ACLs. Add a deterministic
  plugin-chain model: explicit attachment order/priority, documented
  combinators, and a safe `first-deny-wins` rule for `access-decision`. Add a
  process-wide Wasm admission ceiling such as
  `wasm.max_total_concurrent_executions`, and, if practical,
  `wasm.max_total_memory_bytes`, so per-plugin limits cannot multiply into an
  unbounded process-wide memory/instance spike. Add reload-impact
  classification for all Wasm config changes before compiled modules are
  hot-swapped. Add first-class Prometheus/OTLP metrics for plugin invocations,
  duration, traps, timeouts, fuel exhaustion, admission rejections, and
  fail-mode outcomes with low-cardinality labels. Add live HTTP tests that load
  real Wasm plugins and prove allow/deny, decoded route-policy selection,
  global admission, reload classification, metrics, timeout, trap, and
  fail-mode behavior. Keep request-header mutation staged until typed host
  calls can pass and mutate request header state safely.
- `v1.7.2`: implement request and response header hooks through bounded
  symbolic host calls. Cover nginx-Lua/OpenResty-style request/response header
  mutation and redaction while proving sensitive headers, cookies, bodies,
  filesystem, network, and admin APIs are unavailable unless an explicit future
  capability grants them. Keep broader synthetic response/body surfaces behind
  later reviewed ABI work.
- `v1.7.3`: implement routing, load-balancer, mirror/shadow, and persistence
  decision hooks. Cover HAProxy-Lua/SPOE-style external-policy workflows with
  bounded typed decisions for pool choice, persistence-key choice, mirror
  enablement, and deny/pass/continue outcomes. Add live tests with two origins
  and a load-balancer route so the plugin decision is observable.
- `v1.7.4`: start cache-policy hooks inspired by VCL but expressed as a
  constrained Rust/Wasm ABI. Cover cache lookup/pass/bypass/continue/deny
  decisions before slice lookup, normal lookup, peer-fill, request collapsing,
  origin-fill protection, and store admission. Cover cache-store
  continue/skip-store/deny decisions after origin response and before cache
  writes. Add live cache tests that prove a plugin can pass selected requests
  without storing while normal requests still produce MISS then HIT, and that a
  plugin can skip or deny storage before memory/disk writes.
- `v1.7.5`: add the next bounded cache-policy ABI slice for cache-key
  components, TTL override, tag assignment, symbolic store-admission
  content-type inspection, and safe fixed response-header mutation, with live
  tests for TTL bounds, tag assignment, image-only store metadata, and
  low-cardinality key validation. Ensure cache-key components are applied to
  complete-object, single-range, and fixed-slice range-cache keys, and enforce
  aggregate component caps across chained hooks.
- `v1.7.6`: harden the mature plugin runtime after the request, response,
  routing, and cache hook families exist. Finish atomic compiled-module reload
  generation handling, broaden admin and metrics visibility across all hook
  families, and add regression tests for
  cross-family chain ordering, concurrent execution isolation, reload hash
  changes, and metrics labels without leaking secrets. This release must not be
  the first point where access-decision ordering, process-wide admission, reload
  classification, or per-plugin metrics appear; those are prerequisites for
  `v1.7.1`.
- `v1.7.7`: optional `wasm-proxy-abi` compatibility preview. Establish a
  separate `proxy-wasm-preview` ABI and host-call namespace, validate that
  namespace independently from `fluxheim-policy-v1`, reject unsupported calls
  deterministically, and add compatibility fixtures. This is capability
  compatibility groundwork, not a promise that arbitrary existing proxy-wasm
  plugins run unchanged; mapping reviewed proxy-oriented calls to Fluxheim's
  typed host calls remains a later reviewed slice. Close the release with
  semaphore-based narrow-to-global Wasm admission, per-service plus
  process-wide auth-request admission, shared epoch ticking, strict native host
  routing with rejection metrics, unique storage-bin roots and one
  process-wide persistence worker, live cache inspection and pre-initialization
  cross-process storage leases, hierarchical per-class request blocking budgets
  with critical and operational headroom, fail-closed disk lookup admission,
  bounded persistent cache parsing, and immutable CI/container build inputs.
- `v1.7.8`: optional `wasm-wasi` capability preview for non-request-body
  policy plugins. Keep filesystem, network, clocks, randomness, environment,
  and inherited process state disabled unless explicitly granted and tested.
- `v1.7.9`: documentation and example parity release. Ship documented,
  runnable examples and live tests for the four migration families:
  F5 iRules-style policy, nginx Lua/OpenResty-style header policy, HAProxy
  Lua/SPOE-style routing/load-balancer policy, and VCL-like cache policy.
- `v1.7.10`: stabilization and release gate hardening. All four example
  families must run through `scripts/test_starter.py`, the stable/deep release
  gates must include the appropriate Wasm checks, and the docs must clearly
  describe supported capability parity and unsupported syntax/runtime parity.
  Keep all in-process native host callbacks finite, non-blocking, panic-free,
  and total over arbitrary guest inputs, with property tests for every ID
  decoder. Before any host-call capability introduces blocking I/O, IPC, sleeps,
  contended waits, assertion-based operations, unchecked indexing/arithmetic,
  or third-party native callback code, design and prove a killable subprocess
  runner with bounded authenticated IPC, process admission, timeout termination,
  and crash cleanup; do not represent thread timeouts or `catch_unwind` as hard
  isolation in an abort-on-panic release. Add opt-in response-hardening profiles,
  typed modern browser isolation/reporting controls, request-aware validated
  CORS with preflight handling and automatic `Vary`, bounded `Retry-After` on
  generated capacity rejections, and broader spoofable identity stripping.
- `v1.7.11`: zero-downtime upgrade release after the Wasm line is stable. Add
  a documented and live-tested design for native binary and
  Podman deployments that can swap Fluxheim versions without a listener gap:
  inherited listener file descriptors, systemd socket activation support,
  readiness-gated new-process startup after every configured background
  service reports ready, old-process drain mode, bounded
  graceful drain timeout, and a container-safe blue/green handoff pattern
  through a stable fronting listener or host-level redirect owner. Add smoke
  coverage that starts an old Fluxheim process, starts a new one, proves new
  requests move to the new process while existing keep-alive/proxy requests
  drain on the old process, and documents which Podman setups cannot be
  truly zero-downtime without a stable fronting layer. Close the HTTP/1 parser
  audit with a validated-only public request-head type, strict RFC 3986 target
  grammar, linear Connection/fragmented-chunk processing, and caller-owned
  bounded chunk output backed by live framing and pipelining regressions.
- `v1.7.12`: standards-based response metadata and reproducible FIPS-backend
  evidence after the zero-downtime slice. Add opt-in RFC 9211 `Cache-Status`
  from real cache outcomes and low-cardinality RFC 9209 `Proxy-Status` from
  generated proxy failures without exposing backend addresses, certificate
  details, DNS names, or arbitrary error strings. Add streaming RFC 9530
  `Content-Digest`/`Repr-Digest` only after proving cache, compression,
  conditional, HEAD, and range-response semantics with live tests; do not
  emulate these fields with static response-header mutation. Add separate,
  pinned CI-only build environments for `profile-fips-openssl` and
  `profile-fips-rustls`. Each environment must run the exact binary it builds,
  verify the expected OpenSSL FIPS or rustls/AWS-LC FIPS provider and dependency
  boundary, exercise real downstream and upstream TLS, and prove incompatible
  algorithms/configurations fail closed. Record provider, compiler, dependency,
  binary, and image digests as release evidence. These are reproducible
  FIPS-capable backend tests, not published "FIPS images" or a claim that
  Fluxheim as a complete product is FIPS validated.
- `v1.8.0`: cross-platform production baseline planning. Replace the old
  "macOS developer-only" posture with a concrete macOS and Windows production
  parity line now that Fluxheim no longer depends on Pingora for the normal
  runtime. Define the supported feature matrix for macOS and Windows against
  Linux: static web, reverse proxy, cache, load-balancer, ACME, admin,
  observability, Wasm-enabled profiles, and focused images. Explicitly mark
  features that need platform-specific alternatives, such as Unix sockets,
  daemon/process management, filesystem trust checks, PHP-FPM supervision,
  service integration, and certificate/key storage.
- `v1.8.1`: macOS production release foundation. Add regular macOS CI for
  Apple Silicon and Intel where runners are available, run profile builds for
  the same public profiles as Linux, and add live smoke coverage for static
  serving, proxying, TLS, ACME dry-run/config validation, cache, admin,
  load-balancer, observability, and selected Wasm hooks. Add launchd service
  templates or an explicitly documented non-service deployment mode, Mac-safe
  production paths, APFS/symlink/ACL/security review notes, and release-asset
  generation for `aarch64-macos` and `x86_64-macos`.
- `v1.8.2`: macOS signed package release. Produce a macOS distribution path
  that can be trusted by normal operators: signed and notarized artifacts with
  an Apple Developer ID, plus either a signed/notarized `.pkg`, a Homebrew
  formula/cask path, or both. The release gate must verify codesign/notary
  status where credentials are available and keep unsigned developer artifacts
  clearly separate from production artifacts. Do not make FIPS/ISO-19790
  claims on macOS unless a separate provider-specific evidence package exists.
- `v1.8.3`: Windows production release foundation. Add Windows CI for
  `x86_64-pc-windows-msvc`, profile builds for the same public profiles as
  Linux where platform semantics allow them, and live smoke coverage for
  static serving, reverse proxying, TLS, cache, admin, load-balancer,
  observability, and selected Wasm hooks. Define Windows-specific behavior for
  paths, ACLs, file locking, symlink handling, signal/shutdown semantics,
  service control, named-pipe or TCP replacements for Unix-socket control
  paths, certificate/key storage, and unsupported or degraded Unix-only
  features.
- `v1.8.4`: Windows signed package release. Add a signed Windows installer and
  distribution path. Prefer an MSIX/App Installer or Microsoft Store-compatible
  package when it fits Fluxheim's service/server model; otherwise ship a
  signed MSI or signed zip with a documented Windows service installation path
  and keep Store publication as a separate compatibility decision. The release
  gate must verify Authenticode signing where credentials are available and
  prove install, service start, smoke request, upgrade, and uninstall behavior.
- `v1.8.5`: cross-platform parity hardening. Compare Linux, macOS, and Windows
  behavior profile by profile, close remaining platform gaps where practical,
  document intentional differences, add `scripts/test_starter.py` entries for
  macOS and Windows smoke flows, and require the stable/deep release gates to
  prove all supported platform assets before the line is complete.
- `v1.9.0`: Fluxheim-owned HTTP/3 and QUIC line. Stop at an opt-in
  `http3`/`http3-experimental` feature using Rust `quinn` for QUIC transport
  and the Rust `h3` stack for HTTP/3 framing behind Fluxheim-owned listener,
  TLS, routing, access-policy, cache/proxy, metrics, logging, and graceful
  shutdown boundaries after the cross-platform production line is stable.
  Preserve HTTP/1.1 and HTTP/2 behavior, advertise `Alt-Svc` only for healthy
  configured QUIC listeners, keep 0-RTT disabled unless explicit replay-safe
  route policy exists, and require interop, malformed-input, packet-loss,
  anti-amplification, timeout, container-network, and mixed-protocol boundary
  tests. Do not add generic UDP proxying, DNS/GSLB, WAF, VPN/firewall
  appliance behavior, or new Wasm ABI scope in this release.

Scope rules:

- TCP stream hook points can be planned only after HTTP request/response and
  cache hooks are stable. Stream filters must be opt-in, bounded by bytes/time,
  safe for long-lived connections, and unable to become an unbounded arbitrary
  bytecode path on raw TCP traffic.
- Cache-policy hooks are inspired by VCL, but implemented as constrained
  typed decisions. Fluxheim must not embed VCL or expose raw cache internals.
- Strict module, memory, table-element, fuel, compile-time, wall-time, log,
  mutation, synthetic-response, and concurrency limits apply to every hook.
- Plugin hashing and admin/metrics visibility are required when those modules
  are enabled.

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

### Future Edge Firewall And VPN Modes

Goal: evaluate whether Fluxheim should grow separate edge-firewall and TLS/VPN
gateway product modes after the proxy, load-balancer, WAF, and Wasm surfaces
are stable.

This is realistic only as separate compile profiles and runtime modes, not as
hidden behavior inside the proxy or load balancer. A future
`profile-edge-firewall` would need packet/routing ownership, stateful firewall
tables, NAT/SNAT/DNAT policy, kernel capability policy, nftables/eBPF or other
OS integration decisions, audit logs, and platform-specific tests. A future
`profile-tls-vpn-gateway` would need identity, key management, tunnel protocol
selection, replay protection, route push policy, client lifecycle management,
revocation, logging/privacy rules, and separate security evidence.

Do not schedule either mode until Fluxheim has a stable extension/runtime
boundary and a clear threat model. These modes may still be valuable because
they are edge functions, but they should be treated like new products with
dedicated release gates rather than as load-balancer features.

### Future - Rust Application SDK

Goal: add a small project-owned Rust companion crate for applications running
behind Fluxheim. The working crate name is `fluxheim-sdk` so it is clearly an
application integration SDK, not the proxy binary itself.

Stable first scope:

- health and readiness response schemas that Fluxheim can consume without each
  app inventing a different JSON shape;
- graceful drain state helpers so applications can mark themselves draining
  before shutdown and let Fluxheim stop sending new traffic;
- Tower/Axum middleware and extractors for trusted Fluxheim request context:
  request ID, trace context, real client IP after Fluxheim's trusted-proxy
  policy, TLS client-certificate identity when Fluxheim verified it, and
  bounded Geo-Context where configured;
- `tracing` helpers that bind Fluxheim request IDs to application spans;
- cache-control response helpers matching Fluxheim's cache policy model;
- authenticated admin/cache purge client utilities for internal app-triggered
  invalidation.

Out of first scope:

- upstream self-registration into Fluxheim backend pools;
- application-driven dynamic weight changes;
- UDP heartbeats;
- persistent h2/gRPC control streams;
- general route or TLS policy mutation from application code.

Those larger control-plane features must wait until the `1.5` runtime backend
management model has stable authentication, authorization, replay protection,
audit events, rate limits, persistence semantics, and documented failure modes.
The SDK should not become a hidden distributed control plane before Fluxheim's
own control plane is ready.

Crate naming and crates.io hygiene:

- keep the canonical `fluxheim` package name project-owned if the main proxy is
  ever published as a crate;
- publish application helpers as `fluxheim-sdk`;
- avoid empty placeholder crates. If names are claimed, they should be real
  project-owned packages with README text explaining the difference between the
  binary package and the SDK.

Repository/layout rule:

- place SDK code in a separate workspace directory such as
  `crates/fluxheim-sdk/`, with its own `Cargo.toml`, README, tests, examples,
  and public API boundary;
- do not mix SDK code into the proxy binary's `src/` modules;
- the initial workspace can live in the Fluxheim repository for shared CI, but
  the directory and dependency boundary should let the SDK move to its own
  GitHub project later without extracting proxy internals.

### Future - Compression Follow-Ups

Compression was pulled forward into the `1.4` production proxy parity line
because it is a normal reverse-proxy expectation rather than a separate feature
family. Keep follow-up compression work as a future compatibility track rather
than consuming the `1.7` slot now used for server bootstrap and listener/TLS
ownership.
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

### Future - Media Transform Pack

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

### 1.9 - HTTP/3 And QUIC

Goal: add opt-in HTTP/3 ingress with Fluxheim-owned UDP listener, QUIC, ALPN,
certificate, routing, policy, and observability integration.

This should be built as a Fluxheim protocol milestone after the `1.6` Pingora
exit has made server bootstrap, listener/TLS ownership, and HTTP runtime
ownership Fluxheim-owned and stable, and after the `1.8` macOS/Windows
production-parity line has settled.
The intended implementation path is the Rust `quinn` crate for QUIC transport
and the Rust `h3` stack for HTTP/3 framing, with Fluxheim-owned adapters around
TLS policy, vhost routing, request limits, access policy, cache/proxy behavior,
metrics, logs, and graceful shutdown.

Stable first scope:

- Compile-time `http3` or `http3-experimental` feature, absent from default
  builds until interop and resilience evidence is strong.
- UDP listener ownership with explicit rootless/container port mapping docs.
- ALPN and certificate selection consistent with HTTP/1.1 and HTTP/2 vhost
  behavior.
- `Alt-Svc` advertisement only when the matching UDP QUIC listener is
  configured, healthy, and mapped to the advertised port.
- Conservative config: `enabled`, `listen`, `advertise_alt_svc`,
  `max_concurrent_streams`, `idle_timeout`, `max_request_body_bytes`, and
  `enable_0rtt = false`.
- 0-RTT disabled by default and rejected until route policy can prove replay
  safety for explicitly idempotent traffic.
- GET/HEAD first, then request-body streaming, upload limits, proxying, static
  serving, cache behavior, access/error logs, dynamic headers, and failure
  semantics matched to the HTTP/1.1 and HTTP/2 paths.

Exit criteria:

- Interop tests with HTTP/3-capable clients and browser `Alt-Svc` discovery.
- Packet loss/reordering tests, malformed frame tests, anti-amplification
  behavior checks, connection-id lifecycle tests, stream timeout tests, and
  mixed HTTP/1.1, HTTP/2, and HTTP/3 request-boundary tests.
- Metrics and logs identify protocol without creating high-cardinality labels.
- Security posture matches the existing HTTP paths: strict parsing, no hidden
  downgrade shortcuts, no legacy fallback on modern listeners, and consistent
  vhost/cache/admin isolation.

Out of first scope:

- Generic UDP proxying, DNS/GSLB, QUIC pass-through, game-server UDP proxying,
  WAF, VPN/firewall appliance behavior, and new Wasm ABI scope.

### Future - Advanced Certificate Automation

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
  next strict-profile hardening step after mode-bit enforcement. Linux
  `openat2(RESOLVE_NO_SYMLINKS)` support is also tracked for collapsing
  remaining check/open windows on secret files where the platform can provide
  it.

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
- Origin CA automation if not stabilized in `1.8`.

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

### Future - Crypto RPC Edge

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
load-balancer = ["proxy", ...] # promoted in the 1.5 load-balancer line
tls = ["ingress", "dep:rustix"]
tls-rustls-backend = ["tls", "pingora/rustls", "dep:rustls"]
tls-rustls = ["tls-rustls-backend", "rustls/ring"]
tls-rustls-fips = ["tls-rustls-backend", "rustls/fips"] # rustls/AWS-LC FIPS candidate path
tls-rustls-iso19790 = ["tls-rustls-fips"] # terminology alias for ISO/IEC 19790 evidence
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
  dispatchable before `1.5`, normally published once the `1.5` line promotes
  the runtime behavior.

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
- `v1.3.4`: OpenSSL FIPS-capable TLS build path and release evidence.
- `v1.3.5`: rustls/AWS-LC FIPS-capable candidate build path and evidence
  workflow.
- `v1.3.7`: managed php-fpm process supervision under the existing `php-fpm`
  feature.
- `v1.4.0`: production proxy parity baseline: edge policy/compression,
  upstream resilience, TLS/protocol parity, mTLS/client certificate policy,
  PROXY protocol, upstream TLS controls, HTTP/2 origin controls, and gRPC
  pass-through policy.
- `v1.4.1`: discovery, mirroring, structured logs, richer rewrite policy,
  regex and method routing, explicit WebSocket/HTTP upgrade proxying, bounded
  auth subrequests, safe bodyless traffic mirroring, and a read-only Unix ops
  socket. Broader typed hook points remain deferred.
- `v1.4.2`: proxy module split and maintenance architecture release. Stop line:
  no new operator-facing proxy feature surface unless required to preserve
  behavior during extraction. Split the current large proxy runtime into focused
  domains such as `php_fpm`, `compression`, route matching/rewrite policy,
  traffic mirroring, auth subrequests, proxy cache glue, PROXY protocol
  framing, access logging, and proxy security helpers. PHP-FPM process
  supervision, spooling, FastCGI transport, retry/timeout classification, and
  response parsing live in `php_fpm`; the remaining PHP code in `proxy.rs`
  should stay limited to Pingora request/session orchestration until the proxy
  core itself is split.
  The first `proxy_cache` slices own request-side cache policy, response
  admission, `Vary` helpers, bounded range-cache request/key/admission policy,
  fixed-slice range planning, freshness, status-header, stale-serving, and
  response-header mutation policy. Cache admin/API request and result DTOs live
  in `cache_api`; later cache slices can move stateful runtime/storage and
  slice object helpers without changing config. Preserve config compatibility
  and pass the existing 1.4.1 smoke/security matrix before moving on.
- `v1.4.3`: config module split and maintenance architecture. Stop line: no new
  operator-facing config features, no config migration, and no behavior changes
  beyond preserving validation while extracting config loading and domain
  validation into focused modules behind stable `crate::config::*` paths.
- `v1.4.4`: Apple Silicon macOS developer support. Scope stops at local
  `aarch64-apple-darwin` build/check/smoke coverage for development profiles,
  Mac-safe dev configs for runtime paths/cache/logs/PHP-FPM, dependency/profile
  cleanup for unused native crates, and setup docs; it is not a production,
  FIPS, Homebrew, notarized-binary, or launchd packaging milestone.
- `v1.4.5`: optional bounded Geo-Context foundation and advanced HTTP policy.
  GeoIP scope stops at local provider-agnostic MMDB country/ASN context for
  MaxMind GeoIP2/GeoLite2 and CIRCL Geo Open datasets, privacy controls,
  route/access decisions, ordered local fallback, and bounded observability;
  built-in dynamic database downloaders, remote lookup sidecars, programmable
  geo logic, and anomaly engines are later work.
- `v1.4.6`: TCP stream proxy foundation with separate stream semantics,
  listener/upstream trust boundaries, and bounded copy controls.
- `v1.4.7`: TCP stream hardening with true per-read idle timeout, stream
  upstream TLS/mTLS where it reuses the existing safe TLS material model, and
  transport-neutral stream load-balancer policy only.
- `v1.5.0`: load-balancer/control-plane line. Promote the focused
  load-balancer image profile and stop at F5 LTM / HAProxy / Envoy-class
  HTTP/TCP load-balancer operations: runtime member-state controls, priority
  groups, persistence, slow-start, adaptive health, circuit breaking,
  queue/overflow policy, locality/failure-domain policy, richer selection
  algorithms, load-balancer-only admin status, audit visibility, and migration
  fixtures. Runtime add/remove-member and selector-specific hash/ring weight
  changes remain later `1.5.x` control-plane work. Include TLS passthrough SNI
  routing only after a bounded
  ClientHello parser, preread buffer limit, and byte replay model are proven. Dynamic
  xDS/Kubernetes/Consul discovery belongs here or a later control-plane line
  after local DNS/file discovery and runtime backend mutation are stable.
- Later macOS production line: only after Level 1 developer support is stable.
  Requires regular macOS CI, runtime smoke coverage, launchd/Homebrew or other
  packaging decisions, signed/notarized binary policy, and a macOS-specific
  filesystem/security review. Keep Linux as the production baseline until that
  line is explicitly scheduled.
- `v1.5.1`: enterprise load-balancer stabilization. Stop at correctness fixes,
  release-profile polish, docs/migration cleanup, bounded operational
  hardening, and test coverage for behavior already shipped in `1.5.0`. Do not
  add runtime add/remove-member, runtime weight mutation, managed affinity
  cookies, cross-instance state sync, UDP/GSLB, WAF, VPN/firewall appliance
  behavior, or Wasm/iRules/Lua scripting in this release.
- `v1.5.2`: runtime load-balancer weight-control line. Stop at authenticated
  runtime weight overrides for already configured members, status/metrics/audit
  visibility, canary traffic-shift migration docs, and focused smoke coverage.
  Do not add runtime add/remove-member, managed affinity-cookie insertion,
  restart-persistent or cross-node state, UDP/GSLB, WAF, VPN/firewall appliance
  behavior, or Wasm/iRules/Lua scripting in this release.
- `v1.5.3`: managed affinity-cookie and HA persistence line. Stop at
  signed/opaque load-balancer `Set-Cookie` insertion for eligible HTTP
  responses, cookie verification on inbound requests, key rotation, configured
  cookie attributes, backend identity privacy, explicit privacy-mode rejection
  unless no-retention behavior is proven, and documented interaction with
  cache, compression, and header policies. Include an active-active
  cookie-mirroring design and tests, but do not add restart-persistent state,
  runtime add/remove-member, xDS/Kubernetes/Consul discovery, UDP/GSLB, WAF,
  VPN/firewall appliance behavior, or Wasm/iRules/Lua scripting in this
  release.
- `v1.5.4`: TLS backend simplification line. Stop at removing the incomplete
  BoringSSL and s2n backend support from the supported matrix, leaving
  rustls as the default/recommended backend and OpenSSL as the supported
  alternative for non-FIPS and FIPS/ISO evidence paths. Update features,
  preflight validation, docs, examples, packaging, release scripts, and tests so
  supported TLS means rustls/rustls-FIPS or OpenSSL/OpenSSL-FIPS only. Do not
  add new TLS backends, HTTP/3/QUIC, native load-balancer internals,
  restart-persistent state, cross-node sync, UDP/GSLB, WAF, VPN/firewall
  appliance behavior, or Wasm/iRules/Lua scripting in this release.
- `v1.5.5`: Fluxheim-native HTTP/error type boundary line. Stop at
  standardizing Fluxheim-owned modules on Rust `http` crate request, response,
  status, method, URI, and header types where practical, plus a
  `thiserror`-backed `FluxError` / `FluxResult` hierarchy for internal error
  propagation. Keep narrow adapters at Pingora `ProxyHttp`, service, and
  transport boundaries, preserve externally visible status codes, messages,
  metrics labels, config validation behavior, release profiles, and tests. Do
  not replace the HTTP proxy runtime, change stream proxy runtime, change
  cache semantics, change load-balancer selection/state behavior, add
  HTTP/3/QUIC, UDP/GSLB, WAF, VPN/firewall appliance behavior, or
  Wasm/iRules/Lua scripting in this release. Defer remaining runtime-heavy
  error-boundary work explicitly: PHP-FPM process supervision and request-body
  spool I/O move with later PHP/HTTP-runtime work, stream connect/copy/shutdown
  helpers move with `v1.5.6`, stream upstream TLS connector ownership moves
  with `v1.5.6`, load-balancer factory/background wiring moves with `v1.5.7`,
  and broader HTTP/server upstream TLS material loading moves with the later
  server/listener/TLS runtime line.
- `v1.5.6`: Fluxheim-native stream-proxy boundary line. Stop at isolating the
  stream data path, listener assumptions, and stream/TLS connector behavior
  behind Fluxheim-owned Tokio-facing interfaces for raw TCP plus upstream
  TLS/mTLS. Preserve existing stream config, route matching, weighted upstream
  selection, drain/backup policy, route-local PROXY protocol receive/send,
  true idle timeouts, lifetime and byte caps, metrics, smoke tests, and
  release-profile behavior. This is also where remaining stream data-path
  `io::Result` helpers should be moved behind Fluxheim-owned error types
  because the stream runtime boundary becomes Fluxheim-owned. Keep any
  dependency-removal gate for the `1.6.x` runtime line. Do not add UDP
  proxying, HTTP/3/QUIC,
  native load-balancer internals, restart-persistent state, cross-node sync,
  WAF, VPN/firewall appliance behavior, or Wasm/iRules/Lua scripting in this
  release.
- `v1.5.7`: Fluxheim-native load-balancer core line. Stop at moving
  load-balancer-owned backend types, backend-set readiness, discovery traits,
  static/file/DNS discovery adapters, TCP/HTTP health-check scheduling,
  background update lifecycle, and existing selector entry points behind
  Fluxheim-owned module or crate boundaries. Preserve current config, admin
  API, status shape, metrics, smoke tests, privacy-mode behavior,
  managed-cookie behavior, and all selection results as far as possible.
  Convert remaining load-balancer construction/factory/background update errors
  onto Fluxheim-owned error types as part of this boundary work, not as
  scattered cleanup. Keep Pingora's HTTP proxy core, upstream transport, and
  build-graph dependencies in place until the `1.6.x` removal line. Do not add
  restart-persistent state, cross-node
  sync, runtime add/remove-member, xDS/Kubernetes/Consul discovery, UDP/GSLB,
  WAF, VPN/firewall appliance behavior, or Wasm/iRules/Lua scripting in this
  release.
- `v1.5.8`: active health-check expansion line. Stop at closing the existing
  HTTP health-check request-header gap, adding standard gRPC health checks,
  adding bounded JSON field validation for common health response bodies, and
  adding health-derived degraded weight signals such as `X-Health-Weight`.
  Custom request headers must be explicitly configured, validated, redacted
  where needed, and omitted from high-cardinality labels. gRPC health should
  implement only the standard Health Checking Protocol with optional service
  name and strict message-size/time limits. JSON validation should be simple
  exact field-path matching, not a full JSONPath language. Degraded weights
  must be bounded, status-visible, separate from configured/runtime operator
  weights, and cleared automatically when normal health resumes. Do not add
  local command execution, database protocol probes, restart-persistent state,
  runtime add/remove-member, xDS/Kubernetes/Consul discovery, UDP/GSLB, WAF,
  VPN/firewall appliance behavior, or Wasm/iRules/Lua scripting in this
  release.
- `v1.5.9`: restart-persistent load-balancer state line. Stop at versioned,
  size-limited, atomically written, auditable persistence for selected runtime
  member overrides and bounded persistence tables after the Fluxheim-native
  backend model is stable. Corrupt or incompatible state must fail closed to
  "ignore and rebuild" rather than poisoning a pool. Do not add cross-node
  state sync, runtime add/remove-member, dynamic discovery control planes,
  UDP/GSLB, or Wasm/iRules/Lua scripting in this release.
- `v1.5.10`: runtime backend-set mutation line. Stop at authenticated
  add/remove/update operations for configured pool members through atomic
  backend-set swaps, including validation, audit events, status/metrics
  visibility, drain behavior, and clear selector limitations for hash, ring,
  Maglev, and power-of-two policies. Do not add xDS/Kubernetes/Consul
  discovery, UDP/GSLB, WAF, VPN/firewall appliance behavior, or Wasm/iRules/Lua
  scripting in this release.
- `v1.5.11`: service-discovery and control-plane integration line. Stop at one
  or more bounded discovery adapters such as Kubernetes, Consul, or xDS after
  local DNS/file discovery and runtime backend mutation are stable. Discovery
  must include authentication/trust boundaries, churn limits, safe fallback,
  status, audit/metrics, and reload behavior. Do not add UDP/GSLB, WAF,
  VPN/firewall appliance behavior, or Wasm/iRules/Lua scripting in this
  release.
- `v1.5.12`: Fluxheim-native background task registry line. Stop at moving
  Fluxheim-owned background implementations off Pingora's generic
  `GenBackgroundService`, direct `background_service()` registration helper,
  and raw `ShutdownWatch` handling for cache metrics, ACME renewal scheduling,
  stale purging, admin watchdog work, load-balancer updates, and future
  discovery refresh loops. Keep Pingora's `ServiceWithDependents` only as the
  outer server-registration adapter until the later server-bootstrap line. Use
  explicit Fluxheim shutdown/readiness tokens, preserve graceful shutdown
  semantics, task ordering where needed, status/metrics visibility, and release
  smoke coverage. Do not change HTTP proxy request handling, add UDP/GSLB, WAF,
  VPN/firewall appliance behavior, or Wasm/iRules/Lua scripting in this
  release.
- `v1.5.13`: Fluxheim-owned cache interface line. Stop at defining and using a
  `FluxCacheStorage`-style interface that captures Fluxheim's existing cache
  hit/miss/admission/stale/purge semantics without depending on Pingora's
  session-bound `Storage`, `HandleHit`, and `HandleMiss` types. Keep the
  existing memory, disk, encrypted disk, tiered, predictor, stale, purge,
  range/slice, and cache-lock behavior unchanged, and provide a narrow adapter
  for the current Pingora HTTP proxy path. Also design, but do not silently
  enable, a future `privacy-cache` mode for explicitly public assets: no
  client-IP cache keys, no `Cookie`/`Authorization` admission, no per-user
  variants, no private/no-store/Set-Cookie storage, strict query-string
  defaults, and preferably memory or encrypted short-TTL disk storage. Do not
  rewrite the cache format, change normal cache policy semantics, add
  cross-node cache replication, add UDP/GSLB, WAF, VPN/firewall appliance
  behavior, or Wasm/iRules/Lua scripting in this release.
- `v1.5.14`: local exec health-check line. Stop at opt-in, bounded local
  command checks for cases that cannot be represented by TCP, TLS, HTTP, gRPC,
  JSON, or database protocol probes. Require absolute allow-listed command
  paths, no shell expansion, no inherited unsafe environment, strict
  timeout/output-size limits, serial process execution per pool, redaction,
  status/audit visibility, and clear compile/profile compatibility. Keep
  authenticated agent checks for a later monitor slice. Do not add arbitrary
  scripting, Wasm policy, runtime backend mutation, UDP/GSLB, WAF,
  VPN/firewall appliance behavior, or database protocol probes in this release.
- `v1.5.15`: database and protocol-aware health-check line. Start with bounded
  Redis `PING`, MySQL/MariaDB handshake, and PostgreSQL SSLRequest health
  probes for stream/load-balancer deployments where TCP connect is not enough.
  Stop at fixed health probes only: no Redis command configuration, key
  inspection, authentication, TLS, MySQL login packets, PostgreSQL
  StartupMessages, SQL execution, schema inspection, or database proxying in
  this slice. Keep PostgreSQL TLS/authenticated readiness, MySQL
  TLS/authenticated readiness, SMTP/LDAP/custom send-expect checks, and
  authenticated agent checks as later monitor slices unless each protocol has
  strict timeout, byte, authentication, privacy, and logging limits. Treat
  database checks as health probes only, not a database proxy feature or query
  execution engine. Do not add UDP/GSLB, WAF, VPN/firewall appliance behavior,
  arbitrary command execution beyond the prior opt-in exec line, or new Wasm
  ABI scope in this release.
- `v1.5.16`: UDP and GSLB exploration line. Stop at explicitly scoped beta
  modules only: DNS UDP load balancing, syslog UDP forwarding, QUIC
  pass-through, game-server UDP proxying, and/or DNS/GSLB traffic steering if
  each target has bounded session/affinity semantics, timeouts, health checks,
  metrics, rootless/container-network behavior, and clear non-goals. Do not
  turn this into a generic catchall UDP or authoritative-DNS platform, and do
  not add WAF, VPN/firewall appliance behavior, or Wasm/iRules/Lua scripting in
  this release. The first slice is the beta `[udp]` config boundary,
  `udp-proxy` feature gate, and scoped DNS/syslog UDP runtime only; production
  profiles must not enable it until the listener/session runtime is promoted.
  Keep `dns-load-balance` documented as internal/beta-only until response-rate
  limiting, amplification controls, and public-DNS deployment guidance are
  reviewed.
- `v1.5.17`: workspace and shared-crate foundation line. Stop at converting
  Fluxheim to a Cargo workspace while keeping the published binary/package
  behavior unchanged, and extracting only low-risk shared code into one or more
  internal crates such as `crates/fluxheim-common` and optionally
  `crates/fluxheim-protocol`. Good first candidates are `FluxError`, bounded
  labels/strings, path-safety helpers, shared IDs, small telemetry event
  shapes, and test support that does not depend on proxy runtime internals.
  Keep all existing feature profiles, binaries, release scripts, RPM/container
  builds, fuzz targets, and documentation paths working. Do not split proxy,
  cache, load-balancer, config, admin, or runtime crates in this release.
- `v1.5.18`: configuration crate extraction and HTTP/2 response hardening line.
  Stop at moving config structs, parsing, validation, config-source loading,
  and config tests behind `crates/fluxheim-config`, with the root `fluxheim`
  crate re-exporting the same public config surface it uses today. Preserve all
  error messages, relative-path behavior, safe-file validation, profile
  compatibility, reload classification inputs, config tester behavior, and
  release metadata checks. Also add the HTTP/2 absolute response-write lifetime
  bound and request-header-count clarification from the HTTP/2 Bomb review. Do
  not change config syntax, migrate operator config files, or split runtime
  behavior beyond the HTTP/2 timeout hardening in this release.
- `v1.5.19`: load-balancer crate extraction line. Stop at moving the
  Fluxheim-owned load-balancer core into `crates/fluxheim-load-balancer`,
  including backend snapshots, discovery adapters, health checks, selection
  algorithms, runtime policy overrides, persistence, queue policy, state files,
  and tests. The crate should depend only on `fluxheim-common`,
  `fluxheim-config`, and reviewed external crates; it must not depend on proxy,
  admin, cache, web, or PHP internals. The root `fluxheim` crate remains the
  binary/orchestration crate and wires admin/proxy/runtime integration through
  narrow APIs. Do not add new load-balancer features in this release.
- `v1.5.20`: web, PHP-FPM, and cache boundary preparation line. Stop at
  extracting the cleanest remaining subsystem crates without changing runtime
  behavior: `crates/fluxheim-web` for static file planning/serving,
  `crates/fluxheim-php-fpm` for managed PHP-FPM/FastCGI, and/or the first
  `crates/fluxheim-cache` core boundary if the `1.5.13` cache-interface work is
  stable enough. This release may also take the smallest low-dependency leaf
  crate wins when they are cleanly separable, especially
  `crates/fluxheim-geoip` for Geo-Context/MMDB lookup helpers and
  `crates/fluxheim-compression` for response-compression negotiation and encoder
  lifecycle helpers. Treat those as boundary moves only: config, metrics, proxy
  behavior, and feature names must stay compatible. Committed steps so far are
  the `crates/fluxheim-cache` boundary with shared cache-header parsing and
  pure cache admin request/result/preview DTOs, runtime totals, and
  activity-reset DTOs moved behind root compatibility re-exports. Cache object
  metadata, activity stats, tier stats, object lookup, and vhost/route runtime
  stats now also live in `crates/fluxheim-cache::api`, with root
  `crate::cache` and `crate::cache_api` compatibility re-exports preserving the
  admin, CLI, metrics, and proxy surfaces. Cache storage-plan DTOs also moved
  into `crates/fluxheim-cache::plan`, while the Pingora storage adapters remain
  in the root cache runtime. Cached object DTOs and `CacheStoreError` now live
  in `crates/fluxheim-cache::object`, again behind root `crate::cache`
  compatibility re-exports. Cache request/key DTOs now live in
  `crates/fluxheim-cache::request`, while root cache-key builders keep their
  existing behavior and compatibility surface. Cache range/slice request DTOs,
  single-range parsing, client range parsing, client-range resolution, and
  required-slice planning plus Content-Range parsing and range-response
  `Content-Range`/`Content-Length` validation, cache-key component formatting,
  temporary HEAD cache bypass detection, and multipart slice range policy
  sizing now also live in
  `crates/fluxheim-cache::request`, with native request/response-header and
  cache-key adaptation now handled by `fluxheim-server`. Pure remaining-TTL and
  synthesized Cache-Control freshness helpers now live in
  `crates/fluxheim-cache::headers`, alongside Vary header parsing and
  configured request-header variance policy, Vary request hash material
  framing, and cacheable response Content-Type matching plus cache-bypass
  cookie/query-string matching, stale-serving allow policy, response
  Age/Cache-Control freshness parsers, and Cache-Control directive
  merge/replacement. Cache purge-index state,
  purge-entry DTOs, storage-local purge result counters, and cache-key path
  matching helpers now live in `crates/fluxheim-cache::purge_index`, while the
  root `crate::cache` module keeps compatibility type names and the Pingora
  storage implementations remain root runtime adapters. Cache Prometheus label
  classifiers now also live in `crates/fluxheim-cache`, while root
  `crate::metrics` remains recorder wiring.
  The `crates/fluxheim-web` boundary now has static
  directory-listing data/rendering plus static byte-range parsing and static
  response planning/conditional request evaluation plus safe relative path and
  directory-listing path helpers plus configured web-root symlink detection
  plus static cache identity formatting moved behind the existing
  `crate::web` surface, and the
  `crates/fluxheim-php-fpm` boundary with timeout
  classification/error-outcome helpers plus managed restart-backoff and
  sanitized `PATH` fallback helpers plus managed php-fpm config rendering and
  config-value validators plus PHP-FPM timeout/retry policy and endpoint
  selection plus PHP-FPM response-header safety guards plus response split,
  `Status` parsing, ASCII trimming, header colon splitting, and managed
  instance-name generation moved behind the native PHP-FPM route adapter and
  `fluxheim-php-fpm` crate surface.
  The `crates/fluxheim-geoip` boundary now owns `GeoContext` and the optional
  local MMDB runtime. The
  `crates/fluxheim-compression` boundary now owns response compression encoder
  lifecycle, output-limit accounting, Accept-Encoding token/qvalue parsing, and
  response policy string matching for Cache-Control directives and Content-Type
  eligibility, active Content-Encoding classification, and input-size bounds
  while the root adapter keeps Pingora-specific header selection, header
  iteration, config extraction, and response mutation. The
  `crates/fluxheim-observability` boundary now owns W3C Trace Context parsing,
  generation, traceparent normalization, and the shared OTLP HTTP agent plus
  symlink-safe custom CA bundle loader and OTLP HTTP endpoint parser behind an
  `otlp-http` crate feature. It also owns the Prometheus-to-OTLP metrics payload
  builder behind an `otlp-metrics` crate feature while the root metrics OTLP
  module remains exporter lifecycle and HTTP post wiring. Access-log helper
  logic for request-id validation/generation, shared low-cardinality status
  classes, response byte counting, and Unix nanosecond timestamps now also lives
  in the observability crate while root access logging keeps Pingora
  request-header integration and JSON event assembly. Shared JSON string
  escaping for access logs and runtime JSON logs also lives in the
  observability crate. Proxy metrics outcome, method, status-class label
  bucketing, and general Prometheus label
  classifiers for host-routing, admin-auth, compression, edge-policy,
  load-balancer event/queue/upstream, stream, ACME, PHP/PHP-FPM, and
  metrics-OTLP exporter events plus bounded ratio and saturating gauge
  conversion helpers also now live in the observability crate while root
  `crate::metrics` remains the Prometheus registry/recorder adapter.
  `LoadBalanceSelection` metric-label mapping now lives in `fluxheim-config`,
  and config-derived cache/load-balancer metrics summary aggregation now also
  lives in `fluxheim-config`, leaving root `crate::metrics` as the
  compatibility wrapper for selection labels and Prometheus gauge publishing.
  The OTLP trace exporter and trace-span payload builder also live behind the
  `crates/fluxheim-observability` `otlp-trace` feature.
  The `crates/fluxheim-protocol` boundary now
  owns PROXY protocol v1/v2 upstream header framing used by the native HTTP and
  stream runtimes. It also owns route method matching and prefix-boundary
  helpers consumed by native route selection. The
  `crates/fluxheim-snapshot` boundary now owns durable config snapshot storage,
  metadata validation, rollback pointer handling, and symlink-safe filesystem
  writes.
  reload-impact classification in `crates/fluxheim-config`, with root admin
  and CLI code calling the owning crate directly.
  Runtime/member weight parsing now also lives in
  `crates/fluxheim-load-balancer`, with root admin kept as the HTTP/query
  endpoint adapter.
  Cache admin summary math helpers now also live in
  `crates/fluxheim-cache::api`, with root admin kept as the JSON response
  adapter.
  Runtime cache-purger metric saturation now also lives in
  `crates/fluxheim-observability`, with root runtime kept as the background-task
  adapter.
  Downstream PROXY-protocol trusted-source parsing now also lives in
  `crates/fluxheim-protocol`, with root runtime kept as the Pingora listener
  adapter.
  HTTP Upgrade token grammar validation now also lives in
  `crates/fluxheim-protocol`, with root proxy kept as the Pingora
  request-header adapter.
  Fluxheim `Via` header value formatting now also lives in
  `crates/fluxheim-protocol`, with root proxy kept as the Pingora header
  mutation adapter.
  Multipart cache Content-Type sanitization now also lives in
  `crates/fluxheim-cache::headers`, with root proxy kept as the slice response
  assembly adapter.
  Cache slice metadata first-header extraction now also lives in
  `crates/fluxheim-cache::headers`, with root proxy kept as the slice identity
  adapter.
  Hop-by-hop `Connection` option token validation now also uses the shared
  `crates/fluxheim-protocol` HTTP token grammar helper.
  Response header rewrite prefix authority-boundary matching now also lives in
  `crates/fluxheim-protocol`, with root header policy kept as the mutation
  adapter.
  Cache CLI header-name validation now also uses the shared
  `crates/fluxheim-protocol` HTTP token grammar helper.
  Config HTTP token validation now also uses the shared
  `crates/fluxheim-protocol` grammar while preserving method-specific
  uppercase checks.
  Cache object lookup summary formatting now lives in
  `crates/fluxheim-cache`, leaving the CLI as the command/output adapter.
  Cache-warm count summaries and bounded status labels now also live in
  `crates/fluxheim-cache`, leaving the CLI to print the prepared summaries.
  Admin cache status JSON now calls the shared `crates/fluxheim-cache`
  storage-tier helper directly instead of keeping a local wrapper.
  The shared protocol HTTP token helper now documents that method-specific
  uppercase policy must be applied by callers, and config validation warns when
  accepted IPv6 trusted-proxy CIDR ranges are broader than `/32`.
  Keep
  Pingora-specific cache/proxy adapters separate from cache core when possible.
  Do not move the main HTTP proxy orchestrator yet; it should remain last
  because it still coordinates all subsystems.
- `v1.5.21`: UDP production-readiness line. Stop at promoting only the scoped
  UDP modes that have reviewed production semantics. Required work before any
  promotion includes per-route UDP metrics/status, explicit public-exposure
  warnings, response-rate limiting or equivalent amplification controls for
  DNS-style request/response forwarding, bounded per-source/per-prefix pressure
  controls where meaningful, upstream health/readiness behavior for UDP pools,
  rootless/container-network deployment guidance, packet-size and truncation
  tests, and clear logging that cannot be turned into packet-rate log spam.
  First pass added per-source session caps, per-source response-rate caps,
  UDP Prometheus counters/gauges, admin UDP status, explicit non-loopback
  listener warnings for DNS-style routes, passive upstream failure ejection,
  rootless/container-network exposure guidance, and smoke-test coverage for
  exact-cap responses, oversized downstream drops, and the new knobs.
  Remaining promotion work should focus on longer-running operational soak
  tests before removing the beta label.
  `syslog-forward` may graduate independently if its one-way semantics are
  reviewed first. Keep QUIC pass-through, game-server UDP proxying, generic
  UDP catchall behavior, authoritative DNS, and GSLB control-plane behavior as
  separate later scopes unless each has its own bounded session, affinity,
  observability, and abuse-control design. If the UDP work needs cleaner
  telemetry wiring, this release may start `crates/fluxheim-observability` as a
  boundary for Prometheus metrics, OTLP metrics, OTLP trace export, and W3C
  trace-context helpers. Keep it as an event/export adapter crate first; do not
  change metric names, label cardinality, trace attributes, or OTLP endpoint
  validation semantics in the same step.
- `v1.5.22`: cache and load-balancer crate-boundary preparation line. Stop at
  tightening `crates/fluxheim-load-balancer` and the planned
  `crates/fluxheim-cache` boundary so both domains expose Fluxheim-owned
  backend/cache interfaces, tests, and root-crate adapters without changing
  runtime behavior or requiring Pingora to disappear from the build graph. The
  load-balancer side should keep selected Fluxheim backend snapshots and policy
  state independent from proxy/admin internals. The cache side should keep HTTP
  cache hit, miss, stale serving, range/slice handling, purge/status behavior,
  and cache writes expressed through Fluxheim-owned interfaces where practical,
  while retaining any temporary Pingora adapters needed by the current HTTP
  runtime. Do not make this a dependency-removal release; actual
  `pingora-load-balancing` and `pingora-cache` compile removal belongs to
  `v1.6.1` and `v1.6.2`. This release may also begin a
  `crates/fluxheim-snapshot` boundary for durable config snapshot IDs,
  metadata, store validation, listing, and rollback file operations if those
  pieces can move without pulling in admin, runtime, or proxy orchestration.
  Keep live reload classification and admin HTTP handlers in the root crate
  until their dependencies are clearer. Implemented `1.5.22` cache slices
  include Fluxheim-owned request views for bypass/revalidation/range selection
  and cache-owned response admission policy for status, content type,
  no-store/Vary, and range-response checks, with root Pingora adapters kept.
- `v1.5.23`: cache-aware origin protection service line. Stop at one small
  differentiator that combines cache and load-balancer state without becoming a
  new proxy runtime: route-scoped origin-fill budgets that apply only to cache
  misses, revalidations, and background refreshes. When an origin pool is
  degraded, queue-saturated, or over its fill budget, Fluxheim should prefer
  bounded stale serving where policy allows, coalesce concurrent fills, and
  expose clear metrics/status for "origin protected" decisions. This should be
  useful for stampede control and brownout handling, and is intentionally
  narrower than a general WAF, scripting system, or global traffic manager. Do
  not add cross-node cache replication or distributed consensus in this stop.
  Implemented first slice: `cache.origin_protection` with per-vhost/route
  `max_concurrent_fills` budgets for Fluxheim-owned range slice fills, plus
  admin status and metrics for rollout visibility. Generic Pingora proxy-cache
  miss/revalidation integration remains a follow-up because it crosses the
  runtime boundary that the `1.6.x` Pingora-removal line will replace.
  Use this final `1.5.x` workspace pass to finish or defer any small leaf-crate
  boundaries started in `v1.5.20`-`v1.5.22` so the `1.6.x` Pingora-removal line
  starts from stable crate APIs. Possible deferrals include `fluxheim-acme`,
  `fluxheim-headers`/HTTP policy helpers, and additional protocol helpers; move
  them only when the dependency direction remains root -> domain crate and no
  circular dependency on proxy/admin/runtime is introduced.

Workspace rule after `v1.5.17`: once the workspace split starts, future release
lines must treat crate boundaries as the default for substantial new
subsystems. A later feature may still add small glue code to the root
`fluxheim` binary/orchestration crate, but large domains should land in
focused crates such as `fluxheim-wasm`, `fluxheim-runtime`,
`fluxheim-server`, `fluxheim-proxy`, `fluxheim-http3`, `fluxheim-defense`, or
other reviewed workspace members. This prevents `1.6`, `1.7`, `1.8`, `1.9`,
and future ecosystem work from rebuilding the current single-crate sprawl.

Workspace feature rule: the root `fluxheim` crate owns the operator-facing
feature profiles and release artifact matrix (`profile-full`,
`profile-load-balancer-edge`, `profile-static-site`, `profile-reverse-proxy`,
`profile-php`, and related build profiles). Internal workspace crates may have
small local feature flags only for their own optional dependencies or narrow
capabilities, but those flags must be mapped deliberately from the root crate.
Do not let domain crates invent independent public feature surfaces that
operators have to compose by hand. This keeps existing profile semantics stable
while allowing `fluxheim-config`, `fluxheim-load-balancer`,
`fluxheim-cache`, `fluxheim-web`, `fluxheim-php-fpm`, `fluxheim-acme`, and
future extension crates to move out of the root crate without feature drift or
circular dependencies.

- `v1.6.0`: Pingora-exit foundation line. Stop at behavior freeze, dependency
  graph gates, parity fixtures, and the first Fluxheim-owned runtime
  boundaries needed to remove Pingora safely. The whole `1.6.x` series must
  remove Pingora from every normal Fluxheim build by its final stabilization
  release, splitting new runtime domains into focused workspace crates where
  useful. Track the remaining large root-module exits here too:
  `fluxheim-snapshot`, `fluxheim-acme`,
  `fluxheim-headers`/`fluxheim-http-policy`, `fluxheim-protocol`, late
  `fluxheim-proxy`/`fluxheim-runtime`, and a possible `fluxheim-admin` after
  domain APIs are stable.
- `v1.6.x`: Pingora-exit implementation releases. Remove
  `pingora-load-balancing`, `pingora-cache`, stream-service entrypoints,
  background service wiring, Pingora HTTP/error wrappers, Pingora server
  bootstrap/listener/TLS handling, and finally Pingora `ProxyHttp`/`Session`
  in staged minor releases. Preserve current operator-facing behavior and make
  each release independently testable before deleting the old adapter. Do not
  carry unfinished structural crate splits into `1.7` unless they are unrelated
  to the Pingora-free runtime boundary. After the final Pingora-free proof,
  do a dedicated hardening cleanup that moves first-party secret buffers and
  drop-clearing structs to `sanitization` containers/derives where practical,
  rather than mixing that API migration into the runtime replacement work.
- `v1.7.0`: shared Wasm sandbox foundation. Stop at compile-time feature
  gates, strict plugin-file loading, resource-limited Wasmtime execution, typed
  plugin manifest validation, and real sandbox smoke tests.
- `v1.7.1`: config integration for the typed plugin registry and attachment
  validation, host-call namespace, per-plugin/per-vhost execution admission
  budgets, admin-visible configured hashes, rejected-config fixtures, and live
  native HTTP/1 access-control hooks with F5-iRules-style allow/deny examples.
  This release also establishes the production hook execution contract:
  explicit attachment order/priority, `first-deny-wins` access-decision
  composition, process-wide Wasm admission ceilings, Wasm-aware reload-impact
  classification, and per-plugin Prometheus/OTLP metrics from the first live
  hook release.
- `v1.7.2`: request-header and response-header hooks, bounded symbolic
  host-call mutation, nginx-Lua/OpenResty-style mutation examples, and
  sensitive field isolation tests.
- `v1.7.3`: routing/load-balancer/mirror/persistence decision hooks with
  HAProxy-Lua/SPOE-style live examples.
- `v1.7.4`: VCL-like cache lookup/store policy hooks for
  lookup/pass/bypass/deny and store continue/skip/deny decisions, with live
  cache HIT/MISS and skip-store tests.
- `v1.7.5`: VCL-like cache policy mutation hooks for bounded symbolic
  cache-key components, fixed-ID TTL/tag store metadata, symbolic content-type
  inspection, and fixed stored response-header metadata, with live
  low-cardinality key, image-only metadata, and TTL expiry tests. Richer
  store-admission mutation remains staged for a later cache-policy slice.
- `v1.7.6`: mature-runtime hardening across all hook families: compiled-module
  cache isolation, cross-family chain regression tests, reload hash-change
  tests, metrics/admin completeness, and secret-safe labels. The initial
  access-decision ordering, global admission, reload classification, and
  per-plugin metrics must already exist from `v1.7.1`.
- `v1.7.7`: optional `wasm-proxy-abi` compatibility preview with deterministic
  unsupported-call rejection plus request-path resource admission, host
  routing/metrics, unique-root cache isolation, process-wide cache persistence,
  bounded cache parsing, and immutable build-input hardening.
- `v1.7.8`: optional `wasm-wasi` capability preview with explicit grants only.
- `v1.7.9`: documentation and example parity release with runnable examples
  and tests for F5 iRules, nginx Lua/OpenResty, HAProxy Lua/SPOE, and VCL-like
  cache policy mappings.
- `v1.7.10`: Wasm stabilization release. All four example families must be in
  `scripts/test_starter.py` and the stable/deep release gates before the line
  is considered complete. Also add opt-in response-hardening profiles, typed
  modern browser controls, request-aware validated CORS with local preflight
  handling and automatic `Vary`, generated capacity-response `Retry-After`,
  and broader spoofable identity stripping without changing default behavior.
- `v1.7.11`: zero-downtime upgrade release after Wasm stabilization. Add
  inherited listener file-descriptor support, systemd socket activation
  guidance, readiness-gated new-process startup, old-process drain mode,
  bounded graceful drain timeout, and a documented Podman blue/green pattern
  that uses a stable fronting listener or host-level redirect owner. Include
  live upgrade smoke tests that prove no listener gap for the supported native
  path and clearly document Podman configurations that cannot be seamless
  without a fronting layer. Complete the HTTP/1 parser audit by making semantic
  validation part of the public parse boundary and proving linear, bounded
  request-target, Connection, and chunked-body handling.
- `v1.7.12`: standards-based response metadata plus reproducible FIPS-backend
  evidence. Implement opt-in RFC 9211 `Cache-Status`, low-cardinality RFC 9209
  `Proxy-Status`, and streaming RFC 9530 digest fields from real runtime state
  with live cache, proxy failure, compression, conditional, HEAD, and range
  tests. Never expose backend topology or synthesize these protocol fields as
  static decorative headers. Add pinned CI-only environments that build and
  execute the same `profile-fips-openssl` and `profile-fips-rustls` binaries,
  verify the intended OpenSSL FIPS and rustls/AWS-LC FIPS provider/dependency
  boundaries, run real downstream/upstream TLS, reject incompatible policy,
  and retain toolchain/provider/binary/image evidence. Do not publish these as
  FIPS images or present the tests as product-level FIPS validation.
- `v1.8.0`: cross-platform production baseline planning. Make macOS and
  Windows first-class release targets where practical, with Linux as the
  reference baseline. Define the supported profile matrix, platform-specific
  gaps, service/install models, release asset shape, and smoke evidence needed
  before either platform is called production-supported.
- `v1.8.1`: macOS production foundation with regular CI, Apple Silicon and
  Intel build profiles, live static/proxy/TLS/cache/admin/load-balancer/Wasm
  smoke coverage, launchd or documented non-service deployment, Mac-safe
  production paths, and APFS/ACL/symlink/certificate-storage review notes.
- `v1.8.2`: macOS signed package release with Apple Developer ID signing and
  notarization. Ship a signed/notarized `.pkg`, Homebrew formula/cask path, or
  both, with release-gate checks for signed/notarized artifacts when
  credentials are available.
- `v1.8.3`: Windows production foundation with Windows CI, MSVC build profiles,
  live static/proxy/TLS/cache/admin/load-balancer/Wasm smoke coverage, Windows
  service behavior, ACL/path/file-locking/symlink review, and replacements or
  documented limitations for Unix-only control paths.
- `v1.8.4`: Windows signed package release with Authenticode signing and an
  installer path. Prefer Microsoft Store/MSIX/App Installer when the Store
  model fits Fluxheim's server/service behavior; otherwise ship signed MSI or
  signed zip/service assets and keep Store publication as a separate packaging
  compatibility decision.
- `v1.8.5`: cross-platform parity hardening. Compare Linux, macOS, and Windows
  behavior profile by profile, close remaining gaps where practical, document
  intentional differences, and add platform smoke entries to the release gates
  and `scripts/test_starter.py`.
- `v1.9.0`: Fluxheim-owned HTTP/3 and QUIC line. Stop at an opt-in
  `http3`/`http3-experimental` feature using Rust `quinn` for QUIC transport
  and the Rust `h3` stack for HTTP/3 framing behind Fluxheim-owned listener,
  TLS, routing, access-policy, cache/proxy, metrics, logging, and graceful
  shutdown boundaries after the cross-platform production line is stable.
  Preserve HTTP/1.1 and HTTP/2 behavior, advertise `Alt-Svc` only for healthy
  configured QUIC listeners, keep 0-RTT disabled unless explicit replay-safe
  route policy exists, and require interop, malformed-input, packet-loss,
  anti-amplification, timeout, container-network, and mixed-protocol boundary
  tests. Do not add generic UDP proxying, DNS/GSLB, WAF, VPN/firewall
  appliance behavior, or new Wasm ABI scope in this release.

## Long-Term Ecosystem

Separate Fluxheim ecosystem crates and projects are tracked in
[Fluxheim Ecosystem Idea](fluxheim-ecosystem-idea.md). The intended shape is to
keep Fluxheim focused while allowing future `fluxheim-sdk`,
`fluxheim-defense`, `fluxheim-router`, and shared `fluxheim-common` style
packages to integrate through explicit APIs and release gates.

## Changelog Shape

Every release should include:

- stable features added;
- beta/experimental features included but not supported as stable;
- security fixes;
- dependency updates;
- migration notes;
- known limitations;
- exact release check command output summary.
