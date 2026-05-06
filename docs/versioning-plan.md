# Versioning Plan

Fluxheim should use SemVer, but with a conservative interpretation: a feature is
not considered stable just because it compiles. A feature becomes stable only
after it has docs, config validation, tests, release checks, and a clear
security boundary.

The main lesson from the roadmap is to avoid shipping one giant 1.0. Version
1.0 should be a small, boring, secure web server and reverse proxy. Larger
modules then graduate in later minor releases.

## Versioning Rules

- `0.x`: incubator releases. Config shape and behavior may still change.
- `1.0.x`: stable core bugfixes only.
- `1.x.0`: add stable, production-supported modules without breaking existing
  1.x configs.
- `2.0.0`: allowed only for breaking config/API behavior or major threat-model
  changes that cannot be feature-gated safely.

Security fixes should be backported to the latest stable minor when practical.

Every stable release must pass the stable release security and stability gate in
`docs/release-checklist.md`. The gate grows with the release: `1.0.x` runs it
against static hosting, reverse proxying, TLS, cache policy, headers, and
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

### 1.0 - Stable Core

Goal: a small stable Fluxheim release for static web hosting and reverse proxy.

Stable scope:

- Static web hosting.
- Reverse proxy.
- Cache module compiled in by default, with runtime cache disabled unless the
  operator configures a storage tier.
- Vhost routing.
- Caddy-inspired TOML config and `conf.d` loading.
- Static/bought certificate support.
- Rustls as the default TLS backend.
- Optional OpenSSL and s2n TLS builds when they pass the release matrix.
- Optional BoringSSL TLS builds on builders with `libclang` available for
  bindgen.
- TLS listener cipher/protocol policy follows the selected Pingora TLS backend
  defaults in `1.0`; user-configurable TLS policy is not stable until a later
  release.
- Secure header policy.
- Optional global cleartext-to-HTTPS redirect.
- Request header/body limits.
- Rootless Podman runtime.
- Release/security checks.

Not in 1.0 stable scope:

- Load balancing.
- ACME runtime issuance.
- Admin snapshots/rollback.
- Prometheus metrics.
- Advanced logging pipelines.
- WAF.
- Cloudflare automation.
- PHP/CGI.
- Legacy HTTP.
- Sentinel Mesh/WireGuard.

Exit criteria:

- Default 1.0 binary contains only stable core modules.
- `--no-default-features --features web` works.
- `--no-default-features --features proxy` works.
- Static+proxy+TLS mixed config has integration coverage through
  `scripts/smoke_1_0_core.sh`.
- No known `cargo audit` advisory without documented exception.
- `cargo deny check` passes.
- The 1.0 security and stability launch gate in `docs/release-checklist.md`
  has been run and recorded. This includes dependency checks, CodeQL/CI,
  malformed request framing tests, header scrubbing checks, local load testing,
  TLS scanning, and a deployment-side DAST pass.
- Fuzz targets exist or have been run for Fluxheim-owned parser and policy
  logic that can affect request routing, filesystem access, redirects, cache
  keys, or cache-header decisions.

### 1.1 - TLS Policy Hardening

Goal: expose explicit TLS policy without making insecure combinations easy.

Stable scope:

- Named TLS policy profiles such as `modern` and `compat`, with `modern` as the
  default.
- Minimum protocol version config, bounded to safe values.
- ALPN policy for HTTP/1.1 and future HTTP/2/HTTP/3 work.
- Per-backend validation that rejects cipher or protocol settings unsupported
  by the selected TLS backend.

Beta scope:

- Explicit cipher-suite allow-lists for operators with compliance requirements.
- Separate upstream TLS policy if upstream transport needs different
  compatibility than public downstream listeners.

Exit criteria:

- Config validation rejects weak protocol versions and empty/unknown cipher
  lists.
- `testssl.sh` scans are recorded for every stable TLS backend in the release
  matrix.
- TLS policy changes are classified correctly as reload-safe or requiring a
  process restart.

### 1.2 - Operations Pack

Goal: add safe operational visibility and controlled reload tooling.

Stable scope:

- Access/error logging with redaction.
- Private admin API on loopback by default.
- Config snapshots.
- Dry-run reload validation.
- Rollback.
- Basic self-healing rollback.
- Prometheus metrics baseline on loopback by default.

Exit criteria:

- Admin and metrics listeners fail validation when exposed remotely without
  explicit opt-in.
- Snapshot and rollback tests pass.
- Logs redact secrets by default.
- Metrics labels are cardinality-safe.

### 1.3 - Load Balancer

Goal: graduate Pingora load balancing to stable.

Stable scope:

- Compile-time `load-balancer` module.
- Multiple upstreams per vhost.
- Round-robin stable default.
- Health checks.
- Upstream TLS/SNI.
- Clear all-nodes-down behavior.

Beta scope:

- Hash-based policies if Pingora support and tests are strong enough.

Exit criteria:

- `--features proxy,load-balancer` release build passes.
- Health check transitions are tested.
- Failover behavior is documented.
- Load-balancer metrics are available when `metrics` is enabled.

### 1.4 - Cache Pack

Goal: add controlled image/static caching.

Stable scope:

- Memory cache with global and per-vhost size limits.
- Disk cache with global and per-vhost directory/size limits.
- Tiered memory+disk cache.
- Full cache-header semantics for static and proxied cacheable responses:
  `Cache-Control`, `Expires`, `ETag`, `Last-Modified`, `Vary`, `Age`,
  `Accept-Ranges`, `If-None-Match`, `If-Modified-Since`, request
  `Cache-Control`, `Pragma`, `Range`, and `If-Range`.
- User-configurable browser/CDN cache headers through global and per-vhost
  header policy.
- Protected purge/status endpoints if admin module is enabled.
- Cache activity counters.

Beta scope:

- Persistent cache index.
- Stale-while-revalidate.
- Partial streaming admission.

Exit criteria:

- Cache cannot exceed configured memory/disk budgets.
- Cache keys are collision-resistant and vhost-isolated.
- Cache respects method/content-type policy and request/response cache
  directives.
- `Vary` handling is tested before negotiated variants are stable. Implemented
  initially with Pingora cache variance keys and unsafe/sensitive `Vary`
  rejection.
- Shared cache admission refuses `Set-Cookie` responses.
- Proxied image-cache admission only stores `200 OK` origin responses with an
  `image/*` `Content-Type`.
- Cache hits emit correct validator/freshness behavior, including `Age` where
  Fluxheim serves from cache. Pingora provides the cache-hit `Age`,
  conditional, and range hooks; Fluxheim still needs an end-to-end regression
  around them.
- Purge endpoints require admin protection and remove all stored `Vary`
  variants for the selected cache identity.

### 1.5 - Media Transform Pack

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

### 1.6 - Certificate Automation

Goal: make certificate lifecycle operational without downtime.

Stable scope:

- ACME runtime issuance for Let's Encrypt and Actalis.
- Renewal queue.
- User-chosen renew-before window.
- Zero-downtime certificate reload through the runtime/snapshot model.
- Own/bought certificates remain fully supported.

Beta scope:

- Cloudflare Origin CA automation behind `cloudflare-origin-ca`.

Exit criteria:

- Renewal failure does not drop active traffic.
- Private key storage permissions are validated.
- Tests cover renewal scheduling and reload classification.

### 1.7 - Privacy And Security Profiles

Goal: provide explicit security/privacy build profiles.

Stable scope:

- `privacy-mode` zero-retention build profile.
- Compile-time incompatibility guards.
- No access logs, request metrics, disk cache, WAF audit logs, or client-IP
  forwarding in privacy builds.

Beta scope:

- Native WAF header/body scoring behind `waf-native`.

Exit criteria:

- Privacy build proves metrics/logging exporters are absent.
- Forwarded IP headers are stripped in privacy mode.
- WAF is dry-run capable and redacts secrets before beta promotion.

### 1.8 - Cloudflare Origin Pack

Goal: support Cloudflare as a verified trusted peer.

Stable scope:

- Trusted Cloudflare IP range loading.
- Safe real-IP restoration only after trust validation.
- Ray ID log correlation.
- Optional IP range refresh with last-known-good fallback.

Beta scope:

- AOP/mTLS automation.
- Origin CA automation if not stabilized in 1.5.

Exit criteria:

- Spoofed `CF-*` headers from non-Cloudflare peers are ignored.
- API tokens are never logged.
- AOP mode clearly distinguishes global, zone-level, and per-hostname trust.

### 1.9 - Advanced Metrics And Logging

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
- OTLP metrics export.
- Compile-time `otel-otlp` exporter to a local OpenTelemetry Collector.
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

### 1.10 - Traffic Policy And Safety Pack

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

### 1.11 - External Authorization And Identity-Aware Routing

Goal: enforce access decisions through a trusted authorization service first,
then add native identity verification and claim-aware routing.

Stable scope:

- Compile-time `auth-request` module.
- Per-vhost/per-route authorization probes.
- Decision handling: allow on `2xx`, deny on `401`/`403`, and treat every other
  auth service status as an error.
- Fail-closed default with explicit `fail_open` opt-in.
- Header allow-lists for auth request metadata, auth response headers copied to
  upstreams, and challenge headers copied to clients.
- Auth backend timeouts and response-size limits.
- Compile-time `identity-oidc` module.
- OIDC discovery and JWKS caching.
- JWT issuer, audience, expiry, and algorithm validation.
- Per-vhost claim-based allow/deny/routing policy.
- Verified header injection after stripping spoofable inbound identity headers.

Beta scope:

- Optional auth-decision caching with bounded positive/negative TTLs.
- Auth backend mTLS.
- OAuth2 token introspection.
- Tenant/subscription-tier based upstream pool selection.

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

### 1.12 - Cluster State

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

### 1.13 - AI Gateway

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

### 1.14 - Sentinel Mesh

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

### 2.0 - Dynamic Runtime Boundary

Goal: add application-server features only after a deliberate major boundary.

Candidate scope:

- PHP-FPM FastCGI bridge.
- Turbine integration if a safe library/sidecar model is proven.
- Perl CGI with process isolation.

Reason for 2.0:

Dynamic runtimes change Fluxheim from a proxy/static server into an application
execution host. That is a larger threat-model change than cache, load balancing,
or certificate automation.

Exit criteria:

- Runtime modules are compile-time optional and disabled by default.
- Process isolation is tested.
- Source files are never served as static fallback.
- Rootless Podman examples exist for every runtime.

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

### 2.2 - WASM Extensibility

Goal: add sandboxed, operator-provided extension logic after the core request
lifecycle, security profiles, WAF, auth, observability, and media-policy needs
are well understood.

Stable scope:

- Compile-time `wasm` module.
- Plugin loading from approved directories.
- Wasmtime-based sandbox evaluation after license/advisory review.
- Request header hook.
- Response header hook.
- Access-control hook returning allow, deny, or continue.
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
- Plugins cannot directly control routing destinations, cache keys, or upstream
  TLS verification.

### Experimental-Only Tracks

These should not be promised in a stable minor until proven:

- HTTP/3/QUIC.
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

The `1.0` default feature set is intentionally narrowed to stable core only:

```toml
default = ["proxy", "web", "cache", "tls-rustls", "security"]
```

Modules such as `load-balancer`, `acme`, `metrics`, `admin`,
`privacy-mode`, `image-filter`, `media-edge`, `wasm`, `waf`, `cloudflare`,
PHP, CGI, and legacy HTTP should be selected explicitly until their target
release graduates them.

Grouped builds should be exposed as Cargo feature aliases, not a custom
`--group` flag. The initial profile aliases are `profile-core`,
`profile-static-site`, `profile-reverse-proxy`, `profile-cache-server`,
`profile-load-balancer`, `profile-observability`, and `profile-privacy`.

Package scripts that accept a raw `--features` value should run
`scripts/validate-features.sh` before Cargo. This catches unsupported feature
combinations, especially multiple TLS backends, before dependency compilation
reaches Pingora.

## Git Tags

Use annotated tags:

```bash
git tag -a v1.0.0 -m "Fluxheim 1.0.0"
git push origin v1.0.0
```

Patch releases should contain fixes only:

- `v1.0.1`: security or bug fixes for stable core.
- `v1.1.1`: fixes for TLS policy hardening.
- `v1.2.1`: fixes for operations pack.
- `v1.3.1`: fixes for load balancer.

## Changelog Shape

Every release should include:

- stable features added;
- beta/experimental features included but not supported as stable;
- security fixes;
- dependency updates;
- migration notes;
- known limitations;
- exact release check command output summary.
