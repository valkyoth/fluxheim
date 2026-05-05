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
- Vhost routing.
- Caddy-inspired TOML config and `conf.d` loading.
- Static/bought certificate support.
- Rustls as the default TLS backend.
- Optional OpenSSL/BoringSSL/s2n TLS builds if they pass the release matrix.
- Secure header policy.
- Request header/body limits.
- Rootless Podman runtime.
- Release/security checks.

Not in 1.0 stable scope:

- Load balancing.
- Cache.
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
- Static+proxy+TLS mixed config has integration coverage.
- No known `cargo audit` advisory without documented exception.
- `cargo deny check` passes.

### 1.1 - Operations Pack

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

### 1.2 - Load Balancer

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

### 1.3 - Cache Pack

Goal: add controlled image/static caching.

Stable scope:

- Memory cache with global and per-vhost size limits.
- Disk cache with global and per-vhost directory/size limits.
- Tiered memory+disk cache.
- Protected purge/status endpoints if admin module is enabled.
- Cache activity counters.

Beta scope:

- Persistent cache index.
- Stale-while-revalidate.
- Partial streaming admission.

Exit criteria:

- Cache cannot exceed configured memory/disk budgets.
- Cache keys are collision-resistant and vhost-isolated.
- Cache respects method/content-type policy.
- Purge endpoints require admin protection.

### 1.4 - Certificate Automation

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

### 1.5 - Privacy And Security Profiles

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

### 1.6 - Cloudflare Origin Pack

Goal: support Cloudflare as a verified trusted peer.

Stable scope:

- Trusted Cloudflare IP range loading.
- Safe real-IP restoration only after trust validation.
- Ray ID log correlation.
- Optional IP range refresh with last-known-good fallback.

Beta scope:

- AOP/mTLS automation.
- Origin CA automation if not stabilized in 1.4.

Exit criteria:

- Spoofed `CF-*` headers from non-Cloudflare peers are ignored.
- API tokens are never logged.
- AOP mode clearly distinguishes global, zone-level, and per-hostname trust.

### 1.7 - Advanced Metrics And Logging

Goal: add richer observability without hurting the request path.

Stable scope:

- Advanced per-vhost metrics buckets.
- Cache/LB/admin/security counters.
- Bounded async logging dispatcher.
- Optional local file sink.

Beta scope:

- Remote logging sink with circuit breaker.
- OTLP metrics export.

Exit criteria:

- Remote sink failure never blocks request workers.
- Cardinality attack tests pass.
- Queue overflow behavior is explicit and tested.

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

### Experimental-Only Tracks

These should not be promised in a stable minor until proven:

- HTTP/3/QUIC.
- Legacy HTTP/1.0 and HTTP/0.9 static listeners.
- Sentinel Mesh/WireGuard smart load balancing.
- Coraza/Proxy-Wasm WAF compatibility.
- Pure Rust PHP interpreter experiments.

## What Changes In Cargo Defaults

Before `1.0`, the default feature set can be broad while development is active.
For `1.0`, default features should be narrowed to stable core only:

```toml
default = ["proxy", "web", "tls-rustls", "security"]
```

Modules such as `load-balancer`, `cache`, `acme`, `metrics`, `admin`,
`privacy-mode`, `waf`, `cloudflare`, PHP, CGI, and legacy HTTP should be
selected explicitly until their target release graduates them.

## Git Tags

Use annotated tags:

```bash
git tag -a v1.0.0 -m "Fluxheim 1.0.0"
git push origin v1.0.0
```

Patch releases should contain fixes only:

- `v1.0.1`: security or bug fixes for stable core.
- `v1.1.1`: fixes for operations pack.
- `v1.2.1`: fixes for load balancer.

## Changelog Shape

Every release should include:

- stable features added;
- beta/experimental features included but not supported as stable;
- security fixes;
- dependency updates;
- migration notes;
- known limitations;
- exact release check command output summary.
