<p align="center">
  <img src="./.github/images/fluxheim-logo-transparent.webp" alt="Fluxheim" width="420">
</p>

<p align="center">
  <b>Memory-safe edge server and reverse proxy built on Pingora.</b><br>
  Modular by design. Secure by default. Ready for rootless containers.
</p>

<div align="center">
  <a href="https://fluxheim.eu">Home Page</a>
  ·
  <a href="docs/config-reference.md">Config Reference</a>
  ·
  <a href="docs/versioning-plan.md">Versioning Plan</a>
  ·
  <a href="SECURITY.md">Security</a>
</div>

<br>

<p align="center">
  <img src="./.github/images/fluxheim.webp" alt="Fluxheim overview">
</p>

# Fluxheim

Fluxheim is a modular Rust edge server built on
[Pingora](https://github.com/cloudflare/pingora). The current main branch is
the `1.2` operations and cache completion line: static sites, vhosts,
route-level proxying, redirects, rustls SNI, managed ACME issuance and renewal,
secure headers, container/native systemd operation, and the production cache
pack are the active focus. The latest released `1.1.x` line remains the
production gateway baseline while `1.2` finishes cache tooling, observability,
and operator ergonomics.

Fluxheim is licensed under the European Union Public Licence 1.2.

## What Works Today

- Static website hosting with MIME detection, index files, `GET`/`HEAD`,
  `ETag`, conditional `304`, and single byte ranges.
- Vhost routing by Host header with default-vhost fallback.
- Whole-vhost and route-level reverse proxying.
- Static/bought certificate support with rustls as the default TLS backend.
- Multi-certificate SNI selection on the default rustls TLS backend.
- Managed ACME certificate issuance and renewal for HTTP-01 and rustls
  TLS-ALPN-01 builds.
- Route-level static, proxy, and redirect actions.
- Route-scoped proxy cache policies with memory, disk, and tiered storage,
  status headers, hard/soft indexed purge endpoints, stale cleanup, and cache
  warming.
- Optional global HTTP-to-HTTPS redirect with safe Host validation.
- External ACME HTTP-01 challenge forwarding helper.
- Secure request/response header policy, including `Server: fluxheim` by
  default and removable by config.
- Native systemd/RPM deployment files.
- Rootless Podman containers for Wolfi, Alpine, SUSE Micro, and Debian.
- Packaged default page at `/srv/fluxheim/index.html` with no external assets.

See [Production Readiness](docs/production-readiness.md) for the precise
stable-core promise and deployment checks.

## Why Fluxheim

- **Rust first**: memory-safe implementation with a pinned stable toolchain.
- **Pingora based**: uses Cloudflare's proxy framework for the core HTTP path.
- **Modular builds**: compile only the modules needed for a deployment.
- **Secure defaults**: strict config validation, request limits, safe filesystem
  handling, dependency policy, and no hidden legacy protocol fallback.
- **Container native**: rootless-first examples and explicit runtime images for
  different operational policies.

## Quick Start

Build the default development binary:

```bash
cargo build
```

Validate the local development config:

```bash
cargo run -- --check-config --config examples/fluxheim.toml
```

Run Fluxheim locally:

```bash
cargo run -- --config examples/fluxheim.toml
```

Then open `http://127.0.0.1:8080` with a Host header that matches the default
vhost, or use curl:

```bash
curl -H 'Host: localhost' http://127.0.0.1:8080/
```

Run the normal local checks:

```bash
scripts/checks.sh
```

## Minimal Static Site Config

```toml
[server]
listen = ["0.0.0.0:8080"]
default_vhost = "site"

[headers.response]
enabled = true
x_content_type_options = "nosniff"
x_frame_options = "DENY"
referrer_policy = "no-referrer"

[[vhosts]]
name = "site"
hosts = ["example.test", "www.example.test"]

[vhosts.web]
root = "/srv/sites/example/public"
index_files = ["index.html"]
deny_dotfiles = true
cache_control = "public, max-age=60"
```

More examples live in [examples](examples). Native packages use
[packaging/default/fluxheim.toml](packaging/default/fluxheim.toml), which
listens on port `80` under the hardened systemd unit with
`CAP_NET_BIND_SERVICE`; containers use
[packaging/container/fluxheim.toml](packaging/container/fluxheim.toml), which
keeps rootless-friendly internal ports `8080` and `8443`. For the `[[vhosts]]`
syntax and the recommended one-vhost-per-file layout, see
[Vhost Config Guide](docs/vhost-config.md). For common multi-site proxy
patterns, see [Gateway Recipes](docs/gateway-recipes.md).

Native/manual binary deployments can use the provided hardened systemd unit;
see [systemd Deployment](docs/systemd.md).

<details>
<summary><b>Feature Builds</b></summary>

The default build is the recommended local/server baseline:

```bash
cargo build
```

It enables:

- `proxy`
- `web`
- `cache`
- `tls-rustls`
- `security`

Individual module features:

| Feature | Default | Notes |
| --- | --- | --- |
| `proxy` | Yes | Pingora reverse proxy runtime and admin plumbing. |
| `web` | Yes | Static file resolver and static response handling. Runtime serving currently uses `proxy` sessions. |
| `cache` | Yes | Cache module compiled in; runtime cache remains disabled until configured. |
| `load-balancer` | No | Pingora load-balancing module and health checks. |
| `metrics` | No | Prometheus metrics listener. |
| `acme` | No | ACME planning/renewal support. Requires TLS config and should be paired with one TLS backend for serving. |
| `acme-client` | No | Live ACME account/order HTTP client and background renewal service for HTTP-01 and rustls TLS-ALPN-01 certificate issuance and renewal. |
| `privacy-mode` | No | Zero-retention static/proxy build profile. |
| `security` | Yes | Security helpers and release hardening checks. |
| `tls` | No | Internal TLS marker used by TLS/ACME code; select a concrete backend for serving. |

For checked TLS policy examples, see
[`examples/tls-modern.toml`](examples/tls-modern.toml) and
[`examples/tls-intermediate.toml`](examples/tls-intermediate.toml).
For managed certificate issuance, see
[`examples/acme-http-01.toml`](examples/acme-http-01.toml). For an issuer that
requires External Account Binding, see
[`examples/acme-actalis.toml`](examples/acme-actalis.toml).
Packaged `1.1.x` builds include `acme-init` for guided issuer bootstrap:

```bash
sudo fluxheim acme-init actalis
sudo fluxheim acme-init letsencrypt
```

Cargo does not provide a separate `--group` flag. Fluxheim uses normal Cargo
feature aliases named `profile-*` for grouped builds.

Recommended profile features:

| Profile feature | Enables | Use case |
| --- | --- | --- |
| `profile-core` | `proxy`, `web`, `cache`, `tls-rustls`, `security` | Same intent as the default build. |
| `profile-static-site` | `proxy`, `web`, `tls-rustls`, `security` | Static sites without Fluxheim cache. |
| `profile-reverse-proxy` | `proxy`, `tls-rustls`, `security` | Reverse proxy without static hosting/cache. |
| `profile-cache-server` | `proxy`, `web`, `cache`, `tls-rustls`, `security` | Static/proxy server with cache enabled. |
| `profile-load-balancer` | `proxy`, `web`, `cache`, `load-balancer`, `tls-rustls`, `security` | Edge server with Pingora load balancing. |
| `profile-observability` | `profile-core`, `metrics`, `metrics-otlp`, `otel-tracing`, `otel-otlp` | Core server with Prometheus metrics, optional local OTLP metrics export, trace context propagation, and optional local OTLP trace export. |
| `profile-privacy` | `proxy`, `web`, `tls-rustls`, `privacy-mode`, `security` | Zero-retention static/proxy profile. |

Example grouped build:

```bash
cargo build --no-default-features --features profile-load-balancer
```

Manual feature selection also works:

```bash
cargo build --no-default-features --features proxy,web,tls-rustls,load-balancer
```

TLS backends are mutually exclusive. Select exactly one backend when TLS is
needed:

| TLS feature | Status |
| --- | --- |
| `tls-rustls` | Default and recommended. |
| `tls-openssl` | Optional OpenSSL backend. |
| `tls-boringssl` | Optional BoringSSL backend. |
| `tls-s2n` | Optional s2n-tls backend. |

Selecting more than one TLS backend is a compile error.
Use `scripts/validate-features.sh` in packaging or custom CI jobs when accepting
user-provided feature strings; Cargo features are additive, and Pingora itself
does not support compiling multiple TLS backends together.

Future optional modules such as `waf`, `cloudflare`, PHP, CGI, and legacy
static HTTP are documented in the architecture docs but are not enabled in the
default build.

Because `cache` is part of the default build, privacy builds must use
`--no-default-features` through `profile-privacy` or an explicit manual feature
set. Combining `privacy-mode` with `cache` or `metrics` fails at compile time.

Small manual builds:

```bash
cargo build --no-default-features --features proxy
cargo build --no-default-features --features proxy,web,tls-rustls
cargo build --no-default-features --features proxy,web,tls-rustls,privacy-mode
```

Validate a custom feature set before building:

```bash
scripts/validate-features.sh proxy,web,tls-rustls,load-balancer
```

</details>

## Current Stable: 1.1 Certificate Operations

Fluxheim does not treat every planned feature as part of the stable core. The
`1.0` release established the first gateway-ready baseline for representative
real multi-site configs. The `1.1` release adds production certificate
operations on top of that baseline.

Included in `1.0`: route-level exact/prefix/fallback matching, route actions
for proxy/static/redirects, route prefix stripping, per-route body limits,
upstream connect/read/send timeout knobs, websocket-safe upgrade smoke coverage
for `/chat/`-style routes, custom upstream error pages, secure static aliases
with optional directory listing, cleartext ACME challenge exceptions, safe
dynamic request-header templates for common proxy migrations, SNI certificate
selection for the default rustls TLS backend and callback-capable TLS backends,
and native systemd deployment files for manually compiled binaries. Direct proxy
upstream DNS names are resolved per request and resolution failures return
upstream errors instead of panicking the worker, which covers local Podman
service names for the non-LB gateway path.

Added in `1.1`: named TLS policy profiles, minimum protocol and ALPN controls,
multi-certificate rustls SNI, managed ACME issuance and renewal for HTTP-01 and
rustls TLS-ALPN-01 builds, Actalis and Google Trust Services EAB-capable issuer
configuration, file-backed secret support for containers/systemd credentials,
safe ACME storage, and guided `acme-init` bootstrap.

Active `1.2` work: cache-server completion and operations diagnostics. The
current development line now includes route/vhost scoped cache policies, memory
and disk cache tiers, cache locks for request collapsing, protected purge/status
operations, cache warm/lookup/key tooling, cache policy metrics, OTLP metrics
export, and end-to-end proxy cache smoke coverage for hit `Age`, conditional
`304`, byte ranges, validator-based upstream revalidation and refresh,
stale-if-error serving, cache-lock request collapsing, `Vary` variants, disk
hits after restart, and debug bypass reasons. `cache-lookup` also supports deploy-script assertions for object
presence, storage tier, HTTP status, stored body size, stored fresh TTL, stored
cache tags, stored header names, cache-lock/tier layout, stale-serving
eligibility, purge-index reachability, and fresh/stale/expired state. Remaining `1.2`
hardening focuses on proxy revalidation edge cases, large-object
range/slice fill, very large disk-cache loader/purger behavior,
production Podman/ACME examples, a separate ACME companion service/timer flow,
admin/metrics operations tooling, rollback/snapshot improvements, and proxy
buffering/backpressure controls for app migrations.

Later releases continue with load balancing, cache improvements, advanced
certificate automation, privacy/security profiles, Cloudflare origin support,
observability, auth, cluster state, AI-aware controls, Sentinel Mesh, PHP/CGI
boundaries, media-edge work, and WASM extensibility.

See [Versioning Plan](docs/versioning-plan.md) and [Roadmap](ROADMAP.md) for
the full release ladder.

## Documentation

- [Roadmap](ROADMAP.md)
- [Changelog](CHANGELOG.md)
- [Versioning Plan](docs/versioning-plan.md)
- [Release Runbook](docs/release-runbook.md)
- [Release Checklist](docs/release-checklist.md)
- [Build, Containers, And Rootless Podman](docs/build-and-podman.md)
- [Feature Matrix](docs/features.md)
- [Config Reference](docs/config-reference.md)
- [Gateway Recipes](docs/gateway-recipes.md)
- [GitHub Repository Setup](docs/github-setup.md)
- [Cache Backends](docs/cache-backends.md)
- [Image Filter](docs/image-filter.md)
- [Programmable Media Edge](docs/programmable-media-edge.md)
- [Certificate Renewal And Reload](docs/certificate-renewal.md)
- [Config Snapshots And Rollback](docs/config-snapshots.md)
- [Logging Architecture](docs/logging-architecture.md)
- [Metrics Architecture](docs/metrics-architecture.md)
- [OpenTelemetry Tracing](docs/opentelemetry-tracing.md)
- [WASM Extensibility](docs/wasm-extensibility.md)
- [External Authorization Request](docs/auth-request.md)
- [Zero-Retention Privacy Mode](docs/zero-retention-privacy-mode.md)
- [WAF Architecture](docs/waf-architecture.md)
- [Cloudflare Origin Support](docs/cloudflare-origin-support.md)
- [PHP Runtime Support](docs/php-runtime-support.md)
- [Perl CGI Support](docs/perl-cgi-support.md)
- [Legacy Static HTTP Support](docs/legacy-static-http.md)
- [Sentinel Mesh](docs/sentinel-mesh.md)

## Security And Dependency Policy

Fluxheim uses:

- pinned Rust stable toolchain;
- checked-in `Cargo.lock`;
- GitHub CI and CodeQL scanning;
- `cargo deny` for license and dependency policy;
- `cargo audit` for advisory checks;
- rootless Podman smoke tests before container releases.

Before publishing or merging security-sensitive changes:

```bash
scripts/release_checks.sh
```

See [SECURITY.md](SECURITY.md) for vulnerability reporting.

## License

Fluxheim is distributed under the
[European Union Public Licence v1.2](LICENSE).
