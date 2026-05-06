<h1 align="center">
  <a href="https://fluxheim.eu">
    <img src="./.github/images/fluxheim-logo-transparent.webp" alt="Fluxheim">
  </a>
</h1>

<p align="center">
  <i>High-performance, modular web server and reverse proxy built on Pingora.</i>
</p>

<div align="center">
  <a href="https://fluxheim.eu">Home Page</a>
</div>

<br>

<p align="center">
  <img src="./.github/images/fluxheim.webp" alt="Fluxheim overview">
</p>

# Fluxheim

Fluxheim is a modular Rust edge server built on
[Pingora](https://github.com/cloudflare/pingora). The project goal is a small,
secure static web server and reverse proxy first, with larger capabilities added
behind explicit compile-time feature flags as they become stable.

Fluxheim is licensed under the European Union Public Licence 1.2.

## Status

Fluxheim is under active early development. The public `1.0` target is
intentionally narrow:

- static website hosting;
- reverse proxying;
- cache module baseline;
- virtual hosts;
- TLS with rustls as the default backend;
- optional cleartext-to-HTTPS redirect;
- strict request limits and secure defaults;
- local and rootless Podman operation.

Features such as load balancing, ACME automation, admin snapshots, metrics,
WAF, Cloudflare origin support, PHP, CGI, and legacy protocols are planned as
opt-in modules and are documented separately until they graduate.

See [Production Readiness](docs/production-readiness.md) for the current
stable-core promise and the checks expected before a real deployment.

## Why Fluxheim

- **Rust first**: memory-safe implementation with a pinned stable toolchain.
- **Pingora based**: uses Cloudflare's proxy framework for the core HTTP proxy.
- **Modular**: compile only the modules needed for a deployment.
- **Secure by default**: strict config validation, request limits, license
  checks, and no hidden legacy protocol fallback.
- **Static-site basics**: MIME detection, index files, `GET`/`HEAD`, `ETag`,
  conditional `304`, and single-range static responses.
- **HTTPS redirect**: optional global cleartext-to-HTTPS redirect with safe
  Host validation and explicit redirect status.
- **Local friendly**: supports normal local binaries and rootless Podman.
- **Container choices**: explicit Wolfi, Alpine, SUSE Micro, and Debian
  Containerfiles for different deployment policies, with documented volume
  mappings for configs, TLS, state, cache, logs, and static roots.

## Quick Start

Build the default development binary:

```bash
cargo build
```

Run checks:

```bash
scripts/checks.sh
```

Validate an example config:

```bash
cargo run -- --config examples/fluxheim.toml --check-config
```

Run Fluxheim locally:

```bash
cargo run -- --config examples/fluxheim.toml
```

## Feature Builds

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
| `privacy-mode` | No | Zero-retention static/proxy build profile. |
| `security` | Yes | Security helpers and release hardening checks. |
| `tls` | No | Internal TLS marker used by TLS/ACME code; select a concrete backend for serving. |

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
| `profile-observability` | `profile-core`, `metrics` | Core server with Prometheus metrics. |
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

## Example Config

```toml
[server]
listen = ["127.0.0.1:8080"]
default_vhost = "example"
trusted_proxies = []

# [server.https_redirect]
# enabled = true
# status = 308
# target_port = 8443

[logging]
level = "info"
format = "json"
target = "stderr"

[logging.file]
enabled = false
# path = "/var/log/fluxheim/fluxheim.log"
append = true

[logging.access]
enabled = true
include_host = true
include_path = true
request_id = true
request_id_header = "x-request-id"

[headers.request]
enabled = true
strip_inbound_client_ip_headers = true
x_forwarded_for = "replace"
x_forwarded_host = true
x_forwarded_proto = true
forwarded = false
remove = ["x-powered-by"]

[headers.request.add]
x-proxy-by = "Fluxheim"

[headers.request.append]
via = "fluxheim"

[headers.response]
enabled = true
x_content_type_options = "nosniff"
x_frame_options = "DENY"
referrer_policy = "no-referrer"
remove = ["server", "x-powered-by"]

[headers.response.add]
cache-control = "public, max-age=60"

[headers.response.append]
vary = ["Accept-Encoding"]

# [[vhosts]] starts one virtual host. Every [vhosts.*] table below belongs to
# this vhost until the next [[vhosts]] line.
[[vhosts]]
name = "example"
hosts = ["example.test"]

[vhosts.web]
root = "/srv/sites/example"
index_files = ["index.html"]
deny_dotfiles = true

[vhosts.proxy]
upstreams = ["127.0.0.1:3000"]
upstream_tls = false

[vhosts.headers.response.add]
access-control-allow-origin = "https://example.test"

[vhosts.headers.response.append]
vary = ["Origin"]
```

More examples live in [examples](examples).
For the `[[vhosts]]` syntax and the recommended one-vhost-per-file layout, see
[Vhost Config Guide](docs/vhost-config.md).
The `examples/privacy.toml` config is designed for
`--no-default-features --features profile-privacy` and keeps Fluxheim access
logging, file logging, request IDs, metrics, and cache disabled.
The `examples/podman-compose.yml` file shows the recommended container volume
layout for configs, TLS certificates, cache, state, logs, and static site roots.

## Documentation

- [Roadmap](ROADMAP.md)
- [Changelog](CHANGELOG.md)
- [Versioning Plan](docs/versioning-plan.md)
- [Release Checklist](docs/release-checklist.md)
- [Build, Containers, And Rootless Podman](docs/build-and-podman.md)
- [Feature Matrix](docs/features.md)
- [Config Reference](docs/config-reference.md)
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

## Release Direction

Fluxheim will not treat every planned feature as part of `1.0`.

- `1.0`: stable static hosting and reverse proxy core.
- `1.1`: TLS policy hardening.
- `1.2`: operational pack: logging, admin snapshots, rollback, metrics.
- `1.3`: load balancer support.
- `1.4`: cache pack.
- `1.5`: media transform pack.
- `1.6`: certificate automation.
- `1.7`: privacy and security profiles.
- `1.8`: Cloudflare origin support.
- `1.9`: advanced logging and metrics.
- `1.10`: declarative redirect/rewrite policy and traffic mirroring for
  release-safety workflows.
- `1.11`: external authorization and identity-aware routing.
- `1.12`: cluster-native shared state.
- `1.13`: AI gateway controls.
- `1.14`: Sentinel Mesh graduation.
- `2.0`: dynamic runtime boundary for PHP/CGI.
- `2.1`: programmable media edge.
- `2.2`: WASM extensibility.

See [Versioning Plan](docs/versioning-plan.md) for the full release ladder.

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
