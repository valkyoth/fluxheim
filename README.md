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
- virtual hosts;
- TLS with rustls as the default backend;
- strict request limits and secure defaults;
- local and rootless Podman operation.

Features such as load balancing, cache, ACME automation, admin snapshots,
metrics, WAF, Cloudflare origin support, PHP, CGI, and legacy protocols are
planned as opt-in modules and are documented separately until they graduate.

## Why Fluxheim

- **Rust first**: memory-safe implementation with a pinned stable toolchain.
- **Pingora based**: uses Cloudflare's proxy framework for the core HTTP proxy.
- **Modular**: compile only the modules needed for a deployment.
- **Secure by default**: strict config validation, request limits, license
  checks, and no hidden legacy protocol fallback.
- **Local friendly**: supports normal local binaries and rootless Podman.

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

Proxy-only:

```bash
cargo build --no-default-features --features proxy
```

Static web server-only:

```bash
cargo build --no-default-features --features web
```

Proxy with load-balancer module:

```bash
cargo build --no-default-features --features proxy,load-balancer
```

Static web plus reverse proxy with rustls:

```bash
cargo build --no-default-features --features proxy,web,tls-rustls
```

## Example Config

```toml
[server]
listen = ["127.0.0.1:8080"]
default_vhost = "example"

[[vhosts]]
name = "example"
hosts = ["example.test"]

[vhosts.web]
root = "/srv/sites/example"
index_files = ["index.html"]
deny_dotfiles = true

[vhosts.proxy]
upstream = "127.0.0.1:3000"
upstream_tls = false
```

More examples live in [examples](examples).

## Documentation

- [Roadmap](ROADMAP.md)
- [Versioning Plan](docs/versioning-plan.md)
- [Release Checklist](docs/release-checklist.md)
- [Build And Rootless Podman](docs/build-and-podman.md)
- [GitHub Repository Setup](docs/github-setup.md)
- [Cache Backends](docs/cache-backends.md)
- [Certificate Renewal And Reload](docs/certificate-renewal.md)
- [Config Snapshots And Rollback](docs/config-snapshots.md)
- [Logging Architecture](docs/logging-architecture.md)
- [Metrics Architecture](docs/metrics-architecture.md)
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
- `1.1`: operational pack: logging, admin snapshots, rollback, metrics.
- `1.2`: load balancer support.
- `1.3`: cache pack.
- `1.4`: certificate automation.
- `1.5`: privacy and security profiles.
- `1.6`: Cloudflare origin support.
- `1.7`: advanced logging and metrics.
- `2.0`: dynamic runtime boundary for PHP/CGI.

See [Versioning Plan](docs/versioning-plan.md) for the full release ladder.

## Security And Dependency Policy

Fluxheim uses:

- pinned Rust stable toolchain;
- checked-in `Cargo.lock`;
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
