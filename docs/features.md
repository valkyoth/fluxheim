# Feature Matrix

Fluxheim uses Cargo features for compile-time module selection. The default
binary is intentionally useful but conservative:

```toml
default = ["proxy", "web", "cache", "tls-rustls", "security"]
```

Use `scripts/validate-features.sh` before packaging custom feature strings:

```bash
scripts/validate-features.sh proxy,web,tls-rustls
```

The validator expands profile aliases and rejects unsupported combinations
before Cargo starts compiling Pingora.

## Stable Core Features

| Feature | Default | Purpose |
| --- | --- | --- |
| `proxy` | Yes | Pingora proxy runtime and upstream forwarding. |
| `web` | Yes | Static file resolver and static response planning. |
| `cache` | Yes | Image cache module. Runtime caching still requires config. |
| `tls-rustls` | Yes | rustls TLS backend. |
| `security` | Yes | Security and release hardening helpers. |

## Optional Implemented Features

| Feature | Default | Purpose |
| --- | --- | --- |
| `load-balancer` | No | Pingora load-balancing support and health-check setup. |
| `metrics` | No | Prometheus metrics listener. |
| `otel-tracing` | No | W3C `traceparent` propagation and access-log trace ID correlation. |
| `otel-otlp` | No | Optional OTLP/HTTP JSON trace export to a local collector or Jaeger endpoint. |
| `acme` | No | ACME config, renewal planning, managed certificate/account paths, local HTTP-01 and rustls TLS-ALPN-01 challenge serving, and the renewal executor contract. |
| `privacy-mode` | No | Zero-retention static/proxy build profile. |
| `tls` | No | Internal marker for TLS-aware code; select a concrete backend for serving. |

## TLS Backends

Select at most one:

| Feature | Status |
| --- | --- |
| `tls-rustls` | Default and recommended. |
| `tls-openssl` | Optional OpenSSL backend. |
| `tls-boringssl` | Optional BoringSSL backend. |
| `tls-s2n` | Optional s2n-tls backend. |

Cargo features are additive, and Pingora does not support compiling multiple
TLS backends together. The feature validator catches this before build.
Pingora `0.8.0` does not expose an mbedTLS backend; supporting mbedTLS would
require a new Pingora TLS integration rather than a Fluxheim feature toggle.
`tls-boringssl` requires a build host with `libclang` available for bindgen.
Use `scripts/validate-tls-backends.sh` to validate the supported TLS backends on
the current machine.

## ACME Client Wiring

`acme` contains the config, storage, challenge, certificate observation, and
renewal-executor pieces. `acme-client` adds the live ACME HTTP client stack used
to load or create issuer accounts and complete HTTP-01 or rustls TLS-ALPN-01
orders through `instant-acme`, plus the runtime background renewal service. Keep
`acme-client` enabled only in builds that perform certificate issuance or
renewal.

## Profile Aliases

Cargo does not have a separate `--group` flag. Fluxheim provides normal Cargo
feature aliases for common deployment shapes.

| Profile | Expands to | Use case |
| --- | --- | --- |
| `profile-core` | `proxy`, `web`, `cache`, `tls-rustls`, `security` | Same intent as default. |
| `profile-static-site` | `proxy`, `web`, `tls-rustls`, `security` | Static sites without Fluxheim cache. |
| `profile-reverse-proxy` | `proxy`, `tls-rustls`, `security` | Reverse proxy without static hosting/cache. |
| `profile-cache-server` | `proxy`, `web`, `cache`, `tls-rustls`, `security` | Static/proxy server with cache enabled. |
| `profile-load-balancer` | `proxy`, `web`, `cache`, `load-balancer`, `tls-rustls`, `security` | Edge server with Pingora load balancing. |
| `profile-observability` | `profile-core`, `metrics`, `otel-tracing`, `otel-otlp` | Core server with Prometheus metrics, trace context propagation, and optional local OTLP trace export. |
| `profile-privacy` | `proxy`, `web`, `tls-rustls`, `privacy-mode`, `security` | Zero-retention static/proxy profile. |

Examples:

```bash
cargo build --no-default-features --features profile-load-balancer
cargo build --no-default-features --features profile-privacy
```

## Incompatible Combinations

| Combination | Reason |
| --- | --- |
| Multiple `tls-*` backends | Pingora exposes one TLS backend at a time. |
| `privacy-mode` + `cache` | Zero-retention builds must not compile request/response cache code. |
| `privacy-mode` + `metrics` | Zero-retention builds must not compile request metrics. |
| `privacy-mode` + `otel-tracing` | Zero-retention builds must not compile trace context propagation. |
| `privacy-mode` + `otel-otlp` | Zero-retention builds must not compile trace export. |

Because `cache` is part of the default build, privacy builds must use
`--no-default-features`.

## Planned Future Features

These are documented architecture tracks, not enabled Cargo features yet:

| Future feature family | Document |
| --- | --- |
| Compression | [Compression](compression.md) |
| Image filter | [Image Filter](image-filter.md) |
| Programmable media edge | [Programmable Media Edge](programmable-media-edge.md) |
| OpenTelemetry OTLP export | [OpenTelemetry Tracing](opentelemetry-tracing.md) |
| WASM extensibility | [WASM Extensibility](wasm-extensibility.md) |
| WAF | [WAF Architecture](waf-architecture.md) |
| Cloudflare origin support | [Cloudflare Origin Support](cloudflare-origin-support.md) |
| External authorization request | [External Authorization Request](auth-request.md) |
| Secure links | [Secure Links](secure-links.md) |
| PHP runtimes | [PHP Runtime Support](php-runtime-support.md) |
| Perl CGI | [Perl CGI Support](perl-cgi-support.md) |
| Legacy static HTTP listeners | [Legacy Static HTTP Support](legacy-static-http.md) |
| WireGuard smart load balancing | [Sentinel Mesh](sentinel-mesh.md) |
