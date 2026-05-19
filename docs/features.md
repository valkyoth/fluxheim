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
| `ingress` | Yes, through `proxy`/TLS profiles | Shared Pingora/Tokio ingress primitives used by proxy, TLS, and ACME-capable focused builds. |
| `tls-rustls` | Yes | rustls TLS backend. |
| `security` | Yes | Security and release hardening helpers. |

## Optional Implemented Features

| Feature | Default | Purpose |
| --- | --- | --- |
| `load-balancer` | No | Pingora load-balancing support and health-check setup. |
| `metrics` | No | Prometheus metrics listener. |
| `metrics-otlp` | No | Optional OTLP/HTTP JSON metrics export to a local Prometheus OTLP receiver or collector. |
| `otel-tracing` | No | W3C `traceparent` propagation and access-log trace ID correlation. |
| `otel-otlp` | No | Optional OTLP/HTTP JSON trace export to a local collector or Jaeger endpoint. |
| `acme` | No | ACME config, renewal planning, managed certificate/account paths, local HTTP-01 and rustls TLS-ALPN-01 challenge serving, and the renewal executor contract. |
| `acme-client` | No | Live ACME account/order HTTP client and background renewal service. |
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

## Cache Encryption Key Utility

`fluxheim cache-keygen` is available in every build profile. It prints one
random 256-bit lowercase hex key suitable for
`[cache.disk.encryption] provider = "local"`. The command does not write files
itself; pipe it into the operator's preferred secret manager, systemd
credential source, or container secret.

## ACME Client Wiring

`acme` contains the config, storage, challenge, certificate observation, and
renewal-executor pieces. `acme-client` adds the live ACME HTTP client stack used
to load or create issuer accounts and complete HTTP-01 or rustls TLS-ALPN-01
orders through `instant-acme`, plus the runtime background renewal service. Keep
`acme-client` enabled only in builds that perform certificate issuance or
renewal.

## PHP Runtime Modules

`php-fpm` enables the `1.3.1` FastCGI bridge for PHP applications. It implies
`proxy` and `web`, uses `fastcgi-client`, and must be selected explicitly:

```bash
cargo build --no-default-features --features profile-web-server,php-fpm,acme-client
```

Only one PHP runtime feature may be selected in one binary. `php-turbine` and
`php-phprs` are reserved feature gates for later `1.3.x` evaluation and do not
add a production runtime yet.

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
| `profile-observability` | `profile-core`, `metrics`, `metrics-otlp`, `otel-tracing`, `otel-otlp` | Core server with Prometheus metrics, optional local OTLP metrics export, trace context propagation, and optional local OTLP trace export. |
| `profile-privacy` | `proxy`, `web`, `tls-rustls`, `privacy-mode`, `security` | Zero-retention static/proxy profile. |
| `profile-full` | `profile-load-balancer` | All stable production modules. |
| `profile-development` | `profile-full`, `php-fpm`, `acme-client`, `metrics`, `metrics-otlp`, `otel-tracing`, `otel-otlp` | Broad development build with all compatible production modules. |
| `profile-web-server` | `proxy`, `web`, `tls-rustls`, `security` | Static webserver profile while serving still uses the shared proxy runtime. |
| `profile-cache-edge` | `proxy`, `cache`, `tls-rustls`, `security` | Cache edge without local static web serving. |
| `profile-proxy-edge` | `proxy`, `tls-rustls`, `security` | Focused reverse proxy edge. |
| `profile-load-balancer-edge` | `proxy`, `load-balancer`, `tls-rustls`, `security` | Load-balancer edge without cache or static web serving. |

Examples that match the official release artifacts:

```bash
cargo build --no-default-features --features profile-full,acme-client,metrics,metrics-otlp,otel-tracing,otel-otlp
cargo build --no-default-features --features profile-development
cargo build --no-default-features --features profile-cache-edge,acme-client
cargo build --no-default-features --features profile-proxy-edge,acme-client
cargo build --no-default-features --features profile-web-server,php-fpm,acme-client
cargo build --no-default-features --features profile-privacy
```

The raw profile aliases do not force `acme-client`; that is intentional for
offline or static-certificate custom builds. Official RPMs, images, and release
tarballs add `acme-client` to the full, cache, and proxy profiles by default.

Focused image profile status:

- TLS and ACME are shared ingress capabilities, not implicit static webserver
  capabilities.
- The `cache` and `proxy` focused profiles compile without local static web
  serving.
- Compatibility aliases may keep the older broad behavior, but published
  focused images are `full`, `cache`, and `proxy`. The `load-balancer` profile
  is prepared for the `1.5` line and can be included manually before then.

## Incompatible Combinations

| Combination | Reason |
| --- | --- |
| Multiple `tls-*` backends | Pingora exposes one TLS backend at a time. |
| `privacy-mode` + `cache` | Zero-retention builds must not compile request/response cache code. |
| `privacy-mode` + `metrics` | Zero-retention builds must not compile request metrics. |
| `privacy-mode` + `metrics-otlp` | Zero-retention builds must not compile metrics export. |
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
| Crypto RPC edge | [Crypto RPC Edge](crypto-rpc-edge.md) |
| WAF | [WAF Architecture](waf-architecture.md) |
| Cloudflare origin support | [Cloudflare Origin Support](cloudflare-origin-support.md) |
| External authorization request | [External Authorization Request](auth-request.md) |
| Secure links | [Secure Links](secure-links.md) |
| PHP runtimes | [PHP Runtime Support](php-runtime-support.md) |
| Perl CGI | [Perl CGI Support](perl-cgi-support.md) |
| Legacy static HTTP listeners | [Legacy Static HTTP Support](legacy-static-http.md) |
| WireGuard smart load balancing | [Sentinel Mesh](sentinel-mesh.md) |
