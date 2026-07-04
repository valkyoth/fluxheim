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
before Cargo starts compiling Fluxheim.

## Stable Core Features

| Feature | Default | Purpose |
| --- | --- | --- |
| `proxy` | Yes | Fluxheim native proxy runtime and upstream forwarding. |
| `web` | Yes | Static file resolver and static response planning. |
| `cache` | Yes | Image cache module. Runtime caching still requires config. |
| `ingress` | Yes, through `proxy`/TLS profiles | Shared native Tokio ingress primitives used by proxy, TLS, and ACME-capable focused builds. |
| `tls-rustls` | Yes | rustls TLS backend. |
| `tls-rustls-fips` | No | rustls/AWS-LC FIPS-capable TLS backend candidate. |
| `security` | Yes | Compile-time security profile marker plus release hardening checks. Runtime enforcement lives in the concrete config, TLS, filesystem, admin, and request-handling modules. |

## Optional Implemented Features

| Feature | Default | Purpose |
| --- | --- | --- |
| `load-balancer` | No | Fluxheim load-balancing support, health checks, and runtime pool policy. |
| `metrics` | No | Prometheus metrics listener. |
| `metrics-otlp` | No | Optional OTLP/HTTP JSON metrics export to a local Prometheus OTLP receiver or collector. |
| `otel-tracing` | No | W3C `traceparent` propagation and access-log trace ID correlation. |
| `otel-otlp` | No | Optional OTLP/HTTP JSON trace export to a local collector or Jaeger endpoint. |
| `acme` | No | ACME config, renewal planning, managed certificate/account paths, local HTTP-01 and rustls TLS-ALPN-01 challenge serving, and the renewal executor contract. |
| `acme-client` | No | Live ACME account/order HTTP client and background renewal service. |
| `compression` | No | Shared response compression config and body-filter integration. |
| `compression-brotli` | No | Brotli response compression for eligible known-length responses. |
| `compression-gzip` | No | gzip response compression for eligible known-length responses. |
| `compression-zstd` | No | Zstandard response compression for eligible known-length responses. |
| `geoip` | No | Local MMDB Geo-Context lookup for MaxMind GeoIP2/GeoLite2 and CIRCL Geo Open datasets, exposed to bounded access policy and structured logs. |
| `stream-proxy` | No | Raw L4 TCP stream proxy service with separate stream routes, source IP/CIDR allow/deny policy, DNS-rebinding guards for hostname upstreams, bounded idle/lifetime/byte caps, route-local PROXY protocol receive/send, stream upstream TLS/mTLS controls, and weighted/drain/backup policy. |
| `wasm` | No | WebAssembly sandbox foundation with strict plugin-file loading, config-level plugin registry validation, typed loader manifests, authenticated registry status visibility, and bounded Wasmtime execution. Request/response policy hooks are staged for later `1.7.x` releases. |
| `wasm-proxy-abi` | No | Reserved Wasm proxy-ABI compatibility feature; currently depends on the sandbox foundation. |
| `wasm-wasi` | No | Reserved Wasm/WASI capability feature; currently depends on the sandbox foundation and remains disabled by default. |
| `privacy-mode` | No | Zero-retention static/proxy build profile. |
| `tls` | No | Internal marker for TLS-aware code; select a concrete backend for serving. |

## TLS Backends

Select at most one:

| Feature | Status |
| --- | --- |
| `tls-rustls` | Default and recommended. |
| `tls-rustls-fips` | Optional rustls/AWS-LC FIPS-capable candidate. |
| `tls-rustls-iso19790` | ISO/IEC 19790 terminology alias for `tls-rustls-fips`. |
| `tls-openssl` | Optional OpenSSL backend. |

Cargo features are additive, and Fluxheim supports exactly one TLS backend per
build. The feature validator catches conflicting TLS backend selections before
build. BoringSSL and s2n-tls are no longer supported Fluxheim backends because
their integrations did not provide the same complete policy, SNI, upstream TLS,
and client-auth coverage as rustls and OpenSSL.
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

Fluxheim `1.3.7` adds managed php-fpm process supervision as a runtime config
mode inside this same `php-fpm` feature, not as a separate Cargo feature. It
still uses the FastCGI bridge; only php-fpm process lifecycle changes from
operator-managed to Fluxheim-supervised.

Fluxheim no longer reserves a pure-Rust PHP/phprs runtime for `1.3.8`. Managed
php-fpm is the supported zero-admin PHP direction.

## Profile Aliases

Cargo does not have a separate `--group` flag. Fluxheim provides normal Cargo
feature aliases for common deployment shapes.

| Profile | Expands to | Use case |
| --- | --- | --- |
| `profile-core` | `proxy`, `web`, `cache`, `tls-rustls`, `security` | Same intent as default. |
| `profile-static-site` | `proxy`, `web`, `tls-rustls`, `security` | Static sites without Fluxheim cache. |
| `profile-reverse-proxy` | `proxy`, `tls-rustls`, `security` | Reverse proxy without static hosting/cache. |
| `profile-cache-server` | `proxy`, `web`, `cache`, `tls-rustls`, `security` | Static/proxy server with cache enabled. |
| `profile-load-balancer` | `proxy`, `web`, `cache`, `compression-gzip`, `compression-zstd`, `compression-brotli`, `load-balancer`, `tls-rustls`, `security` | Edge server with Fluxheim load balancing and all compression codecs compiled in. |
| `profile-observability` | `profile-core`, `metrics`, `metrics-otlp`, `otel-tracing`, `otel-otlp` | Core server with Prometheus metrics, optional local OTLP metrics export, trace context propagation, and optional local OTLP trace export. |
| `profile-privacy` | `proxy`, `web`, `tls-rustls`, `privacy-mode`, `security` | Zero-retention static/proxy profile. |
| `profile-full` | `profile-load-balancer`, `geoip`, `stream-proxy`, `traffic-mirror` | All stable production modules, including GeoIP, traffic mirroring, and the current stream/load-balancer runtime lines. |
| `profile-development` | `profile-full`, `php-fpm`, `acme-client`, `metrics`, `metrics-otlp`, `otel-tracing`, `otel-otlp` | Broad development build with all compatible production modules. |
| `profile-web-server` | `proxy`, `web`, `compression-gzip`, `compression-zstd`, `compression-brotli`, `tls-rustls`, `security` | Static webserver profile while serving still uses the shared proxy runtime. |
| `profile-cache-edge` | `proxy`, `cache`, `compression-gzip`, `compression-zstd`, `compression-brotli`, `tls-rustls`, `security` | Cache edge without local static web serving. |
| `profile-proxy-edge` | `proxy`, `compression-gzip`, `compression-zstd`, `compression-brotli`, `tls-rustls`, `security` | Focused reverse proxy edge. |
| `profile-load-balancer-edge` | `proxy`, `load-balancer`, `compression-gzip`, `compression-zstd`, `compression-brotli`, `tls-rustls`, `security` | Load-balancer edge without cache or static web serving. |
| `profile-fips-openssl` | `proxy`, `security`, `tls-openssl-fips` | FIPS-capable OpenSSL proxy build that links to the operator-selected OpenSSL provider. |
| `profile-iso19790-openssl` | `profile-fips-openssl`, `tls-openssl-iso19790` | ISO/IEC 19790 terminology alias for the same OpenSSL validated-provider proof path. |
| `profile-fips-rustls` | `proxy`, `security`, `tls-rustls-fips` | FIPS-capable rustls/AWS-LC candidate build. |
| `profile-iso19790-rustls` | `profile-fips-rustls`, `tls-rustls-iso19790` | ISO/IEC 19790 terminology alias for the same rustls/AWS-LC candidate path. |

Starting in `1.6.34`, normal Fluxheim profiles no longer compile Pingora
crates. The internal `pingora-compat` feature name remains as a historical
compatibility boundary only; official release profiles use Fluxheim-owned
runtime, listener, TLS, HTTP, cache, load-balancer, admin, metrics, stream, and
background-service paths.

Examples that match the official release artifacts:

```bash
cargo build --no-default-features --features profile-full,acme-client,metrics,metrics-otlp,otel-tracing,otel-otlp
cargo build --no-default-features --features profile-development
cargo build --no-default-features --features profile-cache-edge,acme-client
cargo build --no-default-features --features profile-proxy-edge,acme-client
cargo build --no-default-features --features profile-load-balancer-edge,acme-client
cargo build --no-default-features --features profile-web-server,php-fpm,acme-client
cargo build --no-default-features --features profile-privacy
cargo build --no-default-features --features profile-fips-openssl
cargo build --no-default-features --features profile-iso19790-openssl
cargo build --no-default-features --features profile-fips-rustls
cargo build --no-default-features --features profile-iso19790-rustls
```

The raw profile aliases do not force `acme-client`; that is intentional for
offline or static-certificate custom builds. Official RPMs, images, and release
tarballs add `acme-client` to the full, cache, proxy, load-balancer, and PHP
profiles by default.

## FIPS-Capable TLS Features

`tls-openssl-fips` is an opt-in OpenSSL 3 FIPS-provider proof path. It expands
to `tls-openssl` and adds OpenSSL provider diagnostics plus default FIPS
property enforcement for configurations that set `[tls.fips] required = true`
or `[tls.iso19790] required = true`. `tls-openssl-iso19790` and
`profile-iso19790-openssl` are terminology aliases for European/international
operator evidence; they use the same validated-provider enforcement path. The
build still depends on the operator installing and configuring a validated
OpenSSL FIPS/ISO provider according to that module's Security Policy.

`tls-rustls-fips` is the rustls/AWS-LC FIPS-capable candidate path. It enables
rustls' `fips` feature, uses `rustls::crypto::default_fips_provider()`, and
checks rustls provider/server-config FIPS indicators when FIPS or ISO-required
mode is active. Building this path pulls in `aws-lc-fips-sys` and requires
CMake, Go, and a C compiler. `tls-rustls-iso19790` and
`profile-iso19790-rustls` are terminology aliases for European/international
operator evidence; they use the same rustls/AWS-LC FIPS candidate logic.

```bash
cargo build --no-default-features --features profile-fips-openssl
cargo build --no-default-features --features profile-iso19790-openssl
cargo build --no-default-features --features profile-fips-rustls
cargo build --no-default-features --features profile-iso19790-rustls
```

Those profile aliases are deliberately narrow proof builds. FIPS/ISO-capable
TLS is not limited to those aliases: custom builds can combine
`tls-openssl-fips` or `tls-rustls-fips` with cache, static web serving, reverse
proxying, or PHP-FPM. Do not add a FIPS-capable TLS backend to an existing
profile alias that already enables `tls-rustls`, because Cargo features are
additive and Fluxheim supports only one TLS backend per binary. Select
the raw modules instead:

```bash
# FIPS/ISO-capable cache edge
cargo build --no-default-features \
  --features proxy,cache,security,tls-openssl-fips

# FIPS/ISO-capable PHP-FPM web build
cargo build --no-default-features \
  --features php-fpm,security,tls-openssl-fips
```

Use `tls-rustls-fips` instead of `tls-openssl-fips` in the raw feature examples
when you want the rustls/AWS-LC candidate path.

These combinations make Fluxheim's TLS boundary FIPS/ISO-capable when the
operator provides the selected backend's validated provider evidence. They do
not automatically make the whole deployment FIPS compliant: PHP application
cryptography, ACME account operations, local cache encryption, OTLP export, and
other non-TLS crypto paths must be separately routed through validated modules,
externally evidenced, or disabled for a strict FIPS-required deployment.

For the cleanest regulated boundary, prefer local/static certificates that were
issued and renewed outside Fluxheim through an approved process. You can compile
`acme-client` into a FIPS-capable TLS build for non-required configs, but
`[tls.fips] required = true` and `[tls.iso19790] required = true` now reject
managed ACME at config validation time. Use externally issued static
certificates, or keep ACME outside the strict FIPS/ISO-required Fluxheim
boundary until ACME account key generation, JWS account signing, EAB, outbound
ACME HTTPS transport, and challenge certificate generation are rerouted or
separately evidenced.

Use `fluxheim crypto` or `fluxheim-config-tester --crypto` to see whether the
binary can load or report the selected FIPS-capable provider in the current
environment. The
`fips-openssl` and `iso19790-openssl` config-tester profiles validate that a
fixture uses `backend = "openssl"` and either `[tls.fips] required = true` or
`[tls.iso19790] required = true`; see `examples/fips-openssl.toml` and
`examples/iso19790-openssl.toml`. The `fips-rustls` and `iso19790-rustls`
profiles validate the same guard with `backend = "rustls"`; see
`examples/fips-rustls.toml`, `examples/iso19790-rustls.toml`, and
`scripts/validate-fips-rustls.sh`. See
[FIPS-Capable Deployments](fips.md) before using this for regulated systems.

Focused image profile status:

- TLS and ACME are shared ingress capabilities, not implicit static webserver
  capabilities.
- The `cache` and `proxy` focused profiles compile without local static web
  serving.
- Compatibility aliases may keep the older broad behavior, but published
  focused images are `full`, `cache`, `proxy`, `php`, and, starting with the
  `1.5` line, `load-balancer`.

## Incompatible Combinations

| Combination | Reason |
| --- | --- |
| Multiple `tls-*` backends | Fluxheim selects one TLS backend per binary. |
| `privacy-mode` + `cache` | Zero-retention builds must not compile request/response cache code. |
| `privacy-mode` + `metrics` | Zero-retention builds must not compile request metrics. |
| `privacy-mode` + `metrics-otlp` | Zero-retention builds must not compile metrics export. |
| `privacy-mode` + `otel-tracing` | Zero-retention builds must not compile trace context propagation. |
| `privacy-mode` + `otel-otlp` | Zero-retention builds must not compile trace export. |
| `privacy-mode` + `wasm` | Zero-retention builds must not compile sandboxed policy extensions. |
| `privacy-mode` + `wasm-proxy-abi` | Zero-retention builds must not compile sandboxed policy extensions. |
| `privacy-mode` + `wasm-wasi` | Zero-retention builds must not compile sandboxed policy extensions. |

Because `cache` is part of the default build, privacy builds must use
`--no-default-features`.

## Planned Future Features

These are documented architecture tracks, not enabled Cargo features yet:

| Future feature family | Document |
| --- | --- |
| Image filter | [Image Filter](image-filter.md) |
| Programmable media edge | [Programmable Media Edge](programmable-media-edge.md) |
| OpenTelemetry OTLP export | [OpenTelemetry Tracing](opentelemetry-tracing.md) |
| Crypto RPC edge | [Crypto RPC Edge](crypto-rpc-edge.md) |
| WAF | [WAF Architecture](waf-architecture.md) |
| Cloudflare origin support | [Cloudflare Origin Support](cloudflare-origin-support.md) |
| External authorization request | [External Authorization Request](auth-request.md) |
| Secure links | [Secure Links](secure-links.md) |
| PHP runtimes | [PHP Runtime Support](php-runtime-support.md) |
| Perl CGI | [Perl CGI Support](perl-cgi-support.md) |
| Legacy static HTTP listeners | [Legacy Static HTTP Support](legacy-static-http.md) |
| WireGuard smart load balancing | [Sentinel Mesh](sentinel-mesh.md) |
