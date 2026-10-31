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

The shell validator is an early policy check, not Cargo's resolver. It expands
aliases only once and currently misses some conflicting nested TLS selections
and the privacy/GeoIP conflict. The real
locked build remains mandatory. See [installation/package selection](../guides/installation.md)
for the difference between these aliases and published artifacts.

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
| `traffic-mirror` | No | Bounded HTTP request mirroring; see [projection and runtime limitations](../guides/traffic-mirroring.md). |
| `php-fpm` | No | Static/PHP FastCGI routing and Unix managed pools or external TCP workers; does not install a PHP interpreter. |
| `metrics` | No | Prometheus metrics listener. |
| `metrics-otlp` | No | Optional OTLP/HTTP JSON metrics export to a local Prometheus OTLP receiver or collector. |
| `otel-tracing` | No | W3C `traceparent` propagation and access-log trace ID correlation. |
| `otel-otlp` | No | Optional OTLP/HTTP JSON trace export to a local collector or Jaeger endpoint. |
| `acme` | No | ACME config, renewal planning, managed certificate/account paths, local HTTP-01 serving and challenge primitives. Native TLS-ALPN-01 serving is incomplete; see [current ACME limits](../guides/acme.md). |
| `acme-client` | No | Live ACME account/order HTTP client and background renewal service. |
| `compression` | No | Shared response compression config and body-filter integration. |
| `compression-brotli` | No | Brotli response compression for eligible known-length responses. |
| `compression-gzip` | No | gzip response compression for eligible known-length responses. |
| `compression-zstd` | No | Zstandard response compression for eligible known-length responses. |
| `geoip` | No | Local MMDB country/ASN lookup for MaxMind GeoIP2/GeoLite2 and CIRCL Geo Open datasets, used by bounded access policy. Current structured events do not export GeoIP fields. See the [GeoIP guide](../guides/geoip.md). |
| `stream-proxy` | No | Raw L4 TCP with route-local source policy, DNS guards, copy-phase lifetime/idle/byte caps, PROXY framing, upstream TLS/mTLS and weighted/drain/backup selection. See [TCP streams](../guides/tcp-streams.md) for restart requirements and current identity/deadline limitations. |
| `udp-proxy` | No | Explicit beta only, excluded from release profiles: per-datagram request/response or one-way forwarding. Not DNS/GSLB, QUIC or game-session support. See [UDP limits and known defects](../guides/udp.md). |
| `wasm` | No | WebAssembly sandbox foundation with strict plugin-file loading, config-level plugin registry validation, typed loader manifests, authenticated registry status visibility, bounded Wasmtime execution, live access-decision hooks, bounded native HTTP/1 request/response header hooks, route-decision hooks, cache-lookup/cache-store hooks, compiled-module identities, and bounded host-call namespaces. |
| `wasm-proxy-abi` | No | Opt-in Wasm proxy-ABI compatibility preview. Depends on `wasm`, requires `[wasm].allow_preview_abi = true`, and rejects unsupported preview calls deterministically. |
| `wasm-wasi` | No | Opt-in WASI Preview 1 capability boundary for access-decision plugins. Depends on `wasm`; clocks and randomness require independent explicit grants, while environment, arguments, inherited stdio, filesystem, sockets/network, and process state remain unavailable. |
| `privacy-mode` | No | Reduced-retention static/proxy profile; [exact privacy boundaries](../guides/zero-retention-privacy-mode.md). |
| `tls` | No | Internal marker for TLS-aware code; select a concrete backend for serving. |

## TLS Backends

Select at most one:

| Feature | Status |
| --- | --- |
| `tls-rustls` | Default and recommended. |
| `tls-rustls-fips` | Optional rustls/AWS-LC FIPS-capable candidate. |
| `tls-rustls-iso19790` | ISO/IEC 19790 terminology alias for `tls-rustls-fips`. |
| `tls-openssl` | Optional OpenSSL backend. |

Cargo features are additive. TLS serving needs one concrete backend; HTTP-only
custom builds can omit TLS. Rust build guards reject conflicting backends even
where the preliminary shell validator misses them. BoringSSL and s2n-tls are no longer supported Fluxheim backends because
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
to load or create issuer accounts and run orders through `instant-acme`, plus
the runtime background renewal service. HTTP-01 has native challenge serving;
the TLS-ALPN-01 client path is not sufficient because the native listener lacks
challenge-store integration. Keep
`acme-client` enabled only in builds that perform certificate issuance or
renewal.

## PHP Runtime Modules

`php-fpm` enables the FastCGI bridge for PHP applications. It implies
`proxy` and `web`, uses `fastcgi-client`, and must be selected explicitly:

```bash
cargo build --no-default-features --features profile-web-server,php-fpm,acme-client
```

Managed php-fpm process supervision is a runtime config
mode inside this same `php-fpm` feature, not as a separate Cargo feature. It
still uses the FastCGI bridge; only php-fpm process lifecycle changes from
operator-managed to Fluxheim-supervised. Managed supervision is Unix-only;
Windows builds support external TCP FastCGI and reject `mode = "managed"`.

PHP is a separately installed runtime, not an embedded interpreter. See
[PHP deployment and routing](../guides/php.md), including the open native
method, directory-CGI, offload and FastCGI-cache gaps. See also
[transport and operations](../guides/php-runtime-support.md) for body suppression,
spool memory, deadline, diagnostic and managed-extension limitations, and the
[complete field reference](php-options.md) for accepted options/defaults.

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
| `profile-privacy` | `proxy`, `web`, `tls-rustls`, `privacy-mode`, `security` | Static/proxy profile with access/forwarding suppression; not whole-deployment zero retention. |
| `profile-full` | `profile-load-balancer`, `geoip`, `stream-proxy`, `traffic-mirror` | Broad edge server; excludes PHP, Wasm, ACME client and observability exporter features unless added separately. |
| `profile-wasm` | `profile-full`, `wasm-proxy-abi`, `wasm-wasi` | Explicit Wasm distribution profile; `profile-full` remains Wasm-free. |
| `profile-development` | `profile-full`, `php-fpm`, `acme-client`, `metrics`, `metrics-otlp`, `otel-tracing`, `otel-otlp` | Broad PHP/cache/observability development build; excludes Wasm and beta UDP. |
| `profile-web-server` | `proxy`, `web`, `compression-gzip`, `compression-zstd`, `compression-brotli`, `tls-rustls`, `security` | Static webserver profile while serving still uses the shared proxy runtime. |
| `profile-cache-edge` | `proxy`, `cache`, `compression-gzip`, `compression-zstd`, `compression-brotli`, `tls-rustls`, `security` | Cache edge without local static web serving. |
| `profile-proxy-edge` | `proxy`, `compression-gzip`, `compression-zstd`, `compression-brotli`, `tls-rustls`, `security` | Focused reverse proxy edge. |
| `profile-load-balancer-edge` | `proxy`, `load-balancer`, `compression-gzip`, `compression-zstd`, `compression-brotli`, `tls-rustls`, `security` | Load-balancer edge without cache or static web serving. |
| `profile-fips-openssl` | `proxy`, `security`, `tls-openssl-fips` | FIPS-capable OpenSSL proxy build that links to the operator-selected OpenSSL provider. |
| `profile-iso19790-openssl` | `profile-fips-openssl`, `tls-openssl-iso19790` | ISO/IEC 19790 terminology alias for the same OpenSSL validated-provider proof path. |
| `profile-fips-rustls` | `proxy`, `security`, `tls-rustls-fips` | FIPS-capable rustls/AWS-LC candidate build. |
| `profile-iso19790-rustls` | `profile-fips-rustls`, `tls-rustls-iso19790` | ISO/IEC 19790 terminology alias for the same rustls/AWS-LC candidate path. |

Normal Fluxheim profiles do not compile Pingora crates. The internal
`pingora-compat` feature name remains as a historical
compatibility boundary only; official release profiles use Fluxheim-owned
runtime, listener, TLS, HTTP, cache, load-balancer, admin, metrics, stream, and
background-service paths.

The first two examples match the published full/Wasm feature strings; the
focused cache/proxy/load-balancer/PHP lines match those server packages.
Development, privacy and FIPS lines are custom builds, not additional official
archive profiles. Use `--locked` with each command for the reviewed lockfile.

```bash
cargo build --no-default-features --features profile-full,acme-client,metrics,metrics-otlp,otel-tracing,otel-otlp
cargo build --no-default-features --features profile-wasm,acme-client,metrics,metrics-otlp,otel-tracing,otel-otlp
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
profiles by default. The dedicated Wasm artifact adds the same production
modules to `profile-wasm`; Wasm remains absent from `profile-full`.

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
[FIPS-Capable Deployments](../guides/fips.md) before using this for regulated systems.

Focused image profile status:

- TLS and ACME are shared ingress capabilities, not implicit static webserver
  capabilities.
- The `cache` and `proxy` focused profiles compile without local static web
  serving.
- Compatibility aliases may keep the older broad behavior, but published
  focused images are `full`, `wasm`, `cache`, `proxy`, `php`, and
  `load-balancer`. The unsuffixed
  `full` image remains Wasm-free.

## Incompatible Combinations

| Combination | Reason |
| --- | --- |
| Multiple `tls-*` backends | Fluxheim selects one TLS backend per binary. |
| `privacy-mode` + `cache` | Zero-retention builds must not compile request/response cache code. |
| `privacy-mode` + `metrics` | Zero-retention builds must not compile request metrics. |
| `privacy-mode` + `metrics-otlp` | Zero-retention builds must not compile metrics export. |
| `privacy-mode` + `otel-tracing` | Zero-retention builds must not compile trace context propagation. |
| `privacy-mode` + `otel-otlp` | Zero-retention builds must not compile trace export. |
| `privacy-mode` + `geoip` | Rust compilation rejects GeoIP lookup in privacy mode; the shell validator currently misses this. |
| `privacy-mode` + compression or any compression codec | Zero-retention builds must not transform response bodies. |
| `privacy-mode` + `wasm` | Zero-retention builds must not compile sandboxed policy extensions. |
| `privacy-mode` + `wasm-proxy-abi` | Zero-retention builds must not compile sandboxed policy extensions. |
| `privacy-mode` + `wasm-wasi` | Zero-retention builds must not compile sandboxed policy extensions. |

Because `cache` is part of the default build, privacy builds must use
`--no-default-features`.

## Planned Future Features

These are documented architecture tracks, not enabled Cargo features yet:

| Future feature family | Document |
| --- | --- |
| Image filter | [Image Filter](../ideas/image-filter.md) |
| Programmable media edge | [Programmable Media Edge](../ideas/programmable-media-edge.md) |
| Crypto RPC edge | [Crypto RPC Edge](../ideas/crypto-rpc-edge.md) |
| WAF | [WAF Architecture](../ideas/waf-architecture.md) |
| Cloudflare origin module | [Unimplemented module proposal](../ideas/cloudflare-origin-support.md) |
| Secure links | [Secure Links](../ideas/secure-links.md) |
| Perl CGI | [Perl CGI Support](../ideas/perl-cgi-support.md) |
| Legacy static HTTP listeners | [Legacy Static HTTP Support](../ideas/legacy-static-http.md) |
| WireGuard smart load balancing | [Sentinel Mesh](../ideas/sentinel-mesh.md) |

OTLP export, external authorization subrequests and PHP-FPM are implemented
feature families, not future-only items. Their guides document current limits:
[OTLP](../guides/opentelemetry-tracing.md),
[authorization](../guides/external-authorization.md), and
[PHP](../guides/php-runtime-support.md). Embedding other interpreters is not
implied by PHP-FPM support.
