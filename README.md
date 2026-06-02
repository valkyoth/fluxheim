<p align="center">
  <b>Memory-safe edge server, reverse proxy and caching server built on Pingora.</b><br>
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
[Pingora](https://github.com/cloudflare/pingora). The current stable release is
`1.4.7`: static sites, vhosts, route-level proxying, redirects, rustls SNI,
managed ACME issuance and renewal, secure headers, container/native systemd
operation, production proxy-cache controls, Prometheus/OpenTelemetry operations
support, focused full/cache-edge/proxy-edge/PHP image profiles, opt-in PHP-FPM
application serving for WordPress-style deployments, managed php-fpm process
supervision, the `fluxheim-acme` companion, release-page config tester
diagnostics, OpenSSL and rustls/AWS-LC FIPS/ISO-capable build paths, and the
first production proxy-parity set: edge ACLs, rate/concurrency limits,
compression, advanced upstream selection, passive health, retry budgets,
PROXY protocol, upstream TLS controls, mTLS/client certificate policy, HTTP/2
origin controls, gRPC pass-through policy, proxy-operations migration blockers,
the `1.4.2` proxy module split, the `1.4.3` config module split, Apple Silicon
macOS Level 1 developer support, bounded GeoIP/Geo-Context policy with local
MMDB support for MaxMind GeoIP2/GeoLite2 and CIRCL Geo Open datasets, and the
TCP stream proxy foundation hardened with true idle timeouts, stream upstream
TLS/mTLS controls, weighted/drain/backup stream upstream policy, PROXY protocol
coverage, and bounded stream write/connect behavior.

Fluxheim is licensed under the European Union Public Licence 1.2.

## What Works Today

### Serving And Routing

| Capability | Status | Notes |
| --- | --- | --- |
| Static websites | ✅ | MIME detection, index files, `GET`/`HEAD`, `ETag`, conditional `304`, and single byte ranges. |
| Vhosts | ✅ | Host-header routing, default-vhost fallback, wildcard hosts, and opt-in strict host routing. |
| Route actions | ✅ | Static, proxy, redirect, and route-level policy blocks. |
| Regex path routing | ✅ | `1.4.1`; requires explicit global `server.regex_enabled = true`. |
| Regex capture variables | ✅ | `1.4.1`; bounded `{route.regex.1}` and `{route.regex.name}` variables for request headers and path-only rewrites. |
| Regex path rewrite templates | ✅ | `1.4.1`; `rewrite_template` maps regex routes to safe upstream paths without nginx-style rewrite loops or `if`. |
| Method-based routing | ✅ | `1.4.1`; optional route `methods = ["GET", "HEAD"]` filters. |
| HTTPS redirects | ✅ | Optional global HTTP-to-HTTPS redirects with safe Host validation. |
| Secure headers | ✅ | Request/response header policy, `Server: fluxheim` by default, removable by config. |
| PHP-FPM applications | ✅ | External php-fpm for existing pools. |
| Managed PHP-FPM | ✅ | Fluxheim-supervised php-fpm pools for zero-admin WordPress-style deployments. |

### Cache

| Capability | Status | Notes |
| --- | --- | --- |
| Proxy cache | ✅ | Vhost and route-scoped cache policies. |
| Memory cache | ✅ | Bounded in-memory cache tier. |
| Disk cache | ✅ | Filesystem and storage-bin disk backends. |
| Tiered cache | ✅ | Memory plus disk storage plans. |
| Encrypted disk cache | ✅ | Optional local-key and OpenBao transit encryption paths. |
| Static-file cache | ✅ | Optional local static-file caching. |
| Range and slice cache | ✅ | Bounded range caching and fixed-slice composition for large objects. |
| Peer fill | ✅ | Optional peer-assisted cache fill for cache-edge deployments. |
| Cache operations | ✅ | Hit/miss headers, cache locks, stale serving, cache warming, protected purge/status endpoints, and key/lookup diagnostics. |

### Proxy, TLS, And Edge Policy

| Capability | Status | Notes |
| --- | --- | --- |
| Reverse proxy | ✅ | Whole-vhost and route-level proxying. |
| Compression | ✅ | Optional gzip, Zstandard, and Brotli with vhost/route controls. |
| Load balancing | ✅ | Weighted round-robin, least/weighted/ratio least connections, least-sessions, least-time EWMA, priority groups, per-upstream in-flight caps, source-IP/header/request-cookie persistence with runtime clear, power-of-two, hash, consistent-hash, backup, drain, disabled/forced-down members, runtime drain/disable/force-down/enable/manual-resume, slow start, retry budgets/statuses, configurable all-down status, and a validated enterprise fixture in `examples/load-balancer-enterprise.toml`. |
| DNS-refreshed upstream pools | ✅ | `1.4.1`; `upstream_dns_refresh_secs` for load-balancer service-name pools. |
| File-refreshed upstream pools | ✅ | `1.4.1`; `upstreams_file` for load-balancer builds with bounded refresh and safe file handling. |
| Passive health | ✅ | Failure, selected 5xx, and latency-based ejection with circuit-open status visibility. |
| Active health checks | ✅ | TCP/TLS and HTTP health checks. |
| Load-balancer status | ✅ | Admin status includes configured pools, selection/health/retry policy metadata, ready/available summary counts, runtime override counts/timestamps, backend readiness, disabled/drained state, in-flight counts, persistence-entry skew, passive failure/ejection and circuit state, slow-start, and least-time latency state. |
| Rate limits | ✅ | Local vhost/route token buckets, delay mode, bounded tables, and optional indeterminate-IP rejection. |
| Concurrency limits | ✅ | Vhost/route in-flight limits with bounded wait queues. |
| IP ACLs | ✅ | Trusted-proxy-aware allow/deny rules. |
| mTLS/client certificates | ✅ | Listener client-auth, fingerprint ACLs, and safe upstream identity forwarding templates. |
| TLS backends | ✅ | rustls default, plus OpenSSL/BoringSSL/s2n build paths where supported. |
| FIPS/ISO-capable builds | ✅ | OpenSSL FIPS provider path and rustls/AWS-LC FIPS-capable candidate path. |
| ACME | ✅ | Managed HTTP-01 and rustls TLS-ALPN-01 issuance/renewal, plus external HTTP-01 forwarding helper. |
| PROXY protocol | ✅ | v1/v2 receive and upstream send. |
| HTTP/2 origins | ✅ | Upstream HTTP version controls and bounded HTTP/2 settings. |
| gRPC pass-through | ✅ | Route-scoped HTTP/2 gRPC policy; no transcoding. |
| WebSocket / HTTP upgrade | ✅ | `1.4.1`; explicit `proxy.websocket = true` on HTTP/1.1 upstream routes. |
| External auth subrequests | ✅ | `1.4.1`; `[proxy.auth_request]` with bounded header/body forwarding. |
| Traffic mirroring | ✅ | `1.4.1`; `traffic-mirror` feature with safe bodyless shadow requests. |
| TCP stream proxying | ✅ | `1.4.6+`; optional `stream-proxy` feature with raw L4 TCP listeners, weighted upstream selection, drain/backup policy, bounded idle/lifetime/byte/connect controls, route-local PROXY protocol receive/send, and stream upstream TLS/mTLS controls. |

### Operations And Packaging

| Capability | Status | Notes |
| --- | --- | --- |
| Admin API | ✅ | Bearer-token auth, loopback defaults, brute-force throttling, authenticated health by default, snapshots, rollback, cache operations. |
| Read-only ops socket | ✅ | `1.4.1`; Unix-domain local status/cache/snapshot/health endpoint with owner/group-only permissions. |
| Prometheus metrics | ✅ | Native metrics profile and bounded labels for edge/cache/LB/PHP events. |
| OpenTelemetry | ✅ | OTLP metrics and tracing export profiles. |
| Structured access logs | ✅ | Trusted client IP, cache phase, route, selected upstream/alias/retries, TLS identity, compression, and optional Geo-Context fields. |
| Config tester | ✅ | Release-page config diagnostics through `fluxheim-config-tester`. |
| Rootless containers | ✅ | Wolfi, Alpine, SUSE Micro, Debian, focused full/cache/proxy/PHP images. |
| Native services | ✅ | systemd units and RPM packaging files. |
| Default page | ✅ | Packaged `/srv/fluxheim/index.html` with no external assets. |

### Planned Or Not Yet

| Capability | Status | Target |
| --- | --- | --- |
| Proxy module split | ✅ | `1.4.2`; access logs, compression, auth subrequests, traffic mirroring, edge policy, route policy, cache API DTOs, request-side cache policy, path safety, upstream TLS loading, PROXY protocol framing, and PHP-FPM process/spool/FastCGI handling are split into focused modules, with a new rule that future feature domains start outside the proxy orchestration file. |
| Config module split | ✅ | `1.4.3`; config loading, shared helpers, domain validation, and large config tests are split into focused `config_*` modules while keeping `crate::config::*` stable. |
| Apple Silicon macOS dev builds | ✅ | `1.4.4`; Level 1 developer support with Mac-safe runtime paths while Pingora macOS support remains experimental. |
| GeoIP/Geo-Context policy | ✅ | `1.4.5`; optional `geoip` feature with local MMDB support for MaxMind GeoIP2/GeoLite2 and CIRCL Geo Open datasets, plus vhost/route country and ASN ACLs. |
| HTTP/3/QUIC | ❌ | Deferred until Pingora support and a bounded design are ready. |
| WASM policy hooks | ❌ | Planned for the later `1.6` extensibility line. |

See [Production Readiness](docs/production-readiness.md) for the precise
stable-core promise and deployment checks. See
[macOS Development Support](docs/macos-development.md) for the Level 1
Apple Silicon developer workflow.

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
| `stream-proxy` | No | Raw L4 TCP stream proxy service with separate stream semantics. Depends on the shared proxy runtime in `1.4.6`; hardened in `1.4.7` with true idle timeouts, stream upstream TLS/mTLS controls, weighted/drain/backup policy, and expanded smoke coverage. |
| `metrics` | No | Prometheus metrics listener. |
| `acme` | No | ACME planning/renewal support. Requires TLS config and should be paired with one TLS backend for serving. |
| `acme-client` | No | Live ACME account/order HTTP client and background renewal service for HTTP-01 and rustls TLS-ALPN-01 certificate issuance and renewal. |
| `php-fpm` | No | PHP-FPM FastCGI bridge for WordPress-style PHP applications. Implies `proxy` and `web`; not included in default/focused images. |
| `privacy-mode` | No | Zero-retention static/proxy build profile. |
| `security` | Yes | Compile-time security profile marker plus release hardening checks. Runtime enforcement lives in the concrete config, TLS, filesystem, admin, and request-handling modules. |
| `tls` | No | Internal TLS marker used by TLS/ACME code; select a concrete backend for serving. |
| `tls-rustls-fips` | No | rustls/AWS-LC FIPS-capable TLS backend candidate for source builds. |

For checked TLS policy examples, see
[`examples/tls-modern.toml`](examples/tls-modern.toml) and
[`examples/tls-intermediate.toml`](examples/tls-intermediate.toml).
For managed certificate issuance, see
[`examples/acme-http-01.toml`](examples/acme-http-01.toml). For an issuer that
requires External Account Binding, see
[`examples/acme-actalis.toml`](examples/acme-actalis.toml).
Packaged builds include `acme-init` for guided issuer bootstrap:

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
| `profile-load-balancer` | `proxy`, `web`, `cache`, `compression-gzip`, `compression-zstd`, `compression-brotli`, `load-balancer`, `tls-rustls`, `security` | Edge server with Pingora load balancing and all 1.4 compression codecs compiled in. |
| `profile-observability` | `profile-core`, `metrics`, `metrics-otlp`, `otel-tracing`, `otel-otlp` | Core server with Prometheus metrics, optional local OTLP metrics export, trace context propagation, and optional local OTLP trace export. |
| `profile-privacy` | `proxy`, `web`, `tls-rustls`, `privacy-mode`, `security` | Zero-retention static/proxy profile. |
| `profile-full` | `profile-load-balancer`, `geoip`, `stream-proxy`, `traffic-mirror` | All stable production modules, including GeoIP, traffic mirroring, and the 1.4 stream foundation. |
| `profile-development` | `profile-full`, `php-fpm`, `acme-client`, `metrics`, `metrics-otlp`, `otel-tracing`, `otel-otlp` | Broad development build with all compatible production modules. |
| `profile-web-server` | `proxy`, `web`, `compression-gzip`, `compression-zstd`, `compression-brotli`, `tls-rustls`, `security` | Static webserver profile while serving still uses the shared proxy runtime. |
| `profile-cache-edge` | `proxy`, `cache`, `compression-gzip`, `compression-zstd`, `compression-brotli`, `tls-rustls`, `security` | Cache edge without local static web serving. |
| `profile-proxy-edge` | `proxy`, `compression-gzip`, `compression-zstd`, `compression-brotli`, `tls-rustls`, `security` | Focused reverse proxy edge. |
| `profile-load-balancer-edge` | `proxy`, `load-balancer`, `compression-gzip`, `compression-zstd`, `compression-brotli`, `tls-rustls`, `security` | Load-balancer edge without cache or static web serving. |
| `profile-fips-rustls` | `proxy`, `security`, `tls-rustls-fips` | rustls/AWS-LC FIPS-capable candidate build. |
| `profile-iso19790-rustls` | `profile-fips-rustls` | ISO/IEC 19790 terminology alias for the same rustls/AWS-LC candidate path. |

Fluxheim 1.3 started the focused image split. The `profile-cache-edge` and
`profile-proxy-edge` aliases are TLS-capable without compiling local static web
serving. Official RPMs, container images, and release tarballs add
`acme-client` to the full, cache, and proxy profiles by default because
managed certificates are the normal production path. Custom source builds can
still omit `acme-client` for fully offline or static-certificate deployments.
`profile-cache-server` and `profile-load-balancer` remain compatibility aliases
for operators who want the older convenience bundles.

FIPS/ISO-capable OpenSSL testing is available with `tls-openssl-fips`, plus the
`tls-openssl-iso19790` terminology alias for ISO/IEC 19790-oriented evidence.
Both require `backend = "openssl"` and an operator-installed OpenSSL 3
validated provider path. Use the `profile-fips-openssl` or
`profile-iso19790-openssl` alias for local validation, run `fluxheim crypto` to
inspect provider availability and OpenSSL default FIPS property status, and read
[FIPS / ISO-Capable Deployments](docs/fips.md) before treating a deployment as
regulated evidence.

The `1.3.5` release line added a rustls/AWS-LC candidate path with
`tls-rustls-fips`, the ISO/IEC terminology alias `tls-rustls-iso19790`,
`profile-fips-rustls`, and `profile-iso19790-rustls`. It builds
`aws-lc-fips-sys`, so local validation requires CMake, Go, and a C compiler,
plus the AWS-LC module certificate/Security Policy evidence for any regulated
deployment.

Example grouped builds that match the official release artifacts:

```bash
cargo build --no-default-features --features profile-full,acme-client,metrics,metrics-otlp,otel-tracing,otel-otlp
cargo build --no-default-features --features profile-development
cargo build --no-default-features --features profile-cache-edge,acme-client
cargo build --no-default-features --features profile-proxy-edge,acme-client
cargo build --no-default-features --features profile-web-server,php-fpm,acme-client
```

Official container images are published to GitHub Container Registry and Quay:

- `ghcr.io/valkyoth/fluxheim`
- `quay.io/valkyoth/fluxheim`

Release tags use the same profile/OS suffixes on both registries, for example
`v1.4.0-wolfi`, `v1.4.0-cache-wolfi`, `v1.4.0-proxy-wolfi`, and
`v1.4.0-php-wolfi`.

Manual feature selection also works:

```bash
cargo build --no-default-features --features proxy,web,tls-rustls,load-balancer
```

PHP support starts in `1.3.1` with an explicit `php-fpm` module. A PHP build
can serve normal static assets from the same root while routing missing paths
and explicit `.php` scripts to php-fpm. See
[`docs/php-runtime-support.md`](docs/php-runtime-support.md),
[`docs/php-fpm-app-recipes.md`](docs/php-fpm-app-recipes.md), and
[`examples/php-fpm.toml`](examples/php-fpm.toml).
Fluxheim `1.3.7` completed the production PHP-FPM line with managed php-fpm
supervision as an opt-in runtime mode. The current Wolfi `v1.4.0-php` image is
self-contained for managed PHP-FPM and includes the Wolfi `php-8.5-fpm`
runtime; non-Wolfi PHP image variants keep the external php-fpm container
config unless customized. Pure-Rust PHP/phprs support is not planned; managed
php-fpm is the supported zero-admin PHP path.

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

## Current Release: 1.5 Load Balancer

Fluxheim does not treat every planned idea as stable. The current release line
is `1.5.x`, starting with the `1.5.0` enterprise load-balancer/control-plane
release.

- `1.0` is the gateway foundation: vhosts, routes, redirects, static serving,
  proxying, SNI/TLS, safe ACME challenge exceptions, systemd/RPM packaging, and
  rootless container operation.
- `1.1` is the certificate operations line: TLS policy profiles, multi-cert
  rustls SNI, managed ACME issuance/renewal, EAB-capable issuers, file-backed
  secrets, `acme-init`, and packaged renewal units.
- `1.2.x` completed the production cache and observability line: vhost/route
  cache policy, memory/disk/tiered cache, local static-file caching,
  storage-bin disk cache, optional disk-cache encryption, peer fill, bounded
  range caching, fixed-slice range composition, cache operations tooling,
  Prometheus metrics, and OpenTelemetry export profiles.
- `1.3.x` completed the split-profile and application-serving line: shared
  ingress/TLS feature profiles, focused full/cache/proxy/PHP images, the
  `fluxheim-acme` companion, release-page `fluxheim-config-tester`, production
  PHP-FPM support with WordPress-compatible front-controller behavior and
  Fluxheim-managed php-fpm supervision, OpenSSL and rustls/AWS-LC FIPS/ISO
  build paths, internal-crypto compliance guards, and the repeatable compliance
  evidence package template.
- `1.4.0` is the production proxy parity baseline: edge ACLs, rate and
  concurrency limits, gzip/zstd/brotli compression, response and URI rewrites,
  advanced load balancing, passive health, retry budgets, active HTTP health
  checks, bounded metrics, upstream connection/socket tuning, mTLS/client cert
  policy, PROXY protocol v1/v2, upstream TLS controls, HTTP/2 origin controls,
  and gRPC pass-through policy.
- `1.4.1` completes the remaining proxy-operations work: dynamic upstream
  discovery, file-watched upstream lists, richer structured logs,
  regex/template rewrite policy, route method matching, explicit WebSocket
  upgrade proxying, bounded auth subrequests, safe bodyless traffic mirroring,
  and a read-only Unix ops socket.
- `1.4.2` is the maintenance architecture release that splits the large proxy
  runtime into focused modules before adding more large proxy features. Access
  logs, compression, auth subrequests, traffic mirroring, edge policy, and
  route policy are extracted domains. Outbound PROXY protocol framing lives in
  `proxy_protocol`. PHP-FPM process supervision, request-body spooling, FastCGI
  transport, retry/timeout handling, and response parsing now live in
  `php_fpm`; the remaining PHP code in `proxy.rs` is the Pingora
  request/session integration layer. The first `proxy_cache` slice holds
  request-side cache policy, response admission, `Vary` helpers, and bounded
  range/slice request, key, admission, freshness, status-header, and stale
  policy; cache admin/API request and result DTOs live in `cache_api`;
  remaining target extractions are stateful cache runtime/storage, slice object
  assembly, and the proxy core.
- `1.4.3` is the config maintenance architecture release. It splits config
  source loading, shared parsers, domain validation, and the large config test
  module into focused `config_*` files while preserving the existing
  `crate::config::*` type paths and operator-facing configuration behavior.
- `1.4.4` is the Apple Silicon macOS Level 1 developer-support release. It
  adds Mac-safe development paths, an Apple Silicon CI/smoke gate, developer
  artifact naming for `aarch64-macos`, and Linux ARM64 release artifact naming
  for `aarch64-linux`. Linux remains the production support baseline.
- `1.4.5` is the bounded GeoIP/Geo-Context release. It adds the optional
  `geoip` feature for local MMDB MaxMind GeoIP2/GeoLite2 and CIRCL Geo Open
  datasets, vhost/route country and ASN access-policy rules, structured access
  log Geo-Context fields, bounded database loading, and documented SDK roadmap
  boundaries for a future `fluxheim-sdk` crate.
- `1.4.6` added the TCP stream proxy foundation with route-local stream
  trust boundaries, bounded copy controls, PROXY protocol support, and
  separate stream semantics.
- `1.4.7` hardened TCP stream proxying with true per-read idle timeouts,
  stream upstream TLS/mTLS controls, weighted/drain/backup upstream policy, and
  expanded stream smoke/security coverage.
- `1.5.0` is the enterprise load-balancer/control-plane line. It promotes the
  load-balancer image profile and focuses on F5/HAProxy/Envoy-class pool
  operations: runtime pool/member mutation, priority groups, persistence,
  slow-start, richer active/adaptive health checks, circuit breaking, queue and
  overflow behavior, locality/failure-domain policy, richer selection
  algorithms, admin/audit visibility, and migration fixtures. It is not a WAF,
  GSLB/DNS appliance, UDP proxy, or iRules-compatible scripting release.

Detailed cache behavior, config examples, operational limits, and smoke-test
coverage are documented in [Cache Backends](docs/cache-backends.md),
[Cache Encryption](docs/cache-encryption.md),
[Config Reference](docs/config-reference.md), and
[Production Readiness](docs/production-readiness.md).

Next lines are planned separately after `1.5`: `1.6` for shared Wasm
extensibility covering nginx-Lua-style hooks and VCL-like cache policy hooks. See
[Versioning Plan](docs/versioning-plan.md) and [Roadmap](ROADMAP.md) for the
full release ladder.

## Documentation

- [Roadmap](ROADMAP.md)
- [Changelog](CHANGELOG.md)
- [Versioning Plan](docs/versioning-plan.md)
- [Release Runbook](docs/release-runbook.md)
- [Release Checklist](docs/release-checklist.md)
- [Build, Containers, And Rootless Podman](docs/build-and-podman.md)
- [Production Readiness](docs/production-readiness.md)
- [Feature Matrix](docs/features.md)
- [OWASP Top 10 2025 Baseline](docs/owasp-top10-2025-baseline.md)
- [FIPS-Capable Deployments](docs/fips.md)
- [Config Reference](docs/config-reference.md)
- [Gateway Recipes](docs/gateway-recipes.md)
- [GitHub Repository Setup](docs/github-setup.md)
- [Cache Backends](docs/cache-backends.md)
- [Cache Encryption](docs/cache-encryption.md)
- [Image Filter](docs/image-filter.md)
- [Programmable Media Edge](docs/programmable-media-edge.md)
- [Certificate Renewal And Reload](docs/certificate-renewal.md)
- [Config Snapshots And Rollback](docs/config-snapshots.md)
- [Logging Architecture](docs/logging-architecture.md)
- [Metrics Architecture](docs/metrics-architecture.md)
- [OpenTelemetry Tracing](docs/opentelemetry-tracing.md)
- [WASM Extensibility](docs/wasm-extensibility.md)
- [Crypto RPC Edge](docs/crypto-rpc-edge.md)
- [External Authorization Request](docs/auth-request.md)
- [Zero-Retention Privacy Mode](docs/zero-retention-privacy-mode.md)
- [WAF Architecture](docs/waf-architecture.md)
- [Rust Supply-Chain Security](docs/supply-chain-security.md)
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
- SBOM and reproducible-build evidence for stable releases;
- `scripts/validate-owasp-top10-2025.sh` for a mapped OWASP Top 10 2025
  baseline over Fluxheim-owned controls;
- rootless Podman smoke tests before container releases.

Before publishing or merging security-sensitive changes:

```bash
scripts/release_checks.sh
```

See [SECURITY.md](SECURITY.md) for vulnerability reporting and
[Rust Supply-Chain Security](docs/supply-chain-security.md) for dependency
review policy.

## License

Fluxheim is distributed under the
[European Union Public Licence v1.2](LICENSE).
