<p align="center">
  <b>Rust edge gateway for websites, applications, caching, and load balancing.</b><br>
  Modular by design. Secure by default. Ready for rootless containers and regulated estates.
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

Fluxheim is a modular Rust edge gateway for static sites, reverse proxying,
edge caching, PHP-FPM application serving, ACME automation, observability,
FIPS/ISO-capable TLS build paths, GeoIP policy, TCP stream proxying, and
enterprise HTTP/TCP load balancing. Normal Fluxheim builds now use
Fluxheim-owned Rust runtime boundaries for server/listener/TLS, HTTP/1,
HTTP/2, WebSocket, cache, load-balancer, admin, metrics, stream, and
background-service paths. The active `1.7.x` line adds a shared WebAssembly
policy runtime for typed, sandboxed operator extensions before the later
HTTP/3/QUIC line. The operator-facing product is Fluxheim: focused release
profiles are available for full, cache, proxy, load-balancer, and PHP
deployments, with matching container images and Linux runtime archives.

The load-balancer line targets F5 LTM, HAProxy, nginx, and Envoy-style HTTP/TCP
pool operations: weighted and adaptive selection, health and circuit state,
slow start, retry budgets, bounded queueing, local persistence, runtime
member-state controls, runtime backend-set mutation, status/metrics/audit
visibility, and a validated enterprise migration fixture. It is not a complete
BIG-IP platform clone: managed affinity cookies remain local to one process,
while cross-instance state sync, production UDP/GSLB, WAF, VPN/firewall
appliance behavior, and syntax-compatible iRules/Lua scripting are documented
future tracks rather than hidden or implied behavior. The `1.7.x` Wasm line is
capability parity through typed host calls, not syntax compatibility with F5
iRules, nginx Lua/OpenResty, HAProxy Lua/SPOE, or VCL. Runtime weight overrides
are local, in-memory controls for round-robin and least-* selectors in the
current load-balancer implementation.

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
| Origin protection | ✅ | `1.5.23`; opt-in vhost/route origin-fill budgets for protected cache fill paths, with cache-key/cache-lookup release-gate assertions. |
| Cache operations | ✅ | Hit/miss headers, cache locks, stale serving, cache warming, protected purge/status endpoints, and key/lookup diagnostics. |

### Proxy, TLS, And Edge Policy

| Capability | Status | Notes |
| --- | --- | --- |
| Reverse proxy | ✅ | Whole-vhost and route-level proxying. |
| Compression | ✅ | Optional gzip, Zstandard, and Brotli with vhost/route controls. |
| Load balancing | ✅ | Weighted round-robin, least/weighted/ratio least connections, least-sessions, least-time EWMA, priority groups, locality preference with fallback, per-upstream tags and in-flight caps, bounded queue/overflow policy, local source-IP/header/request-cookie persistence, signed/opaque managed affinity cookies, runtime persistence clear, weighted power-of-two, hash, consistent-hash, bounded-load consistent-hash, static-pool Maglev hash, nginx-compatible Ketama static-ring hash, backup, drain, disabled/forced-down members, runtime drain/disable/force-down/enable/manual-resume, runtime weight overrides for round-robin and least-* selectors, slow start, retry budgets/statuses, configurable all-down status, and a validated enterprise fixture in `examples/load-balancer-enterprise.toml`. |
| DNS-refreshed upstream pools | ✅ | `1.4.1`; `upstream_dns_refresh_secs` for load-balancer service-name pools. |
| File-refreshed upstream pools | ✅ | `1.4.1`; `upstreams_file` for load-balancer builds with bounded refresh and safe file handling. |
| HTTP control-plane upstream discovery | ✅ | `1.5.11`; `upstreams_http_url` for bounded pull-based JSON discovery with optional bearer-token authentication. See `examples/load-balancer-http-discovery.toml`. |
| Passive health | ✅ | Failure, selected 5xx, and latency-based ejection with circuit-open status visibility. |
| Active health checks | ✅ | TCP/TLS, HTTP, standard gRPC, Redis `PING`, MySQL/MariaDB handshake, PostgreSQL SSLRequest, exact JSON scalar body validation, `X-Health-Weight` degraded weight signals, and opt-in bounded local exec checks. Agent checks and additional database protocol probes remain future load-balancer health-check work. |
| Load-balancer status | ✅ | Admin status includes configured pools, discovery mode/refresh health, selection/health/retry policy metadata, ready/available summary counts, runtime override counts/timestamps, backend readiness, disabled/drained state, in-flight counts, persistence-entry skew, passive failure/ejection and circuit state, slow-start, and least-time latency state; discovery refreshes also emit bounded success/failure events. |
| Load-balancer boundaries | Limited | Local persistence and runtime overrides can be restart-persisted with `proxy.load_balance.runtime_state_file`; managed affinity cookie signing keys remain process-local; Fluxheim does not yet apply runtime weights to hash/ring selectors, share managed-cookie keys, or sync state across active-active nodes. |
| Rate limits | ✅ | Local vhost/route token buckets, delay mode, bounded tables, and optional indeterminate-IP rejection. |
| Concurrency limits | ✅ | Vhost/route in-flight limits with bounded wait queues. |
| IP ACLs | ✅ | Trusted-proxy-aware allow/deny rules. |
| mTLS/client certificates | ✅ | Listener client-auth, fingerprint ACLs, and safe upstream identity forwarding templates. |
| TLS backends | ✅ | rustls default/recommended, plus OpenSSL for operators who need OpenSSL integration or OpenSSL FIPS provider deployments. |
| FIPS/ISO-capable builds | ✅ | OpenSSL FIPS provider path and rustls/AWS-LC FIPS-capable candidate path. |
| ACME | ✅ | Managed HTTP-01 and rustls TLS-ALPN-01 issuance/renewal, plus external HTTP-01 forwarding helper. |
| PROXY protocol | ✅ | v1/v2 receive and upstream send. |
| HTTP/2 origins | ✅ | Upstream HTTP version controls and bounded HTTP/2 settings. |
| gRPC pass-through | ✅ | Route-scoped HTTP/2 gRPC policy; no transcoding. |
| WebSocket / HTTP upgrade | ✅ | `1.4.1`; explicit `proxy.websocket = true` on HTTP/1.1 upstream routes. |
| External auth subrequests | ✅ | `1.4.1`; `[proxy.auth_request]` with bounded header/body forwarding. |
| Traffic mirroring | ✅ | `1.4.1`; `traffic-mirror` feature with safe bodyless shadow requests. |
| TCP stream proxying | ✅ | Optional `stream-proxy` feature with Fluxheim-owned L4 TCP listener/data-path and upstream TLS connector boundaries, source IP/CIDR allow/deny policy, hostname-upstream DNS-rebinding guards, weighted upstream selection, drain/backup policy, bounded idle/lifetime/byte/connect controls, route-local PROXY protocol receive/send, and stream upstream TLS/mTLS controls. |
| UDP/GSLB beta boundary | Limited | `1.5.16`; separate `[udp]` config namespace and `udp-proxy` feature gate with beta DNS-style request/response forwarding, bounded response waits, oversized-response drops, drop-log rate limiting, and syslog one-way forwarding. Public DNS reflector hardening, QUIC pass-through, game proxying, production UDP support, and generic UDP/GSLB platform behavior are not included yet. |

### Operations And Packaging

| Capability | Status | Notes |
| --- | --- | --- |
| Admin API | ✅ | Bearer-token auth, loopback defaults, brute-force throttling, authenticated health by default, snapshots, rollback, cache operations. |
| Read-only ops socket | ✅ | `1.4.1`; Unix-domain local status/cache/health endpoint with owner/group-only permissions; snapshot listing requires bearer auth. |
| Prometheus metrics | ✅ | Native metrics profile and bounded labels for edge/cache/LB/PHP events. |
| OpenTelemetry | ✅ | OTLP metrics and tracing export profiles. |
| Structured access logs | ✅ | Trusted client IP, cache phase, route, selected upstream/alias/retries, TLS identity, compression, and optional Geo-Context fields. |
| Config tester | ✅ | Release-page config diagnostics through `fluxheim-config-tester`. |
| Rootless containers | ✅ | Wolfi, Alpine, SUSE Micro, Debian, focused full/cache/proxy/load-balancer/PHP images. |
| Native services | ✅ | systemd units and RPM packaging files. |
| Default page | ✅ | Packaged `/srv/fluxheim/index.html` with no external assets. |

### Planned Or Not Yet

| Capability | Status | Target |
| --- | --- | --- |
| Proxy module split | ✅ | `1.4.2`; access logs, compression, auth subrequests, traffic mirroring, edge policy, route policy, cache API DTOs, request-side cache policy, path safety, upstream TLS loading, PROXY protocol framing, and PHP-FPM process/spool/FastCGI handling are split into focused modules, with a new rule that future feature domains start outside the proxy orchestration file. |
| Config module split | ✅ | `1.4.3`; config loading, shared helpers, domain validation, and large config tests are split into focused `config_*` modules while keeping `crate::config::*` stable. |
| Load-balancer module split | ✅ | `1.5.0`; health checks, backend state, persistence, selection algorithms, backend policy/status, and file/DNS discovery are split into focused `load_balancer/*` modules while keeping `crate::load_balancer::*` stable. |
| Apple Silicon macOS dev builds | ✅ | `1.4.4`; Level 1 developer support with Mac-safe runtime paths while some upstream macOS support remains experimental. |
| GeoIP/Geo-Context policy | ✅ | `1.4.5`; optional `geoip` feature with local MMDB support for MaxMind GeoIP2/GeoLite2 and CIRCL Geo Open datasets, plus vhost/route country and ASN ACLs. |
| Pingora-free runtime | ✅ | `1.6.34`; normal Fluxheim builds no longer compile Pingora crates. Server/listener/TLS, HTTP/1, HTTP/2, WebSocket, cache, load-balancer, admin, metrics, stream, and background-service paths run through Fluxheim-owned Rust crates. |
| HTTP/3/QUIC | ❌ | Planned as a Fluxheim-owned `1.9` protocol milestone using the Rust `quinn`/`h3` stack after the `1.8` macOS/Windows production parity line. |
| WASM extensibility | 🧪 | Active `1.7.x` line. `1.7.0` added the optional `wasm` feature, strict plugin-file loading, bounded Wasmtime execution, and real-Wasm smoke coverage. `1.7.1` adds config-level plugin registry validation, deterministic attachment ordering, admission limits, metrics, and live native HTTP/1 access-decision hooks. `1.7.2` adds bounded native HTTP/1 request/response header hooks. `1.7.3` starts bounded native HTTP/1 route-decision hooks with configured canary and mirror branch selection, including selected native load-balanced and persistent routes. `1.7.4` starts VCL-like cache-policy hooks with bounded cache-lookup and cache-store decisions for continue/pass/bypass/skip-store/deny around cache lookup and storage. Direct backend choice, plugin-provided persistence keys, dynamic mirror/shadow target choice, and richer cache-key/TTL/tag store policy hooks remain staged for later `1.7.x`. |

See [Production Readiness](docs/production-readiness.md) for the precise
stable-core promise and deployment checks. See
[macOS Development Support](docs/macos-development.md) for the Level 1
Apple Silicon developer workflow.

## Why Fluxheim

- **Rust first**: memory-safe implementation with a pinned stable toolchain.
- **Production edge core**: Fluxheim owns the config, security, operations,
  load-balancer, cache, PHP-FPM, stream, observability, and HTTP runtime model
  through project-owned Rust crates.
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
| `proxy` | Yes | Fluxheim-owned native reverse-proxy runtime for HTTP/1, HTTP/2 origins, WebSocket upgrades, cache integration, load-balancer routing, and edge policy. |
| `web` | Yes | Static file resolver and static response handling used by the native server path. |
| `cache` | Yes | Cache module compiled in; runtime cache remains disabled until configured. |
| `load-balancer` | No | Fluxheim load-balancing module, health checks, and runtime pool policy. |
| `stream-proxy` | No | Raw L4 TCP stream proxy service with separate stream semantics, Fluxheim-owned listener loop and async IO boundary, upstream TLS/mTLS controls, true idle timeouts, weighted/drain/backup policy, and expanded smoke coverage. |
| `metrics` | No | Prometheus metrics listener. |
| `acme` | No | ACME planning/renewal support. Requires TLS config and should be paired with one TLS backend for serving. |
| `acme-client` | No | Live ACME account/order HTTP client and background renewal service for HTTP-01 and rustls TLS-ALPN-01 certificate issuance and renewal. |
| `php-fpm` | No | PHP-FPM FastCGI bridge for WordPress-style PHP applications. Implies `proxy` and `web`; not included in default/focused images. |
| `privacy-mode` | No | Zero-retention static/proxy build profile. |
| `security` | Yes | Compile-time security profile marker plus release hardening checks. Runtime enforcement lives in the concrete config, TLS, filesystem, admin, and request-handling modules. |
| `wasm` | No | Optional `1.7.x` WebAssembly policy runtime. `1.7.4` supports live native HTTP/1 access-decision hooks, bounded request/response header hooks, constrained route-decision hooks with configured canary and mirror branch selection, selected native load-balanced/persistent routes, bounded cache-lookup hooks, and bounded cache-store skip/deny hooks. Later `1.7.x` releases add direct backend choice, plugin-provided persistence keys, dynamic mirror/shadow target choice, and richer cache-key/TTL/tag store policy hooks. |
| `wasm-proxy-abi` | No | Reserved compatibility preview for a reviewed safe subset of proxy-oriented Wasm ABI calls; depends on `wasm` and remains off by default. |
| `wasm-wasi` | No | Reserved WASI capability preview; depends on `wasm` and remains off by default with no filesystem/network/process capabilities unless explicitly granted in a later release. |
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
| `profile-load-balancer` | `proxy`, `web`, `cache`, `compression-gzip`, `compression-zstd`, `compression-brotli`, `load-balancer`, `tls-rustls`, `security` | Edge server with Fluxheim load balancing and all compression codecs compiled in. |
| `profile-observability` | `profile-core`, `metrics`, `metrics-otlp`, `otel-tracing`, `otel-otlp` | Core server with Prometheus metrics, optional local OTLP metrics export, trace context propagation, and optional local OTLP trace export. |
| `profile-privacy` | `proxy`, `web`, `tls-rustls`, `privacy-mode`, `security` | Zero-retention static/proxy profile. |
| `profile-full` | `profile-load-balancer`, `geoip`, `stream-proxy`, `traffic-mirror` | All stable production modules, including GeoIP, traffic mirroring, stream, and load-balancer runtime lines. |
| `profile-development` | `profile-full`, `php-fpm`, `acme-client`, `metrics`, `metrics-otlp`, `otel-tracing`, `otel-otlp` | Broad development build with all compatible production modules. |
| `profile-web-server` | `proxy`, `web`, `compression-gzip`, `compression-zstd`, `compression-brotli`, `tls-rustls`, `security` | Static webserver profile using Fluxheim's native server path. |
| `profile-cache-edge` | `proxy`, `cache`, `compression-gzip`, `compression-zstd`, `compression-brotli`, `tls-rustls`, `security` | Cache edge without local static web serving. |
| `profile-proxy-edge` | `proxy`, `compression-gzip`, `compression-zstd`, `compression-brotli`, `tls-rustls`, `security` | Focused reverse proxy edge. |
| `profile-load-balancer-edge` | `proxy`, `load-balancer`, `compression-gzip`, `compression-zstd`, `compression-brotli`, `tls-rustls`, `security` | Load-balancer edge without cache or static web serving. |
| `profile-fips-rustls` | `proxy`, `security`, `tls-rustls-fips` | rustls/AWS-LC FIPS-capable candidate build. |
| `profile-iso19790-rustls` | `profile-fips-rustls` | ISO/IEC 19790 terminology alias for the same rustls/AWS-LC candidate path. |

Starting in `1.6.34`, normal Fluxheim profiles no longer compile Pingora
crates. The internal `pingora-compat` feature name remains only as a
source-quarantine cfg for legacy adapter code while the dead source is removed;
it is not part of any supported release profile.

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
cargo build --no-default-features --features profile-load-balancer-edge,acme-client
cargo build --no-default-features --features profile-web-server,php-fpm,acme-client
```

Official container images are published to GitHub Container Registry and Quay:

- `ghcr.io/valkyoth/fluxheim`
- `quay.io/valkyoth/fluxheim`

Release tags use the same profile/OS suffixes on both registries. The first
`1.7.x` image tags include `v1.7.0-wolfi`, `v1.7.0-cache-wolfi`,
`v1.7.0-proxy-wolfi`, `v1.7.0-load-balancer-wolfi`, and `v1.7.0-php-wolfi`;
follow-up `1.7.x` releases use the same suffix pattern, for example
`v1.7.4-wolfi`, `v1.7.4-cache-wolfi`, `v1.7.4-proxy-wolfi`,
`v1.7.4-load-balancer-wolfi`, and `v1.7.4-php-wolfi`.

Release note for `1.5.15`: the signed git tag `v1.5.15` is the canonical code
tag. The GitHub Release page is published under `v1.5.15-release` because the
original immutable GitHub Release object for `v1.5.15` was accidentally
deleted; GitHub reserves immutable release tag names and does not allow the
original release page to be restored through the normal release UI/API.

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
supervision as an opt-in runtime mode. The Wolfi PHP image is self-contained
for managed PHP-FPM and includes the Wolfi `php-8.5-fpm` runtime; non-Wolfi PHP
image variants keep the external php-fpm container config unless customized.
Pure-Rust PHP/phprs support is not planned; managed php-fpm is the supported
zero-admin PHP path.

TLS backends are mutually exclusive. Select exactly one backend when TLS is
needed:

| TLS feature | Status |
| --- | --- |
| `tls-rustls` | Default and recommended. |
| `tls-openssl` | Optional OpenSSL backend. |
| `tls-rustls-fips` / `tls-rustls-iso19790` | rustls/AWS-LC FIPS-capable candidate backend. |
| `tls-openssl-fips` / `tls-openssl-iso19790` | OpenSSL FIPS provider backend. |

Selecting more than one TLS backend is a compile error.
Use `scripts/validate-features.sh` in packaging or custom CI jobs when accepting
user-provided feature strings; Cargo features are additive, and Fluxheim
supports one TLS backend per build.

Future optional modules such as `waf`, `cloudflare`, PHP, CGI, and legacy
static HTTP are documented in the architecture docs but are not enabled in the
default build.

Because `cache` is part of the default build, privacy builds must use
`--no-default-features` through `profile-privacy` or an explicit manual feature
set. Combining `privacy-mode` with `cache` or `metrics` fails at compile time.
A future `privacy-cache` line is planned for explicitly public assets only,
with no client-IP cache keys, no per-user variants, no `Cookie`/`Authorization`
admission, and strict shared-cache safety rules; normal cache remains outside
the current privacy build promise.

Small manual builds:

```bash
cargo build --no-default-features --features proxy
cargo build --no-default-features --features proxy,web,tls-rustls
cargo build --no-default-features --features proxy,web,tls-rustls,privacy-mode
cargo build --no-default-features --features proxy,web,tls-rustls,wasm
```

Validate a custom feature set before building:

```bash
scripts/validate-features.sh proxy,web,tls-rustls,load-balancer
```

</details>

## Current Release: 1.7 Wasm Extensibility

Fluxheim does not treat every planned idea as stable. The current release line
is `1.7.x`, the shared Wasm extensibility line. It follows the `1.6.x`
Pingora-exit line, where normal Fluxheim builds stopped compiling Pingora
crates and moved request handling onto Fluxheim-owned Rust runtime boundaries.

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
- `1.4.x` completed the production proxy parity and platform-hardening line:
  edge ACLs, rate/concurrency limits, gzip/zstd/brotli compression,
  regex/template rewrites, method routing, WebSocket upgrades, auth
  subrequests, traffic mirroring, read-only ops socket, passive and active
  health checks, retry budgets, PROXY protocol v1/v2, upstream TLS controls,
  mTLS/client certificate policy, HTTP/2 origin controls, gRPC pass-through,
  Apple Silicon Level 1 development support, bounded GeoIP/Geo-Context policy,
  TCP stream proxying with idle timeouts and stream upstream TLS/mTLS controls,
  and the proxy/config/module splits that keep future feature domains in
  focused files.
- `1.5.x` is the enterprise load-balancer/control-plane line. It promotes the
  load-balancer image profile and focuses on F5/HAProxy/Envoy-class pool
  operations: runtime pool/member mutation, priority groups, persistence,
  slow-start, richer active/adaptive health checks, circuit breaking, queue and
  overflow behavior, locality/failure-domain policy, richer selection
  algorithms, admin/audit visibility, migration fixtures, bounded UDP/GSLB
  beta exploration, and the workspace/shared-crate foundation that prepares the
  config, load-balancer, cache, web, PHP-FPM, and future extension crates. It
  is not a production WAF, full GSLB/DNS appliance, generic UDP proxy, or
  iRules-compatible scripting release. See
  [Load Balancer Migration Notes](docs/load-balancer-migration.md) for HAProxy,
  nginx, and F5 pool mappings.
- `1.6.x` is the Pingora-exit line. It starts with baseline evidence,
  modularity gates, runtime-fact/policy-proof planning, and crate-boundary
  guardrails, then removes Pingora from normal Fluxheim builds in staged
  releases while preserving current operator-facing behavior.
- `1.7.x` is the shared Wasm extensibility line. It starts with strict plugin
  file loading, bounded Wasmtime execution, config-level plugin registry
  validation, deterministic attachment ordering, process/plugin/attachment
  admission ceilings, Wasm-aware reload classification, metrics, live native
  HTTP/1 access-decision hooks, and bounded request/response header hooks.
  Later `1.7.x` releases add routing/load-balancer decisions,
  mirror/persistence decisions, VCL-like cache policy hooks, optional
  proxy-ABI/WASI previews, and runnable examples for F5 iRules-style policy,
  nginx Lua/OpenResty-style header policy, HAProxy Lua/SPOE-style
  routing/load-balancer policy, and VCL-like cache policy.

Detailed cache behavior, config examples, operational limits, and smoke-test
coverage are documented in [Cache Backends](docs/cache-backends.md),
[Cache Encryption](docs/cache-encryption.md),
[Config Reference](docs/config-reference.md), and
[Production Readiness](docs/production-readiness.md).

The `1.8` line is the macOS/Windows production-parity line, and HTTP/3/QUIC
moves to the following Fluxheim-owned `1.9` protocol line based on the Rust
`quinn`/`h3` stack. See [Versioning Plan](docs/versioning-plan.md) and
[Roadmap](ROADMAP.md) for the full release ladder.

## Documentation

- [Roadmap](ROADMAP.md)
- [Changelog](CHANGELOG.md)
- [Versioning Plan](docs/versioning-plan.md)
- [Modularity Policy](docs/modularity-policy.md)
- [Runtime Baseline](docs/runtime-baseline.md)
- [Runtime Parity Fixtures](docs/runtime-parity-fixtures.md)
- [Extraction Dependency Graph](docs/extraction-dependency-graph.md)
- [Runtime Facts And Policy Proofs](docs/runtime-facts-and-policy-proofs.md)
- [Release Runbook](docs/release-runbook.md)
- [Release Checklist](docs/release-checklist.md)
- [Build, Containers, And Rootless Podman](docs/build-and-podman.md)
- [Production Readiness](docs/production-readiness.md)
- [Feature Matrix](docs/features.md)
- [OWASP Top 10 2025 Baseline](docs/owasp-top10-2025-baseline.md)
- [FIPS-Capable Deployments](docs/fips.md)
- [Config Reference](docs/config-reference.md)
- [Load Balancer Migration Notes](docs/load-balancer-migration.md)
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
- [Wasm Policy Example Parity](docs/wasm-policy-example-parity.md)
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

For focused live testing, `scripts/test_starter.py` provides a human-facing
menu over the maintained smoke scripts. It can run categories such as
load-balancer, cache, WordPress, database health checks, privacy mode, Wasm,
observability, containers, and RPM builds without memorizing every script name.
The observability smoke starts disposable Prometheus and Jaeger containers by
default unless `FLUXHEIM_PROMETHEUS_URL` or `FLUXHEIM_JAEGER_URL` point at
already-running services:

```bash
scripts/test_starter.py --list
scripts/test_starter.py --category load-balancer
scripts/test_starter.py --run privacy
scripts/test_starter.py --run wasm
```

See [SECURITY.md](SECURITY.md) for vulnerability reporting and
[Rust Supply-Chain Security](docs/supply-chain-security.md) for dependency
review policy.

## License

Fluxheim is distributed under the
[European Union Public Licence v1.2](LICENSE).
