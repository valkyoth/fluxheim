<p align="center">
  <b>Rust edge gateway for websites, applications, caching, and load balancing.</b><br>
  Modular builds. Rootless containers. Explicit security and operational controls.
</p>

<div align="center">
  <a href="https://fluxheim.eu">Home Page</a>
  ·
  <a href="docs/README.md">Documentation</a>
  ·
  <a href="docs/reference/config-reference.md">Config Reference</a>
  ·
  <a href="docs/reference/supported-headers.md">Header Reference</a>
  ·
  <a href="SECURITY.md">Security</a>
</div>

<br>

<p align="center">
  <img src="./.github/images/fluxheim.webp" alt="Fluxheim overview">
</p>

# Fluxheim

Fluxheim is a modular Rust webserver and edge gateway. Serve static websites
and PHP applications, reverse-proxy services, cache responses, balance traffic,
automate certificates, and inspect your deployment through logs, metrics and
traces.

[Download a release](https://github.com/valkyoth/fluxheim/releases/latest) ·
[Read the guides](docs/README.md) · [Browse configurations](examples)

## Features

These tables describe this source checkout. For a deployed release, use its
tagged documentation and [release notes](release-notes).
A check means implemented, not enabled in every binary or container.
Choose the appropriate [build features](docs/reference/features.md) or
[packaged profile](docs/guides/portable-releases.md); runtime configuration
still controls what is enabled.
Read each guide's limitations before relying on a feature. The
[coverage ledger](docs/reference/documentation-coverage.md) tracks outstanding
corrections and qualification; a table entry is not release approval.

### Server And Routing

| Feature | Supported | Documentation |
| --- | --- | --- |
| Static files, MIME types, index pages and GET/HEAD | ✅ | [Static serving and publication limits](docs/guides/static-files.md) |
| Static conditional requests, single byte ranges and directory listings | Limited | [Current semantics and directory URL gaps](docs/guides/static-files.md#validators-and-byte-ranges) |
| Virtual hosts, wildcard hosts, default site and strict host matching | ✅ | [Vhosts](docs/guides/vhost-config.md) |
| Static, proxy and redirect routes; method filters | ✅ | [HTTP routing](docs/guides/routing.md) |
| Opt-in regex routes, capture variables and path rewrites | ✅ | [Rewrites and current capture limits](docs/guides/routing.md#use-a-bounded-regex-rewrite) |
| HTTP-to-HTTPS redirects | ✅ | [Listeners and redirects](docs/reference/config-reference.md#server) |
| Reverse proxy with HTTP/1.1 and HTTP/2 origins | ✅ | [Connections, deadlines and gateway pages](docs/guides/reverse-proxy.md) |
| HTTP/1.1 WebSocket upgrades | Limited | [Configuration and open authorization/handshake limits](docs/guides/websocket.md) |
| gRPC route filtering and H2 transport primitives | Limited | [Trailer and streaming gaps; not general gRPC pass-through](docs/guides/grpc.md) |
| gzip, Zstandard and Brotli response compression | Limited | [Configuration, negotiation gaps and CPU limits](docs/guides/compression.md) |
| Request header forwarding and mutation | Limited | [Request headers and identity limitations](docs/guides/request-headers.md) |
| Response headers, browser policy and redirect/cookie rewriting | Limited | [Response headers and current limits](docs/guides/response-headers.md) |
| CORS origin allowlists and local preflights | Limited | [CORS and current inheritance/wildcard limits](docs/guides/cors.md) |
| External authorization subrequests | Limited | [Authorization and current security limits](docs/guides/external-authorization.md) |
| Opt-in traffic mirroring | Limited | [Sampling and current projection limits](docs/guides/traffic-mirroring.md) |
| PROXY protocol receive/send | Limited | [HTTP support and HTTPS trust-policy blocker](docs/guides/proxy-protocol.md) |
| TCP stream proxying, upstream TLS and connection limits | Limited | [TCP streams and current boundaries](docs/guides/tcp-streams.md) |
| DNS-style UDP forwarding and one-way syslog forwarding | Beta | [UDP setup, limits and restrictions](docs/guides/udp.md) |

### Access And TLS

| Feature | Supported | Documentation |
| --- | --- | --- |
| Trusted-proxy-aware IP allow/deny rules | Limited | [Access policy and mapped-CIDR limitation](docs/guides/access-control.md) |
| GeoIP country and ASN allow/deny rules | ✅ | [GeoIP](docs/guides/geoip.md) |
| Rate limits, delay mode and concurrency limits | Limited | [Admission, queues and current lifetime/table limits](docs/guides/rate-and-concurrency-limits.md) |
| rustls or OpenSSL TLS backends | ✅ | [HTTPS and TLS](docs/guides/tls.md) |
| Client certificates, fingerprint rules and upstream mTLS | ✅ | [Fingerprint authorization](docs/guides/access-control.md#require-and-pin-a-client-certificate), [client authentication](docs/guides/tls.md#require-client-certificates-mtls) and [proxy TLS](docs/guides/upstream-tls.md) |
| FIPS-capable backend build paths | Conditional | [Required provider and deployment evidence](docs/guides/fips.md) |
| ACME issuance and renewal: HTTP-01, EAB and ARI | Limited: scheduling and recovery corrections pending | [Certificates, ACME and current limits](docs/guides/acme.md) |
| External HTTP-01 challenge forwarding | ✅ | [Challenge forwarding](docs/reference/acme-options.md#external-http-01-forwarding) |
| Privacy build profile | ✅ | [Privacy boundaries](docs/guides/zero-retention-privacy-mode.md) |

FIPS-capable builds are not a claim that Fluxheim or every deployment is
certified. GeoIP describes database-derived network information, not proof of
a person's location or identity.

### Cache

| Feature | Supported | Documentation |
| --- | --- | --- |
| Vhost and route-scoped proxy caching | ✅ | [Caching](docs/guides/cache.md) |
| Bounded memory cache | ✅ | [Memory caching](docs/guides/cache.md#choose-a-cache) |
| Disk cache, storage-bin backend and memory/disk tiers | ✅ | [Persistent caching](docs/guides/cache.md#add-persistent-storage) |
| Encrypted disk cache with local keys or OpenBao Transit | ✅ | [Cache encryption](docs/guides/cache-encryption.md) |
| Local static-file memory caching | ✅ | [Static cache](docs/guides/cache.md#local-static-files) |
| Range caching and fixed-slice composition | ✅ | [Range and slice limits](docs/guides/cache-ranges.md) |
| Peer-assisted fill (variant restrictions apply) | ✅ | [Peer fill and safety limits](docs/guides/cache-peer-fill.md) |
| Origin-fill concurrency protection | ✅ | [Origin protection](docs/guides/cache.md#protect-the-origin) |
| Cache locks, revalidation, stale serving and hit/miss diagnostics | ✅ | [Cache configuration](docs/reference/config-reference.md#cache) |
| Warming, protected purge, status and object/key inspection | ✅ | [Cache operations](docs/guides/cache-operations.md) |

### Load Balancing

| Feature | Supported | Documentation |
| --- | --- | --- |
| Weighted round-robin, least-connections, least-sessions and power-of-two | ✅ | [Load balancing](docs/guides/load-balancer.md#select-backends) |
| Hash, consistent hash, bounded-load hash, Maglev and Ketama | ✅ | [Algorithms and boundaries](docs/reference/load-balancer-options.md#selection) |
| Priority groups, locality, backup, drain and disabled members | ✅ | [Pool configuration](docs/reference/config-reference.md#proxy) |
| In-flight caps, bounded queues and slow start | ✅ | [Pool configuration](docs/guides/load-balancer.md#passive-health-slow-start-and-queueing) |
| Active TCP/TLS, HTTP, gRPC, exec and database health checks | ✅ | [Health checks](docs/guides/load-balancer.md#health-checks) |
| Passive transport/status failure ejection and circuit state | ✅ | [Health policy](docs/guides/load-balancer.md#passive-health-slow-start-and-queueing) |
| Bounded retries and shared pool retry budgets | ✅ | [Retry policy](docs/guides/load-balancer.md#retry-and-latency-boundaries) |
| Weighted least-time selection and passive header-latency thresholds | ✅ | [Latency measurement](docs/guides/load-balancer.md#what-latency-measures) |
| DNS, file and HTTP backend discovery | ✅ | [Discovery](docs/guides/load-balancer.md#discover-backends) |
| Source-IP, header, request-cookie and managed-cookie affinity | ✅ | [Persistence](docs/guides/load-balancer.md#keep-related-requests-together) |
| Runtime member controls, backend-set updates and pool status | ✅ | [Operations](docs/guides/load-balancer.md#operate-a-pool) |
| Optional local restart-persistent runtime state | ✅ | [State and restrictions](docs/guides/load-balancer.md#operate-a-pool) |

Persistence and runtime overrides are not an active-active cluster state
service. Managed-cookie signing keys remain process-local, and runtime weight
overrides do not apply to every selector.
Native HTTP retry and latency policies have explicit replay and measurement
[boundaries](docs/guides/load-balancer.md#retry-and-latency-boundaries).

### PHP And Extensions

| Feature | Supported | Documentation |
| --- | --- | --- |
| PHP/FastCGI with externally managed pools | ✅ | [PHP deployment](docs/guides/php.md) |
| Managed PHP-FPM: static, dynamic and ondemand pools | Unix only | [Managed PHP-FPM](docs/guides/php.md#let-fluxheim-start-php-fpm) |
| Front-controller routing and mixed static/PHP sites | Documented routing limits | [PHP routing](docs/guides/php.md#understand-request-routing) |
| PHP request-body replay and application recipes | Collected ingress; documented memory limits | [PHP runtime](docs/guides/php-runtime-support.md) |
| PHP container images with application extensions | ✅ | [PHP images and prerequisites](docs/guides/php-runtime-support.md) |
| Sandboxed Wasm access, headers, routing and cache policy hooks | ✅ | [Wasm](docs/guides/wasm-extensibility.md) |
| Opt-in proxy ABI and WASI compatibility surfaces | Preview | [Compatibility boundaries](docs/guides/wasm-extensibility.md) |

PHP is a separate runtime, not embedded in Fluxheim. Windows supports external
FastCGI over TCP and rejects managed PHP-FPM. Wasm is an explicit build/profile
choice; it is not syntax-compatible iRules, Lua or VCL execution.

### Operations And Visibility

| Feature | Supported | Documentation |
| --- | --- | --- |
| Structured text/JSON logging, bounded queues and typed event fields | ✅ | [Logging and disclosure boundaries](docs/guides/logging.md) |
| Native access completion and configurable access fields | Limited | [Current fields and unused options](docs/guides/logging.md#every-logging-option) |
| Protected log files and rotation | ✅ | [File lifecycle](docs/guides/logging.md) |
| Request IDs and distributed trace correlation | ✅ | [Correlation and tracing](docs/guides/opentelemetry-tracing.md) |
| Per-vhost and module trace annotations | Limited: native enrichment pending | [Current span fields](docs/guides/opentelemetry-tracing.md#current-span-fields) |
| Prometheus metrics with bounded labels | ✅ | [Metrics](docs/guides/metrics.md) |
| Metrics bearer-token authentication | Limited: Unix private-file enforcement pending | [Credential permissions and rotation](docs/guides/metrics.md#scrape-authentication-and-lifecycle) |
| OTLP metric and trace export, retry and recovery | ✅ | [OTLP export](docs/guides/otlp-export.md) |
| Grafana/Prometheus/Jaeger and SigNoz integration examples and dashboards | ✅ | [Collector integrations](docs/guides/collector-integrations.md) |
| Exporter-health dashboard panels | Limited: direct scrape required | [Signal-path limitations](docs/guides/collector-integrations.md#read-each-dashboard-panel) |
| Prometheus operational alert examples | Limited: persistent log-worker alert pending | [Rules and boundaries](docs/guides/collector-integrations.md#alert-rules-and-their-limits) |
| Authenticated admin operations and owner-only Unix operations socket | ✅ | [Admin API and roles](docs/guides/admin.md) |
| Configurable operations-socket group mode and Unix control-token leaf enforcement | Limited | [Current limitations and safe settings](docs/guides/admin.md) |
| Read-only operational status and restricted observer credentials | ✅ | [Operational status API](docs/guides/operational-status.md) |
| Verified configuration snapshots, reload and explicit rollback | ✅ | [Snapshots](docs/guides/config-snapshots.md) |
| Automatic recovery identity and overlapping validation | Limited | [Current recovery boundaries](docs/guides/config-snapshots.md#current-recovery-limitations) |
| Configuration loading, split files and validation | Limited | [Composition rules and diagnostics](docs/guides/configuration.md) |
| CLI validation and standalone configuration tester | Limited: mode and profile checks | [Commands and validation](docs/guides/command-line.md) |
| Foreground service, process settings and graceful drain | Limited | [Active settings, shutdown and current limits](docs/guides/service-lifecycle.md) |
| Inherited listeners and externally supervised blue/green deployment | ✅ | [Upgrade requirements and systemd restart distinctions](docs/guides/zero-downtime-upgrades.md) |

Audit queue admission does not guarantee durable audit storage. The admin API
has specific supported operations, not complete server management; see the
[management API boundary](docs/reference/management-api-handoff.md).
JSON escaping and typed event restrictions do not provide general secret
redaction for arbitrary legacy or dependency log messages.

### Packaging And Deployment

| Feature | Supported | Documentation |
| --- | --- | --- |
| Linux x86_64 and ARM64 portable packages | ✅ | [Portable releases](docs/guides/portable-releases.md) |
| macOS Apple Silicon portable packages | Unsigned | [macOS](docs/guides/macos-development.md) |
| Windows x86_64 native packages | Unsigned | [Windows packages](docs/guides/portable-releases.md) |
| Focused full, Wasm, cache, proxy, load-balancer, PHP and config-tester profiles | ✅ | [Package selection and compiled capabilities](docs/guides/installation.md) |
| Rootless Wolfi, Alpine, Debian and SUSE containers | ✅ | [Build and Podman](docs/guides/build-and-podman.md) |
| Container OS/PHP refreshes independent of Fluxheim releases | ✅ | [Runtime refresh](docs/guides/container-runtime-refresh.md) |
| RPM packages and hardened systemd services | ✅ | [systemd deployment](docs/guides/systemd.md) |

SUSE PHP uses BCI; other SUSE profiles use Micro. Windows ARM64 and Intel macOS
are not supported release targets. HTTP/3 is deferred; production UDP/GSLB,
a WAF and a full management UI are not implemented. Plans are tracked in the
[roadmap](docs/roadmap/observability-commit-plan.md), not implied by these tables.

## Quick Start

Build with the repository's pinned Rust toolchain, validate the example, then
start the server from the repository root. This example serves an included
static page; it needs no database, PHP pool or upstream application:

```bash
cargo build --locked
cargo run --locked -- --validate-config --config examples/configuration/single.toml
cargo run --locked -- --config examples/configuration/single.toml
```

From another terminal:

```bash
curl -H 'Host: configuration.example.test' http://127.0.0.1:8080/
```

Expected body: `configuration-single-ok`. Stop with Ctrl+C. Port 8080 must
be free; this is a loopback HTTP demonstration, not a public TLS deployment.

For your own static site, replace the host names and root in this configuration:

```toml
[server]
listen = ["127.0.0.1:8080"]
default_vhost = "site"

[[vhosts]]
name = "site"
hosts = ["example.test", "www.example.test"]

[vhosts.web]
root = "/srv/sites/example/public"
index_files = ["index.html"]
deny_dotfiles = true
cache_control = "public, max-age=60"
```

The directory must exist and be readable by the service user.
This example binds locally; public deployment also needs appropriate listeners,
network/firewall rules and TLS. See [vhost setup](docs/guides/vhost-config.md)
and [production readiness](docs/guides/production-readiness.md).

## Documentation

- [Documentation index](docs/README.md): guides, reference, architecture and evidence.
- [Configuration reference](docs/reference/config-reference.md): accepted settings.
- [Build features](docs/reference/features.md): choose modules and TLS backends.
- [Deployment guide](docs/guides/build-and-podman.md): builds and rootless containers.
- [Gateway recipes](docs/guides/gateway-recipes.md): multi-site and proxy examples.
- [Observability guide](docs/guides/observability.md): logs, metrics, traces and alerts.
- [Executable examples](examples): starting configurations and integrations.

## Development And Security

Run local checks and select live tests:

```bash
scripts/checks.sh
scripts/test_starter.py --list
```

Use `scripts/release_checks.sh` for release qualification.
The [collector gate](docs/guides/collector-integrations.md) checks stored signals
and dashboards against running collector products; skipped external services
are not release evidence.

Fluxheim uses a locked dependency graph, CI, CodeQL, RustSec advisory checks,
dependency/license policy and native/container smoke tests. Checksums and
repeat builds do not by themselves prove independent build provenance.
Read [supply-chain policy](docs/guides/supply-chain-security.md) for the trust
model and [SECURITY.md](SECURITY.md) for vulnerability reporting.

## License

Fluxheim is distributed under the
[European Union Public Licence v1.2](LICENSE).
