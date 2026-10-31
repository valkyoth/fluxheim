# Documentation Index

Start with [installation and package selection](guides/installation.md), then
the [working configuration examples](guides/configuration.md). Use the
[configuration reference](reference/config-reference.md) for individual settings
and the [feature matrix](reference/features.md) for custom builds.
For development, the active work is the [1.9 observability commit plan](roadmap/observability-commit-plan.md).

| Folder | Purpose |
| --- | --- |
| guides | Operator/developer procedures and supported behavior; individual pages label remaining proposals |
| reference | Accepted configuration and compile-time feature reference |
| architecture | Internal design contracts; current status is distinguished from historical proposals |
| roadmap | Active sequencing and deferred plans; a version assignment is not a shipped feature |
| ideas | Discussion drafts and speculative designs, not release commitments or copy-ready configuration |
| evidence | Dated qualification, audit records, historical baselines and machine-readable policy inputs |

Evidence applies only to its recorded revision/platform/tests. An evidence
template is not a completed audit. Historical Pingora/1.6 documents remain for
traceability, not as instructions for today's native runtime. Ideas can contain
already-implemented subsets; consult the reference and current tests for support.
Release notes remain in [release-notes](../release-notes); executable examples
remain in [examples](../examples). Run commands from the repository root unless
a guide explicitly says otherwise.

## Choose A Task

| I want to... | Start here |
| --- | --- |
| Serve a website or forward to an application | [Static files](guides/static-files.md), [reverse proxy](guides/reverse-proxy.md), [routing](guides/routing.md) |
| Run PHP or WordPress | [PHP](guides/php.md), [application recipes](guides/php-fpm-app-recipes.md) |
| Configure HTTPS and renew certificates | [TLS](guides/tls.md), [ACME](guides/acme.md) |
| Cache content or distribute traffic | [Caching](guides/cache.md), [load balancing](guides/load-balancer.md) |
| Inspect traffic, failures and performance | [Operational visibility](guides/observability.md), [collectors and dashboards](guides/collector-integrations.md) |
| Change configuration or recover a deployment | [Admin operations](guides/admin.md), [snapshots and rollback](guides/config-snapshots.md) |
| Decide whether my deployment is ready | [Production checklist](guides/production-readiness.md), [documentation review status](reference/documentation-coverage.md) |

These pages describe this checkout. Use the matching tagged documentation for
an installed release. Example success, a configuration parse and release
qualification are different checks; see each guide's limitations and evidence.

## Guides

- [Configuration loading: files, conf.d, paths, validation and merge limits](guides/configuration.md)
- [Command line, validation modes and standalone configuration tester](guides/command-line.md)
- [Configuration composition: every root section and merge rule](reference/configuration-loading.md)
- [Build and Podman](guides/build-and-podman.md)
- [Gateway recipes](guides/gateway-recipes.md)
- [Vhost configuration](guides/vhost-config.md)
- [HTTP host selection, route priority, rewrites and redirects](guides/routing.md)
- [Static files, directory listings, validators and byte ranges](guides/static-files.md)
- [External proxy authorization and identity boundaries](guides/external-authorization.md)
- [Traffic mirroring, sampling and current projection limits](guides/traffic-mirroring.md)
- [Reverse proxy, connection reuse, timeouts and gateway error pages](guides/reverse-proxy.md)
- [WebSocket routes, tunnel lifetime and current authorization/handshake limits](guides/websocket.md)
- [gRPC route filters and unresolved trailer/streaming limits](guides/grpc.md)
- [PROXY protocol receive/send and HTTPS trust-policy limitation](guides/proxy-protocol.md)
- [Proxy transport option reference and platform restrictions](reference/proxy-transport-options.md)
- [Caching: setup, public-content policy and troubleshooting](guides/cache.md)
- [Cache option reference](reference/cache-options.md)
- [Byte ranges and fixed-slice caching](guides/cache-ranges.md)
- [Peer-assisted cache fill and current safety limits](guides/cache-peer-fill.md)
- [Cache inspection, warming and protected invalidation](guides/cache-operations.md)
- [Cache restart recovery, storage-bin layout and maintenance](guides/cache-recovery.md)
- [Cache backends: tier selection, budgets, on-disk state and inspection](guides/cache-backends.md)
- [Cache encryption](guides/cache-encryption.md)
- [Automatic certificates: ACME setup, renewal and troubleshooting](guides/acme.md)
- [Complete ACME option reference](reference/acme-options.md)
- [ACME storage, recovery and incident operations](guides/acme-recovery.md)
- [ACME accounts, issuers and registration](guides/acme-accounts.md)
- [HTTPS, certificates and client authentication](guides/tls.md)
- [Downstream TLS options](reference/tls-options.md)
- [Verified HTTPS origins and upstream client certificates](guides/upstream-tls.md)
- [Certificate lifecycle, storage and recovery](guides/certificate-renewal.md)
- [Cloudflare/CDN origins: existing capabilities and limits](guides/cloudflare-origin-support.md)
- [Response compression: codecs, policy, negotiation and resource limits](guides/compression.md)
- [CORS: browser origins, scoped policies, preflights and cache limits](guides/cors.md)
- [Response headers: browser policy, mutations, redirects and cookies](guides/response-headers.md)
- [Request headers: forwarding, trusted proxies and template limitations](guides/request-headers.md)
- [Response header option reference](reference/response-header-options.md)
- [Configuration snapshots](guides/config-snapshots.md)
- [Container runtime refresh](guides/container-runtime-refresh.md)
- [FIPS and ISO-capable deployments](guides/fips.md)
- [GeoIP](guides/geoip.md)
- [Access control: IP rules, certificate pins and route scope](guides/access-control.md)
- [Rate and concurrency limits: budgets, delay, queues and recovery](guides/rate-and-concurrency-limits.md)
- [TCP streams: forwarding, failover, source policy, TLS and limits](guides/tcp-streams.md)
- [Beta UDP: request/response, syslog, limits and exposure boundaries](guides/udp.md)
- [GitHub setup](guides/github-setup.md)
- [Load balancing: setup, health, discovery and operations](guides/load-balancer.md)
- [Load-balancer option reference](reference/load-balancer-options.md)
- [Load-balancer migration](guides/load-balancer-migration.md)
- [Logging and protected file rotation](guides/logging.md)
- [Operational visibility: setup, examples, alerts and troubleshooting](guides/observability.md)
- [Management API handoff: available contracts and missing workflows](reference/management-api-handoff.md)
- [macOS development](guides/macos-development.md)
- [Maintenance releases](guides/maintenance-releases.md)
- [Tracing and request correlation](guides/opentelemetry-tracing.md)
- [OTLP export failure, recovery and shutdown](guides/otlp-export.md)
- [Collectors and Grafana/SigNoz dashboards](guides/collector-integrations.md)
- [Read-only operational status API](guides/operational-status.md)
- [Admin API, roles and local operations](guides/admin.md)
- [Operational status OpenAPI 3.1 description](reference/operational-status.openapi.json)
- [Operational status JSON Schema](reference/operational-status.schema.json)
- [PHP application recipes](guides/php-fpm-app-recipes.md)
- [PHP deployment, routing and static assets](guides/php.md)
- [PHP runtime](guides/php-runtime-support.md)
- [PHP and FastCGI option reference](reference/php-options.md)
- [Portable releases](guides/portable-releases.md)
- [Installation and package selection](guides/installation.md)
- [Production readiness](guides/production-readiness.md)
- [Release checklist](guides/release-checklist.md)
- [Release notes template](guides/release-notes-template.md)
- [Release runbook](guides/release-runbook.md)
- [Supply-chain security](guides/supply-chain-security.md)
- [systemd](guides/systemd.md)
- [Service lifecycle and every process setting](guides/service-lifecycle.md)
- [Wasm extensibility](guides/wasm-extensibility.md)
- [Wasm configuration options and limits](reference/wasm-options.md)
- [Wasm policy ABI, ordering and protocol boundaries](reference/wasm-policy-abi.md)
- [Windows release builders](guides/windows-release-builders.md)
- [Dedicated Windows QEMU VM](guides/windows-qemu.md)
- [Zero-downtime upgrades](guides/zero-downtime-upgrades.md)
- [Privacy profile: suppression, application data and retention boundaries](guides/zero-retention-privacy-mode.md)

## Reference And Architecture

- [HTTP header quick reference](reference/supported-headers.md)
- [Documentation coverage and review status](reference/documentation-coverage.md)
- [Configuration](reference/config-reference.md)
- [Features](reference/features.md)
- [Logging: current status and historical design](architecture/logging-architecture.md)
- [Metrics: current status and historical design](architecture/metrics-architecture.md)
- [Metrics meanings, limits and dashboard queries](guides/metrics.md)
- [Structured event capture, redaction and byte limits](architecture/structured-events.md)
- [Modularity policy](architecture/modularity-policy.md)
- [Runtime facts and policy proofs: 1.6 design](architecture/runtime-facts-and-policy-proofs.md)

## Roadmap

- [Active 1.9 observability plan](roadmap/observability-commit-plan.md)
- [Versioning history and future sequencing](roadmap/versioning-plan.md)
- [Deferred HTTP/3 and QUIC](roadmap/http3-quic-commit-plan.md)
- [Common Criteria readiness direction](roadmap/common-criteria-roadmap.md)

## Ideas

- [Cloudflare origin module proposal (not implemented)](ideas/cloudflare-origin-support.md)
- [Management API and UI direction](ideas/management-api-direction.md)
- [September 2026 product-direction draft](ideas/new-plan-idea-2026-09-13.md)
- [Ecosystem](ideas/fluxheim-ecosystem-idea.md)
- [External authorization design](ideas/auth-request.md)
- [Crypto RPC edge](ideas/crypto-rpc-edge.md)
- [Image filter](ideas/image-filter.md)
- [Legacy static HTTP](ideas/legacy-static-http.md)
- [Load-balancer HA](ideas/load-balancer-ha.md)
- [Perl CGI](ideas/perl-cgi-support.md)
- [Programmable media edge](ideas/programmable-media-edge.md)
- [Secure links](ideas/secure-links.md)
- [Sentinel Mesh](ideas/sentinel-mesh.md)
- [WAF](ideas/waf-architecture.md)

## Evidence And Policy Inputs

- [Observability Commit 01 inventory and proposed budgets](evidence/observability-baseline.md)
- [Observability Commit 01 Linux raw measurements](evidence/observability-01-linux.json)
- [Observability Commit 02 verification](evidence/observability-02.md)
- [Observability Commit 02 Linux raw measurements](evidence/observability-02-linux.json)
- [Observability Commit 03 operational event coverage](evidence/observability-03.md)
- [Observability Commit 03 security remediation](evidence/observability-03-security.md)
- [Observability Commit 03 pre-mutation audit admission](evidence/observability-03-audit-admission.md)
- [Observability Commit 04 bounded logging dispatcher](evidence/observability-04.md)
- [Observability Commit 05 protected file lifecycle](evidence/observability-05.md)
- [Observability Commit 06 request and trace correlation](evidence/observability-06.md)
- [Observability Commit 07 bounded operational metrics](evidence/observability-07.md)
- [Observability Commit 07A dedicated Windows VM qualification](evidence/observability-07a.md)
- [Observability Commit 08 exporter lifecycle qualification](evidence/observability-08.md)
- [Observability Commit 09 operational API qualification](evidence/observability-09.md)
- [Observability Commit 10 collector qualification](evidence/observability-10.md)
- [Commit 10A ACME scope and packaged renewal qualification](evidence/observability-10a.md)
- [Commit 11 native packages and real collector qualification](evidence/observability-11.md)
- [Commit 11 native archive identities and checksums](evidence/observability-11-archives.json)
- [Commit 12 refreshed candidate and operator qualification](evidence/observability-12.md)
- [Documentation and native balancing checkpoint](evidence/observability-13-15.md)
- [Commit 12 native archive identities and checksums](evidence/observability-12-archives.json)
- [Commit 12 local performance measurements](evidence/observability-12-performance.json)
- [Commit 12 ARM performance measurements](evidence/observability-12-performance-arm.json)
- [Commit 12 macOS performance measurements](evidence/observability-12-performance-macos.json)
- [Observability Commit 04 fatal-abort remediation](evidence/observability-04-fatal.md)
- [Observability Commit 04 watchdog and critical-exit retest](evidence/observability-04-watchdog.md)
- [Observability Commit 04 core dump deployment policy](evidence/observability-04-core-limits.md)
- [Observability Commit 04 Linux non-dumpable startup](evidence/observability-04-nondumpable.md)
- [Observability Commit 04 CI portability and test boundaries](evidence/observability-04-ci-portability.md)
- [Observability Commit 04 Linux performance samples](evidence/observability-04-linux.json)
- [1.8.3 qualification](evidence/maintenance-1.8.3-qualification.md)
- [Windows filesystem audit](evidence/dependency-audits/windows-filesystem-security.md)
- [OWASP baseline](evidence/owasp-top10-2025-baseline.md)
- [Compliance evidence template](evidence/compliance-evidence-template.md)
- [Modularity exceptions](evidence/modularity-exceptions.md)
- [Wasm example parity](evidence/wasm-policy-example-parity.md)
- [Historical extraction graph](evidence/extraction-dependency-graph.md)
- [Historical runtime baseline](evidence/runtime-baseline.md)
- [Runtime parity fixtures](evidence/runtime-parity-fixtures.md) and [machine inventory](evidence/runtime-parity-fixtures.tsv)
- [Native cutover target inventory](evidence/native-runtime-cutover-targets.tsv)
- [Historical Pingora patch](evidence/pingora-core-patch.md)
- [Pingora dependency exceptions](evidence/pingora-dependency-exceptions.tsv)
- [Pingora HTTP error exceptions](evidence/pingora-http-error-boundary-exceptions.tsv)
- [Deferred HTTP/3 source contract](evidence/http3-source-contract.md)
- [Deferred HTTP/3 feasibility](evidence/http3-migration-feasibility.md)
- [Deferred HTTP/3 source lock](evidence/http3-source-lock.json)
