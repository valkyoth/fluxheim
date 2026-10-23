# Documentation Index

Start with the [configuration reference](reference/config-reference.md),
[feature matrix](reference/features.md) and [deployment guide](guides/build-and-podman.md).
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

## Guides

- [Build and Podman](guides/build-and-podman.md)
- [Gateway recipes](guides/gateway-recipes.md)
- [Vhost configuration](guides/vhost-config.md)
- [Cache backends](guides/cache-backends.md)
- [Cache encryption](guides/cache-encryption.md)
- [Certificate renewal](guides/certificate-renewal.md)
- [Cloudflare origin support](guides/cloudflare-origin-support.md)
- [Compression](guides/compression.md)
- [Configuration snapshots](guides/config-snapshots.md)
- [Container runtime refresh](guides/container-runtime-refresh.md)
- [FIPS and ISO-capable deployments](guides/fips.md)
- [GeoIP](guides/geoip.md)
- [GitHub setup](guides/github-setup.md)
- [Load-balancer migration](guides/load-balancer-migration.md)
- [macOS development](guides/macos-development.md)
- [Maintenance releases](guides/maintenance-releases.md)
- [Tracing: implemented propagation and pending export wiring](guides/opentelemetry-tracing.md)
- [PHP application recipes](guides/php-fpm-app-recipes.md)
- [PHP runtime](guides/php-runtime-support.md)
- [Portable releases](guides/portable-releases.md)
- [Production readiness](guides/production-readiness.md)
- [Release checklist](guides/release-checklist.md)
- [Release notes template](guides/release-notes-template.md)
- [Release runbook](guides/release-runbook.md)
- [Supply-chain security](guides/supply-chain-security.md)
- [systemd](guides/systemd.md)
- [Wasm extensibility](guides/wasm-extensibility.md)
- [Windows release builders](guides/windows-release-builders.md)
- [Zero-downtime upgrades](guides/zero-downtime-upgrades.md)
- [Privacy mode](guides/zero-retention-privacy-mode.md)

## Reference And Architecture

- [Configuration](reference/config-reference.md)
- [Features](reference/features.md)
- [Logging: current status and historical design](architecture/logging-architecture.md)
- [Metrics: current status and historical design](architecture/metrics-architecture.md)
- [Structured event capture, redaction and byte limits](architecture/structured-events.md)
- [Modularity policy](architecture/modularity-policy.md)
- [Runtime facts and policy proofs: 1.6 design](architecture/runtime-facts-and-policy-proofs.md)

## Roadmap

- [Active 1.9 observability plan](roadmap/observability-commit-plan.md)
- [Versioning history and future sequencing](roadmap/versioning-plan.md)
- [Deferred HTTP/3 and QUIC](roadmap/http3-quic-commit-plan.md)
- [Common Criteria readiness direction](roadmap/common-criteria-roadmap.md)

## Ideas

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
