# Fluxheim 1.2.0 Release Notes

## Release Metadata

- Version: `1.2.0`
- Release date: 2026-05-12
- Git tag: `v1.2.0`
- Release type: stable operations and cache completion pack

## Summary

Fluxheim `1.2.0` completes the production cache and observability work started
after `1.1.0`. It adds fuller reverse-proxy cache controls, stronger purge and
disk-index behavior, Prometheus and OpenTelemetry coverage, and hardened admin
control-plane defaults.

## Highlights

- Vhost and route cache policies with memory, disk, or tiered storage.
- Cache status and reason headers for cache-participating proxy responses.
- Cache key controls for namespaces, selected key parts, query participation,
  request-header variance, and origin `Vary` handling.
- Cache admission controls for content types, extensions, response status TTLs,
  request headers, cookies, query parameters, origin response headers, and
  `Set-Cookie` hiding or refusal.
- Stale-on-error and stale-while-revalidate policy support.
- Request-collapsing locks and cacheability predictor integration.
- Disk cache v5 metadata with full startup reconciliation, purge-index rebuilds,
  stale cleanup, safer path handling, and debounced checkpoint persistence.
- Protected admin cache status, activity, reset, exact purge, bulk purge,
  indexed purge, prefix purge, tag purge, wildcard purge, stale purge, and soft
  purge support.
- `fluxheim cache-key`, `fluxheim cache-lookup`, and `fluxheim cache-warm`
  helpers for cache inspection and prefill workflows.
- Prometheus cache, storage-pressure, and activity metrics.
- OTLP metrics export and OTLP trace export coverage, including local
  Prometheus and Jaeger smoke paths.
- Hardened admin/control-plane behavior, including stricter remote-admin
  guardrails, authenticated admin health by default, admin auth throttling,
  strict host-routing mode, host anomaly counters, and stricter sensitive-path
  trust checks.
- RPM and native packaging now build with `profile-observability,acme-client`
  for ACME and observability coverage in packaged deployments.

## Validated Scope

- GitHub CI green before tag.
- CodeQL/code scanning has no open release-blocking alerts before tag.
- RPM package builds and runs.
- Packaged default and container configs validate.
- Proxy cache smoke verifies HIT behavior, cached-hit `Age`, conditional `304`,
  and byte-range `206` behavior through the proxy path.
- Observability smoke verifies Prometheus metrics and OTLP export paths when
  local Prometheus and Jaeger endpoints are available.

## Known Limits

- Local/static vhost response caching remains planned for `1.2.1`; `1.2.0`
  cache storage applies to proxy cache paths.
- Slab/bin disk storage is planned for `1.2.2`.
- Distributed cache coordination is planned for `1.2.3`.
- Optional remaining cache refinements such as partial streaming admission,
  cache import/export, richer ban predicates, and HEAD-to-GET parity are
  reserved for `1.2.4` if still needed after production testing.
- Wasm-based extension points, including cache-rule hooks comparable to VCL/Lua
  style customization, are planned for `1.4`.
- HTTP/3/QUIC, ECH, and post-quantum TLS policy remain future milestones.

## Checksums And Signatures

Record during the release:

- Commit: to be filled after the release-prep commit
- Local gate: GitHub CI green before tag; local release metadata checks passed
- CodeQL/code scanning: no open release-blocking alerts before tag
- Source archive checksums: to be filled
- Binary checksums: to be filled
- SBOM checksums: to be filled
- Reproducible build: to be filled
- Container digests: to be filled
- Tag signature: to be filled
