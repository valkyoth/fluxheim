# Metrics Architecture

Fluxheim metrics capture aggregate health and performance. Logs explain what
happened for an individual event; metrics answer questions such as request rate,
error rate, p95/p99 latency, cache efficiency, and upstream health.

The safe baseline is the existing Prometheus pull endpoint. Advanced per-vhost
aggregation and remote push exporters are future optional add-ons.

## Goals

- Keep `/metrics` pull mode available as the reliable baseline.
- Avoid global locks on request worker hot paths.
- Avoid unbounded label cardinality from attacker-controlled input.
- Make remote push optional and non-blocking.
- Keep local metrics available even when remote exporters fail.

## Feature Flags

Planned feature split:

```toml
metrics = ["dep:prometheus"]
metrics-advanced = ["metrics"]
metrics-push = ["metrics-advanced"]
metrics-otlp = ["metrics-advanced", "dep:opentelemetry-otlp"]
```

Reviewed optional crate candidates:

- `metrics 0.24.5`, MIT: facade option.
- `hdrhistogram 7.5.4`, MIT/Apache-2.0: latency histogram option.
- `opentelemetry-otlp 0.31.1`, Apache-2.0: optional OTLP exporter.
- `dashmap`: latest observed release is `7.0.0-rc2`; avoid RC releases for MVP
  core. Re-evaluate a stable release if a concurrent map is needed.

## Cardinality Rules

Metrics must never create labels directly from arbitrary remote input.

Allowed labels:

- configured vhost name
- fixed request method bucket
- static status class
- known module name, for example `proxy`, `static`, `cache`, `admin`
- configured upstream name/address only when it came from config
- fixed legacy listener name

Forbidden labels:

- raw `Host`
- path
- query string
- user-agent
- referer
- client IP
- request ID
- arbitrary upstream response header values

Unknown or unsafe traffic must merge into fixed buckets:

- `unknown`
- `invalid_host`
- `legacy_unidentified`
- `overflow`

This prevents Host-header and path-cardinality attacks from exhausting memory or
making Prometheus unusable.

## Hot Path Design

For each runtime snapshot, Fluxheim should prebuild metric buckets for configured
vhosts. Request handling should resolve to a stable vhost index and update a
bucket directly.

Per bucket:

- atomic request counters by status class
- atomic byte counters where byte counts are available
- atomic cache counters, or snapshot from cache activity counters
- latency buckets

Current cache baseline:

- `fluxheim_cache_vhosts`
- `fluxheim_cache_enabled_vhosts`
- `fluxheim_cache_tiered_vhosts`
- `fluxheim_cache_configured_routes`
- `fluxheim_cache_policy_routes`
- `fluxheim_cache_enabled_routes`
- `fluxheim_cache_tiered_routes`
- `fluxheim_cache_memory_tiers`
- `fluxheim_cache_disk_tiers`
- `fluxheim_cache_activity_total{tier,event}`

The configuration gauges are aggregate, label-free, and populated from
validated configuration when the metrics listener starts.
`fluxheim_cache_activity_total` uses only bounded labels: `tier` is `memory`,
`disk`, or `other`, and `event` is `hit`, `miss`, `store`, `store_refusal`,
`eviction`, `purge`, or `other`. These metrics intentionally avoid raw hosts,
paths, queries, cache keys, and purge identities. Per-vhost and per-route cache
runtime metrics should only be added with configured-name labels and the same
bounded concepts used by admin JSON and OpenTelemetry attributes.

Latency plan:

1. Start with fixed histogram buckets implemented as atomics. This is easiest
   to bound and export.
2. Evaluate `hdrhistogram` later with sharded/thread-local recorders and
   background aggregation. Avoid a single locked histogram on the request path.

## Metrics To Track

Per vhost:

- request totals by status class
- latency histogram
- inbound/outbound bytes when available
- route module totals: static, proxy, cache, admin, future PHP/CGI, future
  legacy static

Cache:

- hits
- misses
- stores
- store refusals
- purges
- memory entries/bytes
- disk entries/bytes

Load balancer:

- selected upstream totals
- retries
- connect failures
- all-nodes-down
- upstream health state transitions

Admin/security:

- admin auth failures
- snapshot/reload/rollback actions
- self-healing confirms/rollbacks
- denied traversal attempts
- denied request-smuggling/legacy misuse attempts

Future PHP/CGI:

- runtime request totals
- runtime status/exit outcomes
- timeouts
- spawn/connect failures
- output limit violations

## Export

Baseline:

- Prometheus/OpenMetrics text through the local metrics listener.
- Loopback by default.

Optional push:

- background Pingora service aggregates and pushes every `10-60s`.
- push failure must never block request workers.
- failed push keeps metrics locally available.
- do not buffer infinite historical metrics in memory.

Optional OTLP:

- behind `metrics-otlp`.
- default off.
- use explicit remote endpoint and timeout config.

Exporter health metrics:

- last successful push timestamp
- consecutive failures
- dropped export batches
- current circuit state
- reconnect attempts

## Legacy Protocol Guardrail

Future HTTP/0.9 and headerless HTTP/1.0 traffic must not create vhost labels from
request data. Use `legacy_unidentified` or a configured legacy listener name.

Legacy metrics should be isolated from normal modern-protocol metrics so old
devices cannot pollute dashboards or trigger cardinality growth.

## Config Shape

Initial target:

```toml
[metrics]
enabled = true
listen = "127.0.0.1:9091"
require_loopback = true

[metrics.advanced]
enabled = false
max_metric_vhosts = 10000
latency_buckets_ms = [1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000]
unknown_vhost_bucket = "unknown"
overflow_bucket = "overflow"

[metrics.push]
enabled = false
protocol = "otlp_http"
endpoint = "https://collector.example.test/v1/metrics"
interval_secs = 30
timeout_secs = 2
retry_initial_secs = 5
retry_max_secs = 300
```

## Implementation Stages

1. Harden current labels: ensure request outcome labels are derived from
   configured vhost names or fixed buckets only. Implemented for
   `fluxheim_proxy_requests_total`: it uses configured vhost names, fixed
   request method buckets, fixed outcome classes, and fixed status classes
   instead of raw status codes.
2. Add vhost-indexed atomic counters.
3. Add fixed atomic latency histograms.
4. Add cache/load-balancer/admin/security counters.
5. Add exporter health metrics.
6. Add optional push exporter.
7. Add optional OTLP exporter.

## Tests

Required tests:

- Unknown Host maps to fixed `unknown` bucket.
- Missing Host and future HTTP/0.9 traffic map to `legacy_unidentified` or a
  configured listener bucket.
- Thousands of fake Host headers do not create new metric labels.
- Latency buckets export expected counts.
- Metrics update path does not require a global mutex.
- Push exporter failure does not block request handling.
- Exporter health metrics update on failure and recovery.
