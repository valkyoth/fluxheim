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
metrics-otlp = ["metrics", "dep:serde_json"]
metrics-advanced = ["metrics"]
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

- `fluxheim_acme_events_total{event}`
- `fluxheim_php_requests_total{vhost,method,outcome,status_class}`
- `fluxheim_php_request_duration_seconds{vhost,method,outcome,status_class}`
- `fluxheim_php_stderr_events_total{vhost,state}`
- `fluxheim_php_fpm_retries_total{vhost,reason}`
- `fluxheim_php_fpm_pool_idle_connections{vhost,pool}`
- `fluxheim_php_fpm_pool_events_total{vhost,pool,event}`
- `fluxheim_cache_vhosts`
- `fluxheim_cache_enabled_vhosts`
- `fluxheim_cache_tiered_vhosts`
- `fluxheim_cache_configured_routes`
- `fluxheim_cache_policy_routes`
- `fluxheim_cache_enabled_routes`
- `fluxheim_cache_tiered_routes`
- `fluxheim_cache_memory_tiers`
- `fluxheim_cache_disk_tiers`
- `fluxheim_cache_lock_enabled_policies`
- `fluxheim_cache_lock_wait_timeout_max_seconds`
- `fluxheim_cache_origin_protection_enabled_policies`
- `fluxheim_cache_origin_protection_max_concurrent_fills`
- `fluxheim_cache_peer_fill_enabled_policies`
- `fluxheim_cache_peer_fill_peers`
- `fluxheim_cache_peer_fill_max_concurrent_requests`
- `fluxheim_cache_activity_total{tier,event}`
- `fluxheim_cache_activity_scope_total{scope,vhost,route,tier,event}`
- `fluxheim_cache_operation_duration_seconds{scope,vhost,route,phase,operation}`
- `fluxheim_cache_purger_runs_total{outcome}`
- `fluxheim_cache_purger_entries_total{result}`
- `fluxheim_cache_purger_duration_seconds{outcome}`
- `fluxheim_edge_policy_events_total{scope,vhost,route,policy,outcome}`
- `fluxheim_load_balancer_events_total{scope,vhost,route,upstream,event}`
- `fluxheim_response_compressions_total{scope,vhost,route,encoding}`
- `fluxheim_stream_connections_total{route,outcome}`
- `fluxheim_stream_bytes_total{route,direction}`

The configuration gauges are aggregate, label-free, and populated from
validated configuration when the metrics listener starts. The local
observability smoke verifies the route/vhost cache policy gauges, the
request-collapsing policy count, and the maximum configured lock wait timeout.
`fluxheim_acme_events_total` uses only bounded lifecycle labels: `event` is
`pending`, `renewed`, `failed`, `reload_success`, `reload_failed`,
`reload_unavailable`, `tick_error`, or `other`. It intentionally avoids domain
names, certificate paths, challenge URLs, and issuer secrets.
`fluxheim_php_requests_total` and `fluxheim_php_request_duration_seconds` use
configured vhost names plus bounded method, outcome, and status-class labels.
`outcome` is `declined`, `redirect`, `forbidden`, `not_found`, `fpm_error`,
`connect_timeout`, `request_timeout`, `connection_error`,
`configuration_error`, `invalid_response`, `intercepted`, `offload`,
`offload_error`, `response`, or `other`; these metrics avoid raw paths,
queries, script filenames, usernames, cookies, and FastCGI params.
`fluxheim_stream_connections_total` and `fluxheim_stream_bytes_total` use
configured stream route names only. Stream connection `outcome` is bounded to
`completed`, `rejected`, `connect_error`, `timeout`, `shutdown`, or `error`.
Stream byte `direction` is bounded to `downstream_to_upstream`,
`upstream_to_downstream`, or `other`.
`fluxheim_php_stderr_events_total` uses configured vhost names plus bounded
`state` labels of `emitted`, `truncated`, or `other`; it counts STDERR presence
without exposing PHP error text.
`fluxheim_php_fpm_retries_total` uses configured vhost names plus bounded
`reason` labels of `connect_timeout`, `connection_error`, or `other`; it counts
retry attempts without exposing upstream addresses, socket paths, raw request
paths, cookies, or FastCGI params.
`fluxheim_php_fpm_pool_idle_connections` and
`fluxheim_php_fpm_pool_events_total` use configured vhost and pool labels. The
`pool` label is `default` for a vhost-level PHP runtime or the configured route
name for a route-level PHP runtime. Pool `event` labels are bounded to `connect`,
`reuse`, `return`, `drop_stale`, `discard_full`, or `other`.
`fluxheim_cache_activity_total` uses only bounded labels: `tier` is `memory`,
`disk`, `policy`, or `other`, and `event` is `hit`, `miss`, `store`,
`store_refusal`, `eviction`, `purge`, `pass`, `bypass`, `stale`,
`revalidate`, `peer_fill_hit`, `peer_fill_miss`, `peer_fill_error`,
`peer_fill_fallback`, `peer_fill_fail_closed`, or `other`. These metrics
intentionally avoid raw hosts, paths, queries, cache keys, peer URLs, and purge
identities.
`fluxheim_cache_activity_scope_total` uses the same bounded `tier` and `event`
labels plus configured-name labels: `scope` is `vhost` or `route`, `vhost` is
the configured vhost name, and `route` is empty for vhost cache or the
configured route name for route cache. It intentionally avoids raw `Host`,
path, query, cache key, and purge identity labels. Cache operation duration
histograms use the same configured-name labels plus bounded `phase` and
`operation` labels. `operation` is `lookup` or `lock_wait`, so dashboards can
separate storage lookup cost from request-collapsing wait time without
high-cardinality request labels.
Cache purger duration histograms use the bounded purger `outcome` label only,
so operators can see when cleanup ticks are getting slow without exposing cache
paths, queries, cache keys, and purge identities. Future OpenTelemetry
attributes should mirror the same low-cardinality concepts used by admin JSON
and Prometheus.

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

- `fluxheim_load_balancer_pools` reports configured load-balancer pool counts
  by bounded `scope` (`vhost` or `route`) and bounded selection algorithm. It
  does not label configured vhost names, route names, or upstream addresses.
- `fluxheim_load_balancer_events_total` counts selected upstreams, retries,
  all-nodes-down/unavailable pools, queue wait/full/timeout outcomes,
  success/failure outcomes, and passive-health ejections with bounded
  configured vhost/route labels. The
  `upstream` label is empty unless the operator configures a safe
  low-cardinality `proxy.upstream_aliases` entry.
- `fluxheim_load_balancer_queue_wait_seconds` observes bounded queue wait and
  timeout duration by configured vhost/route and bounded queue outcome. It
  does not label raw upstream addresses.
- richer upstream health state transition metrics remain planned; they should
  not label raw upstream addresses unless an explicit low-cardinality alias is
  configured.

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
- Local smoke coverage starts Fluxheim with `profile-observability`, sends a
  proxied request, verifies `traceparent` propagation, checks the local metrics
  listener for Fluxheim series, and optionally queries a Prometheus HTTP API.
  Use `scripts/smoke_observability_local.sh`; set
  `FLUXHEIM_PROMETHEUS_REQUIRE_FLUXHEIM=1` when a local Prometheus scrape job is
  expected to contain Fluxheim metrics, and
  `FLUXHEIM_PROMETHEUS_REQUIRE_OTLP=1` when Prometheus must have its OTLP
  metrics receiver enabled.

Optional push:

- initial implementation spawns a background exporter thread when
  `[metrics.otlp]` is enabled.
- future Pingora service integration can add richer lifecycle and health
  reporting.
- push failure must never block request workers.
- failed push keeps metrics locally available.
- do not buffer infinite historical metrics in memory.

Optional OTLP:

- behind `metrics-otlp`.
- default off.
- use explicit endpoint, interval, service name, and timeout config.
- can target a Prometheus HTTP OTLP metrics receiver at
  `/api/v1/otlp/v1/metrics` when Prometheus is started with
  `--web.enable-otlp-receiver`.
- covers metrics only; traces still need an OpenTelemetry Collector or tracing
  backend.
- implemented now for counters, gauges, and histograms gathered from the
  existing Prometheus registry. Summaries remain a future exporter extension.

Exporter health metrics:

- implemented now for OTLP metrics exporter attempts:
  `fluxheim_metrics_otlp_exports_total{outcome}` with bounded `success`,
  `failure`, or `other` outcomes.
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

[metrics.otlp]
enabled = false
endpoint = "http://127.0.0.1:9090/api/v1/otlp/v1/metrics"
service_name = "fluxheim"
interval_secs = 15
timeout_secs = 2
# tls_ca_cert_path = "/etc/fluxheim/otlp-ca.pem"

[metrics.advanced]
enabled = false
max_metric_vhosts = 10000
latency_buckets_ms = [1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000]
unknown_vhost_bucket = "unknown"
overflow_bucket = "overflow"

```

The OTLP metrics exporter accepts `http://` and `https://` endpoints. Use
loopback HTTP for same-host collectors and HTTPS for remote collectors.
`metrics.otlp.tls_ca_cert_path` can point at a PEM CA bundle for private PKI
collectors; otherwise the HTTPS client uses the bundled WebPKI roots. Plaintext
HTTP to a non-loopback collector logs a startup warning.

## Implementation Stages

1. Harden current labels: ensure request outcome labels are derived from
   configured vhost names or fixed buckets only. Implemented for
   `fluxheim_proxy_requests_total`: it uses configured vhost names, fixed
   request method buckets, fixed outcome classes, and fixed status classes
   instead of raw status codes.
2. Add vhost-indexed atomic counters.
3. Add fixed atomic latency histograms.
4. Add cache/load-balancer/admin/security counters.
5. Add optional OTLP exporter. Implemented initially for counters/gauges over
   local OTLP/HTTP JSON.
6. Add exporter health metrics.
7. Add production-grade push/exporter lifecycle, retry, circuit breaker, and
   histogram support.

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
