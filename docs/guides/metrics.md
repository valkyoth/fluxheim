# Metrics

Requires a build with `metrics` (for example `profile-observability`). No new
public listener is enabled by this release. Bind locally, or configure the
existing protected token-file option and restrict network access:

```toml
[metrics]
enabled = true
listen = "127.0.0.1:9091"
require_loopback = true
# token_file = "/run/secrets/fluxheim-metrics-token"
```

Read `GET /metrics` with Prometheus. Optional `[metrics.otlp]` exports the same
registry, names, descriptions, labels and cumulative measurements. Duration
units are seconds (`s`), byte units are bytes (`By`), other quantities use `1`.
Zero-retention privacy builds continue to reject the `metrics` feature entirely;
this checkpoint does not relax that boundary. In metrics-enabled builds,
request/trace IDs, raw Host values, paths, queries, bodies, certificates and
client IPs are never new metric labels.
Access-log filtering and sampled tracing do not disable aggregate measurements.
See [OTLP export lifecycle](otlp-export.md) for collector authentication, byte
limits, retries, shutdown and local exporter-health metrics. Oversized export
snapshots are rejected without disabling local scraping.

## Request And Connection Measurements

| Metric | Labels / meaning |
| --- | --- |
| `fluxheim_http_requests_total` | `method`, `status_class`, `outcome`; one logical routed HTTP request at downstream completion, failure or cancellation |
| `fluxheim_http_request_duration_seconds` | `outcome`; monotonic time from routing ingress through downstream completion, including upstream waits |
| `fluxheim_http_requests_active` | Requests not yet completed, including open upgraded tunnels |
| `fluxheim_http_response_body_bytes_total` | Accounted body bytes on successful downstream completion; excludes headers, framing, tunnel bytes and partial failed writes |
| `fluxheim_upstream_attempts_total` | `outcome`; request-scoped transport attempts, including explicit safe retries |
| `fluxheim_upstream_attempt_duration_seconds` | `outcome`; monotonic attempt duration including acquisition/connect time |
| `fluxheim_upstream_attempts_active` | Currently executing request-scoped attempts |
| `fluxheim_listener_connections_total` | `outcome=accepted/rejected`; native HTTP listener task admission, including management/metrics and Unix listeners |
| `fluxheim_listener_connections_active` | Admitted tasks, including TLS handshake, HTTP/2 multiplexing and upgraded connections; task cancellation releases the gauge |
| `fluxheim_downstream_tls_handshakes_total` | `outcome=succeeded/failed/timeout`; rustls and OpenSSL downstream handshake results; excludes cancelled handshakes and pre-handshake setup failures |

Completion outcomes are `completed`, `failed`, `cancelled`. HTTP 5xx with a
successfully written response is `completed` plus `status_class=5xx`, not a
transport failure. Attempt HTTP 5xx counts as `failed`. A retry does not add a
logical request. Cancellation uses `unknown` status when no final status is
available. HTTP/2 streams complete individually; they do not each create a TLS
handshake. Successful writes/EOS submission are not proof of remote receipt.
WebSocket request/attempt duration includes the tunnel lifetime; successful
tunnel completion currently has unknown status and zero HTTP body bytes.

Methods are GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS, TRACE, CONNECT, OTHER.
Status classes are 1xx through 5xx, other, unknown. Request and attempt histograms
have bounds `0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30`
seconds: 16 exported samples per label tuple including +Inf, sum and count.
Existing PHP/cache/load-balancer/Wasm histogram bounds are unchanged.

These new logical measurements are process-wide, not per-vhost. They cover
requests reaching the host router, not malformed requests rejected by a parser,
management requests handled outside that router, or detached background work.
Do not sum them with `fluxheim_proxy_requests_total` or
`fluxheim_php_requests_total`: those existing families describe handler work.
They are not additional traffic. FastCGI protocol fixtures prove the boundary,
not PHP application or database-internal instrumentation.

## Failures And Telemetry Health

| Metric | Meaning |
| --- | --- |
| `fluxheim_operational_failures_total{reason}` | Typed owner observations: DNS, connection, TLS verification/handshake, protocol, cache read/write/encryption, PHP, Wasm, ACME, reload, rollback, telemetry/internal failures |
| `fluxheim_security_events_total{reason}` | Typed authentication/authorization, Host/path/limit/rate/admission/Wasm/context rejections |
| `fluxheim_admin_operations_total{operation,outcome}` | Reported snapshot/reload/rollback/self-healing/cache/LB/certificate mutation outcomes; includes reserved-audit outcome commits even if later logging fails |
| `fluxheim_log_dispatch_events_total{lane,outcome}` | Existing ordinary/security/audit/legacy dispatch counters exposed directly, including filtered, saturation, unavailable, sink-error and discard outcomes |
| `fluxheim_log_dispatch_state{lane,state}` | Availability, worker alive, capacity, pending, and applicable reserved/active-producer gauges |
| `fluxheim_metric_series_budget{state}` | Variable admission usage, total limit and fixed reserve |
| `fluxheim_metric_series_overflow_total` | Updates coalesced into overflow or gauge observations discarded at an admission limit |

Failure observations are not unique failed requests: multiple owners can report
one incident. Admin outcomes are neither a uniquely identified human nor proof
of durable audit persistence. Dispatcher stages overlap: do not sum accepted,
encoded and written to get an event count. A missing dispatcher reports
`state=available` as zero, rather than a healthy-looking set of zero failures.
Snapshots use atomics; simultaneously sampled stages need not reconcile exactly.

Existing ACME events, cache tier/activity/capacity and purge counters, PHP pool/
retry/outcome metrics, load-balancer selection/retry/ejection/queue metrics, Wasm
execution/admission metrics, TCP stream and UDP measurements retain their names
and meanings. Cache activity reset does not reset Prometheus lifetime counters.

## Series Budget And Reloads

The fixed ceiling is **20,000 samples**, not configurable in this checkpoint.
19,000 are available to existing variable-label families; 1,000 are reserved for
finite operational/health/scalar domains. Each variable family is additionally
limited to 2,048 samples so one resource family cannot consume the entire budget.
Histogram buckets count toward both ceilings. The earlier proposed configurable
100,000 hard maximum is not an implemented configuration knob.

Admission precedes child allocation. At most six labels with 128 bytes each are
stored. Existing producers supply configured vhost/route/pool/plugin identities
and finite policy/method/outcome values, never raw request targets. Oversized
identities and exhausted budgets coalesce counters/histograms into one tuple
whose labels are all `overflow`; this tuple is reserved. This preserves aggregate
totals but loses dimensional detail. Include overflow when summing traffic.
Gauges cannot meaningfully merge arbitrary observations: excess gauge identities
are discarded, increment the overflow counter and are not exported as a false
aggregate. Alert on overflow and on missing expected configured series.

Counter/histogram identities are retained, bounded, for the process lifetime.
Removing and recreating a name resumes its previous cumulative total; a reused
name means the same monitoring identity. Churn does not free counter slots for
endless new allocations. Restart resets counters/admission. Use `rate`/`increase`
on each instance before aggregation so Prometheus can handle resets correctly.

Successful administrative reload refreshes aggregate configuration gauges and
retires PHP idle-pool observations; rejected reloads leave these intact. Draining
old handlers can still publish bounded observations until they finish. Missing
pool values mean no current observation, not zero idle capacity. Counter families
are never reset by configuration reload. UDP lifetime/session accounting remains
owned by the existing UDP runtime, not an HTTP reload.

## Dashboard Queries

Example queries for the signal contract (live backend/dashboard qualification
remains Commit 10):

```promql
sum(rate(fluxheim_http_requests_total[5m]))
sum(rate(fluxheim_http_requests_total{status_class="5xx"}[5m]))
sum(rate(fluxheim_http_requests_total{outcome=~"failed|cancelled"}[5m]))
histogram_quantile(0.95, sum by (le) (rate(fluxheim_http_request_duration_seconds_bucket[5m])))
sum(fluxheim_http_requests_active)
sum(rate(fluxheim_upstream_attempts_total{outcome="failed"}[5m]))
sum(rate(fluxheim_listener_connections_total{outcome="rejected"}[5m]))
sum by (reason) (rate(fluxheim_operational_failures_total[5m]))
sum by (lane, outcome) (rate(fluxheim_log_dispatch_events_total{outcome=~"queue_full|rate_limited|unavailable|sink_errors|discarded"}[5m]))
sum(rate(fluxheim_metric_series_overflow_total[5m]))
```

Add your scrape `job`/`instance` filters before aggregating. Histogram quantiles
require summing bucket rates by `le`, not averaging per-instance quantiles. An
empty vector must render as unavailable, not healthy zero. Quantiles beyond the
largest finite bucket lose tail resolution. Failure count is not a unique-error
rate and summed dispatcher stages are not a unique-drop count.

Explicitly unavailable panels: complete per-backend active-health state, TLS
certificate-expiry gauges, kernel/wire byte
accounting, database queries, and app-internal PHP spans. Show existing passive
ejection/selection events as events, not as a substitute for an active-health
gauge. Features absent from the build or unused may have no event series.

## Verification

`scripts/smoke_request_correlation.py --binary PATH` starts the real server and
checks exact request/attempt/byte totals alongside HTTP/1.1, TLS HTTP/2,
FastCGI, retry, reset and WebSocket behavior. It runs in native Linux, macOS and
Windows CI. On Linux,
`--container-image registry.opensuse.org/opensuse/tumbleweed:latest` runs the
supplied binary in that already-pulled rootless Podman image. This smoke accepts
only this tested runtime image, using host networking for the
loopback fixture and a private writable fixture mount. This is runtime proof,
not packaging validation of every published image.

See [checkpoint evidence](../evidence/observability-07.md) for actual results,
resource bounds and remaining release gates.
