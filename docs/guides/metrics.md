# Metrics

Metrics answer questions such as how many requests arrived, how long they took,
and whether the cache or telemetry pipeline is failing. They are aggregate
measurements, not a request log or a trace of an application's database calls.

Requires a build with `metrics` (for example `profile-observability`). The
listener is disabled by default and is separate from public vhost listeners.
Start with loopback and a private token file:

```toml
[metrics]
enabled = true
listen = "127.0.0.1:9091"
require_loopback = true
token_file = "/run/secrets/fluxheim-metrics-token"
```

Read `GET /metrics` with Prometheus. Optional `[metrics.otlp]` exports the same
registry, names, descriptions, labels and cumulative measurements. Duration
units are seconds (`s`), byte units are bytes (`By`), other quantities use `1`.
Zero-retention privacy builds continue to reject the `metrics` feature entirely;
this checkpoint does not relax that boundary. In metrics-enabled builds,
request/trace IDs, raw Host values, paths, queries, bodies, certificates and
client IPs are not operational metric labels.
Access-log filtering and sampled tracing do not disable aggregate measurements.
See [OTLP export lifecycle](otlp-export.md) for collector authentication, byte
limits, retries, shutdown and local exporter-health metrics. Oversized export
snapshots are rejected without disabling local scraping.

## Working Example

[Complete proxy recipe](../../examples/metrics/proxy.toml) runs public HTTP at
127.0.0.1:8080, forwards to an origin on 127.0.0.1:9001 and exposes metrics only at
127.0.0.1:9091. Copy it into an owner-controlled configuration directory. The
relative `metrics-token` filename is resolved beside the configuration file,
not beside the executable. On Unix, from that directory:

```sh
umask 077
openssl rand -hex 32 > metrics-token
chmod 600 metrics-token
fluxheim --config proxy.toml
```

Use an existing HTTP origin at the configured address. In a separate terminal:

```sh
curl --fail --resolve metrics.example.test:8080:127.0.0.1 \
  http://metrics.example.test:8080/
```

Give the monitoring agent its own protected copy of the token. A Prometheus
scrape fragment, when Prometheus runs on the **same host/network namespace**, is:

```yaml
scrape_configs:
  - job_name: fluxheim
    scrape_interval: 15s
    metrics_path: /metrics
    authorization:
      type: Bearer
      credentials_file: /run/secrets/fluxheim-metrics-token
    static_configs:
      - targets: ['127.0.0.1:9091']
```

The credentials file is read by Prometheus, so its path and read permission must
work inside that process/container too. Container loopback is not host loopback.
Use a same-network-namespace agent, or a separately authenticated TLS proxy for
remote collection; do not publish this HTTP listener to the Internet. See the
[collector examples and dashboards](collector-integrations.md) for runnable
Prometheus/Grafana and SigNoz arrangements.

## Every Configuration Option

These are the complete leaf fields of `[metrics]` and `[metrics.otlp]`. They are
global, not per vhost/route. Unknown fields are rejected. There is no configurable
scrape interval inside Fluxheim: Prometheus chooses when to read `/metrics`.

| Option | Default | Meaning and validation |
| --- | --- | --- |
| `metrics.enabled` | `false` | Start the dedicated HTTP scrape listener; requires the `metrics` build feature. Also required when metrics OTLP export is enabled. |
| `metrics.listen` | `"127.0.0.1:9091"` | Numeric IP and port, for example `"[::1]:9091"`; not a DNS name. Parsed even when disabled. Port 0 is accepted but unsuitable for a fixed scrape target. |
| `metrics.require_loopback` | `true` | When enabled, reject non-loopback bind addresses. Setting false permits a remote bind; it does **not** add TLS, a token, a firewall or trusted-proxy rules. |
| `metrics.token_env` | absent | Legacy parsed field, always rejected even when metrics are disabled. Use a file instead. |
| `metrics.token_file` | absent | Optional scrape bearer-token file. Without it, anyone who can reach the listener can scrape. Empty paths and unsafe parents are rejected; active startup reads and validates the file. |
| `metrics.otlp.enabled` | `false` | Push cumulative metrics as OTLP/HTTP JSON; requires `metrics-otlp` and `metrics.enabled`. Not a second scrape server. |
| `metrics.otlp.endpoint` | `"http://127.0.0.1:9090/api/v1/otlp/v1/metrics"` | Complete metrics ingestion URL, at most 2048 bytes. HTTPS except numeric loopback HTTP; no credentials, query or fragment. DNS `localhost` is not the HTTP exception. |
| `metrics.otlp.service_name` | `"fluxheim"` | OTLP service identity, 1-128 visible ASCII bytes, without controls. Use a stable deployment name rather than a request-derived value. |
| `metrics.otlp.interval_secs` | `15` | Push collection interval, 1-3600 seconds. Independent of Prometheus scraping. |
| `metrics.otlp.timeout_secs` | `2` | Export request timeout, 1-60 seconds. |
| `metrics.otlp.tls_ca_cert_path` | absent | Optional PEM CA bundle for an HTTPS collector; relative to the config file. Otherwise uses bundled WebPKI roots. |
| `metrics.otlp.bearer_token_file` | absent | Separate protected collector credential, not the scrape token. Requires HTTPS even for loopback. Relative to the config file. |

Disabled OTLP blocks skip exporter policy validation. In contrast, the parent
metrics block still checks listen syntax, `token_env`, empty token paths and
supplied path trust. Enabling OTLP without metrics fails validation. A FIPS-required
configuration has additional transport restrictions; see [FIPS](fips.md).
See [OTLP configuration and lifecycle](otlp-export.md) for delivery bounds,
collector CA trust, credential rules, retries and shutdown behavior.

## Scrape Authentication And Lifecycle

The built-in endpoint is **plain HTTP**, including when public vhosts use HTTPS.
Public vhost ACLs, external authentication and rate limits do not automatically
protect the metrics service. Keep loopback, firewall it separately and use a
token when local processes are not all trusted. A bearer token does not encrypt
remote traffic. Prefer an authenticated TLS gateway or secure OTLP export for
off-host monitoring.

| Request | Result |
| --- | --- |
| `GET /metrics` with required token | 200, Prometheus text exposition |
| `HEAD /metrics` with required token | 200, empty body, length of the generated representation |
| `/metrics?anything` | Same endpoint; query does not select/filter metrics |
| `/`, `/metrics/` or another path | 404, not a dashboard or health endpoint |
| Missing/wrong token on `/metrics` | 401 and `WWW-Authenticate: Bearer realm="metrics"` |
| Unsupported method with correct token | 405 and `Allow: GET, HEAD` |

Use `Authorization: Bearer TOKEN` with that exact scheme spelling. Authentication
is checked before method dispatch on the metrics path. The file is UTF-8, at most
8192 bytes **including its trailing newline**; surrounding whitespace is trimmed
and an empty result is rejected. Use a random single-line token. Missing,
oversized or invalid-UTF-8 files fail active service startup, not anonymous fallback.
Parent links and writable parents are rejected; do not use a symlinked secret
mount without checking compatibility.

**Current limitation:** unlike the Windows
confidential-file ACL opener, the Unix metrics reader does not enforce private
leaf-file permissions. Do not interpret successful startup as a confidentiality
check. Provision the token as service-owned mode 0600 in an owner-controlled
directory, with no group/other writes or untrusted ancestor links. Group/world
readability or writability must be prevented by deployment permissions until the
queued correction is implemented. Keep token values out of command arguments,
logs and the repository. On Windows, use a protected ACL admitting only the
service identity and trusted administrators/system.

The token is read once when constructing the service. Replacing its file does
**not** rotate the running credential; restart/upgrade Fluxheim and update the
collector's copy in a coordinated window. Changing any `metrics.*` configuration
is classified as requiring a process upgrade, not snapshot-only reload. A bind
failure is fatal to startup; choose a free dedicated port. Scrapes observe current
in-memory counters; they are not durable storage. Retention belongs to the
monitoring backend.

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

PHP handler counters and duration histograms count direct and fallback PHP
dispatch once, including rejected requests and gateway errors. `outcome=response`
means the handler produced a response, not that PHP or the downstream write
succeeded; use `status_class` to distinguish HTTP errors. Dropping an active
handler reports `outcome=cancelled,status_class=unknown`. Static files and
FastCGI retries are not additional PHP requests. Duration ends when the handler
returns, before downstream response delivery.

A zero **Log sink errors** or **Metric cardinality overflow** panel is expected
in a healthy deployment. **Active requests** is an instantaneous gauge: short
requests can finish between scrapes and leave a flat zero despite nonzero request
rates. **PHP requests / second** should increase during sustained PHP traffic;
missing PHP instrumentation is not evidence of an idle application.

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

## Subsystem Metrics And Known Gaps

Registration of a metric family does not prove its producer runs. Variable-label
families can be absent until the first observation. Use the feature guide for
the event meanings and supported runtime; do not invent zeros for missing series.

| Area | Measurements and current boundaries |
| --- | --- |
| [Cache](cache.md) | Configuration, memory/disk occupancy, activity, latency and purge families. Configuration capacity is not measured resident memory. Cache activity reset does not reset Prometheus lifetime counters. |
| [Load balancer](load-balancer.md) | Configured pools, selection/retry/ejection events and queue-wait histogram; not complete active-health status or every accepted latency policy. |
| [PHP](php.md) | Request/outcome/duration producers are live. Specific native pool/retry/STDERR metric producers remain unwired. |
| [Access control](access-control.md) | Legacy scoped edge-policy producer remains unwired for auth/ACL/admission decisions. Operational security observations are a different signal. |
| [ACME](acme.md) | Bounded lifecycle event counter; not certificate-expiry inventory. A separate one-shot companion process does not share the server's registry. |
| [Wasm](wasm-extensibility.md) | Execution count, duration and admission rejection by bounded plugin/phase/outcome identities; not application-internal spans. |
| [TCP streams](tcp-streams.md) | Connection outcomes and directional copied bytes; separate from logical HTTP traffic. |
| [UDP](udp.md) | Datagram/drop/active-session families; active gauge incorrectly stays zero with an unlimited cap. |

Inspect a real scrape for the selected build/workload. The registry and label
allowlists live in `src/metrics_registry*.rs` and
`crates/fluxheim-observability/src/metrics_labels.rs`. Legacy and operational
families can describe overlapping work: sum only compatible signals.

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

Example queries for the signal contract. The
[collector integration guide](collector-integrations.md) covers the qualified
dashboards; [alert rules and tests](../../examples/observability/alerts.yml) add
scrape availability, sink failure, cardinality overflow and OTLP loss examples:

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

`python3 scripts/smoke_metrics_examples.py --binary target/debug/fluxheim`
executes the complete recipe with an actual local origin: authenticated and
anonymous scraping, methods/paths, request counts, secret canaries, file rotation
and restart, malformed token rejection, and the Unix permission-gap
characterization. It uses private temporary fixtures, numeric loopback ports and
bounded child cleanup. The characterization is not acceptance of weak permissions.
Configuration tests cover all defaults, inactive validation and restart policy;
the Python documentation guard checks every leaf field against the option table.

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
