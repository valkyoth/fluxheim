# OpenTelemetry Tracing

Tracing connects a request's work across services. A trace ID identifies the
whole operation; a span ID identifies one part, such as handling a request or
trying an upstream. A request ID is a separate diagnostic identifier, not a
trace and not an authorization credential.

Fluxheim produces native request-completion and upstream-attempt spans.
Tracing is optional and vendor-neutral. Real collector/backend ingestion is
covered by the [integration guide](collector-integrations.md) and
[native qualification](../evidence/observability-11.md).

## Configuration

Build with `otel-tracing` for propagation and correlated logs, or `otel-otlp`
for OTLP/HTTP JSON export too. `profile-observability` includes both.

```toml
[logging]
format = "json"

[logging.access]
enabled = true
request_id = true
request_id_header = "x-request-id"

[tracing]
enabled = true
mode = "propagate_only"
traceparent = true
log_trace_id = true

[tracing.otlp]
enabled = true
endpoint = "http://127.0.0.1:4318/v1/traces"
service_name = "fluxheim"
queue_size = 8192
timeout_secs = 2
# tls_ca_cert_path = "/etc/fluxheim/otlp-ca.pem"
# bearer_token_file = "/run/secrets/collector-token" # HTTPS only
```

HTTPS is required for non-loopback collectors, including private addresses and
DNS names. Without a custom CA bundle, HTTPS uses bundled WebPKI roots. Plain
HTTP is accepted only for numeric loopback addresses, not `localhost`.
The exporter has a bounded queue and drops new spans when full. Request tasks
never wait for collector network I/O. Export is best effort, not durable audit
storage: shutdown/crash can lose queued spans. gRPC export, advanced sampling
and durable acknowledgement are not implemented.

See [OTLP export lifecycle](otlp-export.md) for protected bearer-token files,
byte/queue limits, retry and partial-success policy, local health and shutdown.

## Every Tracing Option

All fields are global; there is no per-route sampling configuration. Unknown
fields and mode names are rejected. `sample_rate`, `always_on`, OTLP/gRPC mode
and exporter client-certificate options are not available.

| Option | Default | Meaning and validation |
| --- | --- | --- |
| `tracing.enabled` | `false` | Enables native trace contexts. Requires `otel-tracing`; rejected by privacy builds. Does not itself enable an exporter. |
| `tracing.mode` | `"propagate_only"` | Only `off` and `propagate_only` parse. Enabled tracing rejects `off`. Despite its name, `propagate_only` can export sampled spans with OTLP enabled; it makes no new sampling decision. |
| `tracing.traceparent` | `true` | Must be true for enabled `propagate_only`; false is not a supported export-without-propagation mode. |
| `tracing.log_trace_id` | `true` | Allows trace/span IDs in structured logs independently of propagation/export. |
| `tracing.otlp.enabled` | `false` | Export sampled spans; requires parent tracing enabled and `otel-otlp`. |
| `tracing.otlp.endpoint` | `"http://127.0.0.1:4318/v1/traces"` | Complete OTLP/HTTP JSON trace URL, up to 2048 bytes. HTTPS except numeric-loopback HTTP; no credentials, query or fragment. |
| `tracing.otlp.service_name` | `"fluxheim"` | Stable service identity, 1-128 visible ASCII bytes including spaces, no controls. Not a vhost selector. |
| `tracing.otlp.queue_size` | `8192` | Pending span payloads, 1-1,000,000, also subject to the fixed byte ceiling. Larger queues do not remove delivery deadlines. |
| `tracing.otlp.timeout_secs` | `2` | Total queue-residence/delivery/backoff budget, 1-60 seconds; not the application's request timeout. |
| `tracing.otlp.tls_ca_cert_path` | absent | Integrity-protected PEM CA bundle, relative to its source config file. Replaces bundled WebPKI roots for this exporter. |
| `tracing.otlp.bearer_token_file` | absent | Confidential collector token file, relative to its source config file. Requires HTTPS even on loopback; not an inline secret or public-listener token. |

With parent tracing disabled, enabling its exporter is rejected. Otherwise
disabled tracing skips trace-policy validation; a disabled exporter skips its
own endpoint/service/limit/file policy checks. Inactive values must still parse
with the correct types. Paths still resolve relative to the source file.
Enabling a block later can expose a previously inactive error.

Any `tracing.*` change requires process restart/upgrade, not snapshot-only reload.
Collector tokens and CA bundles load at exporter creation; file replacement alone
does not update the running exporter. Coordinate restart and collector credentials.
See [OTLP export](otlp-export.md) for exact bounds and [metrics](metrics.md) for
the independent local scrape service.

## Complete Local Example

[The complete proxy configuration](../../examples/tracing/proxy.toml) expects
an HTTP origin at 127.0.0.1:9001 and an OTLP/HTTP JSON collector at
127.0.0.1:4318. Fluxheim listens at 127.0.0.1:8080 and exposes diagnostics at
127.0.0.1:9091. It trusts **loopback for this demonstration only**: every local
process can supply a sampled parent. Review direct-peer ownership before copying
this rule to a public/shared-proxy deployment.

Start from an owner-controlled configuration directory:

```sh
fluxheim --config proxy.toml
```

Send a trusted sampled example (these are demonstration IDs, not secrets):

```sh
curl --fail --resolve traces.example.test:8080:127.0.0.1 \
  -H 'x-request-id: tracing-guide-request' \
  -H 'traceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01' \
  http://traces.example.test:8080/
```

Expect one server span and one client span for a successful single-attempt proxy
request. They share the trace ID but have different span IDs. The client span
is a child of Fluxheim's server span, which is a child of the supplied parent.
Without the parent, an ordinary curl creates an **unsampled** local context:
IDs can appear in logs/headers but no spans are exported. Change the final `01`
to `00` to demonstrate trusted unsampled context.

For propagation without a collector, set `tracing.otlp.enabled = false`. For
export without trace IDs in logs, set `tracing.log_trace_id = false`. Turning
off `logging.access.enabled` suppresses access events, not span export. To
disable tracing entirely, set both tracing and its exporter `enabled = false`.
The native router strips inbound traceparent/tracestate/baggage even when no
trace is created: disabled tracing is not transparent pass-through. Disabling
request-ID management leaves that header unmanaged rather than removing it;
use an explicit header policy if the downstream must not receive it.

## Trust And Sampling

Only a direct transport peer matching `server.trusted_proxies` may supply an
accepted request ID or trace parent. Forwarded IP headers cannot grant trust.
Do not trust arbitrary public clients or shared container networks just to
enable traces. IDs are diagnostic correlation, never authorization credentials.

Request IDs must be a single header containing 1..128 ASCII letters, digits,
periods, hyphens or underscores. Duplicates, even identical values, are invalid.
Missing, invalid or untrusted IDs are replaced with a cryptographically random
`fh-` identifier, never truncated. `request_id_header` accepts only
`x-request-id` or `x-correlation-id` (case-insensitive). Other names are rejected
whenever `request_id = true`, even if access-log output is disabled. These two
headers are diagnostic identifiers, not authentication or proxy identity.

A trace parent must be a single 55-byte W3C version-00 value with nonzero trace
and parent span IDs. Invalid, conflicting or untrusted parents produce a fresh
trace. Every request has a fresh server span ID. `baggage` and `tracestate` are
not implicitly forwarded or stored.

The existing `propagate_only` mode makes no new sampling decision. Only an
accepted trusted parent's sampled bit enables export. Locally generated roots
are unsampled. With OTLP enabled, sampled requests and attempts are exported;
unsampled requests still have IDs in enabled logs and propagation. There is no
hidden sample-all default. To test export, send a sampled parent from a
genuinely trusted upstream proxy.

`logging.access.enabled = false` suppresses access events, not security/errors.
`logging.access.request_id = false` disables request-ID capture and generation.
`tracing.log_trace_id = false` suppresses trace/span IDs in logs independently
of export. Compile-time `privacy-mode` prevents request correlation/access events
and rejects enabled tracing configuration.

## Completion And Attempts

- One access completion attempt and, when sampled, one server span cover each admitted
  application request. HTTP/1.1 keep-alive requests and multiplexed HTTP/2
  streams have separate contexts.
- Successful response writing records `completed`, meaning acceptance by the
  local transport, not proof of remote application consumption. HTTP/1.1 flush
  and HTTP/2 end-of-stream submission are the respective boundaries.
- Write errors record `failed`; dropped handler/response futures record
  `cancelled`, including timeout/shutdown cancellation. Drop never emits a
  second outcome after completion. Failed partial writes report zero body
  bytes instead of claiming full delivery. Cancellation may have no status.
- Streaming/upgrade takeover has one lifetime outcome on tunnel completion,
  error or cancellation, without frame contents or guessed status/byte counts.
- Rejections before a complete request reaches the router, such as malformed
  HTTP heads or incomplete uploads, do not get fabricated correlated outcomes.

Exactly-once completion does not promise delivery. Access records share the
bounded ordinary dispatcher: admission-lock contention, rate limiting, a full
queue or sink failure can drop records. Inspect authenticated status counters;
do not use access logs as a lossless audit journal.

HTTP sends and FastCGI transport attempts get separate child spans. Safe
stale-connection retries get new span IDs. Load-balancer and PHP retries count
against the same logical request. Static/cache hits need no upstream attempt.
FastCGI transport spans do not claim an HTTP status before parsing. Bounded
protocol-error events are correlated with the logical request.

Provenance is established before header rewriting. Explicit header policy can
remove propagation without erasing internal IDs. Attempts replace an existing
traceparent with their child context but do not reinsert a removed header.
No request-ID response header is automatically added. Correlation alone does
not add IDs to cache keys. Detached background tasks do not inherit foreground
context or emit another foreground completion. Cache revalidation retains its
existing outbound header snapshot; this commit does not create separately
instrumented background traces or rewrite those cache-refresh headers. Health
checks likewise do not inherit the request's local correlation scope.

## Data Boundaries

Access events contain finite method/outcome, status, duration, successful body
bytes, attempt count and bounded IDs. Native spans contain bounded essentials
and parentage, not complete module timing or route/vhost labels yet.

Raw paths/URLs, queries, client IPs, cookies, authorization, bodies and arbitrary
errors are not captured. Legacy `include_host`, `include_path`, `include_route`,
`include_client_ip`, `include_upstream` and `include_cache_phase` settings do not
expand this structured schema into raw-data capture.
Their currently unused configuration contract is tracked as the documented limitation; see the
[logging option inventory](logging.md#every-logging-option) and planned correction
before relying on those settings for a field-selection policy.

### Current Span Fields

| Field | Native producer behavior |
| --- | --- |
| Trace/span/parent IDs and kind | Server request and client attempt parentage; new span IDs for retries |
| Name | Fixed `HTTP request` or `Upstream attempt`, never the URL |
| Method and status | Finite method bucket and optional HTTP status; missing status is not guessed success |
| Error/status | HTTP 5xx or transport failure marks error; HTTP 4xx is not automatically a span error |
| Timestamps | Unix nanoseconds, end clamped not to precede start. Metrics use separate monotonic durations. |
| Body sizes | Request body length; successful server response body bytes. Attempt response bytes are currently zero, not measured transfer size. |
| Attempt number | Present on client attempts; incremented for request-scoped retries |
| `service.name`, `service.version` | Configured exporter identity and compiled crate version |
| `fluxheim.vhost` | Currently empty, not the configured vhost name |
| Route, cache phase/timings, load-balancer alias/retries, compression and PHP annotations | Serializer supports optional fields but the native producer does not populate them |

**Current limitation:** native module/resource enrichment is incomplete.
Do not build per-vhost or cache-latency dashboards from serializer-only fields.
Earlier reference text promising them was incorrect. The queued correction must
use bounded configured identities and measured module data, not raw Host values,
URLs or guessed timings. This is separate from access-log controls.
Database queries, application stack frames and PHP-internal spans require
application instrumentation; Fluxheim is not an injected application APM agent.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| IDs in logs but no export | Export enabled? Direct peer trusted and accepted parent sampled? Generated roots are unsampled. |
| Parent or request ID replaced | Direct-peer trust, duplicates and bounded syntax; forwarded client IP cannot confer trust. |
| Export works but log IDs absent | `log_trace_id`, access/filter policy and dispatcher health; span export does not depend on log admission. |
| Accepted counter rises but backend empty | Accepted means queued. Check success/partial/failed/dropped counters and backend time range/service filter. |
| Missing module/resource fields | Current native limitations above; no configuration switch populates these fields. |
| Token or CA change has no effect | Restart/upgrade; file replacement is not exporter reload. |

## Live Verification

The standard-library guide smoke runs the actual example with an HTTP origin
and JSON collector, including trust/sampling, disabled tracing/export, log-ID
suppression and the native attribute gap:

```sh
python3 scripts/smoke_tracing_examples.py --binary target/debug/fluxheim
```

For broader HTTP/2, FastCGI and cancellation coverage:

```sh
python3 -m venv target/correlation-venv
target/correlation-venv/bin/python -m pip install -r scripts/request_correlation_requirements.txt
cargo build --locked --no-default-features --features profile-observability,php-fpm --bin fluxheim
target/correlation-venv/bin/python scripts/smoke_request_correlation.py --binary target/debug/fluxheim
```

On Windows use `target/correlation-venv/Scripts/python.exe` and
`target/debug/fluxheim.exe`. The smoke starts a real Fluxheim process plus local
HTTP, FastCGI protocol and OTLP fixtures. It decodes actual access JSON and
spans for concurrent HTTP/1.1 and TLS HTTP/2 requests, retry/reset behavior and
hostile context. It is not a PHP interpreter or proof that an APM backend
stored the spans; those have separate release gates.
