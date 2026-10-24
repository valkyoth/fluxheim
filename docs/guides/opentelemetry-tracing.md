# OpenTelemetry Tracing

Unreleased 1.9.0 adds native request completion and upstream-attempt spans.
Tracing is optional and vendor-neutral. Collector/backend ingestion is a later
gate in the [observability plan](../roadmap/observability-commit-plan.md).

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
```

Use HTTPS for remote collectors. Without a custom CA bundle, HTTPS uses bundled
WebPKI roots. Plain HTTP produces a startup warning, including loopback.
The exporter has a bounded queue and drops new spans when full. Request tasks
never wait for collector network I/O. Export is best effort, not durable audit
storage: shutdown/crash can lose queued spans. gRPC export, advanced sampling
and durable acknowledgement are not implemented by this commit.

## Trust And Sampling

Only a direct transport peer matching `server.trusted_proxies` may supply an
accepted request ID or trace parent. Forwarded IP headers cannot grant trust.
Do not trust arbitrary public clients or shared container networks just to
enable traces. IDs are diagnostic correlation, never authorization credentials.

Request IDs must be a single header containing 1..128 ASCII letters, digits,
periods, hyphens or underscores. Duplicates, even identical values, are invalid.
Missing, invalid or untrusted IDs are replaced with a cryptographically random
`fh-` identifier, never truncated. Choose a dedicated `x-` header: protocol,
authentication and proxy-identity headers cannot be used for correlation.

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

## Live Verification

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
