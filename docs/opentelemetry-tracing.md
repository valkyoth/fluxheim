# OpenTelemetry Tracing

Status: future optional observability module.

Planned Cargo features:

- `otel-tracing`
- `otel-otlp`

Latest crate candidates checked on 2026-05-05:

- `opentelemetry 0.31.0`
- `opentelemetry_sdk 0.31.0`
- `opentelemetry-otlp 0.31.1`
- `tracing-opentelemetry 0.32.1`

Tracing is different from metrics and logs. Metrics show aggregate behavior,
logs record events, and traces explain the path of a specific request through
Fluxheim and its upstream services.

## Design Goals

- Keep OpenTelemetry code out of default builds.
- Use W3C Trace Context propagation.
- Correlate access logs, security events, and traces through a trace ID.
- Pair new operational observability with Prometheus metrics where practical:
  metrics provide aggregate service health, while OpenTelemetry explains the
  request path behind those aggregate signals.
- Keep tracing overhead bounded through sampling and background export.
- Avoid storing secrets, cookies, authorization headers, raw request bodies, or
  high-cardinality labels in spans.
- Make tracing incompatible with `privacy-mode` unless a future privacy-preserve
  propagation-only mode is explicitly designed.

## Stage 1: Trace Context Propagation

The first useful milestone is propagation without exporting spans.

Behavior:

- extract a valid `traceparent` header from incoming requests;
- reject malformed trace context without reflecting it;
- generate a new trace ID when no valid context exists;
- inject the selected context into upstream proxy requests;
- include the trace ID in structured access logs when logging is enabled;
- strip or normalize unsupported tracing headers according to policy.

This gives operators log/backend correlation even before Fluxheim exports full
traces.

## Stage 2: Internal Spans

After propagation is stable, Fluxheim should create spans around key request
operations.

Planned spans:

- `fluxheim.request`: root request span;
- `fluxheim.vhost_route`: host/SNI routing and policy selection;
- `fluxheim.request_filter`: request limits, header policy, and security
  checks;
- `fluxheim.auth_request`: future external authorization probe;
- `fluxheim.cache_lookup`: memory/disk cache lookup and hit/miss decision;
- `fluxheim.cache_store`: cache admission and write;
- `fluxheim.cache_purge`: admin-triggered cache invalidation by scope, prefix,
  wildcard, tag, or future soft-purge operation;
- `fluxheim.upstream_select`: load-balancer selection;
- `fluxheim.upstream_connect`: TCP/TLS connect and handshake;
- `fluxheim.upstream_response`: upstream first-byte and response metadata;
- `fluxheim.body_filter`: compression, image transforms, WAF body scanning, or
  other future body work;
- `fluxheim.static_file`: static resolution and body read path.

Span attributes must use bounded, low-cardinality values:

- vhost name;
- route name;
- status class;
- cache tier and hit/miss;
- upstream pool name, not arbitrary upstream URL;
- configured policy names;
- error class, not raw error strings when they may contain paths or secrets.

Avoid:

- raw path by default;
- query strings;
- cookies;
- authorization values;
- request/response bodies;
- client IP unless a non-privacy deployment explicitly enables it.

## Stage 3: OTLP Export

Full export should be optional and intended to send data to a local
OpenTelemetry Collector.

Requirements:

- export in a background worker;
- use bounded queues;
- expose exporter health through metrics/admin status when those modules are
  enabled;
- support explicit overflow behavior: `drop_new`, `drop_oldest`, or
  `block_startup_only`;
- never block request workers on collector availability;
- support TLS to the collector where the selected crate stack permits it;
- redact all configured sensitive fields before export.

The first exporter target should be OTLP over gRPC or HTTP, depending on the
most maintained Rust support at implementation time.

## Sampling

Tracing every request can be too expensive for a proxy. Sampling must be
configurable.

Planned sampling modes:

- `off`;
- `propagate_only`;
- fixed probabilistic sampling;
- status-aware sampling;
- latency-aware sampling;
- always sample admin/security failures when those modules are enabled.

Recommended future default for enabled export:

- sample a small percentage of normal successful requests;
- sample all `5xx` responses;
- sample requests slower than a configured latency threshold;
- respect inbound sampled flags only when the direct peer is trusted.

## Configuration Sketch

```toml
[tracing]
enabled = true
mode = "propagate_only"
traceparent = true
log_trace_id = true

[tracing.sampling]
success_ratio = 0.01
sample_5xx = true
slow_request_threshold = "500ms"

[tracing.otlp]
enabled = false
endpoint = "http://127.0.0.1:4317"
protocol = "grpc"
timeout = "250ms"
queue_size = 8192
overflow = "drop_new"
```

## Security Requirements

- Disabled by default at compile time and runtime.
- Remote export disabled unless explicitly configured.
- Collector endpoint must be validated.
- Trace and span IDs must be validated before reuse.
- Do not trust inbound sampled flags from untrusted peers by default.
- Do not expose trace IDs as authorization or session identifiers.
- Do not store trace context in cache keys.
- Do not propagate trace context to auth, metadata, ad, or AI decision services
  unless that service is explicitly configured to receive it.
- Redact trace attributes before logging/export.
- Reject with config validation when combined with `privacy-mode`, unless the
  future mode is strictly propagation-only and documented separately.

## Test Plan

- Extract valid `traceparent`.
- Reject malformed `traceparent`.
- Generate trace context when absent.
- Inject trace context into upstream requests.
- Correlate trace ID in access logs when logging is enabled.
- Ensure malformed trace headers are never reflected.
- Ensure untrusted sampled flags do not force sampling.
- Verify sampling decisions for success, slow, and `5xx` requests.
- Verify exporter queue overflow behavior.
- Verify collector failure never blocks request handling.
- Verify sensitive span attributes are redacted.
- Verify OpenTelemetry code is absent from default and privacy builds.
