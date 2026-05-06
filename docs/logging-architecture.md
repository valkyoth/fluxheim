# Logging Architecture

Fluxheim logging should be structured, asynchronous, and explicit about the
tradeoff between request latency and durability. Logging must never hide
security-relevant events, and remote logging failure must not break normal
traffic.

## Goals

- Use `tracing` as the core instrumentation API.
- Emit production logs as JSON through serde-backed formatting.
- Keep stdout available as the default sink for systemd, Podman, and local
  debugging.
- Avoid disk or network writes on request worker hot paths.
- Add remote logging only behind explicit config and optional compile features.
- Make overflow behavior explicit instead of pretending logs are always both
  non-blocking and lossless.

Latest reviewed crates:

- `tracing 0.1.44`, MIT.
- `tracing-subscriber 0.3.23`, MIT.
- `tracing-appender 0.2.5`, MIT.
- `tracing-serde 0.2.0`, MIT.

## Log Classes

Fluxheim should split logs by intent:

- `access`: one event per completed request.
- `error`: internal failures and unexpected runtime errors.
- `security`: rejected requests, request-smuggling attempts, admin auth
  failures, path traversal, denied PHP/CGI execution, and TLS/cert permission
  failures.
- `audit`: admin operations such as snapshot, rollback, reload, purge, cache
  activity reset, certificate renewal, and future account/key changes.

Security and audit logs should not be silently disabled per vhost. They may be
rerouted or filtered by level, but Fluxheim should make disabling them an
explicit high-risk operator choice.

## Event Fields

Access events should include:

- timestamp
- level
- target/module
- request_id
- vhost
- method
- path
- query_present
- protocol
- status
- latency_ms
- remote_addr
- user_agent, length-capped
- referer, length-capped
- upstream, when proxied
- cache_status, when cache participates
- tls, when known
- legacy_protocol, when future legacy static listeners are used

Audit/security events should include action/outcome fields and avoid raw secret
values.

## Pipeline

The desired pipeline has three stages:

1. Capture: request path emits `tracing` events with structured fields.
2. Buffer: events enter a bounded async queue.
3. Dispatch: a background dispatcher writes to configured sinks.

The request worker must never perform slow remote network logging directly.

## Overflow Policy

Fluxheim must expose an explicit overflow policy:

- `drop_new`: fastest; increments dropped-log metrics.
- `block`: preserves logs but can slow request handling.
- `spool`: writes to a bounded durable disk queue; best durability but more
  operational complexity.

Without `spool`, Fluxheim must not claim zero data loss. With `block`, Fluxheim
must not claim zero request latency impact.

## Sinks

Initial sinks:

- `stdout`: default.
- `file`: optional structured local file.
- `remote_tcp_tls`: future production sink for Vector, Logstash, or similar.
- `remote_udp`: future non-critical sink only; never for audit/security.

Remote sinks should be optional compile-time support, for example
`logging-remote`. Durable disk queue support should be behind `logging-spool`.

## Circuit Breaker

Remote dispatch should use a circuit breaker:

- `connected`: send to remote sink.
- `tripped`: remote failed; write to stdout or spool.
- `recovering`: attempt periodic reconnect/heartbeat.

On send failure, the dispatcher should immediately fallback for that event,
trip the remote sink, and increment metrics. Reconnect attempts should use
bounded exponential backoff.

## Security Requirements

- Redact `Authorization`, `Cookie`, `Set-Cookie`, admin bearer tokens, ACME EAB
  values, API keys, and configured sensitive headers/fields.
- Never log request bodies by default.
- Length-cap paths, headers, error messages, and upstream error text.
- Use serde/JSON formatting, not hand-built JSON strings.
- Mark fallback source, for example `log_sink="stdout-fallback"` or
  `log_sink="spool-fallback"`.
- Make audit/security logs available to stdout even when remote logging fails.
- Protect local log files and spool directories with owner-only permissions
  where supported.

## Config Shape

Initial target:

```toml
[logging]
level = "info"
format = "json"
target = "stderr"
queue_size = 65536
overflow = "spool" # drop_new | block | spool

[logging.access]
enabled = true
include_host = true
include_path = true
request_id = true
request_id_header = "x-request-id"

[logging.security]
enabled = true

[logging.audit]
enabled = true

[logging.file]
enabled = false
path = "/var/log/fluxheim/fluxheim.jsonl"

[logging.remote]
enabled = false
protocol = "tcp_tls"
address = "10.0.0.5:5044"
timeout_secs = 2
retry_initial_secs = 5
retry_max_secs = 300

[logging.spool]
enabled = true
path = "/var/lib/fluxheim/log-spool"
max_size_bytes = "1GiB"
```

Implemented baseline: `logging.access.enabled` controls a compact JSON access
event emitted from Pingora's `logging` hook. It records method, optional raw
host, vhost,
optional query-free path, status, low-cardinality status class, error flag,
request ID, request body bytes seen, response body bytes seen, and latency. If
request IDs are enabled, Fluxheim reuses a valid inbound request ID from
`request_id_header` or generates one and passes it upstream before normal header
policy mutations run. This baseline uses the existing `log` stack. stderr/stdout
and a disabled-by-default
`[logging.file]` sink are implemented; the async dispatcher and remote sinks
remain future work.

`logging.level` and `logging.format` are applied at startup through
`env_logger`; `RUST_LOG` can still override the level for local debugging.
Changing either setting after startup currently requires a process upgrade
because the logger is initialized once. JSON format emits structured internal
runtime records, while access events remain direct JSON access records.

## Implementation Stages

1. Add typed access-log config, request IDs, and baseline JSON access events
   through `log`.
2. Add `tracing`, JSON stdout formatting, and bridge existing `log` records.
3. Add access/security/audit event schema and request ids.
4. Add bounded dispatcher queue with `drop_new` and `block` policies.
5. Add file sink and protected local spool directory.
6. Add remote TCP/TLS sink with circuit breaker and fallback.
7. Expose log health through Prometheus/admin status:
   dropped logs, spooled logs, remote failures, current circuit state, and
   reconnect attempts.

## Tests

Required tests:

- JSON output contains expected request fields.
- Secret fields are redacted.
- Long fields are capped.
- Queue overflow follows configured policy.
- Remote failure falls back to stdout/spool.
- Circuit breaker trips and recovers.
- Audit/security events are emitted for admin failures and denied requests.
- File/spool path validation rejects insecure paths where possible.
