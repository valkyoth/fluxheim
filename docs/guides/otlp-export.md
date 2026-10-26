# OTLP Export Lifecycle

Unreleased 1.9.0 supports optional OTLP/HTTP JSON metrics and traces. This is
best-effort telemetry, not durable audit storage, an application APM agent, or
exactly-once delivery. Collector failure does not make the public listener or
local metrics listener unready. Backend/dashboard qualification is Commit 10.

## Configure A Collector

`profile-observability` includes `metrics-otlp` and `otel-otlp`. A local collector
can receive plaintext HTTP on loopback. Explicitly configured private addresses
remain supported; the operator is responsible for collector/network trust.

```toml
[metrics]
enabled = true
listen = "127.0.0.1:9091"

[metrics.otlp]
enabled = true
endpoint = "https://collector.example.net/v1/metrics"
service_name = "fluxheim"
interval_secs = 15
timeout_secs = 2
tls_ca_cert_path = "/etc/fluxheim/collector-ca.pem"
bearer_token_file = "/run/secrets/collector-token"

[tracing]
enabled = true

[tracing.otlp]
enabled = true
endpoint = "https://collector.example.net/v1/traces"
service_name = "fluxheim"
queue_size = 8192
timeout_secs = 2
tls_ca_cert_path = "/etc/fluxheim/collector-ca.pem"
bearer_token_file = "/run/secrets/collector-token"
```

Both file options are optional. Without a custom CA, HTTPS uses bundled WebPKI
roots. Certificate chains and server names are verified; verification cannot be
disabled. Custom CA files must be regular files in an integrity-protected path,
not linked or writable by untrusted users. The token file must additionally be
confidential: owner-only `0600` on Unix, or the existing confidential-secret ACL
policy on Windows. Paths resolve relative to the configuration directory.

Put only the token in the file, not the `Bearer ` prefix. The reader accepts a
trailing CR/LF, limits the file to 4096 bytes and rejects embedded whitespace or
control characters. Bearer authentication requires HTTPS, including loopback.
The token is read at exporter creation; replace it securely and restart Fluxheim
to rotate it. The retained token buffer is zeroized on drop, but transient HTTP/
TLS library copies are not a protected-memory guarantee. mTLS client credentials
and arbitrary authentication headers are not implemented.

Endpoint length is capped at 2048 bytes. Credentials in URLs, query strings,
fragments and control characters are rejected. Redirects are never followed,
so authentication cannot be forwarded to a redirect target. Environment HTTP
proxies are deliberately disabled for this connection. Use a directly configured
collector or collector gateway instead. Collector reply bodies, diagnostic
messages and authorization values are not emitted by exporter diagnostics.

Tracing retains its existing trusted-parent sampling policy. Enabling OTLP does
not sample all traffic; see [tracing](opentelemetry-tracing.md).

## Limits And Admission

| Resource | Limit / behavior |
| --- | --- |
| Trace batch | One completed span per request; at most 256 bytes per string field before JSON encoding |
| Metrics batch | One cumulative snapshot; preflight rejects oversized input before building a second JSON tree |
| Metrics preflight | At most 1024 families; names 256 bytes, descriptions 1024; 16 labels per point, label names 128/value 256; 128 histogram buckets; aggregate weighted input budget 512 KiB |
| Queued trace items | `queue_size`, 1..1,000,000; default 8192, subject also to the byte ceiling |
| Queued metrics items | One pending snapshot; an active snapshot can also be in flight |
| Payload storage | At most 8 MiB queued string capacity plus one active payload of at most 4 MiB per worker; queue-entry/JSON/transport overhead is additional |
| Wire request | At most 4 MiB; oversized snapshots are dropped as a whole, not truncated into invalid OTLP |
| Response | At most 16 KiB headers and 16 KiB successful-response body; error bodies are not consumed |
| Concurrent delivery | One HTTP request per worker; at most 32 workers process-wide |
| DNS | One process-wide blocking resolver worker and one waiting lookup; at most 16 returned addresses, caller wait capped at two seconds |
| Attempts | At most three, including the initial request |
| Elapsed budget | `timeout_secs`, 1..60 seconds, including queue residence and backoff; each individual HTTP operation is capped at two seconds |
| Backoff | 100 ms then 200 ms, each with 0..50 ms jitter, subject to the elapsed deadline |

Admission never waits on collector I/O or queue capacity. A short mutex protects
queue bookkeeping; it is never held during delivery, retry waits or payload
encoding. This is not a lock-free queue. New data is dropped when the queue is
full, stopped or out of byte budget. Expired queued data is discarded without
contacting the collector. Metrics collection
still obtains the existing bounded registry snapshot; exporter limits are not
a new bound on arbitrary third-party Prometheus collector implementations.

OS DNS calls cannot be cancelled portably. A stuck OS lookup can retain the
single DNS thread until the resolver returns, but cannot create more DNS threads
per retry. Numeric collector IPs do not use that worker. HTTPS names must still
match the certificate; do not disable verification to work around DNS failure.

## Results And Recovery

The [OTLP specification](https://opentelemetry.io/docs/specs/otlp/) defines HTTP
200 success, partial success, and the retryable HTTP statuses used here.

- HTTP 200 with a JSON object and no rejection/warning is successful. An empty
  HTTP 200 body is tolerated for existing collectors. Invalid JSON, invalid
  partial-success fields and oversized replies are terminal failures.
- A partial-success reply or warning is counted separately and never retried.
  Rejected subsets cannot be recovered from that reply. Its free-text message
  is deliberately not copied into logs or metric labels.
- HTTP 429, 502, 503 and 504 are retryable. Other statuses, including 400,
  401, 403 and redirects, are terminal for that batch. Certificate/protocol
  invalid-data errors are terminal; transient transport failures can retry.
- Numeric `Retry-After` seconds are honored within the deadline. A delay that
  cannot fit causes a drop rather than an extended sleep. HTTP-date values are
  not interpreted in this checkpoint; they use the bounded backoff instead.
- Exhausted retries, encoding/admission rejection and shutdown discards are
  losses, not deferred persistent work. New batches can succeed after collector
  recovery without replaying a disk backlog. Metrics remain cumulative.

A lost response can occur after the collector accepted a batch. Retrying the
same payload can therefore duplicate data. Success means collector acceptance,
not durable storage or eventual availability in a dashboard.

## Shutdown

Stopping a worker rejects new admission and requests a two-second best-effort
drain. Dropping the last producer also requests shutdown. During normal native
runtime shutdown, request tasks drain first; a final process-wide exporter wait
uses one shared two-second deadline, not two seconds per worker. Existing
per-attempt timeouts bound in-flight operations. The DNS exception above remains.

Forced termination, crashes and exhaustion of the drain deadline can lose queued
or in-flight data. No journal is written and no export acknowledgement is required
for an HTTP response or administrator mutation to succeed.

## Local Health

When metrics and an OTLP feature are compiled, `/metrics` includes these fixed
families with only `signal="metrics"` or `signal="traces"`:

- `fluxheim_otlp_accepted_total`: batches admitted, not delivered.
- `fluxheim_otlp_success_total`: fully successful replies, including tolerated
  empty responses.
- `fluxheim_otlp_partial_total`: partial/warning replies; not a rejected-point count.
- `fluxheim_otlp_failed_total`: batches that failed delivery or expired.
- `fluxheim_otlp_dropped_total`: rejected admissions, failed batches and shutdown
  discards. Partial batches have their own counter rather than a fabricated loss count.
- `fluxheim_otlp_retries_total`: retries admitted after backoff.
- `fluxheim_otlp_queued_bytes`: queued string capacity, excluding the active batch.
- `fluxheim_otlp_active_requests`: HTTP requests currently in progress.

These diagnostics are local-only, not fed back into OTLP. They use saturating
process-lifetime counters and reset on restart. Gauges aggregate workers, so a
process with multiple trace workers may show more than one active trace request.
Zero activity alone does not prove an exporter is configured or healthy.
The existing `fluxheim_metrics_otlp_exports_total{outcome}` still records final
metrics success/failure; partial replies count as failure there.

## Exercise Failure And Recovery

```sh
cargo test --locked -p fluxheim-observability --all-features otlp_
cargo build --locked --no-default-features --features profile-observability,php-fpm --bin fluxheim
python3 -m venv target/correlation-venv
target/correlation-venv/bin/python -m pip install -r scripts/request_correlation_requirements.txt
target/correlation-venv/bin/python scripts/smoke_otlp_lifecycle.py --binary target/debug/fluxheim
```

On Windows use `target/correlation-venv/Scripts/python.exe` and
`target/debug/fluxheim.exe`. Linux can additionally use
`--container-image registry.opensuse.org/opensuse/tumbleweed:latest` with that
runtime image already pulled. This runs the supplied binary in rootless Podman,
not a newly published release image. The smoke checks live serving/scraping,
HTTP/auth failures, malformed/oversized/partial replies, stalled response bodies,
recovery, bounds and a collector-secret canary. Rust tests cover TLS, protected
credentials and worker shutdown; Windows subprocess termination in the Python
smoke is not proof of graceful Windows service shutdown.
