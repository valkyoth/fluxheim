# Operational Visibility

Applies to **1.9.0, currently unreleased**. Start here to connect a symptom to
logs, metrics and traces. Fluxheim still serves without any external collector;
Grafana and SigNoz are optional observers, not management interfaces.

## Choose The Signal

| Question | Start with | Important limit |
| --- | --- | --- |
| Why did a request fail? | Structured error/access events and their request ID | One incident can produce several owner observations; not every parser rejection becomes an access event |
| Is traffic or latency changing? | [Prometheus metrics](metrics.md) | Global logical request totals differ from handler/attempt totals; do not add them together |
| Where did a sampled request wait? | [Server and upstream-attempt spans](opentelemetry-tracing.md) | No database queries or application-internal PHP spans without upstream instrumentation |
| Is recovery pending? | [Operational status](operational-status.md) | Readiness describes admin recovery, not end-to-end health of every origin |
| Is telemetry being lost? | Local dispatcher/exporter counters and status | Collector acceptance, file writes and memory admission do not prove durable persistence |

## Start Locally

The repository includes a [complete local config](../../examples/observability/local.toml)
with JSON access events, local metrics and a static site. It enables no admin
listener, collector, trusted proxy, or file sink. Use a `full` or `wasm` archive
for the shipped telemetry capabilities, or build the smaller development profile:

```sh
cargo build --locked --no-default-features --features profile-observability --bin fluxheim
umask 077
mkdir -p target/visibility-demo/site
cp examples/observability/local.toml target/visibility-demo/fluxheim.toml
printf '%s\n' 'Fluxheim visibility check' > target/visibility-demo/site/index.html
target/debug/fluxheim --config target/visibility-demo/fluxheim.toml --check-config
target/debug/fluxheim --config target/visibility-demo/fluxheim.toml
```

In another terminal:

```sh
curl --fail http://127.0.0.1:8088/
curl --fail http://127.0.0.1:9091/metrics
```

Keep the fixture directory private. On Windows use a private directory under
the service user's profile, PowerShell file commands and `fluxheim.exe`; retain
the relative paths and numeric loopback listeners. Windows config paths can
use forward slashes. Do not translate Unix modes into permissive Windows ACLs.
The native [archive matrix](../evidence/observability-11.md) covers platform
filesystem and serving behavior; this shell recipe is for Unix shells.

The metrics listener is intentionally tokenless **only for this local demo**.
Other local processes can read it. For a shared host, use
`metrics.token_file` with a private random token and configure Prometheus's
`authorization.credentials_file`. Keep network isolation as well as authentication.
Never place a bearer token in a URL, shell argument, repository or dashboard.
Use the separate observer token for operational status, not the control token.

## Add A Collector

Append [otlp-local.toml](../../examples/observability/otlp-local.toml) to the demo
config only after a same-host Collector is listening on 127.0.0.1:4318. These
are additional TOML tables, not a second standalone server configuration.
For a remote collector, change both endpoints to HTTPS and configure the CA
and optional bearer-token file as in [OTLP export](otlp-export.md).
`http://localhost`, remote plaintext, URL credentials and redirects are rejected.

Metrics export begins on its interval. **No traces is expected for untrusted
traffic:** only an accepted, sampled parent from a configured direct trusted
proxy enables span export. Fresh local roots are unsampled. Do not widen
`server.trusted_proxies` merely to make a dashboard populate. Use the real
[collector gate](collector-integrations.md) for a disposable sampled-traffic
proof; it tests delivery, stored data, outage and recovery in both products.

For Grafana, configure Prometheus/Jaeger data sources and import the repository
dashboard. For SigNoz, import its separate Perses dashboard and forward OTLP
through a Collector. Detailed [import/provisioning instructions](collector-integrations.md#import-grafana)
include stable identifiers, filters, log-to-trace navigation and tested versions.
Empty panels mean missing/disabled/unobserved data, not healthy zero values.
Native OTLP log export, gRPC export and exporter mTLS are not implemented;
optional filelog collection is performed by the Collector.

## Fields And Events

Structured events and legacy diagnostics share the chosen sink, not a schema.
Use `schema_version`/`data.kind` to identify structured records; do not infer
their type by parsing the human-readable message.

| Record | Stable fields / interpretation |
| --- | --- |
| Legacy JSON | `timestamp`, `level`, `target`, `message`; messages are not a closed security-redacted schema |
| Structured envelope v1 | `schema_version`, `service_version`, `timestamp_unix_nanos`, `level`, fixed `message`, `data`, optional `resource`/`correlation`, `redacted`, `truncated` |
| Access `data` | Finite method/outcome, optional status, `duration_micros`, `bytes_sent`, `attempts`; one logical completion, not one per retry |
| Error/security | Finite reason code; error attempts may identify an upstream retry |
| Audit | Operation, outcome, actor class and optional revision; a shared token is not an individually identified user |
| Correlation | Bounded request ID and trace/span IDs when enabled and trusted; never an authorization credential |

See the [complete event schema and reason vocabulary](../architecture/structured-events.md)
and [metric names, units and label budgets](metrics.md). Structured messages do
not contain raw headers, URLs, query values, cookies, bodies or error chains.
Legacy debug logs are not automatically covered by that guarantee. Keep debug
off in routine production operation and treat all logs as confidential.
An access `completed` outcome can have HTTP 500: it means the response was
written, not that the application succeeded or the client consumed the bytes.

## Reload Or Restart?

| Change | Apply policy |
| --- | --- |
| `logging.access.*` | Snapshot-safe routing configuration; validation and privacy still apply; existing in-flight requests can retain old policy |
| Logging level/format/target/file/crash file; `RUST_LOG` | Process restart/upgrade; `RUST_LOG` is read at startup and overrides the configured filter |
| `metrics.*`, `tracing.*`, `admin.*` | Process restart/upgrade, including endpoint, listener, token-file path and sampling/propagation configuration |
| Token file contents | Restart the owning service/exporter; changing a file is not credential rotation by reload |
| Rename ordinary log file | Automatic safe reopen on a worker record, at most once per second; not a config reload |
| Unsafe replacement file | Old trusted handle retained; correct replacement permissions and generate a record |
| Active sink trust/write failure | Terminal sink failure; correct cause and restart, not just rename |

The classifier in `crates/fluxheim-config/src/reload.rs` determines actual
reload impact. A successful snapshot creation is not proof of live application.
See [snapshot/recovery operations](config-snapshots.md) before automating changes.

## Troubleshooting

| Symptom | Check and action |
| --- | --- |
| Metrics 401/403 or scrape down | Build capability, listener address, firewall and token-file permissions; never remove authentication to hide a scrape failure |
| No trace in backend | Direct-peer trust, single valid sampled traceparent, tracing/OTLP flags, local delivery counters and backend service filter |
| More attempts than requests | Retries are separate upstream work; cache/static hits may have zero attempts |
| IDs absent in logs | Access/tracing policy, effective `RUST_LOG`, trusted provenance and privacy build; no response ID is automatically added |
| Admin mutation returns `audit_unavailable` | Preserve INFO audit outcomes (`RUST_LOG=warn,fluxheim::event::audit=info`), then inspect lane capacity and worker/sink state |
| `audit_delivery_failed` with `operation_may_have_completed` | Read recovery/config state before retrying; a rejected response is not proof the mutation was undone |
| Log rotation errors | Replacement must be 0600/private ACL, regular and trusted; use rename on Windows and inspect reopen counters before compressing old logs |
| OTLP partial/failed/dropped increases | Inspect endpoint trust/auth, timeout and backend capacity. Partial success is not retried; no durable backlog is replayed |
| Series overflow | Reduce configured identity churn/cardinality; overflow retains aggregate counters but loses dimensions; excess gauges are discarded |
| Status 200 but `recovery_required` | Treat body readiness separately from HTTP success and telemetry health; investigate rollback failure, do not blindly confirm |

The [alert examples](../../examples/observability/alerts.yml) use scrape job
`fluxheim`. Change the job/filter and evaluate thresholds for your deployment.
`FluxheimScrapeMissing` detects the whole job being absent, not one removed
instance; maintain expected-target inventory externally. Sink-error and loss
alerts fire on recent increases, not persistent latches: also monitor status
worker/sink state. Missing optional OTLP metrics are not a healthy zero.
Validate changes with the matching Prometheus `promtool test rules alerts-test.yml`
from `examples/observability`; fixtures cover healthy, failed, absent and loss cases.

## Loss, Privacy And Platform Boundaries

Local logs have bounded ordinary/security/audit lanes and a separate legacy lane.
They can drop on contention, rate/capacity limits, failed sinks and abrupt exit.
Audit admission precedes protected mutations but does not guarantee durable
storage afterward. Local logging drains for at most 500 ms; OTLP uses a shared
two-second exporter deadline after request drain. Scheduling and stalled OS I/O
are not hard real-time guarantees. There is no on-disk retry journal or fsync
per ordinary record. External supervision and independent audit storage remain
deployment responsibilities.

Privacy builds reject metrics and enabled tracing/file/access logging and cannot
be relaxed at runtime. Linux executables verify non-dumpable startup before
configuration; other OS dump policy, swap, privileged inspection and child
process protection remain operator tasks. Windows PHP is external TCP FastCGI;
Windows ARM64 and macOS Intel are not release targets. See [security limits](../../SECURITY.md)
and the [management handoff](../reference/management-api-handoff.md) for what a
future interface may safely assume. No full management API or GUI ships here.
