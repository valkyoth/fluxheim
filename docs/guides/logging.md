# Logging And File Lifecycle

Use logs to investigate request outcomes, operational failures, security decisions
and administrative changes. Fluxheim writes bounded asynchronous records to one
stream or protected file. It does not provide an Apache/nginx combined-log format,
an arbitrary field/template language or native OTLP log export.

Native access completion and correlation are implemented; see the
[operational overview](observability.md) and [tracing guide](opentelemetry-tracing.md).
See the [configuration reference](../reference/config-reference.md),
[structured event contract](../architecture/structured-events.md) and
[logging architecture](../architecture/logging-architecture.md).

## Quick Start

[examples/logging/proxy.toml](../../examples/logging/proxy.toml) is a complete
loopback proxy example. Start your HTTP application on `127.0.0.1:9001`, then use
a proxy-capable binary:

```bash
fluxheim --config examples/logging/proxy.toml --validate-config
fluxheim --config examples/logging/proxy.toml
```

In another terminal:

```bash
curl -H 'Host: logs.example.test' http://127.0.0.1:8080/example
```

By default, expect a JSON access-completion record on stderr after the response.
If the origin is unavailable, expect a gateway error and an operational error
record instead of a successful origin response. No metrics/admin listener is
enabled by this example. Move the config into a private service directory and
change addresses deliberately before public deployment.

## Every Logging Option

These are global settings. There are no per-vhost/route logging tables, queue
size controls, sampling controls, retention rules or configurable rotation timer.
Paths resolve relative to the file defining them; create trusted parents first.

| Field | Default | Effect |
| --- | --- | --- |
| `logging.level` | `info` | `off`, `error`, `warn`, `info`, `debug`, `trace`; fallback filter when RUST_LOG is absent |
| `logging.format` | `json` | `json` or `text`; applies to ordinary and typed event records, not fatal diagnostics |
| `logging.target` | `stderr` | `stderr` or `stdout`; ignored for ordinary output when file logging is enabled |
| `logging.crash_file` | unset | Optional separate private fatal-diagnostic file; always append, no automatic reopen |
| `logging.file.enabled` | `false` | Replace ordinary stream output with one shared file, not duplicate it |
| `logging.file.path` | unset | Required when file output is enabled; even a supplied inactive path is validated |
| `logging.file.append` | `true` | `false` truncates only at startup after trust/alias checks; reopen always appends |
| `logging.access.enabled` | `true` | Permit native access-completion events, still subject to effective filtering and queue/rate admission; false by default in privacy builds |
| `logging.access.include_host` | `true` | Accepted but unused by native access events; the documented limitation |
| `logging.access.include_client_ip` | `true` | Accepted but unused by native access events; the documented limitation |
| `logging.access.include_cache_phase` | `true` | Accepted but unused by native access events; the documented limitation |
| `logging.access.include_path` | `true` | Accepted but unused by native access events; the documented limitation |
| `logging.access.include_route` | `true` | Accepted but unused by native access events; the documented limitation |
| `logging.access.include_upstream` | `true` | Accepted but unused by native access events; the documented limitation |
| `logging.access.request_id` | `true` | Manage the selected request-correlation header and include the admitted ID in request-scoped events; independent of access output |
| `logging.access.request_id_header` | `x-request-id` | Only x-request-id or x-correlation-id, case-insensitive, while request_id is enabled |

**Current limitation:** the six `include_*` fields currently neither add data when true
nor emit empty fields when false. Native access records have no host, path,
client-IP, route, upstream or cache-phase field. They also do not implement the
old compression/TLS/client-certificate/alias fields described by the historical
producer. Do not design parsers or incident procedures around those fields.
[the local follow-up](../roadmap/observability-commit-plan.md#post-documentation-corrections)
requires an explicit privacy/compatibility decision and implementation or
deprecation; this documentation does not silently enable raw identifying data.

### Filtering And Admin Availability

`RUST_LOG` overrides `logging.level` using the existing env_logger target/level
and message-regex syntax. Remove it when testing the TOML level. For example:

```bash
# Quiet ordinary logs while retaining all audit outcome levels.
RUST_LOG='warn,fluxheim::event::audit=info' fluxheim --config fluxheim.toml

# Only typed request completions (not suitable for a mutating admin service).
RUST_LOG='off,fluxheim::event::access=info' fluxheim --config fluxheim.toml
```

| Typed target | Severity | Message used for regex matching |
| --- | --- | --- |
| `fluxheim::event::access` | INFO, including completed HTTP errors | Request outcome |
| `fluxheim::event::error` | ERROR | Operation failed |
| `fluxheim::event::security` | WARN | Security policy decision |
| `fluxheim::event::audit` | INFO success, WARN rejection, ERROR failure | Administrative operation outcome |

For typed events, regex matching sees that fixed message, not URL, request ID,
status or serialized JSON. For legacy logs it sees the bounded captured message.
Neither filtering nor JSON escaping is a general secret-redaction engine for
arbitrary legacy/dependency log text. Avoid broad debug/trace collection without
reviewing its content and retention policy.

Admin mutations reserve audit capacity after authentication and before mutation.
All three audit severities must pass the filter. A global `warn`, `error` or
`off` filter without an audit override can therefore cause `audit_unavailable`,
not just quieter logs. Full/unavailable audit capacity also prevents admission.
Automatic certificate renewal/reload observations are best effort, not the same
pre-mutation contract. See [admin configuration](../reference/config-reference.md#admin)
for operation semantics.

### Access Completion And Correlation

Structured access `data` contains `kind`, `outcome`, `method`, `status`,
`duration_micros`, `bytes_sent` and `attempts`. The enclosing record has schema
and service versions, a nanosecond timestamp, severity, fixed message,
correlation and redaction/truncation flags. Use `schema_version` and `data.kind`
to distinguish these from legacy timestamp/level/target/message records.

`completed` means the response completed, not HTTP success: a fully sent 500 can
be completed. `failed` records transport/output failure; `cancelled` is the
drop-time fallback when no completion was recorded. Status may be null. Timing
starts when the native request telemetry context begins, not necessarily when
the first network byte arrives. Byte counts describe the producer's response
accounting, not a NIC-level bandwidth counter. Not every parser/connection
rejection reaches this context; this is not a complete security audit of all
network input. WebSocket completion is tied to tunnel lifetime.

With request IDs enabled, a unique valid incoming value is retained only from a
transport peer covered by `server.trusted_proxies`. Otherwise Fluxheim generates
`fh-` plus 32 hexadecimal characters and replaces the configured header before
routing. Accepted values are 1-128 ASCII letters/digits, dot, dash or underscore.
Duplicates, empty, invalid and oversized values are replaced rather than shortened.
If random generation fails, an ID may be absent. Trust is not inferred from an
X-Forwarded-For value. Do not broaden trusted proxies just to preserve IDs.

```toml
[logging.access]
enabled = false
request_id = true
request_id_header = "x-correlation-id"
```

This disables access output but keeps request/error correlation and header
management. Setting `request_id = false` disables that management; it does not
promise to strip arbitrary incoming diagnostic headers. These IDs must never
be authentication/authorization inputs. The runtime normalizes the request
header, not a guaranteed response header for the browser.

Trace IDs additionally depend on tracing configuration and `tracing.log_trace_id`;
see [OpenTelemetry tracing](opentelemetry-tracing.md). Privacy builds suppress
access events and correlation and reject enabled file/crash logging. They do
not turn arbitrary third-party log text into audited, secret-free output.

## Bounds And Loss

| Lane | Fixed bounds | Behavior under pressure |
| --- | --- | --- |
| Legacy logs | 128 outstanding records, 8 concurrent capture calls; 4096-byte message, 1024-byte target, 8192-byte encoded line | Drop/count full, busy, oversized, recursive or unavailable records; no producer-side sink wait |
| Ordinary typed events (access/error) | 128 queue entries, at most 100 admissions per one-second window | Drop/count; access and errors share this lane |
| Security events | Separate 128 entries and 100 admissions/window | Independent admission; still shares the file sink if configured |
| Audit events | Separate 128 capacity including reservations and 100 admissions/window | Reserved admission for gated mutations; no durable acknowledgement |

Rate admission also fails on budget-lock contention; 100 is a ceiling, not a
delivery guarantee. Typed encoded records are capped at 8192 bytes including
text framing/newline. Text typed events are a level/kind prefix followed by the
same JSON model; legacy text is timestamp/level/target/message with controls
escaped. Text mode is not a conventional combined access-log format.

No setting increases these bounds or makes logging lossless. Alert on loss and
sink counters, not merely file existence. Collection agents, storage quotas,
retention and shipping to a log backend are external responsibilities; native
OTLP metrics/traces do not imply OTLP log export.

## Select An Output

The default is stderr. For container or service-manager collection, use the
existing stdout/stderr target without an internal file:

```toml
[logging]
level = "info"
format = "json"
target = "stderr" # or "stdout"
```

To write ordinary records to a dedicated file instead, add:

```toml
[logging.file]
enabled = true
path = "/var/log/fluxheim/events.log"
append = true
```

Create the parent directory first, owned by the service identity or root, with
no untrusted write access. A Unix deployment can use mode 0700 or an appropriate
0750 directory and a 0600 file. Newly created files use 0600. Existing files
must be private regular files with no group/other permission bits: 0640 and 0644
are rejected, not just writable modes such as 0666. Symlink components are
rejected. Do not use a shared writable log directory to bypass these checks.
On Windows, use a local absolute path such as `C:/Fluxheim/logs/events.log` and
the same trusted-owner/ACL rules as other Fluxheim state files. Reparse points
and untrusted ACLs fail closed; creation installs the protected confidential ACL.
Existing files and replacements must also satisfy the confidential-file ACL
policy: read access for untrusted principals is rejected, including Everyone
and Guests. Fluxheim does not silently change existing files' permissions.

Each process needs its own log file. Unix uses append mode; Windows seeks to EOF
under the shared sink lock. Neither policy promises safe concurrent rotation
or record ordering across different processes. Do not point overlapping upgrade
processes at the same file; prefer service-manager collection in that workflow.

`append = false` truncates only during startup, after validating the opened file
and checking that it is not the crash sink. Reopen always appends, including to
a pre-existing replacement. Logging configuration changes require restart;
configuration snapshot reload is not a log-reopen command. The exception is
`logging.access.*`, which is snapshot-safe routing policy, not sink configuration.

Privacy-mode builds prohibit file logging. This change does not relax their
configuration policy or introduce additional diagnostic fields.

## Rotate By Renaming

Rename `events.log` to an archive name in the same trusted directory. Fluxheim
checks the configured path at most once per second, on the next record processed
by any logging worker. It opens or creates a safe replacement and atomically
switches the shared handle. No signal or admin command is required. An idle
server has no timer that opens files; there must be a record to trigger the check.

All four workers (legacy, ordinary, security and audit) share the handle. Each
whole encoded record is written under one lock, including short OS writes.
Rotation cannot split a record across handles. Within a lane, queue order is
preserved; ordering between lanes is unspecified. Records already queued before
rotation can go to the replacement. Records processed before the next check can
still go to the renamed file. Wait for the reopen counter before compressing or
removing the old file. Archive naming, compression and retention are external
operator responsibilities; Fluxheim does not manage them.

On Unix, deletion causes safe recreation at the next check. Until then records
can still go to an unlinked/open old file and become inaccessible. Windows
[DeleteFile](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-deletefilew)
can keep deletion pending until the last handle closes, preventing reopen.
In that case Fluxheim retains its trusted handle and increments `reopen_errors`;
restart to release the pending deletion and recreate the file. Use rename, not
delete, for Windows rotation. If removal unlinks the name immediately and a
replacement can be safely opened, recreation proceeds normally. Do not assume
that every Windows removal leaves a pending delete. Truncation of the same
file resumes at its new EOF, without an offset-sized hole. Copy-and-truncate has
an unavoidable race with the external copier and is not a lossless policy.
Prefer rename and retain the old file until the reopen succeeds.

## Failures And Recovery

- **Replacement cannot be opened or trusted:** keep writing to the previous
  trusted handle; increment `reopen_errors`. Try again on a subsequent worker
  record after one second. This includes directory/symlink replacements,
  crash-file aliases, ACL failures and Windows sharing conflicts. It does not
  redirect to stdout/stderr. Fix the path or permissions to recover.
- **Rotation tool creates a readable file:** configure it to create mode 0600
  (or a confidential Windows ACL), or let Fluxheim create the replacement.
  A 0644/0640 replacement is rejected and the old private handle is retained.
- **Opened file loses trust or writing fails:** latch the shared sink as failed.
  This includes ENOSPC, confidentiality loss (even 0600 to 0644/0640) and partial
  writes followed by error. The opened handle is checked before each record,
  independently of the one-second reopen interval.
  No record is retried, replayed, or redirected to another sink. A partial final
  record may remain. Freeing space or restoring permissions does not clear the
  latch: inspect the log, correct the cause and restart Fluxheim.
- **Worker behavior:** existing bounded queues and loss counters still apply.
  A lane encountering the failed sink stops; other lanes discover failure on
  their next write. Do not treat an idle lane's worker flag as sink health.
  Normal HTTP service remains independent of log I/O. Admin mutations continue
  to depend on the existing audit-admission rules, not durable sink completion.
- **Shutdown:** stop admissions and perform the existing bounded drain. File
  handles close after the final worker releases them; status counters alone do
  not retain them. An OS write that never returns cannot be cancelled by this
  mutex. Shutdown may abandon a blocked worker until process exit; it must not
  block the main shutdown path indefinitely.

The fatal sink (`logging.crash_file`, or stderr when unset) is separate and
restart-only. Ordinary rotation never reopens it or uses it as a fallback.
Crash hard-link aliases are rejected before truncation and during reopen.

## Fatal Diagnostics And Core Dumps

To separate last-chance diagnostics from ordinary collection, add a **different**
private file to the existing `[logging]` table:

```toml
[logging]
level = "info"
format = "json"
target = "stderr"
crash_file = "/var/log/fluxheim/fatal.log"
```

The parent must already exist. Startup opens the file securely, preserves its
contents and rejects aliasing the ordinary log, including hard-link aliases.
An unsafe configured crash file fails startup, rather than silently downgrading
to stderr. Do not redirect stdout/stderr to it separately.

Explicit invariant failures bypass filters/queues and attempt one fixed line:
`FATAL_SECURITY reason=<finite reason code>`. This is not JSON, a backtrace or
an arbitrary raw error. It remains active with `RUST_LOG=off`. The fatal path
appends and requests `sync_data()`; a failed file write falls back to stderr.
Without a crash file, stderr is used regardless of the ordinary target.

A watchdog started before serving attempts to force termination after a 250 ms
diagnostic grace period if reporting/exit stalls. Scheduling latency remains
outside this bound; an external supervisor is still required. Failures before
watchdog initialization terminate without attempting blocking diagnostics.
Do not expect every generic panic or external kill to produce this finite record.

The retained fatal handle is not periodically reopened or revalidated like the
ordinary file. Keep it private for the process lifetime and retain any renamed
file until restart; monitor/rotate it with a restart plan. A successful sync
attempt is not a durable administrative journal and the watchdog can interrupt
it. See [fatal diagnostics](../reference/config-reference.md#fatal-invariant-diagnostics)
for the exact boundaries.

Linux executables disable and verify kernel memory-dump eligibility before
loading configuration/secrets. Failure exits silently rather than risking a
blocked diagnostic while dumpable. macOS/Windows dump policy, swap, privileged
inspection and external child processes need deployment-level controls; see
[service lifecycle](service-lifecycle.md). The optional crash file contains
finite diagnostic lines, not a memory/core dump.

## Observe The Sink

An already-enabled, authenticated `/_fluxheim/status` response contains
`legacy_logging.file_sink` (null for stdout/stderr). No listener or public
diagnostic header is enabled by this feature.

| Field | Meaning |
| --- | --- |
| `check_interval_ms` | Minimum interval between worker-triggered checks: 1000 |
| `checks` | Reopen checks attempted, including unchanged safe files |
| `reopens` | Successful switches to a different file identity |
| `reopen_errors` | Failed candidate checks; the old handle is retained |
| `write_errors` | First failing sink write, including trust-check failure |
| `failed` | Shared terminal failure; restart required |
| `handle_open` | A worker still retains the shared sink |

Counters saturate and are read without taking the writer lock. The snapshot
is not a transaction across counters. No paths, raw OS errors or record contents
are exposed. Use the existing per-lane counters to inspect admission losses.

`legacy_logging` also reports pending/capacity, worker liveness, written and
dropped/oversized/busy/error counters. The structured dispatcher has separate
ordinary/security/audit lane counters and audit reservations. Authenticated
[operational status](operational-status.md) provides a bounded health projection;
enabling logging does not automatically enable either admin endpoint. With
metrics compiled/enabled, use the [metrics guide](metrics.md) for loss/sink
series and alerting. Zero errors alone does not prove delivery: check filters,
admissions, pending work and worker liveness as well.

## Troubleshooting

| Symptom | What to check |
| --- | --- |
| No access event for a completed request | Effective RUST_LOG/INFO filtering, access.enabled, privacy build, ordinary lane limits and whether the request reached telemetry |
| Missing path/client/route/cache fields | the documented limitation: current native events do not emit them, regardless of include_* settings |
| INFO configured but output still quiet | Service/container environment may set RUST_LOG; restart after changing sink/filter configuration |
| Admin mutation returns audit_unavailable | Permit all audit severities and check audit queue/rate/worker health; do not bypass admission |
| Stream empty after enabling file output | File replaces stdout/stderr for ordinary records; fatal and pre-initialization CLI diagnostics remain separate |
| Rotation keeps writing the old file | Wait for a record after the check interval; check replacement permissions/ACL, sharing and crash aliases |
| Log stops after freeing disk or fixing active permissions | Terminal sink failure requires restart; no replay or automatic recovery is promised |
| Logrotate replacement is rejected | Create 0600, not 0640/0644, or let Fluxheim create it; keep the directory trusted |
| Collector does not see OTLP logs | Native OTLP export is metrics/traces only; ship local logs with an external agent |

## Verification And Source Map

Build a proxy-capable binary and run the actual guide plus existing lifecycle
checks:

```bash
cargo build --locked --no-default-features --features profile-observability --bin fluxheim
python3 scripts/smoke_logging_examples.py --binary target/debug/fluxheim
python3 scripts/smoke_operational_events.py --binary target/debug/fluxheim
python3 scripts/smoke_log_file_rotation.py --binary target/debug/fluxheim
```

The first smoke checks JSON/text, stderr/stdout/file routing, startup truncation,
effective filtering, request IDs independent of access output and current unused
field behavior. Rotation has separate permission/error/alias recovery checks.
These tests do not certify all input paths or guarantee lossless collection.

Implementation: [configuration](../../crates/fluxheim-config/src/config_logging.rs),
[initialization/filtering](../../src/runtime_logging.rs),
[file lifecycle](../../src/runtime_log_file.rs),
[request producer](../../crates/fluxheim-server/src/native_request_telemetry.rs),
[event contract](../../crates/fluxheim-observability/src/event.rs),
[bounded dispatcher](../../crates/fluxheim-observability/src/operational_dispatch.rs)
and [fatal diagnostics](../../crates/fluxheim-common/src/fatal.rs).

## Assurance Boundary

This is bounded best-effort logging, not a durable journal: no per-record fsync,
integrity chain, replay spool or external acknowledgement is added. An audit
mutation may finish before its queued outcome reaches the sink. A crash, disk
failure or saturation can lose records. Same-identity/root attackers remain
outside the filesystem trust boundary; directory checks are not protection from
a compromised privileged administrator. See the
[qualification record](../evidence/observability-05.md) for tests and platform gaps.
