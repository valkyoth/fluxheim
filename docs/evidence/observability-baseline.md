# Observability Commit 01 Baseline

Status: inventory and contract-test checkpoint, 2026-10-23. Base:
`2c9d059f`. Not accepted until incremental pentest, exact-commit GitHub CI and
operator approval. No production telemetry implementation changes in this
checkpoint. Measurements and future acceptance limits are distinct below.

## What Exists Versus What Is Planned

| Surface | Actual owner and behavior | Gap / follow-up |
| --- | --- | --- |
| Runtime logs | src/runtime_logging.rs: synchronous env_logger; JSON or text; stderr default, stdout/file optional; RUST_LOG override | No centralized redaction/byte cap, typed audit model, async queue or reopen lifecycle (02-05) |
| Access logs | fluxheim-config/config_logging.rs and observability/access_log.rs: configuration and ID/escaping helpers | No native request completion producer found; old Pingora claims are historical (03/06) |
| Trace propagation | server/native_http1_route_trace.rs and route_proxy_handler.rs: fresh span ID; retain valid trace ID, trust sampled bit only for trusted peer | Not an exported server span; static/PHP, completion/cancellation and retry correlation need qualification (06) |
| Trace export | observability/otlp_trace.rs: library encoder, one thread, count-bounded channel, nonblocking try_send | No native runtime instantiation/submission; no byte cap, batch, retry, drop counter or joined drain (06/08) |
| Metrics HTTP | src/metrics_native.rs: GET/HEAD metrics, optional protected bearer-token file, configured loopback restriction | Collection/encoding size and concurrency not globally budgeted (07/09) |
| Metrics push | src/metrics_otlp.rs, runtime_background.rs: cumulative registry export on interval; synchronous HTTP in background task | Blocking exporter call, no bounded payload/batch/retry or partial-success interpretation (08) |
| OTLP transport | observability/otlp_http.rs: HTTP/HTTPS, private CA optional, redirects disabled, global timeout, 1 MiB CA read limit | No configured authorization headers; collector auth needs explicit reviewed design, not assumed support (08) |
| Admin | src/admin/request_router.rs and response_helpers.rs: authenticated status and mutations, optional public health | No complete management API or versioned operational OpenAPI yet (09) |
| Collectors | scripts/smoke_observability_local.sh: Prometheus pull/push checks, propagation, optional Jaeger lookup | Jaeger trace requirement defaults off; no Grafana/SigNoz assets. Must prove stored traces/panel queries (10) |

Paths in this inventory are repository-relative; abbreviated crate paths mean
`crates/fluxheim-<name>/src/`. Library support and metric registration are not
proof that a live request emits that signal.

## Producer Inventory

| Family | Owner / capture point | Semantics and missing proof |
| --- | --- | --- |
| Proxy | server/native_http1_proxy_response_finish.rs; native_http1_proxy_metrics.rs; src/metrics_cache.rs | Counts finished proxy response selection, not confirmed socket delivery; early failures/cancellation and retries need coverage |
| Static, HTTP/2, WebSocket | server/native_http1_web*, native_http2*, native_http1_websocket* | Shared request/response adapters do not prove completion accounting for multiplexed/streaming traffic; define one logical completion in 06 |
| Cache | server/native_http1_cache*, src/metrics_cache.rs, runtime_background.rs | Storage activity, configured policies, scope and runtime totals; distinguish cache lookup, wait and purge timing; reload-churn bounds pending |
| Load balancer | fluxheim-load-balancer metrics/callback paths, src/metrics.rs | Selections, retries, queue waits, pool configuration and aliases; coverage/duplicate audit in 03/07 |
| PHP | fluxheim-php-fpm callbacks, src/metrics_registry_php.rs | Outcome, duration, stderr presence, retry/pool helpers; confirm native hook coverage, not only recorder tests |
| TCP stream | src/stream_proxy.rs | Connection outcome and bytes by configured route; no HTTP request ID implied |
| UDP | src/udp_proxy.rs and src/udp_proxy/service.rs | Datagram direction/outcome, active sessions and bounded drop reasons; no request/span per packet by default |
| TLS/ACME | src/stream_tls*, fluxheim-tls, runtime_background.rs | TLS errors may precede HTTP and have no request ID; bounded ACME event counter exists, more failure categories in 03 |
| Wasm | native Wasm recorder callbacks, src/metrics.rs | Plugin execution count/duration and admission; compile/profile dependent |
| Admin/recovery | src/admin/* and runtime_admin* | Auth failures/throttling; reload/snapshot/rollback currently lack one consistent typed audit envelope |
| Export health | src/metrics_otlp.rs | Metrics attempt success/failure counter exists; trace drops only debug-logged in library |

Enumerate concrete metric definitions in src/metrics_registry_core.rs,
metrics_registry_cache_activity.rs, metrics_registry_cache_gauges.rs and
metrics_registry_php.rs. Existing recorder tests cover these families; 07 must
prove owner-to-export deltas with actual traffic before dashboard claims.

## Current Wire Contract

Golden fixtures live in `tests/fixtures/observability/` and are consumed by Rust
tests, not copied into a fake collector. Changing them requires a compatibility
decision and test review, not blindly regenerating expected output.

| Signal / field | Type / units / optionality | Privacy and lifecycle |
| --- | --- | --- |
| JSON timestamp | Required string, UTC millisecond wall time | Not a monotonic duration; clock correction can move backwards |
| JSON level, target, message | Required strings; exactly four top-level fields today | Escaping prevents JSON injection, NOT secret redaction; arbitrary log messages remain caller-owned |
| Text log | Timestamp, level, target, message plus newline | No equivalent centralized control-character/redaction/size contract yet |
| Access event | No native serialized contract yet | Do not invent fixture events that the server cannot emit |
| Prometheus counter | Cumulative numeric value; `_total` convention | Process lifetime; configured resource names + finite method/status/outcome labels |
| Prometheus gauge | Instantaneous number; units in name/help | Zero is not proof of enabled/healthy subsystem; some families are lazy |
| Prometheus histogram | Cumulative buckets, `+Inf`, sum, count; durations in seconds | Bucket count multiplies series; resets/reload retention must be audited |
| OTLP resource/scope | service.name, service.version; scope name fluxheim/version | No unique service.instance.id currently; multi-instance dashboards need identity design in 06-08 |
| OTLP numbers | Counter sum monotonic/cumulative; gauge asDouble; wall-time nanos string | Encoder currently assigns unit `1` to all counters/gauges, including byte gauges; units need review in 07 |
| OTLP histograms | Cumulative temporality; per-bucket counts + explicit bounds, numeric count | Current histogram unit `s`; no start timestamp. Freeze existing encoding, qualify backend semantics in 08/10 |
| Trace IDs/times | Hex trace/span IDs; optional parent; wall nanos strings | Helper regenerates span ID, clears untrusted sampling; IDs are not authorization |
| Trace attributes | Method/vhost, optional route/status/cache/PHP/compression/alias; body sizes bytes, cache timings ms | Library model only; no body/cookie/header/query fields; safe alias filter does not redact arbitrary other strings |
| Trace status | `STATUS_CODE_OK`/`ERROR` from caller bool | Not proof of complete HTTP status/error semantic mapping |

Labels must never come from arbitrary host/path/query/client IDs. Current safe
method set: GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS, TRACE, CONNECT, OTHER.
Status buckets: 1xx..5xx/other, plus unknown where optional. Configured labels
are not automatically memory-bounded across reloads; process-global registries
and old label retention need explicit 07 tests.

## Admin Route Inventory And Recovery Boundary

GET: configured health path, `/_fluxheim/status`, `/cache/status`,
`/load-balancer/status`, `/udp/status`, `/snapshots` (all abbreviated paths use
the `/_fluxheim` prefix).

POST: `/cache/activity/reset`; `/self-heal/{confirm,fail,report}`;
`/load-balancer/{member-state,member-weight,member-add,member-remove,member-update}`;
`/load-balancer/persistence/clear`; `/cache/{purge,purge-bulk,purge-index,
purge-prefix,purge-tag,purge-stale,purge-wildcard}`; `/snapshot`, `/rollback`,
`/reload`. These existing mutations are not permission to add arbitrary CRUD.

HTTP authentication precedes self-healing deadline enforcement. An authenticated
GET can currently trigger recovery; a failed rollback must block subsequent
routing/confirmation. Public health bypasses that path. The Unix ops socket has
its own read-only allowlist and token rules, not the same recovery path. Preserve
these distinctions until explicitly reviewed in 09. Never claim all existing
GET endpoints are side-effect-free.

## Configuration And Compatibility

- Runtime logging format/filter/file selection is initialized once. Treat it
  as restart-required; try_init currently ignores a preinstalled logger error.
- Metrics listener/exporter ownership is established at startup; do not promise
  live reconfiguration without a test. Routed trace configuration follows the
  native handler generation; exporter lifecycle is not yet wired there.
- Default logs are JSON/info/stderr. Access flags default enabled with host,
  path and client-IP inclusion outside privacy mode, although native emission
  is missing. Do not call these flags privacy-minimizing defaults.
- Metrics, tracing and remote exports default off. Existing feature-disabled
  rejection tests and privacy-mode restrictions remain authoritative.
- `metrics.advanced`, `logging.spool`, `logging.queue_size` and
  `tracing.sampling` historical sketches are rejected; new regression coverage
  ensures docs do not silently turn into accepted configuration.
- Choose OpenAPI **3.1.0**, with JSON Schema 2020-12 response fixtures for 09.
  Validate actual responses in that checkpoint; no complete spec is claimed now.
- Public names/fields are retained. Correct units/semantics through documented
  additive fields or explicit deprecations. No silent metric rename for a dashboard.

## Proposed Numeric Acceptance Budgets

These are design ceilings to review with the operator before Commit 02, **not
limits enforced by current code**. Configuration may lower them. If existing
valid configuration exceeds a new ceiling, specify an actionable validation
error/migration before implementation; do not silently clamp operator choices.

| Resource | Proposed ceiling | Owner checkpoint |
| --- | --- | --- |
| Captured event | 8 KiB encoded, 32 fields, 1 KiB per string except message 4 KiB; account JSON escape expansion before queueing | 02 |
| Local queue | Default 4096 events/8 MiB; hard max 65536 events/64 MiB; reserve 256 events/1 MiB within the total for security/audit | 04 |
| Worker/producer | At most 2 local writer workers; nonblocking submission default; any blocking option <=10 ms | 04 |
| Metric cardinality | Default 20000/hard max 100000 exported series including buckets; bounded overflow bucket and reload cleanup | 07 |
| Export | Max 1 MiB batch, 256 spans/batch, 16 MiB queued bytes, 2 in-flight requests per signal, response read <=64 KiB | 08 |
| Retry | At most 3 retries / 30 s total for a batch; existing configured request timeout <=60 s; no unbounded retry queue | 08 |
| Status | <=1 MiB response, <=100 ms collection deadline, <=8 concurrent collections, no history by default | 09 |
| Drain | <=5 s total telemetry drain, additionally bounded by runtime shutdown deadline; no waiting forever for blocked writer | 04/08 |

Performance proposal: compare the SAME build/hardware/load before and after a
checkpoint, three or more alternating samples. Investigate median throughput
loss >5%, p95/p99 latency rise >10% (with 1 ms noise floor), CPU/request rise >10%,
or RSS increase beyond configured buffers +16 MiB. These are review triggers,
not CI timing assertions or universal guarantees. Saturated sinks must satisfy
the same finite memory/shutdown limits even when events drop. Native thresholds
need recorded calibration on each OS before relevant runtime changes are accepted.

## Evidence And Acceptance

Run the baseline harness with an optimized `profile-observability` binary. It
records HTTP round trips, CPU/RSS when available, scrape output and observed
log/trace delivery. This is a loopback diagnostic, not a maximum-throughput
benchmark: client and origin share the host. No fake success for missing spans.

Performance evidence does not establish a saturated logger guarantee today:
there is no native access producer to saturate with request traffic. Commit 04
must add deterministic blocked-writer and actual native pipe tests before its
acceptance. macOS/Windows/ARM performance and collector gates remain pending;
the 1.8.3 packaging runs cannot substitute for them.

Each later evidence record must include base/final SHA, toolchain/profile,
commands/exit statuses, sanitized raw results, native gaps, budgets, pentest,
GitHub URL/SHA and explicit approval. Record final checkpoint SHA in the next
acceptance record rather than embedding a self-referential hash in this file.

### Local Run: 2026-10-23

Host: Linux x86_64, AMD Ryzen 9 9950X3D, 32 logical CPUs, kernel 7.2.4,
Rust 1.99.1. Optimized binary, `--no-default-features --features
profile-observability`; two runtime threads, loopback Python origin/client on
the same host, eight client workers, 20 warmup requests, three alternating
off/on pairs of 500 measured HTTP/1.1 requests. No TLS or remote collectors in
this diagnostic. The fixture accepts JSON; it is not a real APM backend.

Commands (exit 0):

```sh
cargo build --locked --release --no-default-features --features profile-observability --bin fluxheim
python3 scripts/observability_baseline.py --binary target/release/fluxheim
```

[Raw samples and identity](observability-01-linux.json) retain binary SHA256,
base commit, dirty-build flag, toolchain/platform, all timings and signal counts.
The binary was built during this checkpoint before documentation-path diagnostic
changes; no native telemetry implementation was changed. This is development
evidence, not a clean tagged-release build or independent reproducibility proof.

| Mode | Median throughput (req/s) | Median p95 / p99 (ms) | Peak RSS range | CPU/sample | Shutdown |
| --- | --- | --- | --- | --- | --- |
| Off | 3541 | 2.85 / 3.75 | 12.60-12.63 MiB | 0.06-0.07 s | ~1.015 s |
| Enabled | 3515 | 2.85 / 3.36 | 12.68-12.91 MiB | 0.06-0.09 s | ~1.015 s |

The short, shared-host samples have warmup/scheduling noise and cannot certify
the proposed performance thresholds. Use longer runs (`--requests 10000`) and
native platform calibration before accepting dispatcher/exporter changes.
"Off" disables configured emission, not compiled metrics callbacks; it is not
a feature-stripped binary benchmark. Additional feature-off build comparisons
remain a requirement of later performance qualification.

Each enabled run delivered four metrics exports to the fixture and a native
Prometheus scrape; each disabled run delivered none. All runs observed zero
access records and zero trace exports, confirming the wiring gaps. Canary
authorization/cookie/query values were absent from collected output on these
successful requests; this is NOT a general secret-redaction proof. HTTP status
and origin body were checked on every measured request.

### Regression And Tooling Evidence

All commands below exited 0 locally:

| Command | Result |
| --- | --- |
| `cargo test --locked --workspace` | 1766 successful test executions; one existing ACME bind-mount test ignored (requires isolated privileged namespace) |
| `cargo test --locked -p fluxheim --lib --no-default-features --features profile-observability` | 242 passed, including admin/recovery, metrics and runtime-log fixtures |
| `cargo test --locked -p fluxheim-observability --all-features` | 22 passed, including parsed OTLP/Prometheus fixtures and finite label domains |
| `cargo test --locked -p fluxheim-config --no-default-features` | 431 passed |
| `cargo test --locked -p fluxheim-config --no-default-features --features metrics-otlp,otel-tracing,otel-otlp observability` | 10 passed |
| `cargo test --locked -p fluxheim-config --no-default-features --features privacy-mode observability` | 7 passed |
| `cargo clippy --locked -p fluxheim --no-default-features --features profile-observability --all-targets -- -D warnings` | passed |
| `python3 scripts/test_observability_baseline.py` | 3 passed |
| `python3 scripts/test_documentation_layout.py` | 3 passed; every document/policy input indexed |
| `python3 scripts/test_development_scope.py` | 7 passed |
| `python3 scripts/test_release_metadata.py` | 3 passed |
| `python3 scripts/test_release_helpers.py` | 14 passed |
| `python3 scripts/test_container_refresh.py` | 35 passed |
| `python3 scripts/test_http3_source_lock.py` | 21 passed; path-move regression only, research not reactivated |

Release-metadata, Wasm-profile/example, Windows security-audit, runtime-fixture,
native-cutover, Pingora boundary/dependency, modularity and OWASP validators also
passed after the move. Formatting, diff integrity and Markdown link checks pass.
CI now runs baseline contract and documentation-layout regressions explicitly.

Pending: incremental pentest, exact-commit GitHub/CodeQL, operator budget review,
native platform performance calibration and later required live backend gates.
Do not advance to Commit 02 without the checkpoint acceptance cycle.
