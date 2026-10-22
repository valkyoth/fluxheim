# 1.9.0 Observability Commit Plan

Status: active planning baseline, updated 2026-10-22 after the v1.8.3 release.
Implementation checkpoints have **not started**. Main stays at **1.9.0
(unreleased)**. This document replaces the earlier ten-checkpoint outline;
no previously accepted implementation checkpoint is being renumbered.

## Release Outcome And Scope

An operator can answer "what failed, why, when, and for which configured
service?" without turning on unsafe debug dumps. Logs, metrics, sampled traces
and authenticated status describe the same outcome, remain bounded, and expose
telemetry failures without stopping healthy application traffic.

Ship one coherent 1.9.0 after the numbered checkpoints. The checkpoints are
reviewable Git commits, not twelve public releases. Use 1.9.x for maintenance
and compatible follow-ups. Existing configuration and privacy defaults remain
valid. New sensitive or expensive detail is opt-in; no public diagnostic
headers or management listener are silently enabled.

**Recommendation:** 1.9.0 is already a substantial release. Build dependable
read-only operational contracts here, then implement complete management in a
separate minor release, provisionally 1.10.0 subject to user approval. Keep
fluxheim-ui in its own repository. See the
[management API discussion](management-api-direction.md) for the coverage
definition, transaction model and release boundary. This is not authorization
to implement the full API now.

### Explicit Exclusions

- HTTP/3 and QUIC remain [deferred research](http3-quic-commit-plan.md).
  Brynja/Vef are future qualification candidates, not production dependencies.
  Normal CI must not start running research probes again.
- No full configuration CRUD, new remote command execution, OS administration,
  GUI, fleet controller or arbitrary secret/file/module upload.
- No new logging network protocols or durable disk spool. Existing OTLP
  metrics/tracing are in scope; OTLP log export is not implied.
- No mandatory migration from log to tracing, new metrics facade or exporter
  SDK unless inventory proves a concrete need and compatibility is tested.
- No exactly-once or lossless audit/logging claims. In-memory telemetry can be
  lost during saturation or abrupt process death.
- No new protocol features hidden inside an observability checkpoint.
  Preserve HTTP/1.1, HTTP/2, WebSocket, stream/UDP, cache, TLS, ACME, PHP,
  load-balancer and Wasm behavior. Windows PHP remains external TCP FastCGI.

## Starting Point And Maintenance Reconciliation

The signed v1.8.3 baseline is
`14d7b6cfc9b16c39a8dc0d4770f59290c8feea48`. The operator confirmed the released
PHP container on a real site. Native packaging passed on Linux x86_64/aarch64,
Apple Silicon macOS and Windows x86_64. These results establish the maintenance
baseline, not proof of future 1.9 runtime changes.

Before implementation, carry forward and verify:

| Maintenance area | Main requirement |
| --- | --- |
| Dependency/toolchain refresh | Rust 1.99.1, Wasmtime/WASI 50 and production/fuzz dependency graphs match 1.8.3 apart from Fluxheim package versions |
| Runtime/security fixes | All production source and container definitions match the accepted maintenance line before new observability edits |
| systemd standalone build | Preserve the explicit rustix time feature and isolated CI test from a8e9bb87 |
| RPM metadata | Preserve the exact patch-level Rust requirement and negative tests from a8e9bb87 |
| Remote packaging | Preserve macOS SSH coordination, early preflight and output-preservation checks from 11ca5988 |
| Container refresh | Keep signed-tag authorization and tested-digest promotion on both branches |
| Release records | Retain 1.8.3 notes/qualification, without relabeling their evidence as a 1.9 gate |

Keep 1.8.x available for reviewed maintenance. Do not merge unfinished 1.9
features back into it. Record source commits for shared fixes. Release helpers
may evolve after a tag; they must still build the immutable signed source.

Preparation verification (2026-10-22): direct comparison with maintenance tip
11ca5988 found identical production Rust sources, container definitions,
vendored code, toolchain and audit policy. Parsed comparison of 23 production
and fuzz manifests/lockfiles matched after normalizing only Fluxheim package
versions. Systemd tests (4), release-helper tests (14), metadata tests (3),
development-scope tests (7) and refresh-security tests (35) passed, as did the
activation example build, targeted Clippy, formatting and documentation links.
This is targeted carry-forward verification, not a new full release gate or
acceptance of Commit 01. Native gates were not rerun for these planning edits.

### Concrete Implementation Inventory

| Area | Current starting files | Work to establish in Commit 01 |
| --- | --- | --- |
| Local logging | src/runtime_logging.rs; crates/fluxheim-config/src/config_logging.rs | Actual JSON/text format, synchronous write sites, startup/reload ownership, file trust checks |
| Access/correlation | crates/fluxheim-observability/src/access_log.rs and trace_context.rs | Request completion sites, ID trust rules, retry/stream semantics |
| Prometheus | src/metrics*.rs; crates/fluxheim-observability/src/metrics_labels.rs | Existing names, label domains, bucket counts, lifecycle/reset behavior |
| OTLP | src/metrics_otlp.rs; crates/fluxheim-observability/src/otlp_http.rs, otlp_metrics.rs and otlp_trace.rs | Existing encoders, buffering, authentication, retry and shutdown ownership |
| Administration | src/admin/request_router.rs, response_helpers.rs, snapshot_runtime.rs; src/runtime_admin.rs | Existing routes, authentication, recovery side effects, status projection and size limits |
| Live proof | scripts/smoke_observability_local.sh; native macOS/Windows smokes | Real collector assertions versus optional/skipped checks |

The [logging](logging-architecture.md), [metrics](metrics-architecture.md) and
[tracing](opentelemetry-tracing.md) documents mix implementation and historical
design ideas. Code and executed evidence take precedence. Correct their
implemented/planned labels before adopting any proposed configuration.

## Architecture And Security Contracts

1. Configuration belongs in fluxheim-config; shared event types, label
   normalization and export encoders belong in fluxheim-observability; runtime
   owners supply measurements. Do not make the shared crate depend on the
   whole server or duplicate runtime state for the future UI.
2. Introduce typed, finite reason codes. Preserve causal categories internally
   while public errors stay generic. Keep raw credentials, cookies, keys,
   request/response bodies and query values out of new telemetry. Existing
   optional path/host logging remains subject to explicit policy and caps.
3. Use configured resource identities, not arbitrary Host, paths, client IPs,
   request IDs or error strings as metric labels. Cap both configured
   cardinality and reload churn; an allowlist alone is not a memory bound.
4. Record durations with a monotonic clock, document wall-clock timestamps,
   units, byte accounting, attempt versus request semantics and cancellation.
5. Use immutable snapshots or short bounded reads for status. Do not hold
   request-path/global locks during formatting, file writes or collector I/O.
6. Authenticate before sensitive status or side effects. Existing self-healing
   rollback failures must remain fail-closed. Do not weaken ACL, reparse,
   symlink or secret-reading protections to make new sink tests pass.
7. Treat client-supplied IDs, forwarded trace context, upstream errors and
   collector replies as untrusted. No unbounded baggage, stack traces or
   arbitrary object serialization in telemetry.
8. Feature-disabled builds must remain small and functional. Logging, metrics,
   OTLP and trace settings that need missing features fail validation clearly.
   Full remains Wasm-free; no default collector is contacted.
9. New status contracts must be usable by CLI and a future UI equally. They
   report feature/platform capabilities and explicit unavailable/disabled
   states, not a plausible zero for missing data.
10. Schema versions, additive changes and deprecations are explicit. Do not
    silently rename existing metric names, labels or JSON fields.

## Review And Acceptance Procedure

Each numbered checkpoint uses this exact cycle:

1. Record base commit, scope, affected platforms and test commands.
2. Implement that checkpoint only, with permanent positive/negative tests.
3. Run focused tests plus the broader checks implied by the blast radius.
4. Commit with the suggested "Observability commit NN: ..." subject.
5. Stop for the user's pentest against the preceding accepted checkpoint.
6. Fix findings with regression tests; retain old regressions and retest.
7. Wait for GitHub CI and CodeQL on the exact final commit to be green.
8. Record accepted SHA, evidence and explicit user approval before Commit NN+1.

A checkpoint can contain remediation commits; numbering marks review
boundaries, not a requirement to squash away evidence. A green CI run is not
a native live test. No skipped requirement is a pass. If an environment is
missing, state the gap and arrange it before acceptance.

After broad security changes, rerun earlier security regressions and explain
why any changed test oracle still proves the original property. Never loosen
an assertion merely to turn a new error path green.

### Evidence And Resource Budgets

Commit 01 creates a versioned baseline/evidence index with exact commands,
features, platform, hardware, load, samples and raw results. It freezes
numeric budgets *before* queue/export implementation is accepted:

| Resource | Required enforceable measurement |
| --- | --- |
| Event capture | Maximum encoded bytes, field counts and per-field bytes; bound before allocation/queueing |
| Local dispatch | Queue entries AND total bytes, producer work, worker count, protected capacity and overflow counters |
| Metrics | Maximum series including histogram buckets and labels over repeated reloads |
| Export | Queue/payload/response bytes, batch size, concurrent requests, retry count/elapsed time |
| Status | Maximum response bytes, collection time, concurrent reads and any retained history |
| Shutdown | Total drain deadline including logger/exporter failure; no indefinite blocking destructor |
| Performance | Telemetry-off baseline, normal-on and saturated-sink p50/p95/p99 latency, throughput, CPU and RSS |

Do not invent universal performance guarantees from one machine. Set reviewed
per-platform thresholds with repeated runs and tolerances. Exceeding an accepted
budget blocks the checkpoint until implementation or an explicit scope decision
resolves it. "Configurable" without a hard validation ceiling is insufficient.

Each checkpoint evidence record includes base/final SHA, commands with exit
status, regression names, native/container artifacts, budget comparison,
known skips, pentest result, CI URL/SHA and user approval. Protect diagnostic
artifacts from secret leakage; do not automatically upload raw captures.

## Commit 01 - Inventory, Schemas And Baseline

Suggested subject: `Observability commit 01: define contracts and baseline`.

Operator value: documented, testable meanings for the data already exposed.

Deliver:
- Inventory every current producer, sink, exporter and admin route, including
  disabled features and HTTP/2/stream/UDP paths.
- Freeze existing JSON, Prometheus and OTLP fixtures with schema/field tables:
  units, optionality, privacy, severity, reason, cardinality and lifecycle.
- Specify logical request versus retry attempt, streaming completion, cancelled
  requests, pre-request TLS errors, and background operations without request IDs.
- Record startup-only versus reloadable settings and compatibility/deprecation.
- Capture resource/performance baselines and agree numeric budgets above.

Tests: parse actual serialized output; verify secret canaries and privacy
defaults; feature-disabled config cases; deterministic method/status buckets.
Run existing observability, logging, admin and metrics tests without changes
to their security properties.

Exit: inventory gaps map to later checkpoints; numeric budgets and baseline
commands are committed. No new admin mutation or runtime backend migration.

## Commit 02 - Bounded Event Model And Redaction

Suggested subject: `Observability commit 02: add safe structured event types`.

Operator value: consistent machine-readable events without sensitive dumps.

Deliver:
- Add typed access, error, security and audit envelopes, version identity,
  finite reason codes, safe resource IDs and bounded optional correlation.
- Define level/filter precedence, including RUST_LOG and privacy mode.
  Preserve explicit operator choices; do not force verbose logging.
- Centralize sanitization, size accounting, truncation markers and serialization
  so text and JSON cannot bypass the same privacy/size contract.
- Define reserved capacity/rate limits for security/audit separately from
  ordinary access events; never promise lossless audit under hostile load.

Tests: CR/LF/control/Unicode inputs, huge nested errors, canary secrets,
truncation boundaries, malformed IDs and property/fuzz tests for new parsers.
Prove byte bounds before buffering and disabled access logs do not implicitly
disable required security/audit events.

Exit: schema fixtures and redaction pass with unchanged public responses.
Existing flags remain valid; no sink I/O is introduced in producers.

## Commit 03 - Failure And Administrative Audit Coverage

Suggested subject: `Observability commit 03: instrument operational failures`.

Operator value: distinguish DNS, refused connection, TLS verification,
timeout, PHP, cache, ACME and rollback failures without debug logging.

Deliver:
- Map causal categories at their actual owner, including denied requests,
  queue admission, upstream retries, cache encryption/store failures, Wasm
  denial/traps, TLS/ACME lifecycle and snapshot/reload outcomes.
- Audit existing authenticated mutations with operation identity, revision
  where available, safe actor class and final outcome. Do not call one shared
  token a uniquely identified human.
- Cover automatic recovery and rejected operations without disclosing secrets.
  Inventory current request-triggered deadline enforcement before changing it.

Tests: fault-inject each category; assert structured private event AND expected
public status/body; check auth-before-side-effects, failed rollback persistence,
duplicate retries, background events and denied operations. Rerun admin and
snapshot recovery regressions.

Exit: a coverage table links each reason to a positive/failure test. No newly
unbounded high-frequency event stream or raw upstream errors.

## Commit 04 - Bounded Logging Dispatcher

Suggested subject: `Observability commit 04: bound asynchronous log dispatch`.

Operator value: slow logging cannot stall serving indefinitely or exhaust RAM.

Deliver:
- Move identified synchronous hot-path writes behind a bounded dispatcher.
  Bound event count, bytes, producers, workers and submission cost.
- Freeze overflow semantics and counters, including security/audit exhaustion.
  Default to bounded loss rather than an unbounded block; any opt-in blocking
  mode needs a finite deadline and explicit latency tradeoff.
- Define initialization failure, dispatcher failure, recursive logging guard,
  reload ownership and shutdown drain deadline.
- Preserve log/tracing interoperability with exactly one completion event;
  migrate backend libraries only if necessary for this contract.

Tests: slow/blocked/closed writer, queue saturation from many producers,
dispatcher failure, cancellation and shutdown with queued events. A mock
writer provides deterministic blocked-I/O coverage; native pipe tests prove
OS behavior. Measure budgets against Commit 01.

Exit: request workers have no unbounded sink wait; every drop is counted.
A blocked OS write cannot make runtime shutdown join indefinitely.

## Commit 05 - Protected File Sink And Rotation Lifecycle

Suggested subject: `Observability commit 05: make log file lifecycle reliable`.

Operator value: rotation and disk failures have predictable recovery.

Deliver:
- Retain existing stdout/stderr/file support and document one tested reopen
  policy. Automatic archival/compression/retention is not an implicit feature.
- Preserve trusted directory/file boundaries during open/reopen/replacement.
  Keep Unix ownership/symlink and Windows ACL/reparse protections.
- Make reopen atomic from the logger's perspective. Define failure fallback,
  log ordering, partial writes, queue treatment and duplicate risk.
- Define behavior for rename rotation, external deletion, truncation, ENOSPC,
  permissions loss and Windows sharing conflicts.

Tests: deterministic failing writers plus native real-file rotation, hostile
path replacement, full/quota-limited storage where supported and concurrent
shutdown/reload. Any platform-specific simulated case is labeled as such.

Exit: old file handles and tasks are released, safe failed-reopen behavior is
proved, and no output is redirected to an untrusted path.

## Commit 06 - Request And Trace Correlation

Suggested subject: `Observability commit 06: unify request and trace correlation`.

Operator value: follow one request across access logs, errors and upstream work.

Deliver:
- Reuse the existing request-ID and trace-context boundary; specify untrusted
  inbound validation, trust policy, generation, propagation and sampling.
- Separate retry attempt IDs/spans from one logical request outcome.
- Define streaming, WebSocket, HTTP/2 multiplexing, disconnect and background
  operation semantics without logging frame/body contents.
- Do not add raw URLs, query values or unbounded baggage by default.

Tests: concurrent interleaved HTTP/1.1 and HTTP/2 requests over static/proxy/PHP;
malformed/oversized context, conflicting headers, retries and cancellations.
Assert no cross-request contamination, duplicate completion or changed header
policy/security outcomes.

Exit: actual emitted JSON and decoded traces link the intended requests only;
unsampled requests remain diagnosable through bounded IDs where configured.

## Commit 07 - Metrics Coverage And Cardinality Lifecycle

Suggested subject: `Observability commit 07: add bounded operational metrics`.

Operator value: actionable rates, latency, saturation and failure measurements.

Deliver:
- Fill measured gaps for admission/connections, upstream health, cache, PHP,
  ACME, TLS, reload, Wasm and telemetry queues/drops; reuse existing counters.
- Define logical requests versus attempts, byte counts, reset semantics and
  histogram buckets. Do not double-count across proxy/cache wrappers.
- Bound configured labels, unknown buckets and churn across repeated reloads.
  Keep lifetime counters meaningful when resources are removed/recreated.
- Keep Prometheus and existing OTLP metric descriptions consistent.

Tests: known traffic/fault sequences with exact deltas, concurrent cancellation,
random Host/path/method input, repeated config churn, histogram bucket costs,
disabled features and privacy mode. Assert RSS/series ceilings.

Exit: metric tables and compatibility fixtures match implementation; no new
arbitrary input is admitted as a series identity.

## Commit 08 - OTLP Failure, Recovery And Shutdown

Suggested subject: `Observability commit 08: bound collector export lifecycle`.

Operator value: collectors can fail and recover without taking the server down.

Deliver:
- Bound existing metrics/trace batches, queues, payloads, response reads,
  simultaneous requests, timeouts, retry count/elapsed time and backoff.
- Define partial success, retryable/nonretryable failures, duplicate delivery,
  dropped data and shutdown drain. No exactly-once export claim.
- Validate collector TLS/authentication, redirect policy and credential
  forwarding; retain approved local/private collectors rather than blindly
  rejecting operator-configured private addresses.
- Expose local export health even when the remote collector is unavailable.
  Never log recursively through the failing exporter.

Tests: unavailable/slow collector, bad TLS, authentication rejection, 429/503,
oversized/malformed/partial-success replies, recovery and shutdown. Assert
byte/task bounds, credential-canary absence and correct retry/drop semantics.

Exit: serving and local scrape continue while export fails; recovery delivers
new data without replay storms or unbounded queues.

## Commit 09 - UI-Ready Read-Only Operational Contract

Suggested subject: `Observability commit 09: expose bounded operational status`.

Operator value: operators and future clients inspect the same stable state.

Deliver:
- Document existing authenticated routes and add only bounded read-only
  projections needed for health, readiness, telemetry health, last reload and
  available listener/upstream/cache/PHP/ACME summaries.
- Include version, compiled capabilities, platform limits, sample timestamp,
  generation/staleness and explicit disabled/unavailable states.
- Commit an OpenAPI description and response/error fixtures for the supported
  status surface. Select a tooling-supported schema version during Commit 01;
  do not invent a second complete API family just for observability.
- Keep old routes compatible. Do not add config drafts/CRUD, token role
  management, arbitrary history queries or a GUI in this checkpoint.
- Distinguish telemetry degradation from readiness failure. Status collection
  must not initiate new operations. Preserve existing recovery enforcement
  semantics until explicitly reviewed; do not bypass failed rollback.

Tests: auth/no-side-effect boundaries, redaction and oversized inventories,
deadline/response/concurrency limits, restart/reload/rollback states, schema
validation and a small API-only client that reads status with no file access.
Test capabilities on reduced profiles and Windows as well as full Unix.

Exit: a future UI can render operational status without parsing logs or
depending on private Rust structs. This does NOT claim complete management.

## Commit 10 - Real Container And Collector Proof

Suggested subject: `Observability commit 10: prove live collector workflows`.

Operator value: documented deployment examples actually export useful data.

Deliver:
- Extend the existing smoke with a required-collectors release mode.
- Start a packaged Fluxheim image, controllable origin, PHP fixture, Prometheus
  and a pinned OTLP collector/trace backend using disposable networking/data.
- Send uniquely identifiable HTTP/HTTPS traffic and query the actual stored
  metrics/traces. Validate log/trace correlation, histograms and failure codes,
  not merely a health endpoint returning 200.
- Exercise cache hit/miss, upstream TLS failures, PHP failures, collector
  stop/restart, sink failure and graceful shutdown under traffic.

Tests: positive/negative assertions with time-bounded polling, no fixed sleeps
as the only synchronization; injected faults must be observed before recovery
is accepted. Verify secret-canary absence in all captured telemetry.

Exit: self-contained rootless Podman path and CI container path pass.
Missing services, unsupported tooling or skipped collector assertions make
this release gate incomplete. Cleanup owns only the test's resources; retain
sanitized failure evidence without dumping secrets.

## Commit 11 - Native Platforms And Extracted Archives

Suggested subject: `Observability commit 11: qualify native release profiles`.

Operator value: shipping archives work on each supported OS, not just CI Linux.

Required matrix:

| Native target | Packages and live proof |
| --- | --- |
| Linux x86_64 | Extract all seven profiles; actual ELF binaries, HTTP/HTTPS, file lifecycle, collectors, PHP and Wasm |
| Linux aarch64 | Same profile checks on ARM hardware/cloud host, not emulation-only |
| macOS Apple Silicon | Native Mach-O execution, file rotation/reopen, trust checks, HTTP/HTTPS, collector delivery and packaged Wasm |
| Windows x86_64 MSVC | Native PE execution, ACL/reparse/sharing, bounded shutdown, external TCP FastCGI and packaged Wasm |

For full, wasm, cache, proxy, load-balancer, php and config-tester, test the
capabilities actually compiled in, rejection of unsupported configuration,
archive integrity and version/commit identity. Config-tester validates configs
rather than being treated as an HTTP server. Test telemetry feature-off builds
separately. Require configured real collector delivery/recovery on each OS;
a remotely hosted disposable collector is acceptable with recorded TLS/network
setup. Do not mark the Mac gate passed after skipping collector checks.

Use off-host HTTP/HTTPS traffic for disposable-host qualification, temporary
credentials and approved firewall rules. Include service startup, reload,
rotation, collector outage and shutdown under traffic. No production CA or
customer traffic is required. Record native OS/toolchain, exact candidate SHA,
commands and artifacts. Cross-compilation is supplemental only.

Exit: all platform/profile rows have evidence or an explicit release-blocking
gap. The 1.8.3 runs are reference baselines, not substitutes.

## Commit 12 - Operator Docs And Final Release Qualification

Suggested subject: `Observability commit 12: qualify Fluxheim 1.9.0`.

Operator value: one complete release with usable diagnostics and honest limits.

Deliver:
- Working configurations, field/metric reference, troubleshooting and bounded
  loss/recovery semantics; example dashboards and alerts tested against fixtures.
- Document authentication, privacy, sampling, rotation and platform limits.
  Keep restart-required settings distinct from reloadable settings.
- Synchronize README, changelog, release notes, Rust/RPM/archive/container
  metadata and the release helper's actual output.
- Finalize a management-API handoff inventory, without claiming future CRUD,
  roles, supervisor restart or fleet orchestration already exist.

Release gate:
- Full locked workspace tests, feature/profile validation, fmt/clippy with
  warnings denied, advisories/licenses, CodeQL and changed-parser fuzz/negative
  cases. Recheck existing PHP, ACME, snapshot and filesystem regressions.
- Run current stable/deep gate plus the new required-collector and native
  archive matrix on the final runtime candidate, with performance budgets.
- Independent whole-release pentest/retest and green GitHub for the exact final
  commit. Earlier incremental green is not final acceptance.
- Record immutable candidate, toolchain, artifact checksums, source/tag trust,
  default-binary reproducibility scope and explicit release authorization.
- Only then sign/tag/build/publish 1.9.0. Source changes after qualification
  require affected tests again; documentation-only changes must prove identical
  runtime inputs and obtain their own CI result.

## Command Baseline

These commands exist today; checkpoints add named tests and required-collector
options rather than pretending a future flag already works:

```bash
cargo fmt --all --check
scripts/validate-release-metadata.sh
python3 scripts/test_release_metadata.py
python3 scripts/test_development_scope.py
sh scripts/validate_release_helpers.sh
perl scripts/check-doc-links.pl
cargo test --locked --workspace
cargo test --locked -p fluxheim-systemd --all-targets
cargo build --locked -p fluxheim-systemd --example activation_ownership_probe
sh scripts/smoke_observability_local.sh
sh scripts/smoke_macos_native_parity.sh
```

Run macOS commands on the Mac, not Linux. Windows uses
`scripts/smoke_windows_native.ps1` and the archive/profile/Wasm smokes.
Inspect existing gate options before execution; the current optional local
collector behavior is not the new required-collector acceptance contract.

## Acceptance Ledger

| Checkpoint | State | Accepted SHA / pentest / CI / live evidence |
| --- | --- | --- |
| Preparation - 1.8.3 reconciliation and this plan | Prepared; review pending | Not an observability implementation acceptance |
| 01 - Inventory, schemas, budgets | Not started | Pending |
| 02 - Event model/redaction | Not started | Pending |
| 03 - Diagnostics/audit | Not started | Pending |
| 04 - Bounded dispatcher | Not started | Pending |
| 05 - File lifecycle | Not started | Pending |
| 06 - Correlation | Not started | Pending |
| 07 - Metrics | Not started | Pending |
| 08 - Export | Not started | Pending |
| 09 - Read-only API | Not started | Pending |
| 10 - Live containers/collectors | Not started | Pending |
| 11 - Native archives | Not started | Pending |
| 12 - Release | Not started | Pending |

The next authorized implementation task is Commit 01, after this plan is
reviewed. Do not start it automatically while the user is discussing scope.
