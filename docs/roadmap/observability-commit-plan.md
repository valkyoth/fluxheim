# 1.9.0 Observability Commit Plan

Status: Commits 01-06 accepted for progression; Commit 07 implemented, awaiting
pentest and exact-SHA GitHub acceptance, 2026-10-25.
Main stays at **1.9.0
(unreleased)**. This document replaces the earlier ten-checkpoint outline;
no previously accepted implementation checkpoint is being renumbered.

## Release Outcome And Scope

An operator can answer "what failed, why, when, and for which configured
service?" without turning on unsafe debug dumps. Logs, metrics, sampled traces
and authenticated status describe the same outcome, remain bounded, and expose
telemetry failures without stopping healthy application traffic.

Ship one coherent 1.9.0 after the numbered checkpoints. The checkpoints are
reviewable Git commits, not separate public releases. Use 1.9.x for maintenance
and compatible follow-ups. Existing configuration and privacy defaults remain
valid. New sensitive or expensive detail is opt-in; no public diagnostic
headers or management listener are silently enabled.

**Recommendation:** 1.9.0 is already a substantial release. Build dependable
read-only operational contracts here, then implement complete management in a
separate minor release, provisionally 1.10.0 subject to user approval. Keep
fluxheim-ui in its own repository. See the
[management API discussion](../ideas/management-api-direction.md) for the coverage
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

The [logging](../architecture/logging-architecture.md), [metrics](../architecture/metrics-architecture.md) and
[tracing](../guides/opentelemetry-tracing.md) documents mix implementation and historical
design ideas. Code and executed evidence take precedence. Correct their
implemented/planned labels before adopting any proposed configuration.

## Architecture And Security Contracts

### Vendor-Neutral APM Deliverables

1.9.0 includes tested integrations, not a vendor-specific APM runtime. Use
Prometheus and OTLP/HTTP at the Fluxheim boundary. No Grafana/SigNoz SDK,
mandatory cloud account, proprietary ingest protocol or default remote endpoint.

- Ship separate importable Grafana and SigNoz dashboards in the repository.
  Cover traffic/errors/latency, connections/admission, upstream health, cache,
  PHP, TLS/ACME, reloads and telemetry health only where measurements exist.
  Support instance/service and configured-resource filters; distinguish missing
  or disabled features from healthy zero values. Never use arbitrary URLs as labels.
- Test Grafana with Prometheus and Jaeger; test self-hosted SigNoz through an
  OpenTelemetry Collector. Tempo/Loki and hosted editions are optional follow-ups,
  not implicitly qualified by these two stacks.
- Optional log collection uses structured files/container logs and collector
  parsing. It does not add native OTLP log export. Test timestamp/severity parsing,
  multiline escaping, trace-ID correlation and secret-canary absence.
- Pin collector/backend images and dashboard schema versions when implementing
  Commit 10. Record tested versions, resource requirements and upgrade procedure.
  Preserve dashboard UIDs and parameterize data-source identities; no embedded
  credentials, public listeners or provisioned default passwords in examples.
- Import dashboards into actual running products and query the backing data
  for known requests, errors and histograms. Verify links from an event to the
  correct stored trace and visually inspect rendered panels. A health check,
  import success or syntactically valid query alone is not acceptance.
- Fluxheim observes its own request processing and upstream boundary. Database
  queries and application-internal spans require instrumentation in WordPress,
  PHP or the upstream application; do not promise automatic deep application APM.

Allocate schema compatibility to Commit 01, correlation to 06, metric queries
to 07, exporter semantics to 08, both live stacks/dashboard imports to 10,
native producer interoperability to 11 and operator instructions to 12. Heavy
backend tests run in a dedicated required integration gate, not every unit test.
Native producers may use remote disposable backends; installing the entire
backend stack on every supported OS is not required.
Commit 13 then reviews documentation for the entire product, including these
integrations, and makes the operator guides discoverable on fluxheim.eu.

### Runtime Contracts

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

Review artifacts: [inventory, contracts and proposed budgets](../evidence/observability-baseline.md),
[local raw measurements](../evidence/observability-01-linux.json), and
[documentation index](../README.md). Proposed ceilings still require operator
review; no checkpoint is accepted merely because these artifacts exist.

Deliver:
- Inventory every current producer, sink, exporter and admin route, including
  disabled features and HTTP/2/stream/UDP paths.
- Freeze existing JSON, Prometheus and OTLP fixtures with schema/field tables:
  units, optionality, privacy, severity, reason, cardinality and lifecycle.
- Specify logical request versus retry attempt, streaming completion, cancelled
  requests, pre-request TLS errors, and background operations without request IDs.
- Record startup-only versus reloadable settings and compatibility/deprecation.
- Capture resource/performance baselines and agree numeric budgets above.
- Organize documentation into guides, reference, architecture, roadmap, ideas
  and evidence, with a discoverable index. Preserve historical records, update
  local links and tooling paths, and label implemented versus proposed behavior.
- Record backend-independent signal/label identities needed by dashboards;
  freeze actual output rather than claiming library encoders prove live export.

Tests: parse actual serialized output; verify secret canaries and privacy
defaults; feature-disabled config cases; deterministic method/status buckets.
Run existing observability, logging, admin and metrics tests without changes
to their security properties.

Exit: inventory gaps map to later checkpoints; numeric budgets and baseline
commands are committed. No new admin mutation or runtime backend migration.

## Commit 02 - Bounded Event Model And Redaction

Suggested subject: `Observability commit 02: add safe structured event types`.

Operator value: consistent machine-readable events without sensitive dumps.

Review artifact: [structured event contract](../architecture/structured-events.md).
Local tests and live compatibility evidence are recorded in the
[Commit 02 evidence](../evidence/observability-02.md).
This checkpoint introduces the capture/encoding boundary; runtime failure owners
are connected in 03, dispatch in 04 and request completion in 06. It does not
claim to sanitize all existing free-form logs or deliver new native access logs.

Deliver:
- Add typed access, error, security and audit envelopes, version identity,
  finite reason codes, safe resource IDs and bounded optional correlation.
- Define level/filter precedence, including RUST_LOG and privacy mode.
  Preserve explicit operator choices; do not force verbose logging.
- Centralize sanitization, size accounting, truncation markers and serialization
  so text and JSON cannot bypass the same privacy/size contract.
- Define reserved capacity/rate limits for security/audit separately from
  ordinary access events; never promise lossless audit under hostile load.
  Security and audit must also have independent reservations from one another.

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

Review artifact: [owner coverage and local verification](../evidence/observability-03.md).
Security follow-up: [early admission and independent audit capacity](../evidence/observability-03-security.md).
Second follow-up: [fail-closed pre-mutation audit reservation](../evidence/observability-03-audit-admission.md).
Keep both prior backpressure/flood regressions and reservation regressions green;
memory admission is not a durable audit journal. Retest and exact-SHA CI are pending.
This remediation brings forward minimal typed-event dispatch from 04, not
acceptance of the full dispatcher milestone or permission to start it.

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

Implementation/evidence: [bounded legacy logging](../evidence/observability-04.md).
Pentest remediation: [fatal diagnostics before abort](../evidence/observability-04-fatal.md).
Retest remediation: [bounded fatal watchdog and critical exits](../evidence/observability-04-watchdog.md).
The earlier two-worker proposal is superseded: Commit 03 already requires three
isolated typed lanes; Commit 04 adds one separately bounded legacy worker rather
than letting arbitrary library messages consume audit/security capacity. Four
fixed workers and 128 records per lane remain far below the original byte/count
ceilings; runtime configuration for queue sizing is not introduced here.

Operator value: slow logging cannot stall serving indefinitely or exhaust RAM.

Deliver:
- Move identified synchronous hot-path writes behind a bounded dispatcher.
  Bound event count, bytes, producers, workers and submission cost.
- Freeze overflow semantics and counters, including security/audit exhaustion.
  Retain the independent audit/security lanes added by the Commit 03 remediation;
  never merge them into a quota that unauthenticated traffic can consume.
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
- Close native-runtime access-log/request-span wiring gaps from Commit 01 before
  claiming log-to-trace correlation. Test actual emitted events, not just encoders.
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
- Define tested dashboard queries, aggregation across instances, rate/reset
  semantics and histogram quantiles. Map every panel to a supported signal;
  missing metrics require implementation or an explicitly unavailable panel.

Tests: known traffic/fault sequences with exact deltas, concurrent cancellation,
random Host/path/method input, repeated config churn, histogram bucket costs,
disabled features and privacy mode. Assert RSS/series ceilings.

Exit: metric tables and compatibility fixtures match implementation; no new
arbitrary input is admitted as a series identity.

## Commit 07A - Dedicated Windows QEMU Builder And Test VM

Suggested subject: `Observability commit 07A: add a dedicated Windows QEMU workflow`.

Operator value: run native Windows builds, live tests and release packaging
locally without renting a cloud builder or changing another project's VM.
This is a separate infrastructure checkpoint after 07 and before 08; it does
not renumber the existing checkpoints or replace their acceptance gates.

Deliver:
- Create a fresh Windows 11 x86_64 installation from official installation
  media with an appropriate owner-supplied license. Give Fluxheim its own disk,
  persistent machine identity, virtual TPM, firmware variables, SSH host keys
  and loopback forwarding ports. Do not clone another project's development
  security settings or modify its running VM, launcher or clean backup.
- Use QEMU with explicit KVM acceleration on the x86_64 Linux host. Fail
  clearly if KVM is unavailable rather than silently falling back to CPU
  emulation. Record guest/host CPU, OS, firmware and virtualization versions;
  retain normal Windows security settings without development test-signing
  exceptions. Document actual Secure Boot/TPM/VBS state and any qualification
  gap rather than weakening settings to get a passing test.
- Provide a small, project-scoped launcher/setup workflow with exclusive
  instance locking, free-space/resource checks, bounded readiness polling,
  normal guest shutdown and explicit reset approval. Prefer existing QEMU
  tooling and Windows provisioning scripts over a new VM management framework.
  Never stop another project's processes or alter host virtualization settings
  automatically. Check port conflicts before launch; bind management endpoints
  to loopback and verify SSH host keys.
- Preserve two powered-off baselines: clean installed Windows, then Windows
  with the pinned build/test tools provisioned. Save disk, firmware variables,
  TPM and identity consistently with integrity manifests. Baselines must not
  be booted writable; restore into an isolated working copy. Preserve required
  encryption recovery material privately. A restore must not discard unsaved
  logs/artifacts or run while the guest is active. Explain disk growth, backup
  refresh after tool/OS updates, and that same-disk snapshots are not backups
  against host disk loss.
- Reuse the Windows provisioning and native release runner. Extend the Linux
  release helper to accept an explicit Windows SSH port or controlled SSH
  alias, consistently across preflight, upload, execution and download.
  Retain cloud-host compatibility; do not implement a second packaging engine.
  Keep strict host verification, signed-source selection, protected toolchain
  policy, non-administrator build identity, locked dependencies and existing
  checksum/reproducibility checks. VM setup/reset is explicit, never a hidden
  destructive side effect of starting the release helper.
- Keep routine development runs distinct from official packaging. Official
  runs start from a reviewed, updated tool-equipped baseline and a clean
  per-run build environment, not an accumulated development checkout. Record
  baseline identity, exact signed source, toolchain, commands and results.
  Preserve the existing reproducibility scope; two builds on this one host
  do not establish independent trust-domain verification.
- Keep release binaries portable across supported x86_64 CPUs: using KVM's
  host CPU model must not silently add Rust `target-cpu=native` or native C/C++
  optimization flags to release builds. VM performance and hardware coverage
  are not equivalent to testing every customer's machine.
- Commit reusable scripts, regression tests and a version-neutral guide.
  Keep licensed installation media, VM disks/state, activation/recovery data,
  credentials, machine-specific handoff notes and private evidence outside Git.
  Do not commit a preactivated VM or require a checked-in license key.

Tests and acceptance:
- Test configuration/command construction, SSH/SCP port consistency, quoting,
  path validation, unavailable KVM, insufficient space, port/lock conflicts,
  failed provisioning/builds, interrupted transfers and checksum mismatches.
  Failure must preserve evidence and must not publish partial outputs.
- Boot the real guest, provision tools, run Windows workspace/security tests
  and the live HTTP/HTTPS, correlation/metrics, cache, TLS, external TCP
  FastCGI and Wasm workflows relevant to the candidate. Use host-originated
  requests through loopback forwarding as well as guest-local tests. This
  proves the host-to-guest path, not public Internet reachability or public
  ACME issuance; keep those distinct where required by release qualification.
- Build and extract all seven Windows profiles using the existing release
  helper/runner, execute each profile's applicable checks, download artifacts,
  verify checksums and confirm the combined release report retains its Windows,
  Linux and macOS sections and existing reproducibility labels.
- Demonstrate graceful shutdown and a restore/rebuild from the Fluxheim
  baseline without changing the baseline or another project's state. Record
  real native execution separately from cross-compilation. Windows 11 evidence
  does not silently replace any separately claimed Windows Server coverage.
- Follow the same pentest/retest, exact-SHA green GitHub/CodeQL and explicit
  user-approval cycle as every other checkpoint. No new cloud account, public
  listener or automatic release publication is required.

Exit: an operator can prepare, boot, test, package, collect results and reset
the dedicated VM using documented commands. AWS remains an alternative native
Windows builder. Commit 11 still qualifies the final candidate's archives;
this checkpoint supplies reusable infrastructure, not advance release approval.

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
- Qualify both Grafana/Prometheus/Jaeger and SigNoz/Collector stacks above.
  Import versioned dashboards, exercise their real queries and inspect rendering.
  Include optional collected JSON logs and log/trace links; sanitize evidence.

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

## Commit 12 - Observability Docs And Release Candidate Qualification

Suggested subject: `Observability commit 12: qualify Fluxheim 1.9.0`.

Operator value: one complete release with usable diagnostics and honest limits.

Deliver:
- Working configurations, field/metric reference, troubleshooting and bounded
  loss/recovery semantics; example dashboards and alerts tested against fixtures.
- Document authentication, privacy, sampling, rotation and platform limits.
  Keep restart-required settings distinct from reloadable settings.
- Publish dashboard import/provisioning instructions, collector examples,
  tested backend versions, signal coverage and the upstream-instrumentation
  boundary. Explain that these dashboards observe Fluxheim, not administer it.
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
- Do not authorize publication here: Commit 13 is required before release.
  Source changes after qualification
  require affected tests again; documentation-only changes must prove identical
  runtime inputs and obtain their own CI result.

## Commit 13 - Documentation

Suggested subject: `Observability commit 13: document all supported functionality`.

Operator value: a customer can understand, configure, operate and troubleshoot
every supported Fluxheim capability without reading Rust or guessing settings.
This is a whole-product documentation checkpoint, not only an observability
guide or a cosmetic website update. It is required before publishing 1.9.0.

### Work Feature By Feature

- Create a coverage matrix from the actual configuration types/validators,
  runtime call sites, CLI commands, admin routes, compile-time features and
  shipping profiles. Record each supported option, mode and operation, its code
  references, guide section, example/test and review status. No undocumented
  public option may disappear behind a generic "advanced settings" link.
- Complete one feature at a time: read its code and existing tests, identify
  supported behavior and gaps, write the guide, execute examples, and review it
  before moving to the next feature. Start with GeoIP, then load balancing,
  cache and ACME; continue until the matrix has no unexplained coverage gaps.
- Reuse or consolidate existing guides rather than create competing copies.
  Give each feature a clear canonical page and link it from the documentation
  index and configuration reference. Preserve historical evidence and keep
  future ideas separate from shipped functionality.
- Audit what the native runtime actually executes, not only accepted config
  fields or library APIs. Mark unsupported, ignored, incomplete, deprecated or
  platform-restricted behavior explicitly. Do not invent options to make an
  example work or present future plans as supported features.

### Coverage And Guide Format

The inventory, not this illustrative list, defines completeness. Include
installation/profiles/containers/services; configuration/includes/vhosts/routes;
static files; reverse proxy/upstream TLS; load balancing/health/state; memory,
disk and encrypted caching; GeoIP; TLS/mTLS/FIPS and ACME issuance/renewal/recovery;
headers/CORS/hardening; compression; limits and abuse protection; PHP/FastCGI;
Wasm; HTTP/1.1, HTTP/2, WebSocket, stream and UDP; logging/metrics/tracing/APM;
privacy; admin API/local operations; snapshots/reload/rollback; diagnostics and
all supported CLI operations. Include enabled-feature and platform restrictions.

Every feature guide must provide:

1. A plain-language explanation, when to use it and when not to use it, with
   technical terms explained before use.
2. Prerequisites: package/profile/features, supported OS, external services,
   data files, permissions, mounts and networking. Explain which component
   supplies each prerequisite and avoid implying it ships inside every image.
3. A minimal complete working configuration, startup/validation commands and
   a request or command with its expected observable result.
4. An option reference derived from the code: exact key/type, units, defaults,
   valid values/ranges, scope/inheritance/precedence, interactions and whether
   restart or reload is required. Distinguish defaults from recommendations.
5. Copy-ready examples for every supported mode and meaningful option/use case,
   including disabling or overriding it. Map every public option to an example;
   group related options where useful rather than enumerate an impractical
   Cartesian product. Provide complete base files for explicitly marked fragments.
6. Realistic deployment recipes, operational lifecycle, common errors and
   troubleshooting with safe diagnostics and expected outcomes. Document
   resource costs, security/privacy tradeoffs, failure behavior and limitations.

Use safe placeholders for credentials and domains, explicit secret-file
permissions and private administrative endpoints. Never require disabling TLS
verification, weakening filesystem trust or exposing FastCGI/admin publicly
just to make a tutorial pass. Destructive examples must be clearly labelled
and tested only with disposable resources.

### Examples And Website Proof

- Keep executable configurations in repository examples/fixtures and reference
  them from the guides. Validate every complete example with the matching
  compiled profile; assemble and validate documented fragments with their base.
  Add negative tests for stated incompatible settings and missing features.
- Parsing alone is not proof. Run each distinct documented workflow against
  live Fluxheim and assert its advertised result, including relevant failure,
  reload and recovery paths. Reuse existing smokes where they prove the recipe;
  add missing coverage. Record exact commands, candidate SHA and results in the
  matrix. Platform-specific instructions require native platform evidence;
  missing environments are a gap, not a pass.
- Identify the fluxheim.eu source repository and publishing workflow. Use the
  repository guides as the canonical content source with a reproducible site
  import/build, avoiding manually maintained divergent copies. Provide a clear
  getting-started path, feature navigation, search and cross-links between
  guides, reference, examples and troubleshooting.
- Separate released documentation from unreleased main and show applicability
  and platform/profile restrictions. Keep routine instructions version-neutral
  where possible; do not hide real compatibility differences. Preserve old
  public URLs with redirects where supported and check internal links/anchors.
- Preview the actual site on desktop and mobile: check readable code blocks,
  navigation/search, example links and representative end-to-end operator
  journeys. Arrange access/approval for the website repository and deployment;
  record its revision and deployment evidence. A local Markdown edit alone
  does not complete the fluxheim.eu deliverable. Do not advertise 1.9 as released
  before release authorization.

Exit and final release gate:
- Every supported capability/option has reviewed code-to-guide-to-example/test
  coverage. No unexplained omissions, untested copy-ready recipes or misleading
  claims. Have an operator follow representative recipes without source-code
  assistance, and resolve the confusing steps they encounter.
- Run documentation/example/site checks and the normal incremental pentest,
  retest and exact-SHA green GitHub/CodeQL cycle. Track progress per feature;
  this large checkpoint may have reviewable documentation/remediation commits.
- Reconcile Commit 12 qualification with the final candidate. Any runtime,
  dependency, packaging or build-input change requires affected gates again;
  documentation-only changes require evidence of unchanged runtime inputs and
  fresh CI, not relabelled old binaries as final-candidate tests.
- Obtain explicit user acceptance of documentation, website and final release
  evidence. Only then authorize signing/tagging/building/publishing 1.9.0 through
  the existing release workflow. Do not begin a new feature project here to
  conceal a documentation-discovered limitation.

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
| 01 - Inventory, schemas, budgets | Accepted for progression | Base implementation 74212e08; dependency remediation 4cc86fe1; plan a04459ae; test-only CI follow-up 29484229. User supplied clean pentest, reported GitHub green and authorized 02. Later queue/performance budgets still need implementation qualification. |
| 02 - Event model/redaction | Accepted for progression | 74dbb160; user supplied clean pentest, reported GitHub green and authorized 03. Producer provenance is a mandatory integration gate. |
| 03 - Diagnostics/audit | Accepted for progression | 27c752a2341297ba10c055eaec234479f42714dc; user accepted the documented non-durable audit limitation, reported GitHub green and authorized 04. |
| 04 - Bounded dispatcher | Accepted for progression | User supplied clean pentest, reported GitHub green after follow-ups through ee98efea and authorized the next commit. [Legacy dispatch, bounds and qualification](../evidence/observability-04.md). |
| 05 - File lifecycle | Accepted for progression | User supplied clean pentest, reported GitHub green after follow-ups through d4a2569b and authorized 06. [Protected file lifecycle and qualification](../evidence/observability-05.md). |
| 06 - Correlation | Accepted for progression | b563894556fa; user supplied clean incremental pentest, reported GitHub green and authorized 07. [Request correlation and live qualification](../evidence/observability-06.md). |
| 07 - Metrics | Implemented; review pending | [Bounded metrics and qualification](../evidence/observability-07.md). Linux/container, native macOS and native Windows checks passed. Pentest and exact-SHA CI remain gates. |
| 07A - Dedicated Windows QEMU builder/test VM | Planned; not implemented | Owner requested a fresh Fluxheim-only VM and local release-helper integration. Preserve other projects and clean backups; native execution and packaging evidence pending. |
| 08 - Export | Not started | Pending |
| 09 - Read-only API | Not started | Pending |
| 10 - Live containers/collectors | Not started | Pending |
| 11 - Native archives | Not started | Pending |
| 12 - Observability docs / candidate qualification | Not started | Pending |
| 13 - Documentation / final release acceptance | Not started | Pending |

Commit 07 implementation is complete. Stop for pentest,
green GitHub checks and explicit approval before starting Commit 07A, then
repeat that acceptance cycle before Commit 08. Adding 07A to this plan does
not authorize VM provisioning, licensing purchases or changes to shared VMs.
