# Fluxheim 1.9.0 Release Notes

**Status: unreleased development draft.** `main` reports 1.9.0 to distinguish
it from the latest published release, v1.8.3. No 1.9.0 release tag or published
archives exist yet.

## Release Outcome

Fluxheim 1.9.0 adds bounded local diagnostics, request correlation, operational
metrics, resilient OTLP/HTTP export and an authenticated read-only status API.
Use the [operator walkthrough](../docs/guides/observability.md) for working
configurations, alerts, troubleshooting, restart rules and privacy boundaries.
No collector, new management listener or GUI is enabled by default.

Packaged systemd services and container deployment examples now disable core
files with zero soft/hard limits. Existing deployments must restart services or
recreate containers with the updated settings; pulling an image alone does not
apply them. Linux server, ACME and config-tester executables additionally mark
themselves non-dumpable before loading configuration and reject startup if the
kernel policy cannot be set or verified. This also prevents kernel-piped dumps;
policy failure exits silently with status 1 so blocked stderr cannot stall it.
External children and other platforms still need separate operator controls. See
[memory-dump security guidance](../SECURITY.md#fatal-termination-and-memory-dumps).

The [observability commit plan](../docs/roadmap/observability-commit-plan.md) defines
logging, metrics and operational visibility as this release's scope:
actionable diagnostics, bounded logging/export, request correlation,
low-cardinality metrics and authenticated status. These implementation
checkpoints preserve privacy and existing
configuration; collectors are not mandatory to run Fluxheim.

The thirteen checkpoints include a documented read-only operational API contract
and a final whole-product documentation review with tested configuration recipes
and publication on fluxheim.eu. The whole-product Commit 13 review is still
required; the observability guides and dashboard integration are implemented.
A full transactional management API and separate UI are
[proposed for later work](../docs/ideas/management-api-direction.md), not promised
or implemented in this release.

## Commit 01 Preparation

The numbered summaries below record implementation history. Statements about
later checkpoints describe the state at that checkpoint, not missing current
features; the implemented 05-11 summary follows them.

- Organize documentation into indexed guides, reference, architecture, roadmap,
  ideas and evidence; update packaging/tooling references without deleting history.
- Freeze runtime JSON, Prometheus and OTLP encoder contracts with regression tests.
- Add a repeatable loopback baseline and record native observability wiring gaps.
  Native access-log completion and request-span export still need implementation;
  propagation and an exporter library alone are not proof of delivered traces.
- Plan importable Grafana and SigNoz dashboards and real backend tests using
  vendor-neutral telemetry. These integrations are not implemented yet.

## Commit 02 Event Contract

- Add typed access, error, security and audit envelopes with finite reasons,
  numeric configured-resource identities and opt-in validated correlation IDs.
- Bound encoded JSON/text events to 8 KiB including framing, and use a closed
  schema without raw errors, headers, URLs, bodies or arbitrary field maps.
- Keep privacy restrictions and effective log filters authoritative; access-log
  disablement does not disable otherwise permitted security/audit events.
- This is a capture/encoding library, not native event emission, asynchronous
  logging or collector delivery. Existing runtime formats remain unchanged;
  later checkpoints connect owners and dispatch. See the
  [contract](../docs/architecture/structured-events.md) for limits and caveats.

## Commit 03 Operational Events

- Emit finite operational reasons at native upstream, TLS, PHP, cache, Wasm and
  policy failure sites. Retrying owners do not infer causes from a final 502/503.
- Audit authenticated admin mutations and automatic expired-validation rollback
  separately. Request headers never select actor identity, logging policy or
  correlation trust; this checkpoint omits correlation and resource identities.
- Retain public response and fail-closed rollback behavior, with regression
  assertions on both outcomes and emitted events. Add live JSON/text/filter
  smoke coverage with private-data canaries.
- Admit typed events before encoding into independent bounded ordinary, security
  and audit queues. Dedicated workers perform sink I/O; public security floods
  cannot spend audit queue capacity. Expose per-lane loss/failure counters through
  authenticated admin status. This is not a lossless/durable audit journal, and
  legacy logging still needs the wider Commit 04 dispatcher migration.
- Reserve audit capacity before admin mutations and automatic deadline rollback.
  Unavailable capacity or disabled audit outcomes return 503 `audit_unavailable`
  before state changes. Enable INFO audit outcomes (for example,
  `RUST_LOG=warn,fluxheim::event::audit=info`). Completion detecting a failed worker
  returns `audit_delivery_failed` with `operation_may_have_completed: true`;
  inspect state before retrying. This does not guarantee persistence across sink
  failures or crashes. See the [admission boundary and tests](../docs/evidence/observability-03-audit-admission.md).
- Replace automatic ACME renewal's raw domain/error outcome messages with typed
  events. Other legacy logs retain their existing formats.

## Commit 04 Bounded Logging

- Preserve fatal security-invariant diagnostics outside asynchronous log queues.
  Explicit aborts synchronously report a finite reason to stderr, or to a private
  `logging.crash_file` opened at startup. The optional file is separate from
  ordinary logs and requests data synchronization; failures fall back to stderr.
  A prestarted watchdog forces an abort after a 250 ms diagnostic grace period
  following wake-up if file I/O or stderr locks stall. Critical listener exits
  also emit finite reasons. Scheduling latency is additional; this is not a
  durable audit journal or a substitute for an external supervisor.
- Route runtime/library `log` calls through a separate bounded worker. Slow or
  closed sinks no longer make those calls wait on file/pipe I/O. Preserve typed
  security/audit capacity and pre-mutation audit reservations.
- Limit legacy records to 128 outstanding, eight concurrent captures, 4 KiB
  message, 1 KiB target and 8 KiB encoded output. Oversized/full/unavailable
  submissions are dropped and counted, not synchronously retried.
- Preserve runtime JSON fields and startup filter precedence. Text output now
  escapes controls, quotes and backslashes so one record remains one line.
- Expose authenticated `legacy_logging` health/loss counters. Fail startup on
  logger installation failure instead of silently using a preinstalled logger.
  Drain all four workers with a shared 500 ms deadline; no durability guarantee.
- Keep reload ownership startup-only, existing file trust checks and the `log`
  facade. No new tracing bridge, duplicate completion producer, collector or
  queue-sizing configuration is introduced. See [evidence and limits](../docs/evidence/observability-04.md).

## Implemented Commits 05-11

- Confidential file logging supports safe rename/reopen, recovery from rejected
  replacement files and terminal failure on active sink trust/write loss.
  Rotation must preserve 0600/private ACLs; readable collector files are rejected.
- Native HTTP/1.1 and HTTP/2 requests have one completion outcome, optional
  request correlation and sampled server/upstream-attempt spans. Only trusted
  direct peers can supply accepted IDs/trace parents. Local roots stay unsampled.
- Metrics distinguish logical requests, retries, active connections, handshake
  results, module failures and telemetry health. Global cardinality is bounded
  to 20,000 exported samples with explicit overflow behavior across reloads.
- Optional OTLP/HTTP metrics/traces use bounded queues, retries, response limits
  and shutdown. Plain HTTP is allowed only for numeric loopback collectors;
  remote/private/DNS collectors and bearer tokens require verified HTTPS.
- GET `/_fluxheim/operational-status` exposes bounded capabilities, configuration
  counts, recovery readiness and telemetry health. Its optional observer token
  cannot invoke mutations or reset control-token authentication failures.
- Importable Grafana and SigNoz dashboards are qualified against actual stored
  metrics/traces and externally collected JSON logs. They observe Fluxheim;
  application/database instrumentation remains outside its request boundary.
- Native qualification covers seven archive profiles on Linux x86_64/ARM64,
  macOS Apple Silicon and Windows x86_64. A local dedicated Windows QEMU VM
  is supported for testing/building within its documented single-owner model.

## Upgrade Notes And Limits

- Logging sink/filter, metrics/export, tracing and admin settings require a
  restart or process upgrade. Access-log routing policy remains snapshot-safe.
  Token-file replacement is not live credential rotation.
- Structured events have a closed schema distinct from legacy diagnostic JSON;
  update collector parsers for both timestamp formats and preserve correlation.
- Logging/audit admission and OTLP are best effort. Sink failure, saturation,
  expiry or process death can lose records; retries can duplicate accepted data.
  No durable audit journal, export spool or exactly-once claim is introduced.
- Keep INFO audit outcomes enabled. Failed admission blocks mutations with
  `audit_unavailable`; post-mutation delivery failure can report
  `operation_may_have_completed`. Inspect state before retrying.
- Privacy-mode restrictions remain compile-time enforced. Windows PHP remains
  external TCP FastCGI; no Windows managed PHP, Windows ARM64 or macOS Intel
  support is added. HTTP/3 remains deferred; full management and UI are future work.

## Implemented Maintenance

Commit 10A corrects operation-scoped ACME validation:

- Both renewal commands can use a PHP/cache-enabled server config without
  requiring those unrelated runtime capabilities in the renewal container.
- Server startup, `--validate-config` and `--check-config` consistently reject
  unsupported enabled features. The PHP package still excludes cache; the full
  Wolfi package still does not install PHP-FPM.
- ACME/TLS, include, secret and storage checks remain enforced. Reload/control
  commands separately validate the control socket. Certificate installation
  alone does not imply activation in an already running gateway.
- Both commands pass real local HTTP-01 issuance in full and PHP images.
  See [renewal guidance](../docs/guides/certificate-renewal.md#renewal-and-server-validation)
  and [qualification evidence](../docs/evidence/observability-10a.md).
  This fix is not present in released 1.8.3 images.

Post-1.8.3 security maintenance:

- Retain the ACME cryptography fixes for RUSTSEC-2026-0385 and
  RUSTSEC-2026-0387; qualification now locks `ctutils` 0.4.7 and
  `crypto-bigint` 0.7.10.
- Refresh 27 compatible production lockfile packages and two fuzz packages for
  candidate qualification, including AWS-LC, Brotli, rustix, ICU and WebPKI roots.
  Rust remains 1.99.1 and Wasmtime/WASI remains 50.0.0. The refresh requires new
  native/archive and collector evidence, not reuse of older binary checksums.

The shared 1.8.3 maintenance is retained, not a new 1.9 observability feature.
Production runtime sources and normalized dependency manifests were compared
with the maintenance branch before starting this implementation train.

- Update Rust to 1.99.1, workspace dependencies and the fuzz lockfile, including
  Wasmtime/WASI 50.0.0, sanitization 2.1.1 and base64-ng 2.1.0. Refresh pinned
  container bases; current GitHub Actions remain pinned to immutable commits.
- Keep workspace and RPM development metadata synchronized at 1.9.0.
- Use Rust 1.99's replacement atomic update API for UDP session admission,
  preserving existing ordering and session-limit behavior.
- Windows release-builder host metadata uses read-only HKLM information
  instead of requiring WMI permissions for the build account.
- Carry forward the standalone systemd rustix feature fix and exact RPM Rust
  minimum, with their CI regressions.
- Carry forward remote macOS release coordination, early builder preflight,
  output preservation and all fourteen release-helper regression tests.

## Independent Container Maintenance

The [runtime refresh workflow](../docs/guides/container-runtime-refresh.md) can refresh
the latest published release's OS and PHP packages without waiting for 1.9.0.
It uses the stable release's application sources and tests each image before
promoting versioned aliases. Unique rebuild tags and digests identify the new
runtime; application versions and signed Git tags do not change.

## Deferred HTTP/3 Research

The [HTTP/3 plan](../docs/roadmap/http3-quic-commit-plan.md), isolated source-locked
Quinn/rustls/h3 probes and [API-gap evidence](../docs/evidence/http3-migration-feasibility.md)
are retained for future evaluation when Brynja/Vef are more mature. Neither is
a production dependency or an approved solution to the gap today. No production
HTTP/3 listener or QUIC dependency was added. Reconnect-only behavior is not a
substitute for the preserved seamless migration/security contract.

Research runs only through the manual GitHub workflow or
`sh scripts/check_http3_research.sh`, not normal CI or local release checks.
Probe security pins are maintained separately; requalification must review
their capabilities and current advisories before any production admission.

## Qualification Still Required

Each observability checkpoint needs focused regressions, incremental pentest,
retest and green GitHub checks. Final acceptance additionally requires real
container/collector and native Linux, Apple Silicon macOS and Windows x86_64
archive tests on the final candidate. A skipped collector, successful
cross-compilation or historical platform run is not current runtime evidence.
