# Fluxheim 1.9.0 Release Notes

**Status: unreleased development draft.** `main` reports 1.9.0 to distinguish
it from the latest published release, v1.8.3. No 1.9.0 release tag or published
archives exist yet.

## Planned Outcome

The [observability commit plan](../docs/roadmap/observability-commit-plan.md) defines
logging, metrics and operational visibility as this release's scope:
actionable diagnostics, bounded logging/export, request correlation,
low-cardinality metrics and authenticated status. These implementation
checkpoints begin with the Commit 01 inventory and baseline. New telemetry must preserve privacy and existing
configuration; collectors are not mandatory to run Fluxheim.

The thirteen checkpoints include a documented read-only operational API contract
and a final whole-product documentation review with tested configuration recipes
and publication on fluxheim.eu. These documentation deliverables are planned,
not yet completed.
A full transactional management API and separate UI are
[proposed for later work](../docs/ideas/management-api-direction.md), not promised
or implemented in this release.

## Commit 01 Preparation

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

## Implemented Maintenance

Post-1.8.3 security maintenance:

- Update the locked ACME cryptography dependency `ctutils` from 0.4.3 to 0.4.4
  to address RUSTSEC-2026-0385 (non-constant-time mask generation and `u128`
  comparisons). No ACME configuration or protocol behavior changes.

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
