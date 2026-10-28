# Commit 10: Real Collector Workflows

Date: 2026-10-28. Base: `76faa3ca`.
Status: implemented and qualified locally with rootless Podman. Pentest and
exact-SHA GitHub acceptance, including Docker execution, remain required.
No release or Commit 11 authorization.

Commit 09 was accepted after the owner's clean security retest and green GitHub
report. This checkpoint changes integration fixtures, dashboards, documentation
and CI, not Rust runtime code or the Cargo dependency graph.

## Scope

The required gate builds `containers/Containerfile.debian` with
`profile-observability,php-fpm`, then runs the packaged executable. The local
candidate image ID is
`sha256:9fceec319c10303ded60f95e2007416dc662a6ed96f54e758a1e0ea1147c7d92`.
The image build uses the production multi-stage recipe and locked Cargo input;
test fixtures are mounted separately. It is not a release image publication.

| Component | Locked version |
| --- | --- |
| Prometheus | 3.15.1 |
| Grafana | 13.2.4 |
| Jaeger | 2.22.0 |
| OpenTelemetry Collector Contrib | 0.163.2 |
| SigNoz | 0.148.0 |
| SigNoz Collector/schema migrator | 0.144.15 |
| ClickHouse | 25.12.5 |
| PHP-FPM | 8.4 FPM Bookworm image |
| Python origin | 3.13 slim Bookworm image |
| Playwright | 1.60.0 |

Exact OCI digests are in [images.json](../../examples/observability/images.json);
browser dependencies have an npm integrity lock. The tested protocols are
Prometheus scraping, OTLP/HTTP and Collector filelog ingestion, not vendor SDKs.

## Acceptance Assertions

- Real HTTP and verified downstream HTTPS requests through the packaged server.
- Real external TCP PHP-FPM success and a deliberately unavailable PHP target.
- Cache miss and hit, with their stored histogram observations.
- A real HTTPS origin whose certificate is not trusted by Fluxheim; request
  failure and the bounded `tls_verification` reason must be recorded.
- Independently stored direct-scrape and OTLP-exported request counters,
  status classes and latency histograms; finite traffic/error/p95 panel results.
- Sampled request IDs, trace IDs and span IDs matched between access events and
  the actual stored Jaeger trace; no substring-only correlation assertion.
- Collector log timestamp/severity/trace parsing and a separately identified
  synthetic multiline parser case, preserving nanosecond integers.
- Actual Collector stop/restart, observed exporter failure while serving
  continues, then a new trace stored after recovery.
- Actual log-file permission drift, observed sink failure, no silent sink
  resumption after repair, and continued successful HTTP responses.
- Normal container exit code zero under host-originated concurrent traffic,
  before the forced-kill deadline, with no OOM termination.
- SigNoz authenticated dashboard import and stored metrics/traces/correlated
  log queries. Browser inspection must show actual charts, not only login or
  health pages. Event-derived links must open the expected stored trace.
- Canary absence in queried telemetry and captured JSON logs. Private failure
  diagnostics are not uploaded as public CI artifacts.

## Validation Record

The complete wrapper passed on 2026-10-28:

```sh
sh scripts/check_collectors.sh release-reports/observability-10-20261028-final
```

That ignored local directory contains `summary.json`, `grafana.png`,
`jaeger-trace.png`, `signoz.png` and `signoz-trace.png`. The summary records both
stacks, the immutable candidate/backend identities, six correlated traces,
observed sink failure and successful shutdown under traffic. Both imported
dashboards passed browser canvas checks and were visually inspected. All 17
panel queries were executed against each backend; the four primary SigNoz
panels additionally required populated range-query results. This does not claim
visual inspection of every lower dashboard panel.

An initial final-wrapper attempt exposed a single-sample chart readiness race:
a valid sample dot was too small for the canvas-pixel threshold. Qualification
now waits for two finite gauge samples in one series, without weakening the
pixel check. A regression covers single, nonfinite and split-series samples.
Installed browser package documentation is excluded from the repository link
check; a regression confirms first-party broken links still fail.

| Check | Result |
| --- | --- |
| Packaged server, both real collector stacks and browser workflows | Passed |
| Collector fixture/security regressions | 29 passed |
| Observability crate, all features | 72 unit tests and 1 compile-fail doc test passed |
| Observability all-target Clippy with warnings denied | Passed |
| Existing observability baseline regressions | 4 passed |
| Existing log-rotation fixture regressions | 11 passed; Windows-native-only test skipped on Linux |
| Documentation layout / release metadata / development scope tests | 4 / 3 / 7 passed |
| Dashboard drift, doc links, release metadata, portable plan and modularity checks | Passed |
| Python compilation, shell/Node syntax, workflow YAML and diff checks | Passed |
| Cargo audit and cargo-deny advisories | Passed; 449 production dependencies, no reported advisories |
| Browser npm audit | No reported vulnerabilities |

No full Rust workspace rerun is claimed for this integration-only checkpoint;
the focused observability suite and production container compilation passed.
No native macOS/Windows execution is claimed by this container checkpoint.
Docker is not installed on the local host; the dedicated mandatory GitHub job
must qualify that path. The rootless Podman result does not stand in for it.

## Boundaries

The fixture creates fresh, private data with random admin credentials and only
loopback host forwards. Backend plaintext endpoints share one disposable network
namespace; remote production OTLP still requires HTTPS. Anonymous local test
databases, test TLS keys and image-root backend processes are not production
deployment guidance. Cleanup is scoped to owned containers/anonymous volumes,
never a system-wide prune.

ACME issuance, load-balancer backend health, active reload workflows, long-term
retention, hosted dashboards, Tempo/Loki and application-internal APM are not
qualified by this fixture. Their dashboard panels are optional measurements,
not proof of those workflows. Commit 11 still requires the native archive matrix.
Queue admission and ordinary file writes remain nondurable audit boundaries.
The synthetic client supplies a sampled `traceparent` but does not export its
own parent span. A backend's missing-parent warning for that client span is
therefore expected; the Fluxheim request and upstream-attempt spans are queried
and matched explicitly. It is not proof of application-internal tracing.

See [Collectors And Dashboards](../guides/collector-integrations.md) for commands,
filters, transport rules and the backend upgrade procedure.

## Pentest Follow-Up: Bind-Mount Boundary

Review of `4f9191fe` confirmed a host-side symlink-following vulnerability in
the integration harness: containers could modify the shared fixture directory
before the host wrote configuration or browser credentials there. This was
not a Rust webserver vulnerability, but could affect the operator running the
gate and required remediation.

The follow-up separates host-only controls/private browser input from runtime
data. All container controls are generated before startup and mounted only as
individual read-only files. No container receives the host control directory,
its parent, or the browser/evidence directories. Runtime mounts are a closed
set: server logs/cache/state and a separate Collector output directory. The
Collector's source log mount is read-only.

Control creation uses descriptor-relative exclusive/no-follow opens and
descriptor-based permissions. Guest-writable log reads, synthetic appends and
permission-failure injection also pin validated single-link regular handles,
rejecting symlinks and special files without blocking on FIFOs. Browser input
is removed before container cleanup even if the browser fails.

Regression tests cover existing/dangling symlinks, hard links, linked parents,
filename traversal, file swaps before chmod/append, special files, read-only
mount enforcement, all-controls-before-start ordering and credential cleanup.
The complete rootless Podman wrapper passed again on 2026-10-28:

```sh
sh scripts/check_collectors.sh release-reports/observability-10-pentest-20261028
```

The ignored output directory contains the success summary and four browser
screenshots. Live mount inspection confirmed individual read-only controls,
only logs/cache/state writable by Fluxheim, and a read-only source log plus
separate writable output for the Collector. All stored-signal, browser,
outage/recovery, sink-failure and shutdown assertions passed unchanged.

Follow-up validation: 38 collector regressions; 72 observability unit tests
and its compile-fail doc test; 4 observability baseline tests; strict
all-feature observability Clippy; Python compilation; dashboard drift;
documentation layout/links; diff checks; and Cargo audit (449 dependencies,
no reported advisories). No Rust, Cargo manifest/lockfile or image pin changed.
The processed pentest file was removed after qualification.
The original Docker collector job passed in GitHub run `40736944356`; that
does not substitute for rerunning CI on the remediation commit.

## Pentest Follow-Up: Log Identity

Retest of `5170d330` confirmed the host-overwrite fix but identified stale-inode
evidence in the sink-failure check. The pinned handle was safe to modify, yet
an unchanged old file could hide resumed logging to a replaced `events.log`.

The harness now checks the current leaf without following symlinks, verifies
single-link regular-file metadata and compares device/inode with the pinned
descriptor around fault/recovery observations. Missing paths fail immediately.
The existing size check remains, and all permission changes still use the
validated descriptor. No pathname-based write/chmod or writable control mount
was reintroduced.

Regression coverage includes unchanged files, equal-content replacement files,
symlinks, hard links, FIFOs, directories, missing paths, replacement during both
fault and recovery requests, and resumed writes to the original inode. These
are bounded checks of observed behavior, not continuous filesystem monitoring
or independent provenance for a hostile candidate.

Qualification on 2026-10-28:

```sh
sh scripts/check_collectors.sh release-reports/observability-10-inode-retest-20261028
```

Both real collector/browser stacks, stored signals, fault/recovery checks,
the strengthened log-sink check and graceful shutdown under traffic passed.
The ignored evidence directory contains the summary and four screenshots;
all owned containers were removed. The 42 collector regressions (including
the earlier host-file protection tests), 72 observability unit tests and
compile-fail doc test, 4 baseline tests, strict observability Clippy, Python
compilation, dashboard drift, documentation layout/links and diff checks
passed. Cargo audit reported no advisories across 449 dependencies.

No Rust runtime, dependency or image changes were required. `PENTEST.md` was
removed after qualification. Exact-commit GitHub checks and pentest retest
remain required before progressing to Commit 11.
