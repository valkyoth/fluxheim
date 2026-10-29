# Collectors And Dashboards

Fluxheim exports Prometheus metrics and OTLP/HTTP metrics and traces. Grafana
and SigNoz are optional consumers, not dependencies of the webserver. These
dashboards observe Fluxheim; they do not administer it. Database queries and
application-internal spans require instrumentation in the upstream application.

## Run The Required Integration Gate

On a Linux machine with rootless Podman, Python 3.11+, Node.js/npm and the
Playwright browser dependencies installed:

```sh
npm ci --ignore-scripts --prefix tools/collector-browser
tools/collector-browser/node_modules/.bin/playwright install chromium
sh scripts/check_collectors.sh /tmp/fluxheim-collector-proof
```

Use a new output directory below the repository's `release-reports/` or `/tmp`
for each run. Linked directories and destinations outside those roots are
rejected before creation. Run-state directories are always created in `/tmp`,
independently of `TMPDIR`. On a supported Linux distribution,
`playwright install --with-deps chromium` can install missing system browser
libraries, but requires administrator privileges. The CI job uses Docker:

```sh
FLUXHEIM_CONTAINER_RUNTIME=docker \
  sh scripts/check_collectors.sh /tmp/fluxheim-collector-proof-docker
```

Allow approximately 8 GiB available RAM, several CPU cores and 20 GiB free
disk space for a cold image build, backend images and disposable data. The
ClickHouse schema initialization can take several minutes. Each container is
limited to two CPUs and 2 GiB; these are per-container limits, not a combined
stack budget. This is an integration fixture, not a benchmark.

The script builds the production Debian container with
`profile-observability,php-fpm`. It does not mount a host-built executable.
Backend images are pinned by digest in
[images.json](../../examples/observability/images.json). The candidate is
resolved to its immutable local image ID before running. A missing image,
browser, collector, dashboard, or expected observation fails the gate.
Before the stack starts, the pinned Prometheus `promtool` evaluates the shipped
[alert-rule fixtures](../../examples/observability/alerts-test.yml) without
networking. These are initial operational alerts, not universal application SLOs.

Tested backend versions (immutable digests in `images.json`): Prometheus 3.15.1,
Grafana 13.2.4, Jaeger 2.22.0, Collector Contrib 0.163.2, SigNoz 0.148.0,
SigNoz Collector 0.144.15 and ClickHouse 25.12.5. Do not silently replace them
with `latest` and assume the dashboard/query proof still applies.

To retest an already-built candidate:

```sh
sh scripts/smoke_observability_local.sh --required-collectors \
  --runtime podman --image YOUR_LOCAL_IMAGE \
  --output /tmp/fluxheim-collector-retest
```

`--stack grafana` is a narrower development check, not full Commit 10 or release
qualification. The release wrapper and CI always require both stacks. The old
smoke without `--required-collectors` remains a quick local check and can skip
external backends; its success does not replace this gate.

## What Is Tested

The test starts real PHP-FPM, HTTP and HTTPS origins, packaged Fluxheim,
Prometheus, an OpenTelemetry Collector, Jaeger, Grafana, ClickHouse, the SigNoz
ingester and SigNoz. It uses fresh databases, generated credentials and a
dedicated network namespace. Published ports bind only to `127.0.0.1` and are
chosen by the container engine. No production services, public CA or user data
are involved. Cleanup removes only containers created by this run and their
anonymous volumes. Image caches remain available for later runs.

The host generates all control files before starting any container. Only
individual read-only configuration, certificate and fixture files are mounted;
their parent directories are never exposed. Writable mounts are limited to
separate runtime log, collected-output, cache and process-state directories.
The Collector reads Fluxheim logs read-only and writes into its own output
directory. Browser credentials remain in an unmounted private directory and
are removed after the browser exits, including on failure.
The browser opens only `browser.json` in that private working directory, not a
command-line filename. Its no-follow reader requires a private, single-link
regular file owned by the current user and caps input at 64 KiB.

Host file creation is exclusive and no-follow. Host reads/appends and permission
fault injection on guest-writable logs use validated regular-file descriptors,
not a later pathname reopen or chmod. Symlinks, hard-linked evidence and special
files are rejected. These controls prevent guest-planted paths from redirecting
host operations; they do not replace the container engine's isolation or make
this fixture a general-purpose hostile-code sandbox.
The sink-failure check also compares the current log pathname's device/inode
with its pinned handle around fault/recovery observations. Missing, replaced
or unsafe leaves fail qualification, rather than treating an unchanged old
inode as proof that logging did not resume. Permission changes remain
handle-based. These are bounded observations, not continuous filesystem
monitoring or independent proof against a deliberately deceptive candidate.

Checks include actual HTTP/HTTPS and PHP responses, cache misses and hits,
untrusted upstream certificates, failed FastCGI connections, stored request
counters and latency histograms, and structured events linked to stored traces.
Direct Prometheus scraping and Collector-exported OTLP metrics use separate jobs,
so one cannot accidentally substitute for the other. Collector outage must
increase local export-failure counters while HTTP continues to work; recovery
must store a newly generated trace. Log permission failure must be observable
without stopping serving. Shutdown must finish successfully under traffic before
the container's forced-kill deadline.

The Collector parses timestamps and severity, preserves trace/span IDs, and
checks a separate multiline JSON parser fixture. The latter is deliberately
synthetic; it is not evidence that Fluxheim emits arbitrary multiline messages.
Credential, cookie and query canaries must not occur in captured telemetry.

Successful evidence consists of `summary.json` and dashboard screenshots.
Failures retain private diagnostic files with generated password/canary values
redacted. Treat those diagnostics as local troubleshooting data: do not publish
raw container logs or temporary credential files. CI uploads only successful
summary/screenshots, not failure logs.

## Import Grafana

1. Configure a Prometheus data source that scrapes Fluxheim's protected metrics
   listener. Keep it private and configure its bearer token when enabled.
2. Import [grafana-dashboard.json](../../examples/observability/grafana-dashboard.json).
3. Select the Prometheus data source, scrape job and instance. The configured
   vhost filter applies only to cache, PHP and load-balancer panels; global
   request and connection counters deliberately have no vhost label.
4. Add a Jaeger data source for the trace backend receiving Fluxheim's OTLP
   spans. Find an access event's `correlation.trace_id` in Jaeger and match its
   `correlation.span_id` to the server span, not merely to any trace at that time.

The dashboard UID is `fluxheim-operations-v1`. Preserve it when provisioning or
upgrading. Data-source credentials and URLs are not embedded in the dashboard.
Missing measurements mean disabled, unavailable, or no observations; they are
not converted to healthy zero values. TLS panels cover handshakes, not certificate
expiry. ACME, load-balancer and admin/reload activity can be absent when unused.

## Import SigNoz

Import [signoz-dashboard.json](../../examples/observability/signoz-dashboard.json)
into the tested self-hosted SigNoz dashboard API/UI. This is its `v6` Perses
dashboard format, not a Grafana dashboard. Set `service` to the OTLP
`service.name` configured in Fluxheim; the fixture uses
`fluxheim-collector-proof`. Set `vhost` to a configured resource name or `.*`.
The SigNoz file uses OTLP histogram `.bucket` and `.count` component names,
not Prometheus `_bucket` / `_count`. See the upstream
[PromQL UTF-8 syntax guide](https://signoz.io/docs/userguide/write-a-prom-query-with-new-format/).
New installations may answer instant queries before the first minute-aligned
chart bucket has data; the gate waits for stored range-query observations too,
including two finite gauge samples so the browser can verify a plotted line.

Send metrics and traces through a Collector to the SigNoz ingester. For optional
logs, use the Collector filelog receiver against Fluxheim's JSON file. Parse
`timestamp_unix_nanos` as an integer epoch in nanoseconds, `level` as severity,
and `correlation.trace_id` / `correlation.span_id` into the OTLP log trace/span
fields. Legacy diagnostics use RFC3339 `timestamp`. Do not use ingest time as a
substitute for event time. Escaped newlines remain part of the JSON record.
SigNoz can then navigate from a log's trace ID to the same stored trace.
The gate also opens backend trace pages using links derived from captured
events. It does not add a native log viewer to Fluxheim or qualify a Loki data
source. This disposable Collector has no persistent filelog cursor: restarting
it can reread records. Configure Collector storage/retention for production;
neither retries nor this fixture promise exactly-once delivery.

Fluxheim does not export native OTLP logs in this release. Log files and rotated
replacements must remain confidential (`0600` on Unix). Run a trusted local log
reader with appropriate identity/access; do not change files to `0640` or `0644`
to accommodate a collector. Fluxheim intentionally rejects those permissions.
See [logging](logging.md) for lifecycle and platform details.

## Transport And Deployment Boundaries

The generated fixtures in [collector_configs.py](../../scripts/collector_configs.py)
and [collector_signoz.py](../../scripts/collector_signoz.py) are deliberately
single-host tests. Their plaintext OTLP endpoints are numeric loopback addresses
inside the shared private namespace. Remote or private-network collectors require
HTTPS; bearer tokens require HTTPS even on loopback. Do not copy these loopback
exceptions to a remotely accessible production listener.

Do not publish the fixture's unauthenticated ClickHouse, Jaeger or Prometheus
ports outside the host. The disposable credentials, test TLS keys, memory trace
store and SQLite database are not a production deployment or retention policy.
Logs and in-memory audit admission are not a durable, independently protected
forensic journal. See [logging](logging.md).

## Upgrade And Qualification

Backend versions and immutable digests are locked together in `images.json`.
Update them deliberately from upstream release metadata, review migration and
dashboard/API compatibility, and run the entire required gate. Do not replace
digests with `latest` or treat a healthy login page as signal qualification.

Dashboard query definitions live in
[generate_observability_dashboards.py](../../scripts/generate_observability_dashboards.py).
After an intentional change, regenerate both JSON files and run the unit and
live checks:

```sh
python3 scripts/generate_observability_dashboards.py
python3 scripts/test_collectors.py
python3 scripts/generate_observability_dashboards.py --check
```

The [Commit 10 evidence](../evidence/observability-10.md) records tested versions,
scope and remaining qualification. These container tests do not replace native
macOS/Windows or extracted-release-profile tests in Commit 11. Tempo, Loki and
hosted Grafana/SigNoz editions are not implicitly qualified by these results.
