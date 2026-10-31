# Collector Integration Fixtures

Start with [local.toml](local.toml) and the
[operator walkthrough](../../docs/guides/observability.md). The optional
[otlp-local.toml](otlp-local.toml) fragment adds a same-host Collector without
implicitly trusting trace parents. [alerts.yml](alerts.yml) is a Prometheus rule
file for job `fluxheim`; [alerts-test.yml](alerts-test.yml) tests healthy, down,
absent and telemetry-loss cases with `promtool test rules alerts-test.yml`.
The separate `alerts-contract-test.yml` characterizes the pending persistent
log-sink alert gap and whole-job absence boundary. It is not a repaired-policy
acceptance test. [prometheus.yml](prometheus.yml) is a same-host authenticated
scrape/rule-loading example; provision its referenced rule and secret files.

Import `grafana-dashboard.json` into Grafana or `signoz-dashboard.json` into
SigNoz. They contain no credentials. Source queries, pinned backend versions and
the required real-container test are maintained together.

See [Collectors And Dashboards](../../docs/guides/collector-integrations.md) for
commands, prerequisites, filters, security boundaries and supported signals.
The Python origin/request files are disposable smoke fixtures, not production
applications. `images.json` pins the tested image digests, not a promise that
those versions will always be current.
