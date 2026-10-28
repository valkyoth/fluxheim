# Collector Integration Fixtures

Import `grafana-dashboard.json` into Grafana or `signoz-dashboard.json` into
SigNoz. They contain no credentials. Source queries, pinned backend versions and
the required real-container test are maintained together.

See [Collectors And Dashboards](../../docs/guides/collector-integrations.md) for
commands, prerequisites, filters, security boundaries and supported signals.
The Python origin/request files are disposable smoke fixtures, not production
applications. `images.json` pins the tested image digests, not a promise that
those versions will always be current.
