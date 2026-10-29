#!/usr/bin/env python3
"""Generate importable dashboards from reviewed, backend-neutral metric queries."""
import argparse
import json
from collector_stack import ASSETS

# %s is a label selector. Missing measurements remain missing, never `or vector(0)`.
PANELS = [
    ("Requests / second", 'sum(rate(fluxheim_http_requests_total{%s}[1m]))', "reqps"),
    ("HTTP 5xx / second", 'sum(rate(fluxheim_http_requests_total{%s,status_class="5xx"}[1m]))', "reqps"),
    ("Request p95 seconds", 'histogram_quantile(0.95, sum by (le) (rate(fluxheim_http_request_duration_seconds_bucket{%s}[1m])))', "s"),
    ("Active requests", 'sum(fluxheim_http_requests_active{%s})', "short"),
    ("Active connections", 'sum(fluxheim_listener_connections_active{%s})', "short"),
    ("Upstream attempts / second", 'sum by (outcome) (rate(fluxheim_upstream_attempts_total{%s}[1m]))', "reqps"),
    ("Failures by reason", 'sum by (reason) (fluxheim_operational_failures_total{%s})', "short"),
    ("Cache operations / second", 'sum by (phase) (rate(fluxheim_cache_operation_duration_seconds_count{%s}[1m]))', "ops"),
    ("PHP requests / second", 'sum(rate(fluxheim_php_requests_total{%s}[1m]))', "reqps"),
    ("TLS handshakes", 'sum by (outcome) (fluxheim_downstream_tls_handshakes_total{%s})', "short"),
    ("ACME events (when enabled)", 'sum by (event) (fluxheim_acme_events_total{%s,event!="overflow"})', "short"),
    ("Exporter failures", 'sum by (signal) (fluxheim_otlp_failed_total{%s})', "short"),
    ("Connection admission", 'sum by (outcome) (fluxheim_listener_connections_total{%s})', "short"),
    ("Admin operations / reloads", 'sum by (operation, outcome) (fluxheim_admin_operations_total{%s})', "short"),
    ("Log sink errors", 'sum by (lane) (fluxheim_log_dispatch_events_total{%s,outcome="sink_errors"})', "short"),
    ("Metric cardinality overflow", 'sum(fluxheim_metric_series_overflow_total{%s})', "short"),
    ("Load balancer events (when enabled)", 'sum by (event) (fluxheim_load_balancer_events_total{%s,event!="overflow"})', "short"),
]


def selector_for(query, base):
    if any(name in query for name in ("fluxheim_cache_", "fluxheim_php_", "fluxheim_load_balancer_")):
        base += ',vhost=~"$vhost"'
    return base


def signoz_query(query):
    # These are known dashboard templates, not a general PromQL rewriter.
    for metric in ("fluxheim_http_request_duration_seconds", "fluxheim_cache_operation_duration_seconds",
                   "fluxheim_php_request_duration_seconds"):
        for component in ("bucket", "count", "sum"):
            query = query.replace(metric + "_" + component + "{", '{"' + metric + "." + component + '",')
    return query


def grafana():
    panels = []
    for i, (title, query, unit) in enumerate(PANELS):
        panels.append({"id": i + 1, "type": "timeseries", "title": title, "interval": "1s", "maxDataPoints": 1000,
            "description": "Missing data means unavailable, disabled, or no observations; not healthy zero. Global request metrics have no vhost label.",
            "gridPos": {"x": i % 2 * 12, "y": i // 2 * 8, "w": 12, "h": 8},
            "datasource": {"type": "prometheus", "uid": "${DS_PROMETHEUS}"},
            "targets": [{"refId": "A", "expr": query % selector_for(query, 'job=~"$job",instance=~"$instance"'), "legendFormat": "__auto"}],
            "fieldConfig": {"defaults": {"unit": unit}, "overrides": []}, "options": {"legend": {"displayMode": "list"}}})
    return {"uid": "fluxheim-operations-v1", "title": "Fluxheim operations", "schemaVersion": 41,
            "version": 1, "tags": ["fluxheim"], "timezone": "browser", "refresh": "5s",
            "time": {"from": "now-15m", "to": "now"}, "panels": panels,
            "templating": {"list": [
                {"name": "DS_PROMETHEUS", "type": "datasource", "query": "prometheus"},
                {"name": "job", "type": "query", "datasource": {"type": "prometheus", "uid": "${DS_PROMETHEUS}"},
                 "query": 'label_values(fluxheim_http_requests_active, job)', "refresh": 1, "multi": False},
                {"name": "instance", "type": "query", "datasource": {"type": "prometheus", "uid": "${DS_PROMETHEUS}"},
                 "query": 'label_values(fluxheim_http_requests_active{job=~"$job"}, instance)', "refresh": 1,
                 "includeAll": True, "allValue": ".*", "multi": True},
                {"name": "vhost", "label": "Configured vhost (cache/PHP/LB only)", "type": "textbox", "query": ".*",
                 "current": {"text": ".*", "value": ".*"}}]}}


def signoz():
    panels, items = {}, []
    for i, (title, query, unit) in enumerate(PANELS):
        id_ = f"panel-{i + 1}"
        panels[id_] = {"kind": "Panel", "spec": {"display": {"name": title,
            "description": "Missing measurements are unavailable, not healthy zero."}, "links": [],
            "plugin": {"kind": "signoz/TimeSeriesPanel", "spec": {"formatting": {"unit": "s" if unit == "s" else "none"}}},
            "queries": [{"kind": "time_series", "spec": {"plugin": {"kind": "signoz/PromQLQuery",
                        "spec": {"name": "A", "query": signoz_query(query) % selector_for(query, '"service.name"=~"$service"')}}}}]}}
        items.append({"x": i % 2 * 6, "y": i // 2 * 8, "width": 6, "height": 8,
                      "content": {"$ref": "#/spec/panels/" + id_}})
    return {"schemaVersion": "v6", "name": "fluxheim-operations-v1", "tags": [], "spec": {
        "display": {"name": "Fluxheim operations", "description": "Fluxheim boundary telemetry; application-internal spans require application instrumentation."},
        "duration": "15m", "refreshInterval": "5s", "variables": [{"kind": "TextVariable", "spec": {
            "name": "service", "value": "fluxheim-collector-proof"}}, {"kind": "TextVariable", "spec": {
            "name": "vhost", "value": ".*"}}], "links": [], "panels": panels,
        "layouts": [{"kind": "Grid", "spec": {"items": items}}]}}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    for name, content in (("grafana", grafana()), ("signoz", signoz())):
        path = ASSETS / f"{name}-dashboard.json"
        encoded = json.dumps(content, indent=2) + "\n"
        if args.check:
            if path.read_text() != encoded:
                raise SystemExit(f"dashboard drift: {path.name}")
        else:
            path.write_text(encoded)


if __name__ == "__main__":
    main()
