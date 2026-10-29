#!/usr/bin/env python3
"""Required packaged-server collector integration. Missing backends never skip."""
import argparse
import base64
import json
import math
import os
from pathlib import Path
import secrets
import subprocess
import tempfile
from urllib.parse import urlencode

from collector_stack import ASSETS, ROOT, Stack, api, http, poll, run_browser, write
from collector_configs import fixtures, collector, grafana_configs, grafana_stack
from generate_observability_dashboards import PANELS
import collector_signoz
import collector_lifecycle
import collector_logs
from collector_files import checked_directory

CANARY = "collector-proof-secret-canary"
PORTS = (8088, 8443, 9090, 16686, 3000, 8080, 8123)


def request(stack, host="cache.test", transport="http"):
    trace, id_ = secrets.token_hex(16), secrets.token_hex(8)
    result = json.loads(stack.command("exec", stack.names["origin"], "python", "/fixture/request.py",
                                      host, trace, id_, transport, timeout=15))
    return trace, id_, result


def query(stack, expression):
    result = api(stack.ports[9090], "/api/v1/query?" + urlencode({"query": expression}))
    assert result["status"] == "success"
    assert CANARY not in json.dumps(result)
    return result["data"]["result"]


def metric(stack, name, labels='job="fluxheim-scrape"'):
    result = query(stack, f"sum({name}{{{labels}}})")
    return float(result[0]["value"][1]) if result else None


def traces(stack, trace):
    status, body = http(stack.ports[16686], "/api/traces/" + trace)
    if status == 404:
        return None
    assert status == 200
    payload = json.loads(body)
    assert CANARY not in body.decode()
    return payload.get("data")


def events(stack):
    path = stack.data / "logs/events.log"
    try:
        text = collector_logs.read_private(path)
    except FileNotFoundError:
        return []
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def import_grafana(stack, password):
    poll(lambda: http(stack.ports[3000], "/api/health")[0] == 200, "Grafana ready")
    auth = {"Authorization": "Basic " + base64.b64encode(f"fluxheim:{password}".encode()).decode()}
    for type_, uid, url in (("prometheus", "fluxheim-prometheus", "http://127.0.0.1:9090"),
                           ("jaeger", "fluxheim-jaeger", "http://127.0.0.1:16686")):
        api(stack.ports[3000], "/api/datasources", {"type": type_, "uid": uid, "name": uid,
            "url": url, "access": "proxy", "isDefault": type_ == "prometheus"}, auth)
    dashboard = json.loads((ASSETS / "grafana-dashboard.json").read_text())
    dashboard["templating"]["list"][0]["current"] = {"text": "fluxheim-prometheus", "value": "fluxheim-prometheus"}
    dashboard["templating"]["list"][1]["current"] = {"text": "fluxheim-scrape", "value": "fluxheim-scrape"}
    dashboard["templating"]["list"][2]["current"] = {"text": "All", "value": "$__all"}
    result = api(stack.ports[3000], "/api/dashboards/db", {"dashboard": dashboard, "overwrite": True}, auth)
    assert result["uid"] == "fluxheim-operations-v1"


def verify(stack, password):
    def ready():
        state = json.loads(stack.command("inspect", stack.names["fluxheim"]))[0]["State"]
        assert state["Running"], "packaged Fluxheim exited; see private log"
        return http(stack.ports[8088])[0] == 200
    poll(ready, "packaged Fluxheim listener")
    poll(lambda: http(stack.ports[9090], "/-/ready")[0] == 200, "Prometheus ready")
    import_grafana(stack, password)
    observations = []
    for host, transport, status, body in (
        ("cache.test", "http", 200, "collector-proof-origin"),
        ("cache.test", "https", 200, "collector-proof-origin"),
        ("php.test", "http", 200, "collector-proof-php"),
        ("php.test", "https", 200, "collector-proof-php"),
        ("php-failure.test", "http", 502, None),
        ("tls-failure.test", "https", 502, None),
    ):
        trace, id_, result = request(stack, host, transport)
        assert result["status"] == status, (host, result["status"])
        if body:
            assert result["body"] == body
        observations.append((trace, id_))
        poll(lambda: traces(stack, trace), "stored trace")
    for trace, id_ in observations:
        log = poll(lambda: next((e for e in events(stack) if e.get("data", {}).get("kind") == "access" and
                   e.get("correlation", {}).get("request_id") == id_), None), "correlated access event")
        assert log["correlation"]["trace_id"] == trace
        assert any(span["spanID"] == log["correlation"]["span_id"] for span in traces(stack, trace)[0]["spans"])
    for source in ("fluxheim-scrape", "fluxheim-otlp"):
        for vhost, status, minimum in (("php", "2xx", 2), ("php-failure", "5xx", 1)):
            labels = f'job="{source}",vhost="{vhost}",method="GET",status_class="{status}",outcome="response"'
            for name in ("fluxheim_php_requests_total", "fluxheim_php_request_duration_seconds_count"):
                poll(lambda: (metric(stack, name, labels) or 0) >= minimum,
                     "stored PHP handler sample " + source + " " + vhost + " " + name)
        poll(lambda: (metric(stack, "fluxheim_http_requests_total", f'job="{source}"') or 0) >= 6,
             "stored " + source + " request counter")
        poll(lambda: bool(query(stack, 'fluxheim_http_request_duration_seconds_bucket{job="' + source + '"}')),
             "stored " + source + " histogram")
    for phase in ("miss", "hit"):
        poll(lambda: bool(query(stack, 'fluxheim_cache_operation_duration_seconds_count{job="fluxheim-scrape",phase="' + phase + '"}')),
             "stored cache " + phase)
    poll(lambda: (metric(stack, "fluxheim_operational_failures_total") or 0) >= 2, "typed failures")
    for labels in ('status_class="5xx"', 'status_class="2xx"'):
        poll(lambda: (metric(stack, "fluxheim_http_requests_total", 'job="fluxheim-scrape",' + labels) or 0) >= 2,
             "stored status class " + labels)
    for reason in ("tls_verification", "php_connect"):
        poll(lambda: (metric(stack, "fluxheim_operational_failures_total", 'job="fluxheim-scrape",reason="' + reason + '"') or 0) > 0,
             "stored failure reason " + reason)
    def populated(expression):
        values = query(stack, expression % 'job="fluxheim-scrape"')
        return bool(values) and all(math.isfinite(float(v["value"][1])) for v in values)
    for _, expression, _ in PANELS[:3]:
        poll(lambda: populated(expression), "finite traffic/error/latency panel")
    for _, expression, _ in PANELS:
        query(stack, expression % 'job="fluxheim-scrape"')
    # Actual outage, new traffic, local scrape and fresh post-recovery trace.
    before = metric(stack, "fluxheim_otlp_failed_total") or 0
    stack.stop("collector")
    def degraded():
        assert request(stack)[2]["status"] == 200
        return (metric(stack, "fluxheim_otlp_failed_total") or 0) > before
    poll(degraded, "observed exporter outage")
    stack.restart("collector")
    trace, _, result = request(stack, transport="https")
    assert result["status"] == 200
    poll(lambda: traces(stack, trace), "new trace after collector restart")
    collector_logs.verify(stack, observations)
    return observations


def main():
    if not __debug__:
        raise SystemExit("collector gate requires Python assertions; unset PYTHONOPTIMIZE")
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", choices=("podman", "docker"), default="podman")
    parser.add_argument("--image", required=True, help="Packaged candidate; never a host-mounted binary")
    parser.add_argument("--stack", choices=("grafana", "both"), default="both")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    os.umask(0o077)
    output = checked_directory(args.output)
    output.mkdir(parents=True, exist_ok=False)
    with tempfile.TemporaryDirectory(prefix="fh-collectors-", dir="/tmp") as directory:
        root = Path(directory) / "control"
        private = Path(directory) / "private"
        root.mkdir(mode=0o700)
        private.mkdir(mode=0o700)
        stack = Stack(args.runtime, root)
        stack.data.mkdir(mode=0o700)
        for name in ("logs", "collected", "cache", "state"):
            (stack.data / name).mkdir(mode=0o700)
        password = "Aa1!" + secrets.token_urlsafe(32)
        try:
            image = stack.candidate(args.image)
            fixtures(root)
            for name in ("origin.py", "request.py"):
                write(root, name, (ASSETS / name).read_text())
            grafana_configs(root, password)
            collector(root, signoz=args.stack == "both")
            if args.stack == "both":
                collector_signoz.configs(root)
            # Every control file exists before the first container. Only
            # individual files are mounted, always read-only; never their root.
            stack.backend("php", ["php-fpm", "-F", "-y", "/fixture/php.conf"],
                          stack.mount("php.conf", "/fixture/php.conf") + stack.mount("index.php", "/fixture/index.php"),
                          owner=True, ports=PORTS)
            origin_mounts = sum((stack.mount(name, "/fixture/" + name)
                                 for name in ("origin.py", "request.py", "cert.pem", "key.pem")), [])
            stack.backend("origin", ["python", "/fixture/origin.py"], origin_mounts, owner=True)
            grafana_stack(stack)
            if args.stack == "both":
                collector_signoz.start(stack)
            stack.backend("collector", ["--config=/etc/collector.json"],
                          stack.mount("collector.json") + stack.runtime_mount("logs") +
                          stack.runtime_mount("collected", writable=True), owner=True)
            server_mounts = sum((stack.mount(name, "/fixture/" + name)
                                 for name in ("fluxheim.toml", "cert.pem", "key.pem", "index.php")), [])
            server_mounts += sum((stack.runtime_mount(name, writable=True) for name in ("logs", "cache", "state")), [])
            stack.start("fluxheim", image, ["--config", "/fixture/fluxheim.toml"],
                        server_mounts, owner=True)
            observations = verify(stack, password)
            if args.stack == "both":
                dashboard_id = collector_signoz.verify(stack, password, observations)
            browser_input = write(private, "browser.json", {"grafana": stack.ports[3000],
                "jaeger": stack.ports[16686], "trace": observations[0][0],
                "signoz": stack.ports[8080] if args.stack == "both" else None,
                "dashboard": dashboard_id if args.stack == "both" else None,
                "password": password, "output": str(output)}, private=True)
            try:
                run_browser(["node", str(ROOT / "tools/collector-browser/check.cjs")], cwd=private)
            finally:
                browser_input.unlink()
            collector_lifecycle.verify(stack, request, metric)
            assert CANARY not in stack.command("logs", stack.names["fluxheim"])
            write(output, "summary.json", {"schema": 1, "passed": True, "stack": args.stack,
                "images": stack.images, "candidate_image": image, "correlated_traces": len(observations),
                "sink_failure_observed": True, "graceful_shutdown_under_traffic": True})
            print("required collector gate: passed")
        except Exception as error:
            if isinstance(error, subprocess.CalledProcessError):
                write(output, "command.private.log", (error.stderr or "").replace(password, "[redacted]").replace(CANARY, "[canary]"), private=True)
            for role, name in stack.names.items():
                try:
                    log = stack.command("logs", name)
                    write(output, role + ".private.log", log.replace(password, "[redacted]").replace(CANARY, "[canary]"), private=True)
                except (OSError, subprocess.SubprocessError):
                    pass
            raise
        finally:
            stack.close()


if __name__ == "__main__":
    main()
