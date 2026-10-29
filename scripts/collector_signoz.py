"""Pinned disposable SigNoz backend and authenticated query assertions."""
import json
import math
import time
from urllib.parse import urlencode
from collector_stack import ASSETS, api, http, poll, write
from generate_observability_dashboards import PANELS, signoz_query


def has_chart_points(response, minimum=1):
    results = response["data"]["data"]["results"]
    return any(sum(value.get("value") is not None and math.isfinite(float(value["value"]))
                   for value in (series["values"] or [])) >= minimum for result in (results or [])
               for aggregation in (result["aggregations"] or []) for series in (aggregation["series"] or [])
               )


def configs(root):
    write(root, "clickhouse.xml", '''<clickhouse>
  <listen_host replace="replace">0.0.0.0</listen_host>
  <tcp_port>9002</tcp_port>
  <max_server_memory_usage>1500000000</max_server_memory_usage>
  <max_thread_pool_size>1024</max_thread_pool_size>
  <background_pool_size>16</background_pool_size>
  <background_schedule_pool_size>8</background_schedule_pool_size>
  <keeper_server>
    <tcp_port>9181</tcp_port><server_id>1</server_id>
    <log_storage_path>/var/lib/clickhouse/coordination/log</log_storage_path>
    <snapshot_storage_path>/var/lib/clickhouse/coordination/snapshots</snapshot_storage_path>
    <raft_configuration><server><id>1</id><hostname>127.0.0.1</hostname><port>9234</port></server></raft_configuration>
  </keeper_server>
  <zookeeper><node><host>127.0.0.1</host><port>9181</port></node></zookeeper>
  <macros><shard>01</shard><replica>01</replica></macros>
  <remote_servers><cluster><shard><replica><host>127.0.0.1</host><port>9002</port></replica></shard></cluster></remote_servers>
  <logger><level>warning</level><console>1</console></logger>
</clickhouse>
''')
    exporters = {
        "clickhousetraces": {"datasource": "tcp://127.0.0.1:9002/signoz_traces", "use_new_schema": True},
        "clickhouselogsexporter": {"dsn": "tcp://127.0.0.1:9002/signoz_logs", "use_new_schema": True},
        "signozclickhousemetrics": {"dsn": "tcp://127.0.0.1:9002/signoz_metrics"},
        "metadataexporter": {"dsn": "tcp://127.0.0.1:9002/signoz_metadata", "enabled": True,
                             "cache": {"provider": "in_memory"}}}
    pipelines = {signal: {"receivers": ["otlp"], "processors": ["batch"], "exporters": [exporter, "metadataexporter"]}
                 for signal, exporter in (("traces", "clickhousetraces"), ("metrics", "signozclickhousemetrics"),
                                           ("logs", "clickhouselogsexporter"))}
    write(root, "signoz-collector.json", {"receivers": {"otlp": {"protocols": {"http": {"endpoint": "127.0.0.1:4321"}}}},
        "processors": {"batch": {"timeout": "1s", "send_batch_size": 128, "send_batch_max_size": 512}},
        "exporters": exporters, "service": {"telemetry": {"metrics": {"level": "none"}}, "pipelines": pipelines}})


def start(stack):
    stack.backend("clickhouse", options=stack.mount("clickhouse.xml", "/etc/clickhouse-server/config.d/fluxheim.xml") +
                  ["-e", "CLICKHOUSE_SKIP_USER_SETUP=1"])
    poll(lambda: http(stack.ports[8123], "/ping")[0] == 200, "ClickHouse ready")
    for operation in (("bootstrap",), ("sync", "up"), ("async", "up")):
        role = "migrate-" + operation[0]
        stack.start(role, stack.images["ingester"]["image"],
                    ["migrate", *operation, "--clickhouse-dsn=tcp://127.0.0.1:9002"])
        result = stack.command("wait", stack.names[role], timeout=300)
        assert result == "0", "SigNoz schema migration failed: " + role
    stack.backend("ingester", ["--config=/etc/signoz-collector.json", "--copy-path=/tmp/config.yaml"],
                  stack.mount("signoz-collector.json"))
    stack.backend("signoz", options=["-e", "SIGNOZ_TELEMETRYSTORE_CLICKHOUSE_DSN=tcp://127.0.0.1:9002",
        "-e", "SIGNOZ_SQLSTORE_SQLITE_PATH=/tmp/signoz.db", "-e", "SIGNOZ_SQLSTORE_PROVIDER=sqlite",
        "-e", "TELEMETRY_ENABLED=false", "-e", "SIGNOZ_ANALYTICS_ENABLED=false",
        "-e", "SIGNOZ_INSTRUMENTATION_METRICS_ENABLED=false"])
    poll(lambda: http(stack.ports[8080], "/api/v1/health")[0] == 200, "SigNoz ready", seconds=120)


def login(stack, password):
    port = stack.ports[8080]
    user = api(port, "/api/v1/register", {"name": "Fluxheim test", "email": "fluxheim@example.test",
               "password": password, "orgDisplayName": "Disposable Fluxheim test", "orgName": "fluxheim-test"})
    organization = user["data"]["orgId"]
    token = api(port, "/api/v2/sessions/email_password", {"email": "fluxheim@example.test", "password": password,
                                                         "orgId": organization})
    return {"Authorization": "Bearer " + token["data"]["accessToken"]}


def verify(stack, password, observations):
    auth = login(stack, password)
    dashboard = json.loads((ASSETS / "signoz-dashboard.json").read_text())
    result = api(stack.ports[8080], "/api/v2/dashboards", dashboard, auth)
    assert result["data"]["name"] == "fluxheim-operations-v1"
    port = stack.ports[8080]
    def query(expression):
        response = api(port, "/prometheus/api/v1/query?" + urlencode({"query": expression}), headers=auth)
        assert response["status"] == "success"
        assert "collector-proof-secret-canary" not in json.dumps(response)
        return response["data"]["result"]
    selector = '"service.name"="fluxheim-collector-proof"'
    def populated(expression, minimum=None):
        values = query(signoz_query(expression) % selector)
        numbers = [float(v["value"][1]) for v in values]
        return bool(numbers) and all(math.isfinite(v) for v in numbers) and (minimum is None or sum(numbers) >= minimum)
    poll(lambda: populated('fluxheim_http_requests_total{%s}', 6), "SigNoz stored request count")
    poll(lambda: populated('fluxheim_http_request_duration_seconds_count{%s}', 6), "SigNoz stored histogram count")
    for vhost, status, minimum in (("php", "2xx", 2), ("php-failure", "5xx", 1)):
        for name in ("fluxheim_php_requests_total", "fluxheim_php_request_duration_seconds_count"):
            expression = name + '{%s,vhost="' + vhost + '",method="GET",status_class="' + status + '",outcome="response"}'
            poll(lambda: populated(expression, minimum), "SigNoz PHP handler sample " + vhost + " " + name)
    for _, expression, _ in PANELS[:3]:
        poll(lambda: populated(expression), "SigNoz finite traffic/error/latency panel")
    for _, expression, _ in PANELS:
        query(signoz_query(expression) % selector)
    # Match the UI's v5 query and variable path, including minute-aligned bins.
    # A new stack can answer instant queries before it has a populated chart bin.
    for panel in list(dashboard["spec"]["panels"].values())[:4]:
        def chart():
            end = int(time.time() * 1000)
            response = api(port, "/api/v5/query_range", {"schemaVersion": "v1", "start": end - 300000,
                "end": end, "requestType": "time_series", "variables": {
                    "service": {"type": "text", "value": "fluxheim-collector-proof"},
                    "vhost": {"type": "text", "value": ".*"}},
                "compositeQuery": {"queries": [{"type": "promql",
                    "spec": panel["spec"]["queries"][0]["spec"]["plugin"]["spec"]}]}}, auth)
            assert "collector-proof-secret-canary" not in json.dumps(response)
            # Two gauge samples form a visible line; one valid sample can be
            # only a tiny dot and fail the independent canvas-pixel check.
            minimum = 2 if panel["spec"]["display"]["name"] == "Active requests" else 1
            return has_chart_points(response, minimum)
        poll(chart, "SigNoz populated dashboard range: " + panel["spec"]["display"]["name"], seconds=150)
    for trace, _ in observations:
        def stored_trace():
            response = api(port, "/api/v1/traces/" + trace + "/summary", headers=auth)
            assert "collector-proof-secret-canary" not in json.dumps(response)
            return response["data"]["totalSpansCount"] > 0
        poll(stored_trace, "SigNoz stored trace")
        def stored_log():
            end = int(time.time() * 1000)
            response = api(port, "/api/v5/query_range", {"schemaVersion": "v1", "start": end - 600000,
                "end": end, "requestType": "scalar", "compositeQuery": {"queries": [{"type": "builder_query",
                "spec": {"name": "A", "signal": "logs", "aggregations": [{"expression": "count()", "alias": "log_count"}],
                         "filter": {"expression": "trace_id = '" + trace + "'"}}}]}}, auth)
            assert "collector-proof-secret-canary" not in json.dumps(response)
            rows = response["data"]["data"]["results"][0]["data"]
            return bool(rows) and rows[0][0] > 0
        poll(stored_log, "SigNoz stored log linked to trace")
    return result["data"]["id"]
