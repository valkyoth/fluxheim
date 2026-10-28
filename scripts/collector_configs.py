"""Small, explicit single-host fixture configuration; never production defaults."""
import shutil
from collector_stack import ROOT, write


def fixtures(root):
    logs = root / "logs"
    logs.mkdir(mode=0o700)
    (root / "cache").mkdir(mode=0o700)
    write(root, "index.php", "<?php header('Content-Type: text/plain'); echo 'collector-proof-php';")
    for source, dest in (("localhost-cert.pem", "cert.pem"), ("localhost-key.pem", "key.pem")):
        shutil.copyfile(ROOT / "tests/fixtures/tls" / source, root / dest)
        (root / dest).chmod(0o600)
    write(root, "php.conf", """[global]
error_log = /proc/self/fd/2
daemonize = no
[www]
listen = 127.0.0.1:9000
pm = static
pm.max_children = 2
catch_workers_output = yes
""")
    write(root, "fluxheim.toml", '''[server]
listen = ["0.0.0.0:8088"]
tls_listen = ["0.0.0.0:8443"]
trusted_proxies = ["127.0.0.1/32"]
[server.process]
threads = 2
pid_file = "/fixture/fluxheim.pid"
upgrade_sock = "/fixture/upgrade.sock"
certificate_reload_sock = "/fixture/reload.sock"
grace_period_seconds = 1
graceful_shutdown_timeout_seconds = 3
[logging]
format = "json"
level = "info"
[logging.access]
enabled = true
include_host = false
include_path = false
[logging.file]
enabled = true
path = "/fixture/logs/events.log"
[metrics]
enabled = true
listen = "127.0.0.1:9091"
[metrics.otlp]
enabled = true
endpoint = "http://127.0.0.1:4318/v1/metrics"
service_name = "fluxheim-collector-proof"
interval_secs = 1
timeout_secs = 2
[tracing]
enabled = true
[tracing.otlp]
enabled = true
endpoint = "http://127.0.0.1:4318/v1/traces"
service_name = "fluxheim-collector-proof"
timeout_secs = 2
[tls]
enabled = true
backend = "rustls"
[[tls.certificates]]
cert_path = "/fixture/cert.pem"
key_path = "/fixture/key.pem"
[[vhosts]]
name = "cache"
hosts = ["cache.test"]
[vhosts.proxy]
upstreams = ["127.0.0.1:8081"]
[vhosts.cache]
enabled = true
max_object_bytes = "256KiB"
[vhosts.cache.memory]
enabled = true
max_size_bytes = "1MiB"
[vhosts.cache.disk]
enabled = true
path = "/fixture/cache"
max_size_bytes = "4MiB"
[[vhosts]]
name = "php"
hosts = ["php.test"]
[vhosts.php]
enabled = true
root = "/fixture"
[vhosts.php.fpm]
mode = "external"
tcp = "127.0.0.1:9000"
allow_private_tcp_upstreams = true
[[vhosts]]
name = "php-failure"
hosts = ["php-failure.test"]
[vhosts.php]
enabled = true
root = "/fixture"
[vhosts.php.fpm]
mode = "external"
tcp = "127.0.0.1:9001"
allow_private_tcp_upstreams = true
[[vhosts]]
name = "tls-failure"
hosts = ["tls-failure.test"]
[vhosts.proxy]
upstreams = ["127.0.0.1:8444"]
upstream_tls = true
upstream_sni = "localhost"
connect_timeout_secs = 2
read_timeout_secs = 2
''')


def collector(root, signoz=False):
    receiver = {"otlp": {"protocols": {"http": {"endpoint": "127.0.0.1:4318"}}},
                "filelog": {"include": ["/fixture/logs/events.log"], "start_at": "beginning",
                            "operators": [{"type": "json_parser", "parse_to": "attributes", "parse_ints": True},
                                          {"type": "severity_parser", "parse_from": "attributes.level"},
                                          {"type": "time_parser", "parse_from": "attributes.timestamp_unix_nanos",
                                           "layout_type": "epoch", "layout": "ns", "if": "attributes.timestamp_unix_nanos != nil"},
                                          {"type": "time_parser", "parse_from": "attributes.timestamp",
                                           "layout_type": "gotime", "layout": "2006-01-02T15:04:05.999999999Z07:00", "if": "attributes.timestamp != nil"},
                                          {"type": "trace_parser", "trace_id": {"parse_from": "attributes.correlation.trace_id"},
                                           "span_id": {"parse_from": "attributes.correlation.span_id"},
                                           "if": 'attributes.correlation != nil and attributes.correlation.trace_id != nil'},
                                          {"type": "add", "field": 'resource["service.name"]', "value": "fluxheim-collector-proof"}]}}
    exporters = {"otlphttp/jaeger": {"endpoint": "http://127.0.0.1:4319"},
                 "prometheus": {"endpoint": "127.0.0.1:9464", "translation_strategy": "NoTranslation",
                                "resource_to_telemetry_conversion": {"enabled": True}},
                 "file": {"path": "/fixture/logs/collected.json"}}
    if signoz:
        exporters["otlphttp/signoz"] = {"endpoint": "http://127.0.0.1:4321"}
    pipelines = {}
    for signal, out in (("metrics", "prometheus"), ("traces", "otlphttp/jaeger"), ("logs", "file")):
        pipelines[signal] = {"receivers": ["filelog" if signal == "logs" else "otlp"],
                             "processors": ["memory_limiter", "batch"],
                             "exporters": [out] + (["otlphttp/signoz"] if signoz else [])}
    write(root, "collector.json", {"receivers": receiver, "processors": {
        "memory_limiter": {"check_interval": "1s", "limit_mib": 256, "spike_limit_mib": 64},
        "batch": {"timeout": "1s", "send_batch_size": 128, "send_batch_max_size": 512}},
        "exporters": exporters, "service": {"telemetry": {"metrics": {"level": "none"}}, "pipelines": pipelines}})


def grafana_stack(stack, password):
    root = stack.root
    write(root, "prometheus.json", {"global": {"scrape_interval": "1s"}, "scrape_configs": [
        {"job_name": "fluxheim-scrape", "static_configs": [{"targets": ["127.0.0.1:9091"]}]},
        {"job_name": "fluxheim-otlp", "static_configs": [{"targets": ["127.0.0.1:9464"]}]}]})
    stack.backend("prometheus", ["--config.file=/etc/prometheus.json", "--storage.tsdb.path=/prometheus"],
                  stack.mount("prometheus.json"))
    write(root, "jaeger.json", {"extensions": {"jaeger_storage": {"backends": {"memory": {"memory": {"max_traces": 5000}}}},
                               "jaeger_query": {"storage": {"traces": "memory"}, "http": {"endpoint": "0.0.0.0:16686"}}},
        "receivers": {"otlp": {"protocols": {"http": {"endpoint": "127.0.0.1:4319"}}}},
        "exporters": {"jaeger_storage_exporter": {"trace_storage": "memory"}},
        "service": {"extensions": ["jaeger_storage", "jaeger_query"],
                    "pipelines": {"traces": {"receivers": ["otlp"], "exporters": ["jaeger_storage_exporter"]}}}})
    stack.backend("jaeger", ["--config=/etc/jaeger.json"], stack.mount("jaeger.json"))
    write(root, "grafana.env", "GF_SECURITY_ADMIN_USER=fluxheim\nGF_SECURITY_ADMIN_PASSWORD=" + password +
          "\nGF_USERS_ALLOW_SIGN_UP=false\nGF_AUTH_ANONYMOUS_ENABLED=false\nGF_ANALYTICS_REPORTING_ENABLED=false\n", private=True)
    stack.backend("grafana", options=["--env-file", str(root / "grafana.env")])
