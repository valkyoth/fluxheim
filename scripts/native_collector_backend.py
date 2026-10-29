#!/usr/bin/env python3
"""Disposable real backends for native hosts, reachable only through loopback/SSH.

stdin accepts only stop, start and quit. Commands affect this run's collector.
No runtime binary, release key or source directory is mounted into a container.
"""
import argparse
import json
from pathlib import Path
import select
import tempfile

from collector_configs import grafana_configs
from collector_stack import Stack, poll, http, write


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", choices=("podman", "docker"), default="podman")
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="fh-native-collectors-", dir="/tmp") as temp:
        root = Path(temp) / "control"
        root.mkdir(mode=0o700)
        stack = Stack(args.runtime, root)
        grafana_configs(root, "unused-no-grafana-started")
        write(root, "native-collector.json", {
            "receivers": {"otlp": {"protocols": {"http": {"endpoint": "0.0.0.0:4318"}}}},
            "processors": {"memory_limiter": {"check_interval": "1s", "limit_mib": 256},
                           "batch": {"timeout": "1s", "send_batch_size": 128, "send_batch_max_size": 512}},
            "exporters": {"otlphttp/jaeger": {"endpoint": "http://127.0.0.1:4319"},
                          "prometheus": {"endpoint": "127.0.0.1:9464", "translation_strategy": "NoTranslation",
                                         "resource_to_telemetry_conversion": {"enabled": True}}},
            "service": {"telemetry": {"metrics": {"level": "none"}}, "pipelines": {
                "metrics": {"receivers": ["otlp"], "processors": ["memory_limiter", "batch"], "exporters": ["prometheus"]},
                "traces": {"receivers": ["otlp"], "processors": ["memory_limiter", "batch"], "exporters": ["otlphttp/jaeger"]}}}})
        try:
            # Stack's first namespace owner is named php; it runs only the pinned
            # Python sleeper here. No writable host mount or privileged initializer.
            stack.start("php", stack.images["origin"]["image"], ["python", "-c", "import time; time.sleep(7200)"],
                        ports=(4318, 9090, 16686), owner=True)
            stack.backend("prometheus", ["--config.file=/etc/prometheus.json"], stack.mount("prometheus.json"))
            stack.backend("jaeger", ["--config=/etc/jaeger.json"], stack.mount("jaeger.json"))
            stack.backend("collector", ["--config=/etc/native-collector.json"], stack.mount("native-collector.json"))
            poll(lambda: http(stack.ports[9090], "/-/ready")[0] == 200, "native Prometheus ready")
            print(json.dumps({"ports": stack.ports, "images": stack.images}), flush=True)
            import sys
            while select.select([sys.stdin], [], [], 7200)[0]:
                command = sys.stdin.readline(32).strip()
                if command in ("", "quit"):
                    break
                if command == "stop":
                    stack.stop("collector")
                elif command == "start":
                    stack.restart("collector")
                else:
                    raise ValueError("expected stop, start or quit")
                print("collector " + command + ": ok", flush=True)
        finally:
            stack.close()


if __name__ == "__main__":
    main()
