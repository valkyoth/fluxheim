#!/usr/bin/env python3
"""Check documented protected cache operations against the trusted local binary."""

import argparse
import http.client
import json
from pathlib import Path
import secrets
import socket
import time

from smoke_cache_examples import origin_server, prepare, replace_once, request, running
from smoke_log_file_rotation import private_fixture, protect_directory


def configuration(public, origin, admin, backend):
    if backend not in ("memory", "filesystem", "storage-bin", "tiered-filesystem", "tiered-storage-bin"):
        raise ValueError("unsupported operations backend")
    source = prepare(public, origin, operations=True)
    source = replace_once(source, 'level = "warn"', 'level = "info"')
    source = replace_once(source, "[cache]\nenabled = true", "[cache]\nenabled = false")
    if backend == "memory":
        source = replace_once(source, "[vhosts.cache.disk]\nenabled = true",
                              "[vhosts.cache.disk]\nenabled = false")
    else:
        if not backend.startswith("tiered-"):
            source = replace_once(source, "[vhosts.cache.memory]\nenabled = true",
                                  "[vhosts.cache.memory]\nenabled = false")
        if backend.endswith("storage-bin"):
            source = replace_once(source, 'backend = "filesystem"', 'backend = "storage-bin"')
            source += '\n[vhosts.cache.disk.storage_bin]\nbin_size_bytes = "1MiB"\n'
    return source + f'''
[admin]
enabled = true
listen = "127.0.0.1:{admin}"
require_loopback = true
token_file = "control-token"
operational_token_file = "observer-token"
snapshot_store = "snapshots"
'''


def api(port, method, path, token=None, headers=None, expected=200):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=3)
    fields = dict(headers or {})
    if token is not None:
        fields["Authorization"] = f"Bearer {token}"
    try:
        connection.request(method, "/_fluxheim/cache/" + path, headers=fields)
        response = connection.getresponse()
        body = response.read(65537)
        assert response.status == expected, (method, path, response.status)
        assert len(body) <= 65536, "oversized cache operation response"
        return json.loads(body) if expected == 200 else None
    finally:
        connection.close()


def connect_metrics(connection):
    deadline = time.monotonic() + 10
    while True:
        try:
            connection.connect()
            return
        except (ConnectionRefusedError, TimeoutError):
            connection.close()
            if time.monotonic() >= deadline:
                raise
            time.sleep(0.05)


def run_case(parent, backend, metrics=False):
    copies = 2 if backend.startswith("tiered-") else 1
    with private_fixture(parent) as directory, \
            origin_server() as (origin, count):
        root = Path(directory)
        for relative in ("state", "state/cache"):
            path = root / relative
            path.mkdir()
            protect_directory(path)
        control, observer = secrets.token_hex(32), secrets.token_hex(32)
        for name, token in (("control-token", control), ("observer-token", observer)):
            path = root / name
            with path.open("x", encoding="ascii") as output:
                output.write(token)
            path.chmod(0o600)
        with socket.socket() as one, socket.socket() as two, socket.socket() as three:
            one.bind(("127.0.0.1", 0))
            two.bind(("127.0.0.1", 0))
            three.bind(("127.0.0.1", 0))
            public, admin = one.getsockname()[1], two.getsockname()[1]
            metrics_port = three.getsockname()[1]
        config = root / "fluxheim.toml"
        source = configuration(public, origin, admin, backend)
        if metrics:
            source += f'\n[metrics]\nenabled = true\nlisten = "127.0.0.1:{metrics_port}"\nrequire_loopback = true\n'
        config.write_text(source, encoding="utf-8")
        with running(config, public):
            deadline = time.monotonic() + 10
            while True:
                try:
                    api(admin, "GET", "status", control)
                    break
                except OSError:
                    if time.monotonic() >= deadline:
                        raise
                    time.sleep(0.05)
            api(admin, "GET", "status", expected=401)
            api(admin, "GET", "status", observer, expected=403)
            api(admin, "POST", "purge-index?vhost=assets", observer, expected=403)

            def fill(path):
                before = count(path)
                assert request(public, path) == "MISS"
                assert request(public, path) == "HIT"
                assert count(path) == before + 1

            def purge(path, headers=None):
                return api(admin, "POST", path, control, headers)

            fill("/assets/app.css")
            purge("activity/reset")
            exact = purge("purge", {
                "x-fluxheim-cache-vhost": "assets",
                "x-fluxheim-cache-host": "cache.test",
                "x-fluxheim-cache-path": "/assets/app.css",
            })
            assert exact["purged"]
            if metrics:
                connection = http.client.HTTPConnection("127.0.0.1", metrics_port, timeout=3)
                try:
                    connect_metrics(connection)
                    connection.request("GET", "/metrics")
                    response = connection.getresponse()
                    text = response.read(2 * 1024 * 1024 + 1).decode("utf-8")
                    assert response.status == 200 and len(text) <= 2 * 1024 * 1024
                    lines = set(text.splitlines())
                    tiers = ("memory", "disk") if copies == 2 else (("memory",) if backend == "memory" else ("disk",))
                    for tier in tiers:
                        assert f'fluxheim_cache_activity_total{{event="purge",tier="{tier}"}} 1' in lines
                        assert f'fluxheim_cache_activity_scope_total{{event="purge",route="",scope="vhost",tier="{tier}",vhost="assets"}} 1' in lines
                finally:
                    connection.close()
            fill("/assets/app.css")
            fill("/assets/second.css")
            bulk = purge("purge-bulk?vhost=assets&host=cache.test"
                         "&path=/assets/app.css&path=/assets/second.css")
            assert bulk["requested"] == bulk["purged"] == 2
            for endpoint, parameter in (("purge-prefix", "path_prefix=/assets/"),
                                        ("purge-wildcard", "pattern=/assets/*.css"),
                                        ("purge-tag", "cache_tag=guide")):
                fill("/assets/app.css")
                result = purge(f"{endpoint}?vhost=assets&{parameter}&limit=10")
                assert result["purged"] == copies, result

            for path in ("/a.css", "/b.css", "/c.css"):
                fill(path)
            partial = purge("purge-index?vhost=assets&limit=1&batches=1")
            assert partial["purged"] == copies and partial["batches"] == 1, partial
            assert partial["truncated"] and partial["repeat_required"], partial
            assert request(public, "/b.css") == "HIT"
            assert request(public, "/c.css") == "HIT"
            assert count("/b.css") == count("/c.css") == 1
            preview = purge("purge-stale?vhost=assets&limit=10&dry_run=true")
            assert preview["scanned"] == 2 * copies and preview["purged"] == 0, preview
            rest = purge("purge-index?vhost=assets&limit=1&batches=3")
            assert rest["purged"] == 2 * copies and rest["batches"] == 2, rest
            assert not rest["truncated"] and not rest["repeat_required"], rest
            for endpoint, parameter in (("purge-prefix", "path_prefix=/assets/"),
                                        ("purge-wildcard", "pattern=/assets/*.css"),
                                        ("purge-tag", "cache_tag=guide")):
                for name in ("one", "two", "three"):
                    fill(f"/assets/{name}.css")
                result = purge(f"{endpoint}?vhost=assets&{parameter}&limit=1&batches=3")
                assert result["purged"] == 3 * copies and result["batches"] == 3, result
                assert not result["truncated"], result
                # The next request must actually reach origin, not merely
                # agree with an administrative removal counter.
                for name in ("one", "two", "three"):
                    path = f"/assets/{name}.css"
                    before = count(path)
                    assert request(public, path) == "MISS"
                    assert count(path) == before + 1
                purge("purge-index?vhost=assets&limit=10")
            fill("/b.css")
            purge("activity/reset")
        print(f"cache operations {backend}: protected commands and bounded purge continuation ok")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("work_root", type=Path)
    parser.add_argument("--metrics", action="store_true", help="Require the metrics-enabled binary and verify exact-purge counters")
    args = parser.parse_args()
    root = args.work_root.resolve(strict=True)
    for backend in ("memory", "filesystem", "storage-bin", "tiered-filesystem", "tiered-storage-bin"):
        run_case(root, backend, args.metrics)


if __name__ == "__main__":
    main()
