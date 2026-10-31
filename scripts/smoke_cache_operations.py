#!/usr/bin/env python3
"""Check documented protected cache operations against the trusted local binary."""

import argparse
import http.client
import json
from pathlib import Path
import secrets
import socket
import tempfile
import time

from smoke_cache_examples import origin_server, prepare, replace_once, request, running


def configuration(public, origin, admin, backend):
    if backend not in ("memory", "filesystem", "storage-bin"):
        raise ValueError("unsupported operations backend")
    source = prepare(public, origin, operations=True)
    source = replace_once(source, 'level = "warn"', 'level = "info"')
    source = replace_once(source, "[cache]\nenabled = true", "[cache]\nenabled = false")
    if backend == "memory":
        source = replace_once(source, "[vhosts.cache.disk]\nenabled = true",
                              "[vhosts.cache.disk]\nenabled = false")
    else:
        source = replace_once(source, "[vhosts.cache.memory]\nenabled = true",
                              "[vhosts.cache.memory]\nenabled = false")
        if backend == "storage-bin":
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


def run_case(parent, backend):
    with tempfile.TemporaryDirectory(prefix="cache-admin-", dir=parent) as directory, \
            origin_server() as (origin, count):
        root = Path(directory)
        (root / "state/cache").mkdir(parents=True, mode=0o700)
        control, observer = secrets.token_hex(32), secrets.token_hex(32)
        for name, token in (("control-token", control), ("observer-token", observer)):
            path = root / name
            with path.open("x", encoding="ascii") as output:
                output.write(token)
            path.chmod(0o600)
        with socket.socket() as one, socket.socket() as two:
            one.bind(("127.0.0.1", 0))
            two.bind(("127.0.0.1", 0))
            public, admin = one.getsockname()[1], two.getsockname()[1]
        config = root / "fluxheim.toml"
        config.write_text(configuration(public, origin, admin, backend), encoding="utf-8")
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
            exact = purge("purge", {
                "x-fluxheim-cache-vhost": "assets",
                "x-fluxheim-cache-host": "cache.test",
                "x-fluxheim-cache-path": "/assets/app.css",
            })
            assert exact["purged"]
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
                assert result["purged"] == 1, result

            for path in ("/a.css", "/b.css", "/c.css"):
                fill(path)
            partial = purge("purge-index?vhost=assets&limit=1&batches=3")
            # documented contract: current defect, not the desired completion contract.
            assert partial["purged"] == partial["batches"] == 1, partial
            assert not partial["truncated"] and not partial["repeat_required"], partial
            assert request(public, "/b.css") == "HIT"
            assert request(public, "/c.css") == "HIT"
            assert count("/b.css") == count("/c.css") == 1
            preview = purge("purge-stale?vhost=assets&limit=10&dry_run=true")
            assert preview["scanned"] == 2 and preview["purged"] == 0, preview
            assert purge("purge-index?vhost=assets&limit=10")["purged"] == 2
            fill("/b.css")
            purge("activity/reset")
        print(f"cache operations {backend}: protected commands and incomplete-purge characterization ok")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("work_root", type=Path)
    root = parser.parse_args().work_root.resolve(strict=True)
    for backend in ("memory", "filesystem", "storage-bin"):
        run_case(root, backend)


if __name__ == "__main__":
    main()
