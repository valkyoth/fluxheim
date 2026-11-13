#!/usr/bin/env python3
"""Qualify required disk cache startup and authenticated reload on loopback."""

import argparse
import json
from pathlib import Path
import re
import secrets
import subprocess
import time

from smoke_admin_examples import request as admin_request
from smoke_cache_examples import ROOT, origin_server, replace_once, request, running, wait_for_storage_index
from smoke_cache_operations import configuration
from smoke_log_file_rotation import private_fixture, protect_directory
from smoke_operational_events import port


def source_for(public, origin, admin, backend, memory, encrypted):
    if backend not in ("filesystem", "storage-bin"):
        raise ValueError("lifecycle fixture requires a disk backend")
    source = configuration(public, origin, admin, backend)
    if memory:
        source = replace_once(source, "[vhosts.cache.memory]\nenabled = false",
                              "[vhosts.cache.memory]\nenabled = true")
    source += '\n[admin.self_healing]\nenabled = false\n'
    source = replace_once(source, 'snapshot_store = "snapshots"',
                          'snapshot_store = "snapshots"\nsnapshot_integrity_key_file = "snapshot-key"')
    if encrypted:
        source += '\n[vhosts.cache.disk.encryption]\nenabled = true\nkey_file = "cache-key"\n'
    return source


def publish(root, filename):
    result = subprocess.run(
        [str(ROOT / "target/debug/fluxheim"), "--config", str(root / filename), "snapshot",
         "--store", str(root / "snapshots"), "--integrity-key-file", str(root / "snapshot-key")],
        capture_output=True, timeout=20, check=False)
    assert result.returncode == 0, "snapshot fixture publication failed"
    with (root / "snapshots/current").open(encoding="ascii") as current:
        identity = current.read(130).strip()
    assert re.fullmatch(r"[A-Za-z0-9_-]{1,128}", identity), "invalid fixture snapshot identity"
    return identity


def action(admin, token, path, expected=200, method="POST"):
    status, _, body = admin_request(admin, "/_fluxheim/" + path, token, method)
    assert status == expected, (path, status, expected)
    assert token.encode() not in body
    return json.loads(body)


def rejected_start(config):
    result = subprocess.run([str(ROOT / "target/debug/fluxheim"), "--config", str(config)],
                            capture_output=True, timeout=20, check=False)
    assert result.returncode != 0, "required disk cache initialization unexpectedly succeeded"
    assert b"cache initialization failed" in result.stderr, "unexpected startup error"


def run_case(parent, backend, memory, encrypted):
    with private_fixture(parent) as directory, origin_server() as (origin, count):
        root = Path(directory)
        for name in ("state", "state/cache"):
            path = root / name
            path.mkdir()
            protect_directory(path)
        token = secrets.token_hex(32)
        for name, value in (("control-token", token), ("observer-token", secrets.token_hex(32)),
                            ("snapshot-key", secrets.token_hex(32)), ("cache-key", secrets.token_hex(32))):
            path = root / name
            with path.open("x", encoding="ascii") as output:
                output.write(value)
            path.chmod(0o600)
        public, admin = port(), port()
        while public == admin:
            admin = port()
        source = source_for(public, origin, admin, backend, memory, encrypted)
        config = root / "fluxheim.toml"
        config.write_text(source, encoding="utf-8")
        baseline = publish(root, "fluxheim.toml")
        candidate = replace_once(source, '[vhosts.cache]\nenabled = true',
                                 '[vhosts.cache]\nenabled = true\n# candidate presentation update')
        prefix, policy = candidate.split('[vhosts.cache]\n', 1)
        candidate = prefix + '[vhosts.cache]\n' + replace_once(
            policy, 'status_reason_header = "x-cache-reason"',
            'status_reason_header = "x-next-cache-reason"')
        (root / "candidate.toml").write_text(candidate, encoding="utf-8")
        with running(config, public):
            deadline = time.monotonic() + 10
            while True:
                try:
                    action(admin, token, "status", method="GET")
                    break
                except OSError:
                    assert time.monotonic() < deadline, "admin readiness timed out"
                    time.sleep(0.05)
            assert request(public) == "MISS"
            assert request(public) == "HIT"
            publish(root, "candidate.toml")
            action(admin, token, "reload", expected=500 if encrypted else 200)
            assert request(public) == "HIT"
            before = action(admin, token, "status", method="GET")["runtime_snapshot"]
            context_change = source + '\n[vhosts.headers.request]\nenabled = true\n[vhosts.headers.request.set]\nx-tenant = "new-tenant"\n'
            (root / "context.toml").write_text(context_change, encoding="utf-8")
            publish(root, "context.toml")
            action(admin, token, "reload", expected=500)
            assert action(admin, token, "status", method="GET")["runtime_snapshot"] == before
            assert request(public) == "HIT"
            bad = replace_once(candidate, 'max_size_bytes = "32MiB"', 'max_size_bytes = "33MiB"')
            (root / "bad.toml").write_text(bad, encoding="utf-8")
            publish(root, "bad.toml")
            action(admin, token, "reload", expected=500)
            assert action(admin, token, "status", method="GET")["runtime_snapshot"] == before
            assert request(public) == "HIT"
            action(admin, token, f"rollback?live=true&to={baseline}", expected=500 if encrypted else 200)
            assert request(public) == "HIT"
            assert count("/asset.css") == 1
            if backend == "storage-bin":
                # Avoid a public/admin bind collision masking the allocator check.
                second = replace_once(source, f"127.0.0.1:{public}", f"127.0.0.1:{port()}")
                second = replace_once(second, f"127.0.0.1:{admin}", f"127.0.0.1:{port()}")
                (root / "second.toml").write_text(second, encoding="utf-8")
                rejected_start(root / "second.toml")
                if encrypted:
                    # The checkpoint's confidential identity cannot expose the URL.
                    from smoke_log_file_rotation import wait_for
                    index = root / "state/cache/.fluxheim-storage-bin-index-v1"
                    def checkpointed():
                        try:
                            with index.open("rb") as handle:
                                lines = handle.read(4097).splitlines()
                        except PermissionError:
                            return False
                        return len(lines) == 2 and len(lines[1].split(b"\t")) == 5
                    wait_for(checkpointed)
                else:
                    wait_for_storage_index(root / "state/cache")
        with running(config, public):
            assert request(public) == "HIT"
            assert count("/asset.css") == 1
        with origin_server() as (replacement, replacement_count):
            changed = source.replace(f"127.0.0.1:{origin}", f"127.0.0.1:{replacement}")
            assert changed != source, "replacement origin was not configured"
            config.write_text(changed, encoding="utf-8")
            with running(config, public):
                assert request(public) == "MISS", "old-origin object survived context change"
                assert request(public) == "HIT"
                assert replacement_count("/asset.css") == 1
                assert count("/asset.css") == 1
        print(f"required cache lifecycle {backend} memory={memory} encrypted={encrypted}: ok")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("work_root", type=Path)
    parent = parser.parse_args().work_root.resolve(strict=True)
    for backend in ("filesystem", "storage-bin"):
        for memory in (False, True):
            for encrypted in (False, True):
                run_case(parent, backend, memory, encrypted)


if __name__ == "__main__":
    main()
