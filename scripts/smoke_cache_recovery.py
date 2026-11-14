#!/usr/bin/env python3
"""Live filesystem recovery, retained-byte and eviction qualification on loopback."""

import argparse
import os
from pathlib import Path
import secrets
import subprocess

from smoke_cache_examples import ROOT, origin_server, prepare, replace_once, request, running
from smoke_log_file_rotation import private_fixture, protect_directory
from smoke_operational_events import port

MAGIC = b"FLUXHEIM-CACHE-v5\n"


def write_fixture(path, content, old=False):
    with path.open("xb") as output:
        output.write(content)
    path.chmod(0o600)
    if old:
        os.utime(path, (1, 1))


def run_case(parent, encrypted):
    with private_fixture(parent) as directory, origin_server() as (origin, count):
        root = Path(directory)
        disk = root / "state/cache"
        for path in (root / "state", disk):
            path.mkdir()
            protect_directory(path)
        public = port()
        source = prepare(public, origin, "filesystem", disk_only=True)
        source = replace_once(source, 'max_size_bytes = "32MiB"', 'max_size_bytes = "8KiB"')
        source = replace_once(source, 'max_object_bytes = "256KiB"', 'max_object_bytes = "4KiB"')
        if encrypted:
            write_fixture(root / "cache-key", secrets.token_hex(32).encode("ascii"))
            source += '\n[cache.disk.encryption]\nenabled = true\nkey_file = "cache-key"\n'
        config = root / "fluxheim.toml"
        config.write_text(source, encoding="utf-8")
        with running(config, public):
            assert request(public) == "MISS"
            assert request(public) == "HIT"
            # Use the writer's real shard and ACL. Giving a synthetic Windows
            # shard inherited permissions would make its fixtures depend on
            # inheritance that the writer deliberately removes on hardening.
            objects = list(disk.glob("*/*.fhc"))
            assert len(objects) == 1, "expected one persisted warm object"
            shard = objects[0].parent
            corrupt = shard / (shard.name + "a" * 62 + ".fhc")
            abandoned = shard / ("." + "a" * 24 + ".tmp")
            fresh = shard / ("." + "b" * 24 + ".tmp")
            ambiguous = shard / ("." + "c" * 24 + ".tmp")
            unrelated = shard / "operator-note.txt"
            corrupt_bytes = b"FLUXHEIM-CACHE-ENC-v1\n" if encrypted else MAGIC
            write_fixture(corrupt, corrupt_bytes, True)
            write_fixture(abandoned, MAGIC, True)
            write_fixture(fresh, MAGIC)
            write_fixture(ambiguous, b"not owned", True)
            write_fixture(unrelated, b"operator data", True)
            # A second process loads a live root without cleaning an active
            # writer's files, including its encryption identity/counter state.
            result = subprocess.run(
                [str(ROOT / "target/debug/fluxheim"), "--config", str(config),
                 "cache-lookup", "--host", "cache.test", "--path", "/asset.css",
                 "--expect-objects", "1"], capture_output=True, timeout=20, check=False)
            assert result.returncode == 0, "live cache inspection failed"
            assert corrupt.read_bytes() == corrupt_bytes
            assert abandoned.read_bytes() == MAGIC
            assert request(public) == "HIT" and count("/asset.css") == 1
        retained = {path: path.read_bytes() for path in (fresh, ambiguous, unrelated)}
        encryption_state = {path: path.read_bytes() for path in disk.iterdir()
                            if path.is_file() and path.name.startswith(
                                (".fluxheim-encryption-", ".fluxheim-gcm-"))}
        before = sum(path.stat().st_size for path in disk.glob("*/*") if path.is_file())
        for iteration in range(2):
            with running(config, public):
                assert request(public) == "HIT" and count("/asset.css") == 1
                assert not corrupt.exists() and not abandoned.exists()
                assert all(path.read_bytes() == data for path, data in retained.items())
                assert all(path.read_bytes() == data for path, data in encryption_state.items())
                after = sum(path.stat().st_size for path in disk.glob("*/*") if path.is_file())
                assert before - after == len(corrupt_bytes) + len(MAGIC), "unexpected retained disk usage"
                if iteration == 1:
                    for index in range(40):
                        assert request(public, f"/eviction-{index}.css") == "MISS"
                    assert request(public) == "MISS", "tracked cache did not evict under pressure"
                    assert request(public) == "HIT"
                    assert all(path.read_bytes() == data for path, data in retained.items())
        print(f"filesystem recovery encrypted={encrypted}: restart HIT, idle cleanup, "
              "live inspection, retained bytes and eviction passed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("work_root", type=Path)
    root = parser.parse_args().work_root.resolve(strict=True)
    for encrypted in (False, True):
        run_case(root, encrypted)


if __name__ == "__main__":
    main()
