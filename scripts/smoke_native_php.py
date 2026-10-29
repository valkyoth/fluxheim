#!/usr/bin/env python3
"""Extract a native PHP package for an externally controlled real-FPM test.

The controller mounts an identical index.php at PHP_ROOT inside a disposable
PHP container, forwards loopback FastCGI, and acknowledges started on stdin.
It tests the READY HTTP/HTTPS listeners, then acknowledges stopped. This fixture
does not emulate PHP; missing external FPM must fail, not skip.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess

from collector_stack import poll
from native_archive import extract_pair, executable
from portable_release_plan import TARGET_LABELS, release_plan
from smoke_log_file_rotation import private_fixture, fixture_parent, request
from smoke_native_archives import configuration
from smoke_native_collector import acknowledged
from smoke_operational_events import ROOT, port

PHP = "<?php header('Content-Type: text/plain'); echo 'native-php-proof|' . $_SERVER['REQUEST_METHOD'] . '|' . file_get_contents('php://input');"


def main():
    if not __debug__:
        raise SystemExit("native qualification requires Python assertions")
    os.umask(0o077)
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--target", choices=TARGET_LABELS, required=True)
    parser.add_argument("--dist", type=Path, default=ROOT / "dist")
    args = parser.parse_args()
    label = TARGET_LABELS[args.target]
    kind = label.split("-")[-1]
    with private_fixture(fixture_parent(False)) as root:
        bundle = release_plan(args.version, kind, args.target, "php")[0][0]
        unpacked = extract_pair(args.dist / (bundle + ".tar.gz"), args.dist / (bundle + ".zip"), bundle, root / "archive")
        binary = executable(unpacked, "fluxheim.exe" if kind == "windows" else "fluxheim", label)
        (root / "index.php").write_text(PHP)
        (root / "index.php").chmod(0o600)
        admin = port()
        text = configuration(root, 39080, 39443, admin, port())
        text += f'''\n[[vhosts]]
name = "localhost"
hosts = ["localhost"]
[vhosts.php]
enabled = true
root = "{root.as_posix()}"
[vhosts.php.fpm]
mode = "external"
tcp = "127.0.0.1:39000"
allow_private_tcp_upstreams = true
'''
        config = root / "fluxheim.toml"
        config.write_text(text)
        print(json.dumps({"php_root": root.as_posix()}), flush=True)
        acknowledged("started")
        with (root / "process.log").open("wb") as output:
            process = subprocess.Popen([str(binary), "--config", str(config)], cwd=root, stdout=output, stderr=output)
            try:
                def ready():
                    assert process.poll() is None, (root / "process.log").read_text()
                    return request(admin, "/_fluxheim/operational-status", "native-archive-control-token")[0] == 200
                poll(ready, "native PHP frontend")
                print("READY", flush=True)
                acknowledged("stopped")
            finally:
                process.terminate()
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                    raise


if __name__ == "__main__":
    main()
