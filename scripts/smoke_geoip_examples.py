#!/usr/bin/env python3
"""Exercise the guide recipes using the parent smoke's verified CIRCL fixture.

Run via smoke_geoip_circl.sh: it builds the trusted local binary and verifies
the database digest. Work files stay under its private, trusted temporary root.
"""

import argparse
import http.client
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import time


ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples/geoip"


def replace_once(text, old, new):
    if text.count(old) != 1:
        raise ValueError(f"example no longer has exactly one {old!r}")
    return text.replace(old, new, 1)


def prepare(base, database, port):
    base = replace_once(base, 'listen = ["127.0.0.1:8088"]',
                        f'listen = ["127.0.0.1:{port}"]')
    base = replace_once(base, 'path = "database.mmdb"',
                        f"path = {json.dumps(str(database))}")
    return replace_once(base, 'root = "site"',
                        f"root = {json.dumps(str(EXAMPLES / 'site'))}")


def request(port, address, path):
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
    try:
        headers = {"Host": "geo.example.test"}
        if address is not None:
            headers["X-Forwarded-For"] = address
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        body = response.read(4097)
        if len(body) > 4096:
            raise AssertionError("unexpectedly large guide response")
        return response.status, body
    finally:
        connection.close()


def run_case(parent, database, label, source, requests, invalid=False):
    with socket.socket() as reservation:
        reservation.bind(("127.0.0.1", 0))
        port = reservation.getsockname()[1]
    with tempfile.TemporaryDirectory(prefix="guide-", dir=parent) as directory, tempfile.TemporaryFile() as error_log:
        config = Path(directory) / "fluxheim.toml"
        content = prepare(source, database, port)
        config.write_text(content, encoding="utf-8")
        command = [str(ROOT / "target/debug/fluxheim"), "--config", str(config)]
        if not invalid:
            subprocess.run(command + ["--validate-config"], check=True, timeout=20,
                           stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                           stderr=subprocess.DEVNULL)
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.DEVNULL, stderr=error_log)
        try:
            if invalid:
                if process.wait(timeout=15) == 0:
                    raise AssertionError(f"{label}: invalid database was accepted")
                error_log.seek(0)
                diagnostic = error_log.read(8192)
                if b"GeoIP runtime:" not in diagnostic or b"os error 2" not in diagnostic:
                    raise AssertionError(f"{label}: unexpected diagnostic: {diagnostic!r}")
                print(f"GeoIP guide: {label}: rejected as expected")
                return
            deadline = time.monotonic() + 15
            while True:
                if process.poll() is not None:
                    raise AssertionError(f"{label}: server exited {process.returncode}")
                try:
                    request(port, None, "/")
                    break
                except (OSError, http.client.HTTPException):
                    if time.monotonic() >= deadline:
                        raise AssertionError(f"{label}: server not ready") from None
                    time.sleep(0.1)
            for address, path, expected in requests:
                status, body = request(port, address, path)
                if status != expected:
                    raise AssertionError(f"{label}: {address} {path}: {status} != {expected}")
                if status == 200 and b"GeoIP policy allowed this request." not in body:
                    raise AssertionError(f"{label}: missing example page")
            print(f"GeoIP guide: {label}: ok")
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database", type=Path)
    parser.add_argument("work_root", type=Path)
    args = parser.parse_args()
    database = args.database.resolve(strict=True)
    parent = args.work_root.resolve(strict=True)
    base = (EXAMPLES / "local.toml").read_text(encoding="utf-8")
    trusted = replace_once(base, "trusted_proxies = []", 'trusted_proxies = ["127.0.0.1"]')
    run_case(parent, database, "untrusted forwarding", base,
             [(None, "/", 403), ("1.1.1.1", "/", 403)])
    run_case(parent, database, "country AND ASN", trusted,
             [("1.1.1.1", "/", 200), ("8.8.8.8", "/", 403), (None, "/", 403)])
    route = (EXAMPLES / "route.toml").read_text(encoding="utf-8")
    # This fragment's root is independent of the complete base's root.
    route = replace_once(route, 'root = "site"', f"root = {json.dumps(str(EXAMPLES / 'site'))}")
    run_case(parent, database, "route denial after vhost admission", trusted + "\n" + route,
             [("1.1.1.1", "/restricted/", 403)])
    disabled = replace_once(trusted, "[vhosts.access]\nenabled = true",
                            "[vhosts.access]\nenabled = false")
    run_case(parent, database, "disabled vhost policy", disabled, [(None, "/", 200)])
    deny = trusted.split("[vhosts.access]\n", 1)[0] + (EXAMPLES / "deny-only.toml").read_text()
    run_case(parent, database, "deny-only and unknown client", deny,
             [("1.1.1.1", "/", 403), (None, "/", 200)])
    # CIRCL has standard country fields but its ASN needs the CIRCL decoder.
    # This proves fallback mechanics, not a separately licensed MaxMind dataset.
    second = '\n[[geoip.databases]]\nprovider = "circl-geo-open"\npath = "database.mmdb"\n'
    second = second.replace('"database.mmdb"', json.dumps(str(database)))
    fallback = replace_once(trusted, 'provider = "circl-geo-open"', 'provider = "maxmind"')
    fallback = replace_once(fallback, "[[vhosts]]", second + "\n[[vhosts]]")
    run_case(parent, database, "fallback fills missing ASN", fallback, [("1.1.1.1", "/", 200)])
    fallback_off = replace_once(fallback, "fallback_enabled = true", "fallback_enabled = false")
    run_case(parent, database, "fallback disabled", fallback_off, [("1.1.1.1", "/", 403)])
    missing = replace_once(fallback_off, second, second.replace(json.dumps(str(database)), '"missing.mmdb"'))
    run_case(parent, database, "invalid second database even without fallback", missing, [], invalid=True)


if __name__ == "__main__":
    main()
