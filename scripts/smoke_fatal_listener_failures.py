#!/usr/bin/env python3
"""Live proof that occupied critical listeners retain a finite exit diagnostic."""
import argparse
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile

from smoke_operational_events import ROOT, port


def run(binary, kind, reason):
    root = ROOT / "target" / "fh"
    root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="fatal-", dir=root) as temporary:
        directory = Path(temporary).resolve()
        crash = directory / "fatal.log"
        with socket.socket(type=socket.SOCK_DGRAM if kind == "udp" else socket.SOCK_STREAM) as occupied:
            occupied.bind(("127.0.0.1", 0))
            if kind != "udp":
                occupied.listen(1)
            address = f"127.0.0.1:{occupied.getsockname()[1]}"
            if kind == "metrics":
                extra = f'[metrics]\nenabled = true\nlisten = "{address}"\n'
            else:
                mode = 'mode = "syslog-forward"\n' if kind == "udp" else ""
                extra = f'''[{kind}]
enabled = true
[[{kind}.routes]]
name = "occupied"
listen = ["{address}"]
upstream = "127.0.0.1:9"
{mode}'''
            config = directory / "fluxheim.toml"
            config.write_text(f'''[server]
listen = ["127.0.0.1:{port()}"]
[server.process]
pid_file = "fluxheim.pid"
upgrade_sock = "upgrade.sock"
certificate_reload_sock = "reload.sock"
threads = 1
[logging]
level = "off"
crash_file = {json.dumps(str(crash))}
[proxy]
upstreams = ["127.0.0.1:9"]
upstream_tls = false
{extra}''')
            result = subprocess.run([str(binary), "--config", str(config)],
                                    cwd=directory, env=dict(os.environ, RUST_LOG="off"),
                                    capture_output=True, timeout=10, check=False)
            assert result.returncode == 1, (kind, result.returncode, result.stderr)
            actual = crash.read_bytes() if crash.exists() else b""
            assert actual == f"FATAL_SECURITY reason={reason}\n".encode(), (
                kind, actual, result.stderr)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    binary = parser.parse_args().binary.resolve(strict=True)
    for kind, reason in [("metrics", "MetricsListenerBindFailed"),
                         ("stream", "StreamListenerBindFailed"),
                         ("udp", "UdpListenerBindFailed")]:
        run(binary, kind, reason)
    print("fatal listener smoke: metrics, TCP stream and UDP exit diagnostics passed")


if __name__ == "__main__":
    main()
