#!/usr/bin/env python3
"""Exercise a built runtime image before its stable tags can be updated."""

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
import uuid

from container_refresh import PROFILES, VARIANTS, release_text, stable_tag


def engine_command(engine, *command, check=True):
    # Literal executables, not CLI-provided program paths. All calls use argv,
    # never a shell; cleanup uses the same boundary as normal execution.
    if engine == "docker":
        result = subprocess.run(["docker", *command], check=check, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    elif engine == "podman":
        result = subprocess.run(["podman", *command], check=check, text=True,
                                stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    else:
        raise ValueError("unsupported container engine")
    return result.stdout.strip()


def check_core_limit(output):
    match = re.search(r"^Max core file size\s+(\S+)\s+(\S+)\s+bytes\s*$", output, re.M)
    if not match or match.groups() != ("0", "0"):
        raise ValueError("running Fluxheim must have zero soft and hard core limits")


def check_php(output, modules, required, variant):
    if re.search(r"PHP (Startup|Warning)|Unable to load dynamic library|undefined symbol", modules, re.I):
        raise ValueError("PHP extension startup failure")
    missing = set(required.splitlines()) - set(modules.splitlines())
    if missing:
        raise ValueError(f"missing PHP extensions: {sorted(missing)}")
    match = re.search(r"PHP (\d+)\.(\d+)\.(\d+)", output)
    if not match:
        raise ValueError("cannot determine PHP runtime version")
    # Wolfi ships upstream releases rather than Debian/SUSE-style backports.
    if variant == "wolfi" and tuple(map(int, match.groups())) < (8, 5, 12):
        raise ValueError("Wolfi PHP must include the PHP 8.5.12 security fixes")


def smoke(args):
    stable_tag({"tag_name": args.version})
    if args.profile not in PROFILES or args.variant not in VARIANTS:
        raise ValueError("unsupported image profile or variant")
    if (len(args.image) > 256 or not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9./:@_-]*", args.image)):
        raise ValueError("invalid image reference")

    def run(*command):
        return engine_command(args.engine, *command)

    version = run("run", "--rm", "--ulimit", "core=0:0", "--network", "none", args.image, "--version")
    if not re.search(rf"^fluxheim {re.escape(args.version.removeprefix('v'))}(?:\s|$)", version, re.M):
        raise ValueError(f"wrong application version: {version}")
    print(version, flush=True)
    if args.profile == "php":
        php = run("run", "--rm", "--ulimit", "core=0:0", "--network", "none", "--entrypoint", "/usr/bin/php-fpm", args.image, "-v")
        modules = run("run", "--rm", "--ulimit", "core=0:0", "--network", "none", "--entrypoint", "/usr/bin/php-fpm", args.image, "-m")
        check_php(php, modules, release_text("php-modules"), args.variant)
        print(php, flush=True)

    marker = "fluxheim-refresh-" + uuid.uuid4().hex

    class Origin(BaseHTTPRequestHandler):
        def do_GET(self):
            body = marker.encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Content-Type", "image/png")
            self.send_header("Cache-Control", "public, max-age=120")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_):
            pass

    origin = ThreadingHTTPServer(("127.0.0.1", 0), Origin)
    thread = threading.Thread(target=origin.serve_forever, daemon=True)
    thread.start()
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
    name = marker
    try:
        with tempfile.TemporaryDirectory(prefix="fluxheim-refresh-") as directory:
            root = Path(directory)
            root.chmod(0o755)
            config = f'[server]\nlisten = ["127.0.0.1:{port}"]\ndefault_vhost = "default"\n'
            config += '[logging]\nlevel = "info"\ntarget = "stderr"\n'
            config += '[[vhosts]]\nname = "default"\nhosts = ["localhost"]\n'
            if args.profile in {"cache", "proxy", "load-balancer"}:
                config += f'[vhosts.proxy]\nupstreams = ["127.0.0.1:{origin.server_port}"]\n'
                if args.profile == "cache":
                    config += '[vhosts.cache]\nenabled = true\nstatus_header = "X-Cache-Status"\nmax_object_bytes = "1MiB"\n[vhosts.cache.memory]\nenabled = true\nmax_size_bytes = "16MiB"\n'
                if args.profile == "load-balancer":
                    config += '[vhosts.proxy.load_balance]\nselection = "round-robin"\n'
                path = "/asset.png"
            elif args.profile == "php":
                config = release_text("php-config").replace("0.0.0.0:8080", f"127.0.0.1:{port}")
                (root / "index.php").write_text(f"<?php echo '{marker}';")
                path = "/index.php"
            else:
                config += '[vhosts.web]\nroot = "/srv/fluxheim"\nindex_files = ["index.html"]\n'
                (root / "index.html").write_text(marker)
                path = "/"
            (root / "smoke.toml").write_text(config)
            for file in root.iterdir():
                file.chmod(0o644)
            run("run", "-d", "--ulimit", "core=0:0", "--name", name, "--network", "host",
                "-v", f"{root}:/srv/fluxheim:ro,Z", args.image,
                "--config", "/srv/fluxheim/smoke.toml")
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
            url = f"http://127.0.0.1:{port}{path}"
            request = urllib.request.Request(url, headers={"Host": "localhost"})
            for attempt in range(60):
                try:
                    with opener.open(request, timeout=2) as response:
                        body = response.read()
                        if response.status == 200 and body == marker.encode():
                            break
                except (OSError, urllib.error.URLError):
                    pass
                if run("inspect", "--format", "{{.State.Running}}", name) != "true":
                    raise RuntimeError("container exited before HTTP readiness")
                time.sleep(1)
            else:
                raise RuntimeError("live HTTP smoke failed")
            check_core_limit(run("exec", name, "cat", "/proc/1/limits"))
            if args.profile == "cache":
                with opener.open(request, timeout=2) as response:
                    if response.read() != marker.encode() or response.headers.get("X-Cache-Status") != "HIT":
                        raise RuntimeError("second cache request was not a HIT")
            print(f"runtime refresh live smoke: {args.profile}/{args.variant} passed", flush=True)
    finally:
        print(engine_command(args.engine, "logs", name, check=False), flush=True)
        engine_command(args.engine, "rm", "-f", name, check=False)
        origin.shutdown()
        origin.server_close()
        thread.join()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", choices=["docker", "podman"], default="docker")
    parser.add_argument("--image", required=True)
    parser.add_argument("--version", required=True)
    parser.add_argument("--profile", choices=["full", "wasm", "cache", "proxy", "php", "load-balancer"], required=True)
    parser.add_argument("--variant", required=True)
    smoke(parser.parse_args())
