"""Owned, disposable container resources for the required collector gate."""
import http.client as http_client
import json
import os
from pathlib import Path
import re
import secrets
import signal
import stat
import subprocess
import time
from collector_files import component, write

ROOT = Path(__file__).resolve().parent.parent
ASSETS = ROOT / "examples/observability"
LIMIT = 8 * 1024 * 1024


def http(port, path="/", data=None, headers=None, method=None):
    connection = http_client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        payload = None if data is None else json.dumps(data)
        connection.request(method or ("GET" if data is None else "POST"), path, payload,
                           {"Content-Type": "application/json", **(headers or {})})
        response = connection.getresponse()
        body = response.read(LIMIT + 1)
        if len(body) > LIMIT:
            raise RuntimeError("collector response exceeded limit")
        return response.status, body
    finally:
        connection.close()


def api(port, path, data=None, headers=None):
    status, body = http(port, path, data, headers)
    if status not in (200, 201):
        # Authentication responses and telemetry must not enter failure reports.
        raise RuntimeError(f"backend API rejected {path.split('?')[0]}: {status}")
    return json.loads(body)


def poll(check, label, seconds=90):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            result = check()
            if result:
                return result
        except (OSError, http_client.HTTPException):
            pass
        time.sleep(0.25)
    raise RuntimeError(f"timed out: {label}")


def run_browser(arguments, timeout=150):
    # A timed-out Node driver must not leave its Chromium children behind.
    with subprocess.Popen(arguments, start_new_session=True) as process:
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=5)
            raise RuntimeError("dashboard browser deadline exceeded") from None
        if code:
            raise RuntimeError("dashboard browser checks failed")


class Stack:
    def __init__(self, runtime, root):
        if runtime not in ("podman", "docker"):
            raise ValueError("unsupported container runtime")
        self.runtime, self.root = runtime, root
        self.data = root.parent / "runtime"
        self.prefix = "fh-collectors-" + secrets.token_hex(6)
        self.names = {}
        self.ports = {}
        self.images = json.loads((ASSETS / "images.json").read_text())
        for entry in self.images.values():
            if not re.fullmatch(r"[a-z0-9./_-]+@sha256:[0-9a-f]{64}", entry["image"]):
                raise ValueError("backend images must be digest pinned")

    def command(self, *args, timeout=120):
        result = subprocess.run([self.runtime, *map(str, args)], check=True, text=True,
                                capture_output=True, timeout=timeout)
        return (result.stdout + (result.stderr if args[0] == "logs" else "")).strip()

    def candidate(self, reference):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9./_:@-]{0,255}", reference):
            raise ValueError("invalid candidate image reference")
        identity = json.loads(self.command("image", "inspect", reference))[0]["Id"]
        if not re.fullmatch(r"(?:sha256:)?[0-9a-f]{64}", identity):
            raise ValueError("container engine did not return an immutable image ID")
        return identity

    def start(self, role, image, args=(), options=(), ports=(), owner=False):
        if not re.fullmatch(r"[a-z][a-z0-9-]{0,31}", role) or role in self.names:
            raise ValueError("invalid or duplicate container role")
        print("collector gate: starting " + role, flush=True)
        name = f"{self.prefix}-{role}"
        command = ["run", "-d", "--name", name, "--label", f"fluxheim.collector-run={self.prefix}",
                   "--security-opt", "no-new-privileges", "--ulimit", "core=0:0",
                   "--log-opt", "max-size=5m", "--memory=2g", "--cpus=2"]
        if self.names:
            command += ["--network", "container:" + self.names["php"]]
            if self.runtime == "podman":
                command += ["--userns", "container:" + self.names["php"]]
        else:
            for port in ports:
                command += ["-p", f"127.0.0.1::{port}"]
        if owner:
            if self.runtime == "podman" and not self.names:
                command += ["--userns=keep-id"]
            command += ["--user", f"{os.getuid()}:{os.getgid()}"]
        self.names[role] = name  # Own cleanup even if startup fails partway through.
        self.command(*command, *options, image, *args, timeout=180)
        if ports:
            bindings = json.loads(self.command("inspect", name))[0]["NetworkSettings"]["Ports"]
            self.ports = {port: int(bindings[f"{port}/tcp"][0]["HostPort"]) for port in ports}
        return name

    def backend(self, role, args=(), options=(), **kwargs):
        return self.start(role, self.images[role]["image"], args, options, **kwargs)

    def mount(self, name, dest=None):
        path = self.root / component(name)
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("control mounts must be regular host-owned files")
        # Neither this directory nor any ancestor is mounted into a container.
        return ["-v", f"{path}:{dest or '/etc/' + name}:ro,z"]

    def runtime_mount(self, name, writable=False):
        if name not in ("logs", "collected", "cache", "state"):
            raise ValueError("unknown runtime mount")
        path = self.data / name
        if not stat.S_ISDIR(path.lstat().st_mode):
            raise ValueError("runtime mount must be a real directory")
        return ["-v", f"{path}:/fixture/{name}:{'rw' if writable else 'ro'},z"]

    def stop(self, role):
        self.command("stop", "--time=8", self.names[role], timeout=20)

    def restart(self, role):
        self.command("start", self.names[role])

    def close(self):
        failures = []
        for name in reversed(list(self.names.values())):
            try:
                self.command("rm", "-f", "-v", name, timeout=30)
            except (subprocess.SubprocessError, OSError):
                failures.append(name)
        if failures:
            raise RuntimeError("could not clean owned containers: " + ", ".join(failures))
