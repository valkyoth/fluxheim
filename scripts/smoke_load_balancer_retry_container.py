#!/usr/bin/env python3
"""Qualify retry policy in the trusted image built by smoke_load_balancer_container.sh.

Linux rootless Podman only. Host networking reaches numeric loopback fixtures;
this is a trusted-image integration test, not an untrusted-image sandbox.
"""

import json
from pathlib import Path
import re
import socket
import subprocess
import tempfile
import time
import uuid

import smoke_load_balancer_examples as smoke

IMAGE = "localhost/fluxheim:load-balancer-smoke"


def engine(*arguments):
    result = subprocess.run(["podman", *arguments], check=False, capture_output=True,
                            text=True, timeout=45)
    if result.returncode:
        raise RuntimeError(f"Podman {arguments[0]} failed ({result.returncode}): {result.stderr[:4096]}")
    return result.stdout.strip()


def run_arguments(name, digest, config):
    if not re.fullmatch(r"fluxheim-retry-[0-9a-f]{32}", name):
        raise ValueError("invalid fixture container name")
    if not re.fullmatch(r"(?:sha256:)?[0-9a-f]{64}", digest):
        raise ValueError("invalid immutable image identity")
    if not config.is_absolute() or any(char in str(config) for char in (":", ",", "\n", "\r")):
        raise ValueError("invalid fixture mount path")
    return ["run", "-d", "--name", name, "--pull=never", "--network=host",
            "--cap-drop=ALL", "--security-opt", "no-new-privileges",
            "--ulimit", "core=0:0", "--memory=256m", "--cpus=2", "--pids-limit=256",
            "-v", f"{config}:/etc/fluxheim/fluxheim.toml:ro,Z", digest,
            "--config", "/etc/fluxheim/fluxheim.toml"]


def container_config(public, first, second, enabled, latency=None):
    source = (smoke.retry_config((smoke.EXAMPLES / "local.toml").read_text(),
                                public, first, second, enabled) if latency is None else
              smoke.latency_config((smoke.EXAMPLES / "local.toml").read_text(),
                                   public, first, second, latency))
    for name in ("fluxheim.pid", "upgrade.sock", "reload.sock"):
        source = smoke.replace_once(source, f'"{name}"', f'"/run/fluxheim/{name}"')
    return source


def run_case(digest, enabled, latency=None):
    first_calls, second_calls = smoke.OriginCalls(), smoke.OriginCalls()
    with smoke.origin("origin-a", first_calls) as (first, ready), smoke.origin("origin-b", second_calls) as (second, _):
        if latency is None:
            ready.clear()
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            public = reservation.getsockname()[1]
        name = "fluxheim-retry-" + uuid.uuid4().hex
        work = smoke.ROOT / "target/fluxheim-lb-container-smoke"
        work.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(prefix="retry-", dir=work) as directory:
            config = Path(directory).resolve() / "fluxheim.toml"
            config.write_text(container_config(public, first, second, enabled, latency), encoding="utf-8")
            config.chmod(0o644)  # Public fixture only; the non-root guest must read it.
            try:
                engine(*run_arguments(name, digest, config))
                deadline = time.monotonic() + 20
                while True:
                    state = json.loads(engine("inspect", name))[0]["State"]
                    if not state["Running"]:
                        raise AssertionError("retry container exited before readiness")
                    try:
                        smoke.listener_ready(public)
                        break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise AssertionError("retry container readiness timeout") from None
                        time.sleep(0.1)
                if latency is None:
                    smoke.assert_retry_sequence(public, enabled, ready, first_calls, second_calls)
                else:
                    smoke.assert_latency_sequence(public, latency, first_calls, second_calls)
                engine("stop", "--time", "15", name)
                state = json.loads(engine("inspect", name))[0]["State"]
                assert not state["Running"] and state["ExitCode"] == 0, "unclean stop"
            except Exception:
                try:
                    print(engine("logs", "--tail", "40", name))
                except RuntimeError:
                    pass  # A failed create has no container logs.
                raise
            finally:
                engine("rm", "--force", "--ignore", name)
    print(f"container {'latency ' + latency if latency else 'retries ' + str(enabled)}: policy, recovery, shutdown: ok")


def main():
    assert engine("info", "--format", "{{.Host.Security.Rootless}}") == "true"
    inspected = json.loads(engine("image", "inspect", IMAGE))[0]
    assert inspected["Config"]["User"] == "65532:65532", "unexpected runtime user"
    digest = inspected["Id"]
    for enabled in (False, True):
        run_case(digest, enabled)
    for mode in ("selection", "passive", "disabled", "body"):
        run_case(digest, False, mode)
    print(f"load-balancer retry container identity: {digest}")


if __name__ == "__main__":
    main()
