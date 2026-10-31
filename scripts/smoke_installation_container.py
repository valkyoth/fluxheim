#!/usr/bin/env python3
"""Run the installation recipe on a trusted, already-built local Wolfi image."""

import http.client
import json
from pathlib import Path
import re
import subprocess
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parents[1]
IMAGE = "localhost/fluxheim:wolfi-smoke"


def engine(*arguments):
    return subprocess.run(["podman", *arguments], check=True, capture_output=True,
                          text=True, timeout=45).stdout.strip()


def main():
    inspected = json.loads(engine("image", "inspect", IMAGE))[0]
    digest = inspected["Id"]
    if not re.fullmatch(r"(?:sha256:)?[0-9a-f]{64}", digest):
        raise ValueError("invalid local image identity")
    assert inspected["Config"]["User"] == "65532:65532", "unexpected image runtime user"
    name = "fluxheim-install-guide-" + uuid.uuid4().hex
    parent = engine("info", "--format", "{{.Host.Security.Rootless}}")
    assert parent == "true", "this fixture requires rootless Podman"
    with tempfile.TemporaryDirectory(prefix="fluxheim-install-guide-") as temporary:
        config = Path(temporary) / "fluxheim.toml"
        config.write_bytes((ROOT / "examples/installation/container.toml").read_bytes())
        config.chmod(0o644)
        mount = f"{config}:/etc/fluxheim/fluxheim.toml:ro,Z"
        engine("run", "--rm", "--pull=never", "--network=none", "--ulimit", "core=0:0",
               "-v", mount, digest, "--config", "/etc/fluxheim/fluxheim.toml", "--validate-config")
        try:
            engine("run", "-d", "--name", name, "--pull=never", "--ulimit", "core=0:0",
                   "--security-opt", "no-new-privileges", "-p", "127.0.0.1::8080",
                   "-v", mount, digest)
            binding = engine("port", name, "8080/tcp")
            match = re.fullmatch(r"127\.0\.0\.1:(\d+)", binding)
            assert match, "fixture must expose only numeric host loopback"
            port = int(match[1])
            expected = (ROOT / "packaging/default/index.html").read_bytes()
            deadline = time.monotonic() + 15
            while True:
                connection = http.client.HTTPConnection("127.0.0.1", port, timeout=1)
                try:
                    connection.request("GET", "/", headers={"Host": "localhost"})
                    response = connection.getresponse()
                    body = response.read(len(expected) + 1)
                    assert response.status == 200 and body == expected, "starter page mismatch"
                    break
                except (OSError, http.client.HTTPException):
                    if time.monotonic() >= deadline:
                        raise AssertionError("installation recipe readiness deadline") from None
                    time.sleep(0.1)
                finally:
                    connection.close()
            engine("stop", "--time", "15", name)
            state = json.loads(engine("inspect", name))[0]["State"]
            assert not state["Running"] and state["ExitCode"] == 0, "unclean container stop"
            engine("rm", name)
        finally:
            engine("rm", "--force", "--ignore", name)
    print(f"installation recipe: rootless UID, private config, HTTP and clean stop: ok ({digest})")


if __name__ == "__main__":
    main()
