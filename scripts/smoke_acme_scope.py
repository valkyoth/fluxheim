#!/usr/bin/env python3
"""Exercise packaged renewal against Pebble with real HTTP-01 validation."""
import argparse
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import ssl
import subprocess
import tempfile
import time

PEBBLE = "ghcr.io/letsencrypt/pebble@sha256:5080492187bea12909c053d7a2b90a9e95104ef1c82381828e7823db71ce7e54"
PYTHON = "docker.io/library/python@sha256:281d39ff02e3b389401586134ff9e6572954687822a58055ec07a60ded4e0b7f"


def command(args, *, check=True, data=None, timeout=180):
    result = subprocess.run(args, input=data, text=True, capture_output=True, timeout=timeout)
    if check and result.returncode:
        raise RuntimeError(f"command failed ({result.returncode}): {result.stdout}\n{result.stderr}")
    return result


def configuration(extra="", *, renewal=True):
    return '''[server]
listen = ["0.0.0.0:5002"]
default_vhost = "scope"
[tls]
enabled = true
[tls.acme]
enabled = true
storage = "/var/lib/fluxheim/acme"
contact_email = "test@example.test"
default_issuer = "pebble"
automation = "external"
[tls.acme.renewal]
reload_after_renewal = false
[[tls.acme.issuers]]
name = "pebble"
directory_url = "https://localhost:14000/dir"
terms_of_service_agreed = true
terms_of_service_url = "https://localhost:14000/terms"
ca_bundle_file = "/etc/fluxheim/ca.pem"
[[vhosts]]
name = "scope"
hosts = ["scope.example.test"]
[vhosts.tls]
enabled = true
[vhosts.tls.acme]
enabled = true
''' + ('''[vhosts.php]
enabled = true
root = "/srv/fluxheim"
[vhosts.php.fpm]
mode = "managed"
php_fpm_binary = "/usr/bin/php-fpm"
socket_dir = "/run/fluxheim/php"
[cache]
enabled = true
[cache.memory]
enabled = true
''' if renewal else "") + extra


def fixtures(root):
    # All host-written control files are completed before any container runs.
    control = root / "control"
    control.mkdir()
    command(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "2",
             "-addext", "basicConstraints=critical,CA:TRUE",
             "-addext", "keyUsage=critical,keyCertSign,cRLSign",
             "-subj", "/CN=Fluxheim test CA", "-keyout", str(control / "ca.key"),
             "-out", str(control / "ca.pem")])
    command(["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=localhost",
             "-keyout", str(control / "server.key"), "-out", str(control / "server.csr")])
    (control / "extensions").write_text(
        "subjectAltName=DNS:localhost,IP:127.0.0.1\nbasicConstraints=critical,CA:FALSE\n"
        "keyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n"
        "authorityKeyIdentifier=keyid,issuer\nsubjectKeyIdentifier=hash\n")
    command(["openssl", "x509", "-req", "-in", str(control / "server.csr"),
             "-CA", str(control / "ca.pem"), "-CAkey", str(control / "ca.key"),
             "-set_serial", "2", "-days", "2", "-extfile", str(control / "extensions"),
             "-out", str(control / "server.pem")])
    (control / "pebble.json").write_text(json.dumps({"pebble": {
        "listenAddress": "0.0.0.0:14001", "managementListenAddress": "0.0.0.0:15000",
        "certificate": "/fixture/server.pem", "privateKey": "/fixture/server.key",
        "httpPort": 5002, "tlsPort": 5001, "externalAccountBindingRequired": False}}))
    (control / "renew.toml").write_text(configuration())
    (control / "server.toml").write_text(configuration(renewal=False))
    # Isolate feature mismatch from PHP filesystem availability.
    (control / "cache.toml").write_text(configuration(renewal=False) +
        "[cache]\nenabled=true\n[cache.memory]\nenabled=true\n")
    (control / "frontend.py").write_bytes(Path(__file__).with_name("acme_pebble_frontend.py").read_bytes())
    for path in control.iterdir():
        if path.name != "ca.key":
            path.chmod(0o644)  # Synthetic fixtures, readable by the image's non-root UID.
    return control


class Smoke:
    def __init__(self, runtime, root):
        self.runtime = {"podman": "podman", "docker": "docker"}[runtime]
        self.control = fixtures(root)
        self.prefix = "fh-acme-scope-" + secrets.token_hex(6)
        self.names = []
        self.anchor = self.prefix + "-ca"
        self.volume = self.prefix + "-state"
        self.control_volume = self.prefix + "-control"
        self.volumes = []

    def prepare_state(self, image):
        for volume in (self.volume, self.control_volume):
            command([self.runtime, "volume", "create", volume])
            self.volumes.append(volume)
        name = self.prefix + "-permissions"
        self.names.append(name)
        command([self.runtime, "run", "--name", name, "--network=none", "--user=0",
                 "--entrypoint=/bin/chown", "-v", f"{self.volume}:/state",
                 image, "65532:65532", "/state"])
        # Rootful Docker preserves the host UID on bind mounts. Copy (without
        # preserving ownership) into an engine volume, then mount it read-only.
        name = self.prefix + "-fixtures"
        self.names.append(name)
        sources = ("renew.toml", "server.toml", "cache.toml", "ca.pem")
        mounts = [argument for source in sources
                  for argument in self.mount(source, "/input/" + source)]
        command([self.runtime, "run", "--name", name, "--network=none", "--user=0",
                 "--security-opt", "no-new-privileges", "--entrypoint=/bin/cp",
                 *mounts, "-v", f"{self.control_volume}:/control", image, "--",
                 *["/input/" + source for source in sources], "/control/"])

    def image(self, value):
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9./_:@-]{0,255}", value):
            raise ValueError("invalid image reference")
        identity = json.loads(command([self.runtime, "image", "inspect", value]).stdout)[0]["Id"]
        if not re.fullmatch(r"(?:sha256:)?[0-9a-f]{64}", identity):
            raise ValueError("container engine did not return an immutable image ID")
        return identity

    def mount(self, name, target):
        return ["-v", f"{self.control / name}:{target}:ro,z"]

    def launch(self, role, image, args, *, entry=None, ca=False, frontend=False, config="renew.toml", wait=True):
        name = self.prefix + "-" + role
        self.names.append(name)
        cmd = [self.runtime, "run", "-d", "--name", name,
               "--security-opt", "no-new-privileges", "--ulimit", "core=0:0",
               "--memory=1g", "--cpus=2", "--log-opt", "max-size=1m"]
        cmd += ["--user", "65532:65532"]
        if ca:
            cmd += ["--add-host", "scope.example.test:127.0.0.1", "-p", "127.0.0.1::14000",
                    "-p", "127.0.0.1::5002", "-e", "PEBBLE_VA_NOSLEEP=1",
                    "-e", "PEBBLE_AUTHZREUSE=0", "-e", "PEBBLE_WFE_NONCEREJECT=0"]
            for source in ("server.pem", "server.key", "pebble.json"):
                cmd += self.mount(source, "/fixture/" + source)
        else:
            cmd += ["--network", "container:" + self.anchor]
            if frontend:
                for source in ("frontend.py", "ca.pem", "server.pem", "server.key"):
                    cmd += self.mount(source, "/fixture/" + source)
            else:
                cmd += ["-v", f"{self.control_volume}:/etc/fluxheim:ro",
                        "-v", f"{self.volume}:/var/lib/fluxheim/acme"]
                args = ["--config", "/etc/fluxheim/" + config, *args]
        if entry:
            cmd += ["--entrypoint", entry]
        command([*cmd, image, *args])
        if not wait:
            return name
        code = command([self.runtime, "wait", name]).stdout.strip()
        logs = command([self.runtime, "logs", name])
        return int(code), logs.stdout + logs.stderr

    def close(self):
        failures = []
        for name in reversed(self.names):
            try:
                command([self.runtime, "rm", "-f", "-v", name], timeout=30)
            except (OSError, subprocess.SubprocessError, RuntimeError):
                failures.append(name)
        for volume in reversed(self.volumes):
            try:
                command([self.runtime, "volume", "rm", volume], timeout=30)
            except (OSError, subprocess.SubprocessError, RuntimeError):
                failures.append(volume)
        if failures:
            raise RuntimeError("failed to clean owned resources: " + ", ".join(failures))


def expect_failure(result, fragment):
    code, logs = result
    if code == 0 or fragment not in logs:
        raise AssertionError(f"expected failure {fragment!r}: {code}\n{logs}")


def verify_ca_validations(logs):
    tokens = set(re.findall(
        r"Attempting to validate w/ HTTP: http://scope\.example\.test:5002/"
        r"\.well-known/acme-challenge/([A-Za-z0-9_-]+)", logs))
    if len(tokens) < 4 or logs.count("set VALID by completed challenge") < 4:
        raise AssertionError("CA did not record four distinct successful HTTP-01 validations")


def qualify(smoke, full, php, legacy):
    smoke.prepare_state(full)
    smoke.launch("ca", PEBBLE, ["-config", "/fixture/pebble.json"], ca=True, wait=False)
    smoke.launch("frontend", PYTHON, ["python3", "-B", "/fixture/frontend.py"], frontend=True, wait=False)
    info = json.loads(command([smoke.runtime, "inspect", smoke.anchor]).stdout)[0]
    port = int(info["NetworkSettings"]["Ports"]["14000/tcp"][0]["HostPort"])
    context = ssl.create_default_context(cafile=str(smoke.control / "ca.pem"))
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    last_error = None
    for _ in range(100):
        connection = http.client.HTTPSConnection("127.0.0.1", port, context=context, timeout=2)
        try:
            connection.request("GET", "/dir", headers={"User-Agent": "Fluxheim-ACME-smoke", "Host": "localhost:14000"})
            response = connection.getresponse()
            directory = json.loads(response.read(65536))
            if response.status == 200:
                break
        except (OSError, http.client.HTTPException) as error:
            last_error = error
            time.sleep(0.1)
        finally:
            connection.close()
    else:
        logs = command([smoke.runtime, "logs", smoke.anchor])
        raise RuntimeError(f"local CA did not become ready ({last_error}): " + logs.stdout + logs.stderr)
    # Detect unexpected CA terms rather than silently accepting changes.
    if directory["meta"]["termsOfService"] != "https://localhost:14000/terms":
        raise AssertionError(f"unexpected test CA terms: {directory['meta']['termsOfService']}")
    if legacy:
        expect_failure(smoke.launch("legacy-full", full, ["acme-renew"]), "php_fpm_binary")
        expect_failure(smoke.launch("legacy-php", php, ["acme-renew"]), "cache module not compiled")
        gateway = smoke.launch("legacy-gateway", php, [], wait=False)
        http_port = int(info["NetworkSettings"]["Ports"]["5002/tcp"][0]["HostPort"])
        for _ in range(100):
            connection = http.client.HTTPConnection("127.0.0.1", http_port, timeout=2)
            try:
                connection.request("GET", "/index.php", headers={"Host": "scope.example.test"})
                response = connection.getresponse()
                body = response.read(65536)
                if response.status == 200 and body:
                    break
            except (OSError, http.client.HTTPException):
                pass
            finally:
                connection.close()
            time.sleep(0.1)
        else:
            logs = command([smoke.runtime, "logs", gateway])
            raise AssertionError("legacy startup did not serve PHP: " + logs.stdout + logs.stderr)
        print("released-image renewal failures reproduced; legacy PHP gateway serves the same config", flush=True)
        return
    gateway = smoke.launch("gateway", full, [], config="server.toml", wait=False)
    ownership = command([smoke.runtime, "exec", gateway, "stat", "-c", "%a:%u",
                         "/etc/fluxheim/server.toml", "/etc/fluxheim/ca.pem"]).stdout.splitlines()
    if ownership != ["644:0", "644:0"]:
        raise AssertionError("config/CA fixtures must be root-owned and not group/world writable")
    for index, flags in enumerate(([], ["--validate-config"], ["--check-config"])):
        expect_failure(smoke.launch(f"server-cache-{index}", php, flags, config="cache.toml"),
                       "cache module not compiled")
        expect_failure(smoke.launch(f"server-php-{index}", full, flags), "php_fpm_binary")
    serials = set()
    segment = "scope-" + hashlib.sha256(b"scope").hexdigest()[:16]
    certificate_dir = "/var/lib/fluxheim/acme/certificates/" + segment
    for index, (image, entry, args) in enumerate((
        (full, "/usr/local/bin/fluxheim", ["acme-renew", "--force-renew"]),
        (php, "/usr/local/bin/fluxheim", ["acme-renew", "--force-renew"]),
        (full, "/usr/local/bin/fluxheim-acme", ["renew", "--force-renew", "--no-reload"]),
        (php, "/usr/local/bin/fluxheim-acme", ["renew", "--force-renew", "--no-reload"]),
    )):
        code, logs = smoke.launch(f"renew-{index}", image, args, entry=entry)
        if code or "renewed: scope" not in logs or "challenges=1" not in logs:
            raise AssertionError(f"renewal {index} failed: {code}\n{logs}")
        certificate = command([smoke.runtime, "exec", gateway, "cat", certificate_dir + "/fullchain.pem"]).stdout
        details = command(["openssl", "x509", "-noout", "-serial", "-ext", "subjectAltName", "-checkend", "86400"],
                          data=certificate).stdout
        if "DNS:scope.example.test" not in details or details in serials:
            raise AssertionError("certificate was not freshly issued for the requested domain")
        serials.add(details)
        mode = command([smoke.runtime, "exec", gateway, "stat", "-c", "%a:%u",
                        certificate_dir + "/privkey.pem"]).stdout.strip()
        if mode != "600:65532":
            raise AssertionError("installed private key permissions changed")
        print(f"renewal {index}: issued and installed, real HTTP-01 challenge passed", flush=True)
    code, logs = smoke.launch("not-due", full, ["acme-renew"])
    if code or "acme attempted: 0" not in logs:
        raise AssertionError("installed certificate was not observed as valid")
    ca_logs = command([smoke.runtime, "logs", smoke.anchor])
    verify_ca_validations(ca_logs.stdout + ca_logs.stderr)
    print("ACME operation scope and server feature parity smoke: ok", flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", choices=("podman", "docker"), default="podman")
    parser.add_argument("--full-image", required=True)
    parser.add_argument("--php-image", required=True)
    parser.add_argument("--reproduce-legacy", action="store_true")
    args = parser.parse_args()
    os.umask(0o077)
    with tempfile.TemporaryDirectory(prefix="fh-acme-scope-", dir="/tmp") as temporary:
        root = Path(temporary)
        smoke = Smoke(args.runtime, root)
        try:
            qualify(smoke, smoke.image(args.full_image), smoke.image(args.php_image), args.reproduce_legacy)
        finally:
            smoke.close()


if __name__ == "__main__":
    main()
