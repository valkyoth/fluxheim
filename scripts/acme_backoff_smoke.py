"""Local-CA failure isolation checks for the packaged background worker."""
import hashlib
import re
import socket
import ssl
import time

from acme_activation_smoke import assert_served


def backoff_configuration(configuration):
    config = configuration(renewal=False, issuer="retry-issuer", released=True)
    return config.replace("reload_after_renewal = true", "reload_after_renewal = false").replace("renew_before_secs = 315360000",
                          "renew_before_secs = 315360000\ncheck_interval_secs = 1\n"
                          "retry_initial_secs = 3\nretry_max_secs = 6").replace(
        "https://localhost:14000/dir", "https://localhost:14000/retry-dir") + '''
[[tls.acme.issuers]]
name = "healthy-issuer"
directory_url = "https://localhost:14000/dir"
terms_of_service_agreed = true
terms_of_service_url = "https://localhost:14000/terms"
ca_bundle_file = "/etc/fluxheim/ca.pem"
[[vhosts]]
name = "healthy"
hosts = ["healthy.example.test"]
[vhosts.tls]
enabled = true
[vhosts.tls.acme]
enabled = true
issuer = "healthy-issuer"
'''


def qualify_backoff(smoke, image, frontend, port, tls, cert_dir, original, command):
    gateway = smoke.launch("retry", image, [], config="backoff.toml", wait=False)
    def attempts():
        log = command([smoke.runtime, "logs", frontend])
        return [int(n) for n in re.findall(r"^retry directory (\d+)$", log.stdout, re.M)]

    def read_leaf(directory):
        return command([smoke.runtime, "exec", gateway, "cat", directory + "/fullchain.pem"],
                       check=False).stdout

    def until(check, reason):
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if check():
                return
            time.sleep(0.2)
        log = command([smoke.runtime, "logs", gateway])
        raise AssertionError(reason + ": " + log.stdout + log.stderr)

    until(attempts, "no directory attempt")
    with socket.create_connection(("127.0.0.1", port), timeout=3) as conn:
        with tls.wrap_socket(conn, server_hostname="scope.example.test") as peer:
            until(lambda: len(attempts()) >= 2, "no retry after first refusal")
            peer.sendall(b"GET / HTTP/1.1\r\nHost: scope.example.test\r\nConnection: close\r\n\r\n")
            with peer.makefile("rb") as stream:
                if not stream.readline(256).startswith(b"HTTP/1.1 "):
                    raise AssertionError("established TLS connection did not survive issuer failures")
    healthy_dir = "/var/lib/fluxheim/acme/certificates/healthy-" + hashlib.sha256(b"healthy").hexdigest()[:16]
    if read_leaf(cert_dir) != original or "BEGIN CERTIFICATE" not in read_leaf(healthy_dir):
        raise AssertionError("failed target lost its certificate or blocked healthy issuance")
    until(lambda: len(attempts()) >= 3 and
          (leaf := read_leaf(cert_dir)) != original and "BEGIN CERTIFICATE" in leaf,
          "retrying issuer did not recover")
    first, second, third = attempts()[:3]
    if second - first < 3_000_000_000 or third - second < 6_000_000_000:
        raise AssertionError("CA saw a retry before its configured minimum delay")
    def installed_without_activation():
        logs = command([smoke.runtime, "logs", gateway])
        return "activation disabled by configuration" in logs.stdout + logs.stderr

    until(installed_without_activation, "worker did not report install-only mode")
    assert_served(port, original)
    print("ACME background: two timed refusals, independent issuance, live TLS and recovery passed", flush=True)
