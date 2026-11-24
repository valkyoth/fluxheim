"""Crash only the disposable renewal client; observe the real gateway."""
import http.client
import re
import time


def qualify_cleanup(smoke, image, frontend, port, segment, cert_dir, phase, command):
    gateway = smoke.launch("cleanup-" + phase, image, [], config="server.toml", wait=False)
    active = "/var/lib/fluxheim/acme/http-01/" + segment + "/.fluxheim-order/active"
    def run(*args):
        return command([smoke.runtime, *args])

    def status(token):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=2)
        try:
            conn.request("GET", "/.well-known/acme-challenge/" + token, headers={"Host": "scope.example.test"})
            response = conn.getresponse()
            if response.status == 200 and not response.read(4096).startswith(token.encode("ascii") + b"."):
                raise AssertionError("challenge body does not match the order")
            return response.status
        finally:
            conn.close()

    certificate = run("exec", gateway, "cat", cert_dir + "/fullchain.pem").stdout
    worker = smoke.launch("paused-" + phase, image, ["renew", "--force-renew", "--no-reload"],
                          entry="/usr/local/bin/fluxheim-acme", config="pause-" + phase + ".toml", wait=False)
    deadline = time.monotonic() + 20
    while "paused issuer response: " + phase not in run("logs", frontend).stdout.splitlines():
        if time.monotonic() >= deadline:
            raise AssertionError("local issuer did not pause at " + phase)
        time.sleep(0.1)
    published = phase not in ("account", "order", "authorization")
    token = "unused"
    if published:
        token = run("exec", gateway, "ls", "-1", active).stdout.strip()
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,256}", token) or status(token) != 200:
            raise AssertionError("gateway did not serve the live order")
    elif "active" in run("exec", gateway, "ls", "-a", active.rsplit("/", 1)[0]).stdout.splitlines():
        raise AssertionError("order published before receiving the authorization")
    run("kill", "--signal", "KILL", worker)
    if run("wait", worker).stdout.strip() != "137":
        raise AssertionError("disposable companion did not terminate as expected")
    if published and run("exec", gateway, "ls", "-1", active).stdout.strip() != token:
        raise AssertionError("expected the ungracefully terminated publisher to leave a file")
    if status(token) != 404:
        raise AssertionError("orphan should still be on disk but must not be served")
    run("stop", gateway)
    restarted = smoke.launch("restarted-" + phase, image, [], config="server.toml", wait=False)
    deadline = time.monotonic() + 15
    while True:
        try:
            if status(token) == 404:
                break
        except (OSError, http.client.HTTPException):
            pass
        if time.monotonic() >= deadline:
            raise AssertionError("restarted gateway did not respond")
        time.sleep(0.1)
    # Positive check on the parent prevents a failed exec from passing.
    remaining = run("exec", restarted, "ls", "-a", active.rsplit("/", 1)[0]).stdout.splitlines()
    if ".fluxheim-acme.lock" not in remaining or "active" in remaining or "retired" in remaining:
        raise AssertionError("gateway did not reconcile abandoned material")
    if run("exec", restarted, "cat", cert_dir + "/fullchain.pem").stdout != certificate:
        raise AssertionError("order recovery changed the installed certificate")
    run("stop", restarted)
    print("ACME cancellation at " + phase + ": publication and restart checks passed", flush=True)
