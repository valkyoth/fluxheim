"""Qualify real TLS-ALPN authorizations, independently of HTTP-01."""
import time

from acme_activation_smoke import assert_served

MODES = ("external", "background")
CONFIGS = tuple(f"alpn-{mode}-{run}.toml" for mode in MODES for run in (1, 2))


def config(configuration, mode, run):
    return (configuration(renewal=False, issuer=f"alpn-{mode}-{run}", released=True)
            .replace('automation = "background"', f'automation = "{mode}"')
            .replace("[tls.acme]\n", '[tls.acme]\nchallenge = "tls-alpn-01"\n')
            .replace('storage = "/var/lib/fluxheim/acme"', f'storage = "/var/lib/fluxheim/acme/{mode}"'))


def qualify(smoke, image, port, segment, command):
    exe = "/usr/local/bin/fluxheim-acme"
    for mode in MODES:
        primary = f"alpn-{mode}-1.toml"
        server = smoke.launch("alpn-" + mode, image, [], config=primary, wait=False)
        root = "/var/lib/fluxheim/acme/" + mode
        pem = root + "/certificates/" + segment + "/fullchain.pem"
        previous = None
        for run in (1, 2):
            conf = f"alpn-{mode}-{run}.toml"
            if run == 2 or mode == "external":
                for _ in range(100):
                    if command([smoke.runtime, "exec", server, "test", "-S", root + "/.alpn/s"], check=False).returncode == 0:
                        break
                    time.sleep(0.1)
                code, logs = smoke.launch(f"alpn-{mode}-renew-{run}", image, ["renew", "--no-reload", "--force-renew"],
                                          config=conf, entry=exe)
                if code or "challenges=1" not in logs:
                    raise AssertionError(f"TLS-ALPN {mode} order {run}: {logs}")
                command([smoke.runtime, "exec", server, exe, "--config", "/etc/fluxheim/" + conf, "reload"])
            deadline = time.monotonic() + 45
            while time.monotonic() < deadline:
                result = command([smoke.runtime, "exec", server, "cat", pem], check=False)
                if result.returncode == 0 and result.stdout != previous:
                    try:
                        assert_served(port, result.stdout)
                        previous = result.stdout
                        break
                    except OSError:
                        pass
                time.sleep(0.2)
            else:
                logs = command([smoke.runtime, "logs", server])
                raise AssertionError(f"TLS-ALPN {mode} order {run} did not activate: {logs.stdout}{logs.stderr}")
        command([smoke.runtime, "stop", server])
        print(f"Real TLS-ALPN {mode}: initial issue, fresh authorization and served replacement passed", flush=True)
