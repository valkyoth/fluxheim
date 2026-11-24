"""Compare installed and served local-CA leaves independently of CLI status."""
import json
import socket
import ssl


def pinned_tls(chain):
    leaf = chain.split("-----END CERTIFICATE-----", 1)[0] + "-----END CERTIFICATE-----"
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_verify_locations(cadata=leaf)
    context.verify_flags |= ssl.VERIFY_X509_PARTIAL_CHAIN
    return context, ssl.PEM_cert_to_DER_cert(leaf)


def assert_served(port, chain, hostname="scope.example.test"):
    context, expected = pinned_tls(chain)
    with socket.create_connection(("127.0.0.1", port), timeout=3) as connection:
        with context.wrap_socket(connection, server_hostname=hostname) as peer:
            if peer.getpeercert(binary_form=True) != expected:
                raise AssertionError("unexpected served leaf")


def companion_matrix(smoke, image, gateway, port, directory, initial, command):
    def execute(*args, check=True):
        return command([smoke.runtime, "exec", gateway, *args], check=check)

    def companion(*args, check=True):
        return execute("/usr/local/bin/fluxheim-acme", "--config", "/etc/fluxheim/served.toml",
                       *args, check=check)

    pem = directory + "/fullchain.pem"
    companion("renew", "--force-renew", "--no-reload")
    staged = execute("cat", pem).stdout
    if staged == initial:
        raise AssertionError("forced install did not replace disk leaf")
    assert_served(port, initial)
    context, _ = pinned_tls(initial)
    with socket.create_connection(("127.0.0.1", port), timeout=5) as connection:
        with context.wrap_socket(connection, server_hostname="scope.example.test") as peer:
            companion("reload")
            assert_served(port, staged)
            peer.sendall(b"GET / HTTP/1.1\r\nHost: scope.example.test\r\nConnection: close\r\n\r\n")
            with peer.makefile("rb") as response:
                if not response.readline(256).startswith(b"HTTP/1.1 "):
                    raise AssertionError("established connection did not survive activation")
    companion("renew", "--force-renew")
    current = execute("cat", pem).stdout
    if current == staged:
        raise AssertionError("companion did not install a fresh leaf")
    assert_served(port, current)
    # This companion shares storage, but not the gateway's Unix socket.
    execute("ln", pem, directory + "/saved-cert")
    execute("ln", directory + "/privkey.pem", directory + "/saved-key")
    code, logs = smoke.launch("detached-renew", image, ["renew", "--force-renew"],
                              entry="/usr/local/bin/fluxheim-acme", config="served.toml")
    detached = execute("cat", pem).stdout
    if not code or "activation not confirmed" not in logs or detached == current:
        raise AssertionError("detached companion did not distinguish install from reload failure")
    assert_served(port, current)
    # The old active handle is independent of both installed generations.
    companion("reload")
    assert_served(port, detached)
    # Replay a legacy Publishing journal with an interrupted first restore.
    execute("mv", directory + "/saved-key", directory + "/.privkey.pem.previous")
    execute("mv", directory + "/saved-cert", directory + "/.fullchain.pem.previous")
    execute("rm", pem)
    execute("ln", directory + "/.fullchain.pem.previous", pem)
    journal = directory + "/.install.transaction"
    execute("touch", journal)
    execute("chmod", "600", journal)
    command([smoke.runtime, "exec", "-i", gateway, "tee", journal], data=json.dumps({
        "phase": "publishing", "transaction": "0" * 32, "cert_existed": True, "key_existed": True,
    }))
    companion("doctor")
    companion("doctor")
    assert_served(port, detached)
    companion("reload")
    assert_served(port, current)
    # Only the disposable engine-owned fixture is changed, never host credentials.
    backup = directory + "/saved-chain.pem"
    execute("mv", pem, backup)
    try:
        execute("cp", "/etc/fluxheim/ca.pem", pem)
        if not companion("reload", check=False).returncode:
            raise AssertionError("invalid replacement pair was acknowledged")
        assert_served(port, current)
    finally:
        execute("mv", backup, pem)
    return current
