#!/usr/bin/env python3
"""Linux/Unix loopback qualification against real installed PHP-FPM, not a mock."""

from contextlib import contextmanager
import http.client
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time

from smoke_geoip_examples import replace_once

ROOT = Path(__file__).resolve().parents[1]
EXTERNAL = ROOT / "examples/php/external.toml"
MANAGED = ROOT / "examples/php/managed.toml"
PHP = """<?php
header('Content-Type: application/json');
header('Cache-Control: public, max-age=60');
if (($_GET['offload'] ?? '') === 'accel') {
    header('X-Accel-Redirect: /style.css');
}
if (($_GET['offload'] ?? '') === 'sendfile') {
    header('X-Sendfile: ' . __DIR__ . '/style.css');
}
if (($_GET['offload'] ?? '') === 'expiry') {
    header('X-Accel-Expires: 0');
}
$counter = __DIR__ . '/counter';
$n = file_exists($counter) ? (int)file_get_contents($counter) : 0;
file_put_contents($counter, (string)($n + 1));
echo json_encode([
    'method' => $_SERVER['REQUEST_METHOD'],
    'script' => $_SERVER['SCRIPT_NAME'],
    'filename' => $_SERVER['SCRIPT_FILENAME'],
    'uri' => $_SERVER['REQUEST_URI'],
    'query' => $_SERVER['QUERY_STRING'],
    'path_info' => $_SERVER['PATH_INFO'] ?? '',
    'body' => file_get_contents('php://input'),
    'counter' => $n + 1
]);
"""


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def prepare(source, listen, fpm):
    source = replace_once(source, 'listen = ["127.0.0.1:8080"]',
                          f'listen = ["127.0.0.1:{listen}"]')
    return replace_once(source, 'tcp = "127.0.0.1:9000"', f'tcp = "127.0.0.1:{fpm}"')


@contextmanager
def running(command, ready_port=None):
    with tempfile.TemporaryFile() as log:
        process = subprocess.Popen(command, stdin=subprocess.DEVNULL, stdout=log, stderr=log)
        try:
            if ready_port is not None:
                deadline = time.monotonic() + 15
                while True:
                    assert process.poll() is None, "process exited before readiness"
                    try:
                        with socket.create_connection(("127.0.0.1", ready_port), timeout=0.2):
                            break
                    except OSError:
                        if time.monotonic() >= deadline:
                            raise AssertionError("readiness timeout") from None
                        time.sleep(0.05)
            yield process
        except Exception:
            log.seek(0)
            print(log.read(8192).decode(errors="replace"))
            raise
        finally:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
                raise


@contextmanager
def gateway(root, source, listen):
    config = root / "fluxheim.toml"
    config.write_text(source)
    command = [str(ROOT / "target/debug/fluxheim"), "--config", str(config)]
    subprocess.run(command + ["--validate-config"], check=True, timeout=20,
                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
    with running(command, listen):
        yield


def request(listen, path="/index.php", method="GET", body=None):
    conn = http.client.HTTPConnection("127.0.0.1", listen, timeout=15)
    try:
        conn.request(method, path, body=body, headers={"Host": "php.example.test"})
        response = conn.getresponse()
        data = response.read(8193)
        assert len(data) <= 8192
        return response.status, dict((k.lower(), v) for k, v in response.getheaders()), data
    finally:
        conn.close()


def common_checks(listen):
    status, fields, data = request(listen, "/index.php?hello=world", "POST", b"sample-body")
    assert status == 200, (status, data)
    parsed = json.loads(data)
    assert parsed["method"] == "POST" and parsed["body"] == "sample-body"
    assert parsed["script"] == "/index.php" and parsed["query"] == "hello=world"
    assert "x-powered-by" not in fields
    assert request(listen, "/style.css")[2] == b"body{}"
    assert request(listen, "/article/hello")[0] == 200
    assert request(listen, "/missing.php")[0] == 404
    assert request(listen, "/wp-content/uploads/payload.php")[0] == 403
    assert request(listen, "/wp-content/uploads/photo.txt")[2] == b"public asset"
    assert request(listen, "/.env")[0] == 403
    assert request(listen, "/index.php/user")[0] == 403
    assert request(listen, method="HEAD")[2] == b""
    with socket.create_connection(("127.0.0.1", listen), timeout=5) as sock:
        sock.sendall(b"POST /index.php HTTP/1.1\r\nHost: php.example.test\r\n"
                     b"Content-Length: 1048577\r\nConnection: close\r\n\r\n")
        response = http.client.HTTPResponse(sock)
        response.begin()
        assert response.status == 413
        response.close()


def characterize(root, source, listen):
    with gateway(root, source, listen):
        common_checks(listen)
        # documented contract: fallback accepts methods rejected by explicit PHP routes.
        assert json.loads(request(listen, method="PUT", body=b"put-body")[2])["method"] == "PUT"
        # documented contract: redirect loses query, and directory CGI names use root index.
        status, fields, _ = request(listen, "/blog?keep=1")
        assert status == 308 and fields["location"] == "/blog/"
        data = json.loads(request(listen, "/blog/")[2])
        assert data["filename"].endswith("/blog/index.php") and data["script"] == "/index.php"
        # documented contract: no offload; internal headers are removed, PHP body retained.
        for mode in ("accel", "sendfile", "expiry"):
            status, fields, data = request(listen, "/index.php?offload=" + mode)
            assert status == 200 and json.loads(data)["query"] == "offload=" + mode
            assert fields["cache-control"] == "public, max-age=60"
            assert not {"x-accel-redirect", "x-sendfile", "x-accel-expires"}.intersection(fields)

    # An explicit PHP action does not inherit static fallback for declined assets.
    route = source.replace("[vhosts.php", "[vhosts.routes.php")
    route = replace_once(route, "[vhosts.routes.php]",
                         '[[vhosts.routes]]\nname = "php-route"\npath_prefix = "/"\n\n[vhosts.routes.php]')
    route = route.split("[vhosts.web]", 1)[0]
    with gateway(root, route, listen):
        assert request(listen)[0] == 200
        assert request(listen, method="PUT", body=b"put-body")[0] == 405
        assert request(listen, "/style.css")[0] == 404

    split = replace_once(source, 'path_info = "disabled"', 'path_info = "split"')
    with gateway(root, split, listen):
        data = json.loads(request(listen, "/index.php/user/1?x=2")[2])
        assert data["path_info"] == "/user/1" and data["query"] == "x=2"
    strict = replace_once(source, 'preset = "wordpress"', 'try_files = "strict"')
    with gateway(root, strict, listen):
        assert request(listen, "/article/hello")[0] == 404
        assert request(listen)[0] == 200

    cached = source + '''\n[vhosts.cache]
preset = "wordpress"
enabled = true
status_ttls = { "200" = 60 }
max_object_bytes = "64KiB"
[vhosts.cache.memory]
enabled = true
max_size_bytes = "1MiB"
'''
    config = root / "fluxheim.toml"
    config.write_text(cached)
    result = subprocess.run([str(ROOT / "target/debug/fluxheim"), "--config", str(config),
                             "--validate-config"], capture_output=True, timeout=20, check=False)
    assert result.returncode != 0 and b"cache policy" in result.stderr
    cached = replace_once(cached, '[vhosts.cache]\n', '[vhosts.cache]\nlocal_static = true\n')
    with gateway(root, cached, listen):
        # documented contract: PHP responses never enter native proxy cache lookup/storage.
        first = json.loads(request(listen)[2])["counter"]
        second = json.loads(request(listen)[2])["counter"]
        assert second == first + 1


def main():
    if not __debug__:
        raise SystemExit("smoke requires assertions")
    if os.name != "posix" or os.geteuid() == 0:
        raise SystemExit("run as a non-root Unix account with /usr/sbin/php-fpm installed")
    os.umask(0o077)
    parent = subprocess.check_output(["sh", str(ROOT / "scripts/secure-smoke-tmp-root.sh"), "short"],
                                     text=True, timeout=10).strip()
    with tempfile.TemporaryDirectory(prefix="p.", dir=parent) as directory:
        root = Path(directory)
        site = root / "public"
        (site / "blog").mkdir(parents=True)
        (site / "wp-content/uploads").mkdir(parents=True)
        for name in ("index.php", "extra.phtml", "blog/index.php", "wp-content/uploads/payload.php"):
            (site / name).write_text(PHP)
        (site / "style.css").write_bytes(b"body{}")
        (site / "wp-content/uploads/photo.txt").write_bytes(b"public asset")
        (site / ".env").write_text("fixture-not-public")
        # Existing host package may not have a service-trusted owner in this dev environment.
        # This private copy is test-only; production must install a trusted executable.
        binary = root / "php-fpm"
        shutil.copyfile("/usr/sbin/php-fpm", binary)
        binary.chmod(0o700)
        listen, fpm = port(), port()
        fpm_config = root / "fpm.conf"
        fpm_config.write_text(f'''[global]
daemonize = no
error_log = {root}/fpm.log
[fixture]
listen = 127.0.0.1:{fpm}
pm = static
pm.max_children = 2
security.limit_extensions = .php
''')
        with running([str(binary), "-F", "-y", str(fpm_config)], fpm):
            characterize(root, prepare(EXTERNAL.read_text(), listen, fpm), listen)
        print("PHP external: execution, static assets, routing, limits and four contract gaps: ok")
        managed = replace_once(MANAGED.read_text(), 'listen = ["127.0.0.1:8080"]',
                               f'listen = ["127.0.0.1:{listen}"]')
        managed = replace_once(managed, 'php_fpm_binary = "/usr/sbin/php-fpm"',
                               f'php_fpm_binary = {json.dumps(str(binary))}')
        managed = replace_once(managed, 'socket_dir = "/run/fluxheim/php"',
                               f'socket_dir = {json.dumps(str(root / "f"))}')
        for manager in ("dynamic", "static", "ondemand"):
            variant = managed
            if manager != "dynamic":
                variant = replace_once(variant, 'process_manager = "dynamic"',
                                       f'process_manager = "{manager}"')
                variant = replace_once(variant,
                                       "start_servers = 2\nmin_spare_servers = 1\nmax_spare_servers = 4\n", "")
            with gateway(root, variant, listen):
                common_checks(listen)
            print(f"PHP managed {manager}: real PHP-FPM execution and routing: ok")
        # documented contract: an accepted extra extension is not propagated to the managed pool.
        extensions = replace_once(managed, '[vhosts.php]\n',
                                   '[vhosts.php]\nallowed_extensions = ["php", "phtml"]\n')
        with gateway(root, extensions, listen):
            status, _, data = request(listen, "/extra.phtml")
            assert status == 403 and b"<?php" not in data
        print("PHP managed: accepted phtml extension rejected by generated pool: ok")


if __name__ == "__main__":
    main()
