#!/usr/bin/env python3
"""Real PHP-FPM layout checks, not certification of third-party applications."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

from smoke_php_examples import ROOT, PHP, gateway, port, prepare, request, running

EXAMPLE = ROOT / "examples/php/flat-root.toml"


def checks(root, listen, fpm):
    source = prepare(EXAMPLE.read_text(), listen, fpm)
    with gateway(root, source, listen):
        assert request(listen, "/assets/style.css")[2] == b"body{}"
        assert json.loads(request(listen, "/article?x=1")[2])["query"] == "x=1"
        for path in ("/private/secret.php", "/uploads/payload.php", "/%70rivate/secret.php"):
            status, _, body = request(listen, path)
            assert status == 403 and b"<?php" not in body, (path, status)
        for path in ("/private/backup.txt", "/config.bak", "/assets/payload.php", "/.env"):
            status, _, body = request(listen, path)
            assert status in (403, 404) and b"fixture-private" not in body, (path, status)
        # Unpublished asset paths may reach the app fallback, but not the static file.
        status, _, body = request(listen, "/assets/secret.txt")
        assert status in (200, 404) and b"fixture-private" not in body
    print("PHP layout: front controller, exact asset and private-path isolation: ok")

    # documented contract: a chosen static action does not inherit PHP execution denial.
    broad = source + '''
[[vhosts.routes]]
name = "unsafe-upload-example"
path_prefix = "/uploads/"
strip_prefix = "/uploads"
[vhosts.routes.web]
root = "app/uploads"
'''
    with gateway(root, broad, listen):
        status, _, body = request(listen, "/uploads/payload.php")
        assert status == 200 and body == b"<?php // fixture-private source\n"
    print("PHP layout: broad static route bypasses PHP-only source protection: characterized")
    blocked = broad + '''
[vhosts.routes.access]
deny = ["0.0.0.0/0", "::/0"]
'''
    with gateway(root, blocked, listen):
        for path in ("/uploads/payload.php", "/%75ploads/payload.php"):
            status, _, body = request(listen, path)
            assert status == 403 and b"<?php" not in body
    print("PHP layout: explicit static route ACL denies access before file delivery: ok")


def main():
    if not __debug__ or os.name != "posix" or os.geteuid() == 0:
        raise SystemExit("requires assertions and non-root Unix with /usr/sbin/php-fpm")
    os.umask(0o077)
    parent = subprocess.check_output(["sh", str(ROOT / "scripts/secure-smoke-tmp-root.sh"), "short"],
                                     text=True, timeout=10).strip()
    with tempfile.TemporaryDirectory(prefix="pa.", dir=parent) as directory:
        root = Path(directory)
        for name in ("app/private", "app/uploads", "public-static/assets"):
            (root / name).mkdir(parents=True)
        (root / "app/index.php").write_text(PHP)
        for name in ("app/private/secret.php", "app/uploads/payload.php", "public-static/assets/payload.php"):
            (root / name).write_text("<?php // fixture-private source\n")
        for name in ("app/private/backup.txt", "app/config.bak", "app/.env", "public-static/assets/secret.txt"):
            (root / name).write_text("fixture-private")
        (root / "public-static/assets/style.css").write_bytes(b"body{}")
        binary = root / "php-fpm"
        shutil.copyfile("/usr/sbin/php-fpm", binary)
        binary.chmod(0o700)
        listen, fpm = port(), port()
        config = root / "fpm.conf"
        config.write_text(f'''[global]
daemonize = no
error_log = {root}/fpm.log
[fixture]
listen = 127.0.0.1:{fpm}
pm = static
pm.max_children = 2
security.limit_extensions = .php
''')
        with running([str(binary), "-F", "-y", str(config)], fpm):
            checks(root, listen, fpm)


if __name__ == "__main__":
    main()
