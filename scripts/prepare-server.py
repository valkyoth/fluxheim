#!/usr/bin/env python3
"""Prepare a host for running a manually compiled Fluxheim binary.

The script is intentionally conservative:
- creates the standard native-install directories;
- writes a basic config and index page only when missing;
- requires --force before replacing existing files;
- has a --dry-run mode for review.
"""

from __future__ import annotations

import argparse
import os
import pwd
import grp
import sys
import tempfile
from pathlib import Path


DEFAULT_CONFIG_PATH = Path("/etc/fluxheim/fluxheim.toml")
DEFAULT_CONF_D = Path("/etc/fluxheim/conf.d")
DEFAULT_TLS_DIR = Path("/etc/fluxheim/tls")
DEFAULT_RUN_DIR = Path("/run/fluxheim")
DEFAULT_STATE_DIR = Path("/var/lib/fluxheim")
DEFAULT_CACHE_DIR = Path("/var/cache/fluxheim")
DEFAULT_LOG_DIR = Path("/var/log/fluxheim")
DEFAULT_WEB_ROOT = Path("/srv/fluxheim")
ALLOWED_INSTALL_ROOTS = (
    Path("/etc/fluxheim"),
    Path("/run/fluxheim"),
    Path("/var/lib/fluxheim"),
    Path("/var/cache/fluxheim"),
    Path("/var/log/fluxheim"),
    Path("/srv/fluxheim"),
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create directories, config, and a default index.html for Fluxheim.",
        epilog=(
            "Path arguments must be absolute and stay below Fluxheim's standard "
            "install roots: /etc/fluxheim, /run/fluxheim, /var/lib/fluxheim, "
            "/var/cache/fluxheim, /var/log/fluxheim, or /srv/fluxheim."
        ),
    )
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)
    parser.add_argument("--conf-d", type=Path, default=DEFAULT_CONF_D)
    parser.add_argument("--tls-dir", type=Path, default=DEFAULT_TLS_DIR)
    parser.add_argument("--run-dir", type=Path, default=DEFAULT_RUN_DIR)
    parser.add_argument("--state-dir", type=Path, default=DEFAULT_STATE_DIR)
    parser.add_argument("--cache-dir", type=Path, default=DEFAULT_CACHE_DIR)
    parser.add_argument("--log-dir", type=Path, default=DEFAULT_LOG_DIR)
    parser.add_argument("--web-root", type=Path, default=DEFAULT_WEB_ROOT)
    parser.add_argument("--listen", default="0.0.0.0:8080")
    parser.add_argument(
        "--host",
        action="append",
        dest="hosts",
        default=None,
        help="Host name for the default vhost. Can be repeated.",
    )
    parser.add_argument(
        "--owner",
        help="User or user:group to own created files. Defaults to current user.",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Replace existing fluxheim.toml and index.html.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print actions without writing files.",
    )
    return parser.parse_args()


def owner_ids(owner: str | None) -> tuple[int, int]:
    if owner is None:
        return os.getuid(), os.getgid()

    user, _, group = owner.partition(":")
    if not user:
        raise ValueError("--owner user cannot be empty")

    uid = pwd.getpwnam(user).pw_uid
    gid = grp.getgrnam(group).gr_gid if group else pwd.getpwnam(user).pw_gid
    return uid, gid


def path_has_existing_symlink_prefix(path: Path) -> bool:
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        try:
            if current.is_symlink():
                return True
        except OSError:
            raise
        if not current.exists():
            return False
    return False


def validate_install_path(label: str, path: Path) -> Path:
    expanded = path.expanduser()
    if not expanded.is_absolute():
        raise ValueError(f"{label} must be an absolute path")
    if any(part in ("", ".", "..") for part in expanded.parts[1:]):
        raise ValueError(f"{label} must not contain empty, current, or parent components")
    if path_has_existing_symlink_prefix(expanded):
        raise ValueError(f"{label} must not be below a symlinked path")

    normalized = expanded.resolve(strict=False)
    if not any(normalized == root or root in normalized.parents for root in ALLOWED_INSTALL_ROOTS):
        allowed = ", ".join(str(root) for root in ALLOWED_INSTALL_ROOTS)
        raise ValueError(f"{label} must be below one of: {allowed}")
    return normalized


def validate_paths(args: argparse.Namespace) -> None:
    args.config = validate_install_path("--config", args.config)
    args.conf_d = validate_install_path("--conf-d", args.conf_d)
    args.tls_dir = validate_install_path("--tls-dir", args.tls_dir)
    args.run_dir = validate_install_path("--run-dir", args.run_dir)
    args.state_dir = validate_install_path("--state-dir", args.state_dir)
    args.cache_dir = validate_install_path("--cache-dir", args.cache_dir)
    args.log_dir = validate_install_path("--log-dir", args.log_dir)
    args.web_root = validate_install_path("--web-root", args.web_root)


def toml_string(value: str) -> str:
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'"{escaped}"'


def toml_array(values: list[str]) -> str:
    return "[" + ", ".join(toml_string(value) for value in values) + "]"


def config_template(args: argparse.Namespace) -> str:
    hosts = args.hosts or ["localhost", "127.0.0.1", "example.test"]
    return f"""[server]
listen = [{toml_string(args.listen)}]
default_vhost = "default"
trusted_proxies = []

[server.process]
daemon = false
pid_file = {toml_string(str(args.run_dir / "fluxheim.pid"))}
upgrade_sock = {toml_string(str(args.run_dir / "fluxheim-upgrade.sock"))}
grace_period_seconds = 2
graceful_shutdown_timeout_seconds = 5

[server.https_redirect]
enabled = false
status = 308

[server.limits]
max_request_header_bytes = "64KiB"
max_uri_bytes = "8KiB"
max_request_headers = 100
max_request_body_bytes = "16MiB"

[logging]
level = "info"
format = "json"
target = "stderr"

[logging.file]
enabled = false
path = {toml_string(str(args.log_dir / "fluxheim.log"))}
append = true

[logging.access]
enabled = true
include_host = true
include_path = true
request_id = true
request_id_header = "x-request-id"

[headers.request]
enabled = true
strip_inbound_client_ip_headers = true
x_forwarded_for = "replace"
x_real_ip = true
x_forwarded_host = true
x_forwarded_proto = true
forwarded = false
remove = ["x-powered-by"]

[headers.request.add]
x-proxy-by = "Fluxheim"
x-forwarded-host = "{{host}}"

[headers.request.append]
via = "fluxheim"

[headers.response]
enabled = true
x_content_type_options = "nosniff"
x_frame_options = "DENY"
referrer_policy = "no-referrer"
remove = ["x-powered-by"]

[headers.response.add]
cache-control = "public, max-age=60"

[headers.response.append]
vary = ["Accept-Encoding"]

[tls]
enabled = false
backend = "rustls"

# To enable HTTPS, add server.tls_listen and certificate paths:
#
# [server]
# tls_listen = ["0.0.0.0:8443"]
#
# [tls]
# enabled = true
# backend = "rustls"
#
# [[tls.certificates]]
# cert_path = "{args.tls_dir / "fullchain.pem"}"
# key_path = "{args.tls_dir / "key.pem"}"

[cache]
enabled = false
image_extensions = ["avif", "gif", "jpeg", "jpg", "png", "svg", "webp"]
methods = ["GET", "HEAD"]
max_object_bytes = "32MiB"

[cache.memory]
enabled = false
max_size_bytes = "1GiB"

[cache.disk]
enabled = false
path = {toml_string(str(args.cache_dir))}
max_size_bytes = "10GiB"

[[vhosts]]
name = "default"
hosts = {toml_array(hosts)}

[vhosts.web]
root = {toml_string(str(args.web_root))}
index_files = ["index.html"]
deny_dotfiles = true
cache_control = "public, max-age=60"
"""


def index_template() -> str:
    return """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Welcome to Fluxheim</title>
  <style>
    body {
      min-height: 100vh;
      margin: 0;
      display: grid;
      place-items: center;
      color: #dbeafe;
      background: #081425;
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    }
    main {
      width: min(42rem, calc(100% - 2rem));
      padding: 2rem;
      border: 1px solid #334155;
      border-radius: 0.5rem;
      background: #111827;
    }
    h1 {
      margin: 0 0 0.75rem;
      color: #8aebff;
      font-size: clamp(2rem, 7vw, 4rem);
      line-height: 1;
    }
    p {
      margin: 0;
      color: #b6c2d1;
      line-height: 1.6;
    }
    code {
      color: #ffb77d;
    }
  </style>
</head>
<body>
  <main>
    <h1>Welcome to Fluxheim</h1>
    <p>
      This page is served from <code>/srv/fluxheim/index.html</code>.
      Replace it with your site content or point a vhost at another web root.
    </p>
  </main>
</body>
</html>
"""


def mkdir(path: Path, uid: int, gid: int, mode: int, dry_run: bool) -> None:
    print(f"mkdir -p {path}")
    if dry_run:
        return
    path.mkdir(parents=True, exist_ok=True)
    os.chmod(path, mode)
    os.chown(path, uid, gid)


def write_file(path: Path, content: str, uid: int, gid: int, mode: int, force: bool, dry_run: bool) -> None:
    if path.exists() and not force:
        print(f"skip existing {path} (use --force to replace)")
        return

    action = "write" if not path.exists() else "replace"
    print(f"{action} {path}")
    if dry_run:
        return

    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_name = None
    try:
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            delete=False,
        ) as tmp:
            tmp_name = Path(tmp.name)
            tmp.write(content)
        os.chmod(tmp_name, mode)
        os.chown(tmp_name, uid, gid)
        os.replace(tmp_name, path)
    finally:
        if tmp_name is not None and tmp_name.exists():
            tmp_name.unlink()


def main() -> int:
    args = parse_args()
    try:
        uid, gid = owner_ids(args.owner)
        validate_paths(args)
    except (KeyError, ValueError) as error:
        print(f"fluxheim prepare-server: {error}", file=sys.stderr)
        return 2

    directories = [
        (args.config.parent, 0o755),
        (args.conf_d, 0o755),
        (args.tls_dir, 0o750),
        (args.run_dir, 0o755),
        (args.state_dir, 0o755),
        (args.state_dir / "acme", 0o750),
        (args.cache_dir, 0o755),
        (args.log_dir, 0o755),
        (args.web_root, 0o755),
    ]

    for path, mode in directories:
        mkdir(path, uid, gid, mode, args.dry_run)

    write_file(
        args.config,
        config_template(args),
        uid,
        gid,
        0o644,
        args.force,
        args.dry_run,
    )
    write_file(
        args.web_root / "index.html",
        index_template(),
        uid,
        gid,
        0o644,
        args.force,
        args.dry_run,
    )

    print()
    print("Next steps:")
    print(f"  fluxheim --check-config --config {args.config}")
    print(f"  fluxheim --config {args.config}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
