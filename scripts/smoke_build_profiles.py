#!/usr/bin/env python3
"""Check documented proxy-only config pairing with a trusted local reduced binary."""

import argparse
from pathlib import Path

from smoke_cli_examples import ROOT, invoke
from smoke_log_file_rotation import fixture_parent, private_fixture


def relocate(source):
    for old, new in (("/run/fluxheim/fluxheim.pid", "fluxheim.pid"),
                     ("/run/fluxheim/fluxheim-upgrade.sock", "upgrade.sock"),
                     ("/run/fluxheim/fluxheim-cert-reload.sock", "reload.sock")):
        if source.count(f'"{old}"') != 1:
            raise ValueError("unexpected packaged runtime path")
        source = source.replace(f'"{old}"', f'"{new}"')
    return source


def run(binary):
    with private_fixture(fixture_parent(False)) as root:
        config = root / "fluxheim.toml"
        proxy = (ROOT / "packaging/container/proxy.toml").read_text()
        config.write_text(relocate(proxy))
        invoke(binary, root, "--config", config, "--validate-config")
        full = (ROOT / "packaging/container/fluxheim.toml").read_text()
        if full.count('root = "/srv/fluxheim"') != 1:
            raise ValueError("unexpected packaged static root")
        (root / "site").mkdir()
        config.write_text(relocate(full).replace('root = "/srv/fluxheim"', 'root = "site"'))
        _, error = invoke(binary, root, "--config", config, "--validate-config", success=False)
        assert "web module not compiled" in error, "expected the static-feature boundary"
    print("proxy-only build: matching config accepted; full static config rejected: ok")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, default=ROOT / "target/debug/fluxheim")
    args = parser.parse_args()
    run(args.binary.resolve(strict=True))
