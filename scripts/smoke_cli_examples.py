#!/usr/bin/env python3
"""Exercise CLI contracts using trusted, locally built executables only."""
import argparse
import os
from pathlib import Path
import re
import subprocess

from smoke_log_file_rotation import fixture_parent, private_fixture
from smoke_operational_events import ROOT

EXAMPLE = ROOT / "examples/cli/proxy.toml"
GUIDE = ROOT / "docs/guides/command-line.md"


def invoke(binary, root, *args, success=True, environment=None):
    env = {key: value for key, value in os.environ.items()
           if not key.casefold().startswith("fluxheim_") and key.casefold() != "rust_log"}
    env.update(environment or {})
    result = subprocess.run([str(binary), *map(str, args)], cwd=root, env=env,
                            stdin=subprocess.DEVNULL, capture_output=True,
                            timeout=20, check=False)
    assert (result.returncode == 0) == success, "unexpected CLI outcome"
    return result.stdout.decode(), result.stderr.decode()


def documented_options(help_text, guide):
    # Inspect generated option lines, not arbitrary mentions in descriptions.
    options = set(re.findall(r"^\s+(?:-\w, )?(--[a-z][a-z0-9-]*)\b", help_text, re.M))
    assert options, "CLI help contained no options"
    assert not options - set(re.findall(r"--[a-z][a-z0-9-]*", guide)), "undocumented CLI option"


def run(binary, tester):
    with private_fixture(fixture_parent(False)) as root:
        source = root / "proxy.toml"
        source.write_text(EXAMPLE.read_text())
        guide = GUIDE.read_text()
        for executable, commands in ((binary, ((), ("snapshot",), ("rollback",),
                ("snapshots",), ("snapshots", "show"), ("snapshots", "diff"),
                ("snapshots", "verify"), ("snapshots", "doctor"), ("snapshots", "prune"),
                ("crypto",), ("acme-renew",), ("acme-init",), ("cache-keygen",),
                ("cache-warm",), ("cache-key",), ("cache-lookup",))), (tester, ((),))):
            for command in commands:
                output, _ = invoke(executable, root, *command, "--help")
                documented_options(output, guide)
            output, _ = invoke(executable, root, "--version")
            assert output.startswith("fluxheim ")

        output, _ = invoke(binary, root, "--config", source, "--validate-config")
        assert not output, "quiet validation unexpectedly printed configuration"
        output, _ = invoke(binary, root, "--config", source, "--check-config")
        assert "cli-guide" in output and "18080" in output
        output, _ = invoke(binary, root, "--config", source, "--check-tls-storage")
        assert "TLS storage check passed" in output
        invoke(binary, root, "--validate-config", environment={"FLUXHEIM_CONFIG": str(source)})
        invoke(binary, root, "--config", source, "--validate-config",
               environment={"FLUXHEIM_CONFIG": str(root / "missing.toml")})
        invoke(binary, root, "--config", source, "--validate-config", "--check-config", success=False)
        invoke(tester, root, success=False)
        invoke(binary, root, "--config", source, "--unknown-option", success=False)

        invalid = root / "invalid.toml"
        invalid.write_text(EXAMPLE.read_text().replace("threads = 1", "threads = 0"))
        invoke(tester, root, "--config", invalid, "--no-runtime-paths", success=False)
        invoke(binary, root, "--config", invalid, "--validate-config", success=False)
        for profile in ("full", "cache", "proxy", "development", "load-balancer"):
            output, _ = invoke(tester, root, "--config", source, "--profile", profile, "--explain")
            assert "runtime-paths: ok" in output and "config tester: ok" in output
        output, _ = invoke(tester, root, "--config", source, "--profile", "proxy",
                           "--no-runtime-paths", "--check-tls-storage", "--explain",
                           "--acme-targets", "--resolve-upstreams", "--crypto", "--runtime-cutover")
        assert "runtime-paths: ok" not in output
        for marker in ("tls-storage: ok", "acme targets: 0", "127.0.0.1:18080 -> 127.0.0.1:18080",
                       "native-runtime-launch-plan", "config tester: ok"):
            assert marker in output, "missing tester diagnostic"
        invoke(tester, root, "--profile", "proxy", environment={"FLUXHEIM_CONFIG": str(source)})

        report_source = root / "report.toml"
        report_source.write_text(EXAMPLE.read_text() + '''
[admin]
enabled = true
listen = "127.0.0.1:8080"
token_env = "FLUXHEIM_CLI_FIXTURE_TOKEN"
snapshot_store = "report-snapshots"
''')
        output, _ = invoke(tester, root, "--config", report_source,
                           "--no-runtime-paths", "--runtime-cutover")
        assert "native-runtime-launch-plan-error\tduplicate-listener\t" in output
        assert "config tester: ok" in output

        # Characterize documented contract until the separate correction is implemented.
        store = root / "snapshots"
        output, _ = invoke(binary, root, "--config", source, "--validate-config",
                           "snapshot", "--store", store, "--message", "isolated CLI contract")
        assert "snapshot:" in output and (store / "current").is_file()
        output, _ = invoke(binary, root, "--config", source, "--validate-config", "--check-tls-storage")
        assert "TLS storage check passed" not in output

        # documented contract: the legacy filter differs by scope and is not the PHP artifact.
        _, error = invoke(tester, root, "--config", source, "--profile", "web-php", success=False)
        assert "does not include reverse proxying" in error
        root_source = root / "root-proxy.toml"
        root_source.write_text(EXAMPLE.read_text().split("[[vhosts]]", 1)[0]
                               .replace('default_vhost = "cli-guide"\n', '')
                               + '[proxy]\nupstream = "127.0.0.1:18080"\n')
        invoke(tester, root, "--config", root_source, "--profile", "web-php")
        for unsupported in ("php", "wasm"):
            invoke(tester, root, "--config", source, "--profile", unsupported, success=False)
    print("CLI guide: help coverage, validation, diagnostics and documented gaps passed")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True, type=Path)
    parser.add_argument("--tester", required=True, type=Path)
    options = parser.parse_args()
    run(options.binary.resolve(strict=True), options.tester.resolve(strict=True))
