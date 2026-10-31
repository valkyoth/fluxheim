#!/usr/bin/env python3
"""Qualify snapshot guide state transitions with a trusted local Fluxheim executable."""
import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tomllib

from smoke_admin_examples import CONTROL, EXAMPLE, OBSERVER, request, server
from smoke_log_file_rotation import fixture_parent, private_fixture, wait_for
from smoke_logging_examples import replace_once
from smoke_operational_events import port


def cli(binary, root, *args, success=True):
    env = {name: value for name, value in os.environ.items()
           if not name.casefold().startswith("fluxheim_") and name.casefold() != "rust_log"}
    result = subprocess.run([str(binary), *map(str, args)], cwd=root, env=env,
                            capture_output=True, timeout=20, check=False)
    assert (result.returncode == 0) == success, "unexpected snapshot CLI outcome"
    assert CONTROL.encode() not in result.stdout + result.stderr
    assert OBSERVER.encode() not in result.stdout + result.stderr
    return result.stdout.decode()


def stored_id(root):
    value = (root / "snapshots/current").read_text().strip()
    assert re.fullmatch(r"[A-Za-z0-9_-]{1,128}", value)
    return value


def action(admin, route, *, method="POST", expected=200):
    code, _, body = request(admin, "/_fluxheim/" + route, CONTROL, method)
    assert code == expected, f"unexpected snapshot route outcome: {code}, expected {expected}"
    return json.loads(body)


def prepare(root, *, window=120):
    for name, value in (("control-token", CONTROL), ("observer-token", OBSERVER),
                        ("snapshot-integrity.key", "0123456789abcdef0123456789abcdef")):
        (root / name).write_text(value)
        (root / name).chmod(0o600)
    for name, content in (("public", "ready"), ("candidate-public", "candidate"),
                          ("third-public", "third")):
        (root / name).mkdir()
        (root / name / "index.html").write_text(content)
    public, admin = port(), port()
    while public == admin:
        admin = port()
    base = replace_once(EXAMPLE.read_text(), "127.0.0.1:8080", f"127.0.0.1:{public}")
    base = replace_once(base, "127.0.0.1:9090", f"127.0.0.1:{admin}")
    base = replace_once(base, "[admin.self_healing]\nenabled = false", "[admin.self_healing]\nenabled = true")
    base = replace_once(base, "validation_window_secs = 30", f"validation_window_secs = {window}")
    base = replace_once(base, "min_successful_checks = 1", "min_successful_checks = 2")
    (root / "baseline.toml").write_text(base)
    (root / "candidate.toml").write_text(replace_once(base, 'root = "public"', 'root = "candidate-public"'))
    (root / "third.toml").write_text(replace_once(base, 'root = "public"', 'root = "third-public"'))
    return base, public, admin


def store_args(root):
    return ("--store", root / "snapshots", "--integrity-key-file", root / "snapshot-integrity.key")


def publish(binary, root, filename):
    cli(binary, root, "--config", root / filename, "snapshot", *store_args(root), "--message", "guide fixture")
    return stored_id(root)


def run(binary):
    with private_fixture(fixture_parent(False)) as root:
        source, public, admin = prepare(root)
        cli(binary, root, "--config", root / "baseline.toml", "--validate-config")
        impact = cli(binary, root, "--reload-from", root / "baseline.toml", "--config", root / "candidate.toml")
        assert "reload impact: snapshot" in impact
        with server(binary, root, source, public):
            # HTTP captures memory, not edits to the original source file.
            (root / "fluxheim.toml").write_text((root / "candidate.toml").read_text())
            baseline = action(admin, "snapshot", expected=201)["snapshot"]
            captured = tomllib.loads((root / f"snapshots/configs/{baseline}.toml").read_text())
            assert Path(captured["vhosts"][0]["web"]["root"]) == root / "public"
            initial = action(admin, "status", method="GET")
            assert initial["snapshot_current"] == baseline
            # documented contract: publication alone does not enroll the running baseline.
            assert initial["runtime_snapshot"] is None and initial["known_good_snapshot"] is None
            candidate = publish(binary, root, "candidate.toml")
            assert request(public, "/")[2] == b"ready"
            action(admin, "reload")
            assert request(public, "/")[2] == b"candidate"
            pending = action(admin, "status", method="GET")["pending_validation"]
            assert pending["previous_snapshot"] is None
            action(admin, "self-heal/fail", expected=400)
            assert request(public, "/")[2] == b"candidate"
            assert action(admin, "status", method="GET")["pending_validation"] is not None
            # Explicit verified live rollback is the documented bootstrap/recovery path.
            action(admin, f"rollback?live=true&to={baseline}")
            assert request(public, "/")[2] == b"ready"

            candidate = publish(binary, root, "candidate.toml")
            action(admin, "reload")
            assert action(admin, "self-heal/report?health=ok")["action"] == "recorded"
            action(admin, "reload")
            pending = action(admin, "status", method="GET")["pending_validation"]
            # documented contract: same-candidate retry resets evidence and targets itself.
            assert pending["previous_snapshot"] == candidate
            assert pending["successful_checks"] == 0
            third = publish(binary, root, "third.toml")
            action(admin, "reload")
            pending = action(admin, "status", method="GET")["pending_validation"]
            assert pending["target_snapshot"] == third and pending["previous_snapshot"] == candidate
            assert request(public, "/")[2] == b"third"
            action(admin, "self-heal/fail")
            assert request(public, "/")[2] == b"candidate"
            status = action(admin, "status", method="GET")
            assert status["known_good_snapshot"] == candidate and status["pending_validation"] is None

            action(admin, f"rollback?live=true&to={baseline}")
            cli(binary, root, "rollback", *store_args(root), "--to", candidate)
            action(admin, "reload")
            assert action(admin, "self-heal/report?health=ok")["action"] == "recorded"
            assert action(admin, "self-heal/report?health=ok")["action"] == "confirmed"
            assert request(public, "/")[2] == b"candidate"
            assert "authenticated" in cli(binary, root, "snapshots", *store_args(root), "verify", candidate)
            assert "changed: vhosts" in cli(binary, root, "snapshots", *store_args(root), "diff", baseline, candidate)
            assert "healthy: true" in cli(binary, root, "snapshots", *store_args(root), "doctor")
            cli(binary, root, "rollback", *store_args(root), "--to", baseline)
            assert request(public, "/")[2] == b"candidate", "pointer-only rollback changed runtime"

        with server(binary, root, source, public):
            # Startup loads source A but restores persisted labels for previously applied B.
            assert request(public, "/")[2] == b"ready"
            status = action(admin, "status", method="GET")
            assert status["snapshot_current"] == baseline
            assert status["runtime_snapshot"] == status["known_good_snapshot"] == candidate
            action(admin, f"rollback?live=true&to={baseline}")
            assert action(admin, "status", method="GET")["runtime_snapshot"] == baseline
            assert "generation:" in cli(binary, root, "snapshots", *store_args(root), "show", baseline)
            assert "unverified" in cli(binary, root, "snapshots", "--store", root / "snapshots", "verify", baseline)
            restart = root / "restart.toml"
            restart.write_text(replace_once(source, "threads = 2", "threads = 3"))
            impact = cli(binary, root, "--reload-from", root / "baseline.toml", "--config", restart)
            assert "reload impact: process-upgrade" in impact
            selected = publish(binary, root, "restart.toml")
            assert action(admin, "reload", expected=409)["error"] == "process_upgrade_required"
            assert stored_id(root) == selected and request(public, "/")[2] == b"ready"
            action(admin, f"rollback?live=true&to={baseline}")

        changed = root / f"snapshots/configs/{selected}.toml"
        original = changed.read_bytes()
        changed.write_bytes(original + b"\n# fixture tampering\n")
        cli(binary, root, "snapshots", *store_args(root), "verify", selected, success=False)
        cli(binary, root, "snapshots", *store_args(root), "doctor", success=False)
        changed.write_bytes(original)
        cli(binary, root, "snapshots", *store_args(root), "prune", success=False)
        cli(binary, root, "snapshots", *store_args(root), "prune", "--keep", "0")
        assert stored_id(root) == baseline
        assert "healthy: true" in cli(binary, root, "snapshots", *store_args(root), "doctor")

    with private_fixture(fixture_parent(False)) as root:
        source, public, admin = prepare(root, window=2)
        baseline = publish(binary, root, "baseline.toml")
        with server(binary, root, source, public):
            publish(binary, root, "candidate.toml")
            action(admin, "reload")
            assert request(public, "/")[2] == b"candidate"
            # Publication precedes durable bookkeeping; wait for both without driving admin recovery.
            def recovered():
                if request(public, "/")[2] != b"ready" or stored_id(root) != baseline:
                    return False
                with (root / "snapshots/self-healing.toml").open("rb") as handle:
                    raw = handle.read(65537)
                assert len(raw) <= 65536
                state = tomllib.loads(tomllib.loads(raw.decode())["state_toml"])
                return state.get("known_good_snapshot") == baseline and "pending_validation" not in state

            wait_for(recovered)
            assert action(admin, "status", method="GET")["pending_validation"] is None
            assert "healthy: true" in cli(binary, root, "snapshots", *store_args(root), "doctor")
    print("snapshot guide: capture/publish/apply/confirm/pointer-only/restart/watchdog checks passed")
    print("documented contract/002: runtime identity and pending-validation replacement characterized")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    run(parser.parse_args().binary.resolve(strict=True))
