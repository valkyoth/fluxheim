#!/usr/bin/env python3
"""Explicit, offline Fluxheim VM checkpoints; no running-guest snapshots."""
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import tempfile
import time
import uuid

from windows_qemu import ROOT, background_priority, vm_lock

STATE = ("windows.qcow2", "uefi-code.bin", "uefi-vars.bin", "identity.json",
         "settings.json", "initial-firmware-sha256.json", "tpm")
BASELINES = ROOT.parent / "windows11-fluxheim-baselines"
IO_BYTES_PER_SECOND = 32 * 1024 ** 2
IO_CHUNK = 1024 ** 2


class IOBudget:
    """Pace application reads/writes; not a device-wide bandwidth guarantee."""

    def __init__(self):
        self.deadline = time.monotonic()

    def charge(self, size):
        if IO_BYTES_PER_SECOND == 0:
            return
        self.deadline += size / IO_BYTES_PER_SECOND
        now = time.monotonic()
        if self.deadline > now:
            time.sleep(self.deadline - now)
        else:
            # Slow I/O must not accumulate credit for a later unbounded burst.
            self.deadline = now


def copy_file(source, destination):
    budget = IOBudget()
    with source.open('rb') as reader, destination.open('xb') as writer:
        while block := reader.read(IO_CHUNK):
            writer.write(block)
            budget.charge(2 * len(block))


def digest(path):
    budget = IOBudget()
    result = hashlib.sha256()
    with path.open("rb") as source:
        while block := source.read(IO_CHUNK):
            result.update(block)
            budget.charge(len(block))
    return result.hexdigest()


def inventory(root):
    files = {}
    for path in root.rglob("*"):
        if path.is_symlink() or not (path.is_file() or path.is_dir()):
            raise ValueError("VM checkpoint must contain only ordinary files/directories")
        if path.is_file() and path != root / "manifest.json":
            files[path.relative_to(root).as_posix()] = digest(path)
    return files


def verify(root):
    if root.is_symlink() or not root.is_dir():
        raise ValueError("invalid checkpoint directory")
    manifest = root / "manifest.json"
    if manifest.is_symlink():
        raise ValueError("linked checkpoint manifest")
    expected = json.loads(manifest.read_text())
    if not isinstance(expected, dict) or not expected:
        raise ValueError("empty checkpoint inventory")
    for name, value in expected.items():
        parts = PurePosixPath(name).parts
        if not parts or parts[0] not in STATE or ".." in parts or "\\" in name:
            raise ValueError("unexpected checkpoint file path")
        if not isinstance(value, str) or not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError("invalid checkpoint digest")
    if inventory(root) != expected:
        raise ValueError("checkpoint checksum or inventory mismatch")
    for name in STATE:
        if not (root / name).exists():
            raise ValueError(f"incomplete checkpoint: {name}")
    return expected


def copy_state(source, destination):
    for name in STATE:
        path = source / name
        if path.is_symlink() or not path.exists():
            raise ValueError(f"missing or linked VM state: {name}")
        if path.is_dir():
            # Inspect before copytree so links cannot silently borrow external state.
            for child in path.rglob("*"):
                if child.is_symlink() or not (child.is_file() or child.is_dir()):
                    raise ValueError("unsupported TPM state entry")
            shutil.copytree(path, destination / name,
                            copy_function=lambda source, target: copy_file(Path(source), Path(target)))
        elif path.is_file():
            copy_file(path, destination / name)
        else:
            raise ValueError("unsupported VM state entry")


def protect(root, readonly):
    for path in root.rglob("*"):
        path.chmod((0o500 if readonly else 0o700) if path.is_dir() else (0o400 if readonly else 0o600))
    root.chmod(0o500 if readonly else 0o700)


def checkpoint(root, target):
    with vm_lock(root):
        if target.exists():
            raise FileExistsError("checkpoint already exists; never overwrite a baseline")
        target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        allocated = sum(path.stat().st_size for name in STATE for path in
                        ([root / name] if (root / name).is_file() else (root / name).rglob("*")) if path.is_file())
        if shutil.disk_usage(target.parent).free < allocated + 32 * 1024 ** 3:
            raise RuntimeError("not enough space for checkpoint plus 32 GiB reserve")
        # Failed copies remain distinctly named for diagnosis, never as valid baselines.
        staging = Path(tempfile.mkdtemp(prefix=".incomplete-", dir=target.parent))
        print("Copying powered-off VM state...", flush=True)
        copy_state(root, staging)
        print("Hashing and independently rereading checkpoint contents...", flush=True)
        (staging / "manifest.json").write_text(json.dumps(inventory(staging), indent=2) + "\n")
        verify(staging)
        protect(staging, readonly=True)
        staging.rename(target)
        print(f"Verified read-only checkpoint: {target}", flush=True)


def restore(root, baseline):
    with vm_lock(root):
        print("Verifying baseline checksums...", flush=True)
        verify(baseline)
        required = sum(path.stat().st_size for path in baseline.rglob("*") if path.is_file())
        if shutil.disk_usage(root.parent).free < required + 32 * 1024 ** 3:
            raise RuntimeError("not enough space to restore while retaining current state")
        staging = Path(tempfile.mkdtemp(prefix=".fluxheim-restore-", dir=root.parent))
        print("Copying baseline into a new working directory...", flush=True)
        copy_state(baseline, staging)
        print("Verifying copied state and unchanged baseline before switching...", flush=True)
        if inventory(staging) != verify(baseline):
            raise ValueError("restored copy checksum mismatch; current VM was not changed")
        protect(staging, readonly=False)
        (staging / "uefi-code.bin").chmod(0o400)
        archived = root.with_name(root.name + "-retained-" + uuid.uuid4().hex)
        root.rename(archived)
        try:
            staging.rename(root)
        except OSError:
            archived.rename(root)
            raise
        print(f"Restored working copy. Previous state and logs retained at {archived}", flush=True)


def main():
    global IO_BYTES_PER_SECOND
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("checkpoint", "verify", "restore"))
    parser.add_argument("name", help="simple checkpoint name, not a path")
    parser.add_argument("--confirm-restore", action="store_true")
    parser.add_argument("--unthrottled-io", action="store_true",
                        help="disable copy/hash pacing for this run; CPU/I/O priority stays low")
    args = parser.parse_args()
    if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,63}", args.name):
        parser.error("invalid checkpoint name")
    os.umask(0o077)
    background_priority()
    if args.unthrottled_io:
        IO_BYTES_PER_SECOND = 0
    print("Copy/hash I/O: " + ("unthrottled" if IO_BYTES_PER_SECOND == 0 else "32 MiB/s"), flush=True)
    baseline = BASELINES / args.name
    if args.action == "checkpoint":
        checkpoint(ROOT, baseline)
    elif args.action == "verify":
        verify(baseline)
        print("Checkpoint checksums: OK")
    else:
        if not args.confirm_restore:
            parser.error("restore requires --confirm-restore; current state will be retained")
        restore(ROOT, baseline)


if __name__ == "__main__":
    main()
