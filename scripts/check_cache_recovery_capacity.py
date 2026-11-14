#!/usr/bin/env python3
"""Read-only filesystem-cache entry preflight. Run offline as the service user."""

import argparse
import os
from pathlib import Path
import re
import stat
import time

# Kept aligned with native_http1_cache_recovery.rs by regression coverage.
OBJECT_LIMIT = 57_344
ENTRY_LIMIT = 65_536


def is_real_directory(metadata):
    return stat.S_ISDIR(metadata.st_mode) and not (
        getattr(metadata, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400))


def check_capacity(root, *, limit=OBJECT_LIMIT, seconds=30):
    root = Path(root).absolute()
    if root.resolve(strict=True) != root or not is_real_directory(root.lstat()):
        raise ValueError("cache root must be a real, non-aliased directory")
    started = time.monotonic()
    entries = 0

    def charge():
        nonlocal entries
        if time.monotonic() - started > seconds:
            raise TimeoutError("cache preflight time limit exceeded")
        entries += 1
        return entries <= limit

    # Count the same root/hex-shard levels as recovery, but use the lower
    # admission cap conservatively. No payload reads, deletion or chmod.
    with os.scandir(root) as children:
        for child in children:
            if not charge():
                return False, entries
            if re.fullmatch(r"[0-9a-f]{2}", child.name):
                if not is_real_directory(child.stat(follow_symlinks=False)):
                    raise ValueError("cache shard is not a real directory")
                with os.scandir(child.path) as files:
                    for _ in files:
                        if not charge():
                            return False, entries
    return True, entries


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("cache_root", type=Path)
    root = parser.parse_args().cache_root
    try:
        ok, entries = check_capacity(root)
    except (OSError, ValueError):
        print("cache capacity preflight: incomplete; use a fresh independent root or investigate offline")
        return 1
    if not ok:
        print(f"cache capacity preflight: over conservative {OBJECT_LIMIT}-entry threshold "
              f"(observed at least {entries}); use a fresh independent root before upgrade")
        return 1
    print(f"cache capacity preflight: {entries} entries, below conservative {OBJECT_LIMIT}-entry threshold")
    print("Capacity only: this does not validate contents, keys, ACLs, read/time budgets or startup.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
