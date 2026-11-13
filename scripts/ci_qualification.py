#!/usr/bin/env python3
"""Select costly release qualification; uncertainty always requests a full run."""

import fnmatch
import json
import os
from pathlib import Path
import re
import subprocess


ROOT = Path(__file__).resolve().parents[1]
RELEASE_PATHS = (
    "Cargo.toml", "Cargo.lock", "**/Cargo.toml", "**/Cargo.lock",
    "build.rs", "**/build.rs", "rust-toolchain*", ".cargo/*", ".gitattributes",
    "packaging/*", "containers/*", ".github/workflows/images.yml",
    "scripts/build_release*", "scripts/portable_release_plan.py",
    "scripts/validate_portable_release_plan.py", "scripts/native_archive.py",
    "scripts/*native_archives*", "scripts/*windows_archive*",
    "scripts/*windows_wasm_archive*", "scripts/reproducible*",
    "scripts/release_helper*", "scripts/*release_builder*",
    "scripts/publish_verified_release.sh", "scripts/verify_windows*",
    "scripts/generate-sbom.sh",
    "scripts/windows_release*", "scripts/validate-1-0-core.sh",
)


def release_paths_changed(paths):
    return any(fnmatch.fnmatchcase(path, pattern) for path in paths for pattern in RELEASE_PATHS)


def full_qualification(event_name, ref, event, head, changed_paths):
    if ref.startswith("refs/tags/") or event_name == "workflow_dispatch":
        return True
    if event_name == "pull_request":
        base = event.get("pull_request", {}).get("base", {}).get("sha", "")
    elif event_name == "push":
        base = event.get("before", "")
    else:
        return True
    if any(not isinstance(sha, str) or re.fullmatch(r"[0-9a-f]{40}", sha) is None
           or sha == "0" * 40 for sha in (base, head)):
        return True
    try:
        return release_paths_changed(changed_paths(base, head))
    except (OSError, subprocess.SubprocessError, UnicodeError, ValueError):
        return True


def git_changed_paths(base, head):
    # Include removed/renamed files under their old names as well as new ones.
    result = subprocess.run(
        ["git", "diff", "--no-ext-diff", "--no-renames", "--name-only", "-z", base, head, "--"],
        cwd=ROOT, check=True, capture_output=True, timeout=60,
    )
    return [name.decode("utf-8") for name in result.stdout.split(b"\0") if name]


def main():
    try:
        event = json.loads(Path(os.environ["GITHUB_EVENT_PATH"]).read_text(encoding="utf-8"))
        full = full_qualification(os.environ.get("GITHUB_EVENT_NAME", ""),
                                  os.environ.get("GITHUB_REF", ""), event,
                                  os.environ.get("GITHUB_SHA", ""), git_changed_paths)
    except (KeyError, OSError, ValueError, AttributeError):
        full = True
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as output:
        output.write(f"full={'true' if full else 'false'}\n")
    print("CI qualification: " + ("full release checks" if full else "development checks; archive/reproducibility checks deferred"))


if __name__ == "__main__":
    main()
