#!/usr/bin/env python3
"""Update Fluxheim's core package version fields.

This helper intentionally avoids editing changelog history, release notes, and
README narrative text. Run `scripts/validate-release-metadata.sh` afterwards;
that gate points at the human-facing files that still need release-specific
wording.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path
from typing import Callable


SAFE_VERSION = re.compile(r"^[0-9]+[.][0-9]+[.][0-9]+(?:[-][0-9A-Za-z.-]+)?$")
PACKAGE_VERSION = re.compile(
    r"(?ms)(\A|\n)(\[package\]\n(?:(?!\n\[).)*?\nversion = \")([^\"]+)(\")"
)
RPM_VERSION = re.compile(r"(?m)^(Version:\s*)(\S+)$")


Replacement = str | Callable[[re.Match[str]], str]


def replace_once(path: Path, pattern: re.Pattern[str], replacement: Replacement) -> bool:
    original = path.read_text(encoding="utf-8")
    updated, count = pattern.subn(replacement, original, count=1)
    if count != 1:
        raise RuntimeError(f"{path}: expected exactly one version field, found {count}")
    if updated == original:
        return False
    path.write_text(updated, encoding="utf-8")
    return True


def cargo_tomls(root: Path) -> list[Path]:
    paths = [root / "Cargo.toml"]
    paths.extend(sorted((root / "crates").glob("*/Cargo.toml")))
    return paths


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Bump Fluxheim Cargo package and RPM spec versions."
    )
    parser.add_argument("version", help="release version, for example 1.6.35")
    args = parser.parse_args()

    version = args.version
    if not SAFE_VERSION.fullmatch(version):
        print(f"unsafe release version: {version}", file=sys.stderr)
        return 2

    root = Path(__file__).resolve().parents[1]
    changed: list[Path] = []

    for path in cargo_tomls(root):
        if replace_once(
            path,
            PACKAGE_VERSION,
            lambda match: f"{match.group(1)}{match.group(2)}{version}{match.group(4)}",
        ):
            changed.append(path)

    rpm_spec = root / "packaging" / "rpm" / "fluxheim.spec"
    if replace_once(rpm_spec, RPM_VERSION, rf"\g<1>{version}"):
        changed.append(rpm_spec)

    if changed:
        print("updated version fields:")
        for path in changed:
            print(f"  {path.relative_to(root)}")
    else:
        print("version fields already matched")

    release_notes = root / "release-notes" / f"RELEASE_NOTES_{version}.md"
    if not release_notes.exists():
        print(f"missing {release_notes.relative_to(root)}")

    print("next: update CHANGELOG.md, README.md, docs/build-and-podman.md,")
    print("      release notes, and RPM changelog, then run")
    print("      scripts/validate-release-metadata.sh")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
