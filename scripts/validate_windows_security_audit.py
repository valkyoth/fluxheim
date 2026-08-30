#!/usr/bin/env python3
from pathlib import Path
import tomllib

VERSION = "0.2.4"
CHECKSUM = "9e2ccdc3c6bf4d4a094e031b63fadd08d8e42abd259940eb8aa5fdc09d4bf9be"
AUDIT = Path("docs/dependency-audits/windows-filesystem-security.md")


def fail(message: str) -> None:
    raise SystemExit(f"windows security audit: {message}")


lock = tomllib.loads(Path("Cargo.lock").read_text(encoding="utf-8"))
matches = [
    package
    for package in lock.get("package", [])
    if package.get("name") == "windows-permissions"
]
if len(matches) != 1:
    fail("expected exactly one windows-permissions package")
package = matches[0]
if package.get("version") != VERSION or package.get("checksum") != CHECKSUM:
    fail("reviewed windows-permissions version or checksum drifted")

evidence = AUDIT.read_text(encoding="utf-8")
for required in (VERSION, CHECKSUM, "Audit date: 2026-08-30"):
    if required not in evidence:
        fail(f"audit evidence is missing {required!r}")

print("windows security audit: exact reviewed dependency evidence is pinned")
