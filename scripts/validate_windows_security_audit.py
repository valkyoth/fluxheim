#!/usr/bin/env python3
import hashlib
from pathlib import Path
import tomllib

VERSION = "0.2.4"
CHECKSUM = "9e2ccdc3c6bf4d4a094e031b63fadd08d8e42abd259940eb8aa5fdc09d4bf9be"
REVIEW_DATE = "2026-09-01"
SOURCE_DIGEST = "de216c1b695ed735b2bae3ac196e85f639cac228a1beb423d045aa1f96b3eb9a"
SOURCE_FILES = (
    Path("crates/fluxheim-windows-security/src/lib.rs"),
    Path("crates/fluxheim-windows-security/src/file_mutation.rs"),
    Path("crates/fluxheim-windows-security/src/path_handles.rs"),
)
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

source_hasher = hashlib.sha256()
for source in SOURCE_FILES:
    source_hasher.update(source.as_posix().encode("utf-8"))
    source_hasher.update(b"\0")
    source_hasher.update(source.read_bytes())
    source_hasher.update(b"\0")
if source_hasher.hexdigest() != SOURCE_DIGEST:
    fail("reviewed first-party Windows security source boundary drifted")

evidence = AUDIT.read_text(encoding="utf-8")
for required in (
    VERSION,
    CHECKSUM,
    SOURCE_DIGEST,
    f"Audit date: {REVIEW_DATE}",
    "NtCreateFile",
    "NtSetInformationFile",
    "SetFileInformationByHandle",
    "CreateDirectoryW",
    "RtlNtStatusToDosError",
    "RetainedPathHandles",
):
    if required not in evidence:
        fail(f"audit evidence is missing {required!r}")

print("windows security audit: dependency and first-party source evidence is pinned")
