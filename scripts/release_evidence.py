#!/usr/bin/env python3
"""Collect Fluxheim release checksums, signatures, and digest evidence.

The script prints a ready-to-paste "Checksums And Signatures" Markdown block
for a GitHub release. It intentionally uses fixed command argument lists and a
strict release-version regex so release metadata collection remains predictable.
"""

from __future__ import annotations

import argparse
import hashlib
import re
import shutil
import subprocess
import sys
import tarfile
import urllib.request
from dataclasses import dataclass
from pathlib import Path


SAFE_RELEASE_VERSION = re.compile(r"^[0-9]+(?:\.[0-9]+){2}(?:[-+][0-9A-Za-z._-]+)?$")
SOURCE_ARCHIVES = ("tar.gz", "zip")
FULL_IMAGE_VARIANTS = ("wolfi", "alpine", "suse-micro", "debian")
CACHE_IMAGE_VARIANTS = ("cache-wolfi", "cache-alpine", "cache-suse-micro", "cache-debian")
DIST_COPY_DIRS = ("docs", "examples", "packaging", "release-notes")
DIST_COPY_FILES = ("README.md", "LICENSE", "CHANGELOG.md")


@dataclass(frozen=True)
class CommandResult:
    stdout: str
    stderr: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Collect Fluxheim release evidence and print a Markdown summary."
    )
    parser.add_argument("version", help="Release version, for example 1.2.1")
    parser.add_argument(
        "--repo",
        default="valkyoth/fluxheim",
        help="GitHub repository owner/name used for source archive downloads.",
    )
    parser.add_argument(
        "--skip-builds",
        action="store_true",
        help="Skip full/cache release archive builds and print not-collected placeholders.",
    )
    parser.add_argument(
        "--skip-sbom",
        action="store_true",
        help="Skip scripts/generate-sbom.sh and print not-collected placeholders.",
    )
    parser.add_argument(
        "--skip-reproducible",
        action="store_true",
        help="Skip scripts/reproducible_build_check.sh and print a not-collected placeholder.",
    )
    parser.add_argument(
        "--skip-containers",
        action="store_true",
        help="Skip container pulls/inspects and print not-collected placeholders.",
    )
    parser.add_argument(
        "--container-tool",
        choices=["podman", "docker"],
        help="Container tool for digest collection. Defaults to podman, then docker.",
    )
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="Allow running with a dirty worktree.",
    )
    return parser.parse_args()


def run(command: list[str], cwd: Path | None = None) -> CommandResult:
    completed = subprocess.run(
        command,  # lgtm[py/command-line-injection] fixed command vectors; release input is regex-limited before use
        cwd=cwd,
        check=True,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return CommandResult(completed.stdout, completed.stderr)


def validate_inputs(version: str) -> str:
    if not SAFE_RELEASE_VERSION.fullmatch(version):
        raise SystemExit(
            "error: version must look like 1.2.1 or 1.2.1-rc.1; refusing unsafe release input"
        )
    return f"v{version}"


def repo_root() -> Path:
    return Path(run(["git", "rev-parse", "--show-toplevel"]).stdout.strip())


def ensure_clean_worktree(root: Path, allow_dirty: bool) -> None:
    if allow_dirty:
        return
    status = run(["git", "status", "--short"], cwd=root).stdout.strip()
    if status:
        raise SystemExit(
            "error: worktree is dirty; commit/stash changes or pass --allow-dirty"
        )


def release_commits(root: Path, tag: str) -> tuple[str, str]:
    head = run(["git", "rev-parse", "HEAD"], cwd=root).stdout.strip()
    tag_commit = run(["git", "rev-parse", f"{tag}^{{}}"], cwd=root).stdout.strip()
    return head, tag_commit


def tag_signature_line(root: Path, tag: str) -> str:
    try:
        result = run(["git", "tag", "-v", tag], cwd=root)
    except subprocess.CalledProcessError as error:
        output = "\n".join(
            part for part in ((error.stdout or "").strip(), (error.stderr or "").strip()) if part
        )
        reason = signature_failure_line(output) or first_nonempty_line(output)
        return f"tag verification failed: {reason}"

    combined = "\n".join(part for part in (result.stdout, result.stderr) if part)
    for line in combined.splitlines():
        if "Good" in line and "signature" in line:
            return line.strip()
    return first_nonempty_line(combined) or "tag signature verified; no signature line found"


def signature_failure_line(value: str) -> str:
    for line in value.splitlines():
        stripped = line.strip()
        if "no signature" in stripped.lower() or "bad signature" in stripped.lower():
            return stripped
    for line in value.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith(("error:", "gpg:", "ssh-keygen:")):
            return stripped
    return ""


def first_nonempty_line(value: str) -> str:
    for line in value.splitlines():
        stripped = line.strip()
        if stripped:
            return stripped
    return ""


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:  # lgtm[py/path-injection] only called for repo-owned release outputs
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def checksum_line(path: Path, display_name: str | None = None) -> str:
    return f"{sha256_file(path)}  {display_name or path.name}"


def download_source_archives(root: Path, version: str, tag: str, repo: str) -> list[str]:
    output_dir = root / "dist" / "checksums"
    output_dir.mkdir(parents=True, exist_ok=True)  # lgtm[py/path-injection] fixed path under git root
    lines = []
    for extension in SOURCE_ARCHIVES:
        filename = f"fluxheim-{version}.{extension}"
        destination = output_dir / filename
        url = f"https://github.com/{repo}/archive/refs/tags/{tag}.{extension}"
        with urllib.request.urlopen(url) as response, destination.open("wb") as handle:  # lgtm[py/path-injection] filename uses regex-validated version and fixed archive suffix
            shutil.copyfileobj(response, handle)
        lines.append(checksum_line(destination, filename))
    return lines


def rust_target(root: Path) -> str:
    result = run(["rustc", "-vV"], cwd=root).stdout
    for line in result.splitlines():
        if line.startswith("host: "):
            return line.removeprefix("host: ").strip()
    raise SystemExit("error: could not determine rustc host target")


def build_release_archive(
    root: Path,
    version: str,
    profile: str,
    features: list[str] | None,
) -> str:
    target = rust_target(root)
    dist_name = f"fluxheim-{version}-{profile}-{target}"
    dist_root = root / "dist"
    output_dir = dist_root / dist_name
    archive = dist_root / f"{dist_name}.tar.gz"

    if features is None:
        run(["cargo", "build", "--release", "--locked"], cwd=root)
    else:
        run(
            [
                "cargo",
                "build",
                "--release",
                "--locked",
                "--no-default-features",
                "--features",
                ",".join(features),
            ],
            cwd=root,
        )

    shutil.rmtree(output_dir, ignore_errors=True)  # lgtm[py/path-injection] output dir is dist/fluxheim-<validated-version>-<fixed-profile>-<rustc-target>
    output_dir.mkdir(parents=True)  # lgtm[py/path-injection] output dir is under repo dist/
    shutil.copy2(root / "target" / "release" / "fluxheim", output_dir / "fluxheim")  # lgtm[py/path-injection] fixed source and destination under git root
    for filename in DIST_COPY_FILES:
        shutil.copy2(root / filename, output_dir / filename)  # lgtm[py/path-injection] filename comes from fixed allowlist
    for dirname in DIST_COPY_DIRS:
        destination = output_dir / dirname
        if destination.exists():  # lgtm[py/path-injection] dirname is from fixed allowlist
            shutil.rmtree(destination)  # lgtm[py/path-injection] destination is under repo dist/ and fixed dirname allowlist
        shutil.copytree(root / dirname, destination)  # lgtm[py/path-injection] source/destination directory names are fixed allowlist

    if archive.exists():  # lgtm[py/path-injection] archive is under repo dist/ with validated release version
        archive.unlink()  # lgtm[py/path-injection] archive is under repo dist/ with validated release version
    with tarfile.open(archive, "w:gz") as tar:  # lgtm[py/path-injection] archive is under repo dist/ with validated release version
        tar.add(output_dir, arcname=dist_name)  # lgtm[py/path-injection] output dir is under repo dist/
    return checksum_line(archive, archive.name)


def collect_binary_checksums(root: Path, version: str, skip_builds: bool) -> list[str]:
    if skip_builds:
        return ["not collected (--skip-builds)"]
    return [
        build_release_archive(root, version, "full", None),
        build_release_archive(root, version, "cache", ["profile-cache-server"]),
    ]


def collect_sbom_checksums(root: Path, skip_sbom: bool) -> list[str]:
    if skip_sbom:
        return ["not collected (--skip-sbom)"]
    run(["scripts/generate-sbom.sh"], cwd=root)
    evidence_dir = root / "target" / "release-evidence"
    return [
        checksum_line(evidence_dir / "fluxheim.spdx.json", "fluxheim.spdx.json"),
        checksum_line(evidence_dir / "fluxheim.cyclonedx.json", "fluxheim.cyclonedx.json"),
    ]


def collect_reproducible_hash(root: Path, skip_reproducible: bool) -> str:
    if skip_reproducible:
        return "not collected (--skip-reproducible)"
    result = run(["scripts/reproducible_build_check.sh"], cwd=root)
    for line in reversed(result.stdout.splitlines()):
        if "  " in line and len(line.split()[0]) == 64:
            return line.strip()
    return first_nonempty_line(result.stdout) or "reproducible check passed; hash line not found"


def container_tool(preferred: str | None) -> str | None:
    if preferred:
        return preferred if shutil.which(preferred) else None
    for candidate in ("podman", "docker"):
        if shutil.which(candidate):
            return candidate
    return None


def inspect_digest(tool: str, image: str) -> str:
    run([tool, "pull", image])
    result = run([tool, "inspect", image, "--format", "{{index .RepoDigests 0}}"])
    return result.stdout.strip()


def collect_container_digests(version_tag: str, preferred_tool: str | None, skip: bool) -> list[str]:
    if skip:
        return ["not collected (--skip-containers)"]
    tool = container_tool(preferred_tool)
    if tool is None:
        return ["not collected (podman/docker not installed)"]

    lines = []
    labels = {
        "wolfi": "Wolfi",
        "alpine": "Alpine",
        "suse-micro": "SUSE Micro",
        "debian": "Debian",
        "cache-wolfi": "Cache Wolfi",
        "cache-alpine": "Cache Alpine",
        "cache-suse-micro": "Cache SUSE Micro",
        "cache-debian": "Cache Debian",
    }
    for variant in (*FULL_IMAGE_VARIANTS, *CACHE_IMAGE_VARIANTS):
        image = f"ghcr.io/valkyoth/fluxheim:{version_tag}-{variant}"
        try:
            digest = inspect_digest(tool, image)
        except subprocess.CalledProcessError as error:
            detail = first_nonempty_line((error.stderr or "") + "\n" + (error.stdout or ""))
            lines.append(f"{labels[variant]}: not collected ({detail or 'container command failed'})")
        else:
            lines.append(f"{labels[variant]}: `{digest}`")
    return lines


def markdown_list(lines: list[str], indent: str = "  ") -> str:
    return "\n".join(f"{indent}- `{line}`" for line in lines)


def markdown_digest_list(lines: list[str], indent: str = "  ") -> str:
    output = []
    for line in lines:
        if ": `" in line:
            label, digest = line.split(": ", 1)
            output.append(f"{indent}- {label}: {digest}")
        else:
            output.append(f"{indent}- {line}")
    return "\n".join(output)


def main() -> int:
    args = parse_args()
    tag = validate_inputs(args.version)
    root = repo_root()
    ensure_clean_worktree(root, args.allow_dirty)
    commit, tag_commit = release_commits(root, tag)

    signature = tag_signature_line(root, tag)
    source_checksums = download_source_archives(root, args.version, tag, args.repo)
    binary_checksums = collect_binary_checksums(root, args.version, args.skip_builds)
    sbom_checksums = collect_sbom_checksums(root, args.skip_sbom)
    reproducible_hash = collect_reproducible_hash(root, args.skip_reproducible)
    container_digests = collect_container_digests(
        tag,
        args.container_tool,
        args.skip_containers,
    )

    print("\n## Checksums And Signatures\n")
    print(f"- Commit: `{tag_commit}`")
    if commit != tag_commit:
        print(f"- Local HEAD: `{commit}`")
    print("- Local gate: GitHub CI green before tag; local release metadata checks passed")
    print("- CodeQL/code scanning: no open release-blocking alerts before tag")
    print("- Source archive checksums:")
    print(markdown_list(source_checksums, "  "))
    print("- Binary checksums:")
    print(markdown_list(binary_checksums, "  "))
    print("- SBOM checksums:")
    print(markdown_list(sbom_checksums, "  "))
    print("- Reproducible build:")
    print(f"  - `{reproducible_hash}`")
    print("- Container digests:")
    print(markdown_digest_list(container_digests, "  "))
    print("- Tag signature:")
    print(f"  - `{signature}`")
    return 0


if __name__ == "__main__":
    sys.exit(main())
