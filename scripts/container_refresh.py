#!/usr/bin/env python3
"""Plan stable-release runtime refreshes without changing application sources."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tomllib

import yaml


VARIANTS = {"wolfi", "alpine", "debian", "suse-micro", "suse-bci"}
PROFILES = {"full", "wasm", "cache", "proxy", "php", "load-balancer"}
UPGRADES = {
    "wolfi": "RUN apk upgrade --no-cache\n",
    "alpine": "RUN apk upgrade --no-cache\n",
    "debian": "RUN apt-get update && apt-get upgrade -y && rm -rf /var/lib/apt/lists/*\n",
    "suse-bci": "RUN zypper --non-interactive refresh && zypper --non-interactive update && zypper --non-interactive clean --all\n",
    # Micro has no package manager; consume the refreshed vendor base instead.
    "suse-micro": "",
}


def capture(*command):
    return subprocess.check_output(command, text=True).strip()


def stable_tag(release):
    tag = release["tag_name"]
    if release.get("draft") or release.get("prerelease") or not re.fullmatch(r"v\d+\.\d+\.\d+", tag):
        raise ValueError("refresh requires a published stable vMAJOR.MINOR.PATCH release")
    return tag


def matrix(source):
    workflow = yaml.safe_load((source / ".github/workflows/images.yml").read_text())
    declared = workflow["jobs"]["images"]["strategy"]["matrix"]
    entries = []
    for profile in declared["profile"]:
        if profile["name"] not in PROFILES:
            raise ValueError("unreviewed image profile")
        for variant in declared["variant"]:
            if variant not in VARIANTS:
                raise ValueError("unreviewed runtime variant")
            if variant == "suse-bci" and profile["name"] != "php":
                continue
            if variant == "suse-micro" and profile["name"] == "php":
                continue
            entries.append({"profile": profile["name"], "variant": variant})
    return {"include": entries}


def suffix(profile, variant):
    if profile not in PROFILES or variant not in VARIANTS:
        raise ValueError("invalid profile or variant")
    return variant if profile == "full" else f"{profile}-{variant}"


def tags(version, profile, variant, revision):
    stable_tag({"tag_name": version})
    if not re.fullmatch(r"[0-9]+-[0-9]+", revision):
        raise ValueError("revision must be RUN_ID-RUN_ATTEMPT")
    tail = suffix(profile, variant)
    aliases = [f"{version}-{tail}"]
    if variant == "wolfi":
        aliases += [version, f"{version}-base"] if profile == "full" else [f"{version}-{profile}"]
    return f"{version}-rebuild-{revision}-{tail}", aliases


def refresh_containerfile(original, variant):
    if variant not in VARIANTS or original.count("\nFROM ${RUNTIME_IMAGE}\n") != 1:
        raise ValueError("unexpected runtime stage; review the refresh adapter")
    return original.replace(
        "\nFROM ${RUNTIME_IMAGE}\n",
        "\nFROM ${RUNTIME_IMAGE} AS runtime\n" + UPGRADES[variant],
    )


def base_reference(containerfile):
    matches = re.findall(r"^ARG RUNTIME_IMAGE=([^\s]+)@sha256:[0-9a-f]{64}$", containerfile, re.M)
    if len(matches) != 1:
        raise ValueError("expected exactly one digest-pinned runtime base")
    return matches[0]


def output(values):
    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as stream:
        for key, value in values.items():
            value = str(value)
            if "\n" in value or "\r" in value:
                raise ValueError("multiline workflow output rejected")
            stream.write(f"{key}={value}\n")


def prepare(source, profile, variant, version):
    stable_tag({"tag_name": version})
    manifest = tomllib.loads((source / "Cargo.toml").read_text())
    if manifest["package"]["version"] != version[1:]:
        raise ValueError("release tag and Cargo version differ")
    if {"profile": profile, "variant": variant} not in matrix(source)["include"]:
        raise ValueError("unsupported image combination")
    workflow = yaml.safe_load((source / ".github/workflows/images.yml").read_text())
    profiles = workflow["jobs"]["images"]["strategy"]["matrix"]["profile"]
    selected = next(entry for entry in profiles if entry["name"] == profile)
    config = selected.get("managed_config", selected["config"])
    if variant == "wolfi" and selected.get("wolfi_config"):
        config = selected["wolfi_config"]
    package_file = selected.get(f"{variant.replace('-', '_')}_runtime_packages_file")
    packages = " ".join((source / package_file).read_text().split()) if package_file else ""
    path = source / "containers" / f"Containerfile.{variant}"
    original = path.read_text()
    base = base_reference(original)
    digest = capture("skopeo", "inspect", "--format", "{{.Digest}}", f"docker://{base}")
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ValueError("invalid runtime base digest")
    # Only this generated recipe changes; Rust, lockfile and configs stay at the release commit.
    (source / "containers/Containerfile.refresh").write_text(refresh_containerfile(original, variant))
    output({"base": f"{base}@{digest}", "features": selected["features"], "config": config, "packages": packages})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["resolve", "prepare", "tags"])
    parser.add_argument("--source", type=Path, default=Path("source"))
    parser.add_argument("--profile", choices=sorted(PROFILES))
    parser.add_argument("--variant", choices=sorted(VARIANTS))
    parser.add_argument("--version")
    args = parser.parse_args()
    if args.operation == "resolve":
        repository = os.environ["GITHUB_REPOSITORY"]
        release = json.loads(capture("gh", "api", f"repos/{repository}/releases/latest"))
        tag = stable_tag(release)
        subprocess.run(["git", "fetch", "--depth=1", "origin", f"refs/tags/{tag}"], check=True)
        commit = capture("git", "rev-parse", "FETCH_HEAD^{commit}")
        subprocess.run(["git", "worktree", "add", "--detach", str(args.source), commit], check=True)
        output({"version": tag, "commit": commit, "matrix": json.dumps(matrix(args.source), separators=(",", ":"))})
    elif args.operation == "prepare":
        prepare(args.source, args.profile, args.variant, args.version)
    else:
        candidate, aliases = tags(args.version, args.profile, args.variant,
                                  f"{os.environ['GITHUB_RUN_ID']}-{os.environ['GITHUB_RUN_ATTEMPT']}")
        output({"candidate": candidate, "aliases": " ".join(aliases)})


if __name__ == "__main__":
    main()
