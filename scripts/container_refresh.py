#!/usr/bin/env python3
"""Plan stable-release runtime refreshes without changing application sources."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
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


# Keep filesystem operands independent of workflow/CLI data. Adding a new
# release layout requires reviewing this allowlist, not accepting arbitrary paths.
RELEASE_FILES = {
    "manifest": Path("source/Cargo.toml"),
    "workflow": Path("source/.github/workflows/images.yml"),
    "wolfi": Path("source/containers/Containerfile.wolfi"),
    "alpine": Path("source/containers/Containerfile.alpine"),
    "debian": Path("source/containers/Containerfile.debian"),
    "suse-micro": Path("source/containers/Containerfile.suse-micro"),
    "suse-bci": Path("source/containers/Containerfile.suse-bci"),
    "packaging/container/php-wolfi-runtime-packages.txt": Path("source/packaging/container/php-wolfi-runtime-packages.txt"),
    "packaging/container/php-alpine-runtime-packages.txt": Path("source/packaging/container/php-alpine-runtime-packages.txt"),
    "packaging/container/php-debian-runtime-packages.txt": Path("source/packaging/container/php-debian-runtime-packages.txt"),
    "packaging/container/php-suse-bci-runtime-packages.txt": Path("source/packaging/container/php-suse-bci-runtime-packages.txt"),
    "php-modules": Path("source/packaging/container/php-required-modules.txt"),
    "php-config": Path("source/packaging/container/php-managed.toml"),
}
CONFIGS = {
    "packaging/container/fluxheim.toml", "packaging/container/cache.toml",
    "packaging/container/proxy.toml", "packaging/container/php.toml",
    "packaging/container/php-managed.toml", "packaging/container/load-balancer.toml",
}
PACKAGE_FILES = {name for name in RELEASE_FILES if name.endswith("-runtime-packages.txt")}


def release_text(key):
    if key not in RELEASE_FILES:
        raise ValueError("unreviewed release file")
    path = RELEASE_FILES[key]
    if any(part.is_symlink() for part in (path, *path.parents)):
        raise ValueError("symlink in release input")
    return path.read_text()


def verified_release_commit(tag, allowed_signers):
    stable_tag({"tag_name": tag})
    if not allowed_signers.strip():
        raise ValueError("protected release allowed-signers secret is required")
    # FETCH_HEAD can name a lightweight tag. Pin the tag object before verifying
    # and use only its signed commit, never a mutable ref after verification.
    oid = subprocess.check_output(["git", "rev-parse", "FETCH_HEAD"], text=True).strip()
    if not re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", oid):
        raise ValueError("invalid fetched object ID")
    kind = subprocess.check_output(["git", "cat-file", "-t", oid], text=True).strip()
    if kind != "tag":
        raise ValueError("release must use an annotated signed tag")
    content = subprocess.check_output(["git", "cat-file", "tag", oid], text=True)
    header = content.split("\n\n", 1)[0].splitlines()
    if (len(header) < 3 or header[1:3] != ["type commit", f"tag {tag}"]
            or not re.fullmatch(r"object ([0-9a-f]{40}|[0-9a-f]{64})", header[0])):
        raise ValueError("signed tag name or target does not match release")
    if (content.count("-----BEGIN SSH SIGNATURE-----") != 1
            or content.count("-----END SSH SIGNATURE-----") != 1):
        raise ValueError("release tag requires exactly one SSH signature")
    # This anchor comes from protected workflow configuration, not release source.
    with tempfile.TemporaryDirectory(prefix="fluxheim-release-trust-") as directory:
        signers = Path(directory) / "allowed_signers"
        signers.write_text(allowed_signers)
        subprocess.run([
            "git", "-c", "gpg.format=ssh", "-c", "gpg.ssh.program=ssh-keygen",
            "-c", "gpg.minTrustLevel=fully",
            "-c", f"gpg.ssh.allowedSignersFile={signers}", "verify-tag", oid,
        ], check=True, stdout=subprocess.DEVNULL)
    return header[0].removeprefix("object ")


def stable_tag(release):
    tag = release["tag_name"]
    if (release.get("draft") or release.get("prerelease") or not isinstance(tag, str)
            or not re.fullmatch(r"v[0-9]{1,10}\.[0-9]{1,10}\.[0-9]{1,10}", tag)):
        raise ValueError("refresh requires a published stable vMAJOR.MINOR.PATCH release")
    return tag


def matrix():
    workflow = yaml.safe_load(release_text("workflow"))
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
    if not re.fullmatch(r"[0-9]{1,20}-[0-9]{1,10}", revision):
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
    lines = []
    for key, value in values.items():
        value = str(value)
        if "\n" in value or "\r" in value:
            raise ValueError("multiline workflow output rejected")
        lines.append(f"{key}={value}")
    print("\n".join(lines))


def prepare(profile, variant, version):
    stable_tag({"tag_name": version})
    manifest = tomllib.loads(release_text("manifest"))
    if manifest["package"]["version"] != version[1:]:
        raise ValueError("release tag and Cargo version differ")
    if {"profile": profile, "variant": variant} not in matrix()["include"]:
        raise ValueError("unsupported image combination")
    workflow = yaml.safe_load(release_text("workflow"))
    profiles = workflow["jobs"]["images"]["strategy"]["matrix"]["profile"]
    selected = next(entry for entry in profiles if entry["name"] == profile)
    config = selected.get("managed_config", selected["config"])
    if variant == "wolfi" and selected.get("wolfi_config"):
        config = selected["wolfi_config"]
    package_file = selected.get(f"{variant.replace('-', '_')}_runtime_packages_file")
    if config not in CONFIGS or (package_file and package_file not in PACKAGE_FILES):
        raise ValueError("unreviewed release configuration or package file")
    packages = " ".join(release_text(package_file).split()) if package_file else ""
    original = release_text(variant)
    base = base_reference(original)
    digest = subprocess.check_output(["skopeo", "inspect", "--format", "{{.Digest}}", f"docker://{base}"], text=True).strip()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", digest):
        raise ValueError("invalid runtime base digest")
    # Only this generated recipe changes; Rust, lockfile and configs stay at the release commit.
    # Exclusive creation refuses a pre-existing file/symlink in the checkout.
    with open("source/containers/Containerfile.refresh", "x", encoding="utf-8") as stream:
        stream.write(refresh_containerfile(original, variant))
    output({"base": f"{base}@{digest}", "features": selected["features"], "config": config, "packages": packages})


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["resolve", "prepare", "tags"])
    parser.add_argument("--profile", choices=sorted(PROFILES))
    parser.add_argument("--variant", choices=sorted(VARIANTS))
    parser.add_argument("--version")
    args = parser.parse_args()
    if args.operation == "resolve":
        repository = os.environ["GITHUB_REPOSITORY"]
        if repository != "valkyoth/fluxheim":
            raise ValueError("refresh is restricted to the release repository")
        signers = os.environ.get("FLUXHEIM_RELEASE_ALLOWED_SIGNERS", "")
        if not signers.strip():
            raise ValueError("protected release allowed-signers secret is required")
        release = json.loads(subprocess.check_output(["gh", "api", "repos/valkyoth/fluxheim/releases/latest"], text=True))
        tag = stable_tag(release)
        subprocess.run(["git", "fetch", "--depth=1", "origin", f"refs/tags/{tag}"], check=True)
        commit = verified_release_commit(tag, signers)
        subprocess.run(["git", "worktree", "add", "--detach", "source", commit], check=True, stdout=subprocess.DEVNULL)
        output({"version": tag, "commit": commit, "matrix": json.dumps(matrix(), separators=(",", ":"))})
    elif args.operation == "prepare":
        prepare(args.profile, args.variant, args.version)
    else:
        candidate, aliases = tags(args.version, args.profile, args.variant,
                                  f"{os.environ['GITHUB_RUN_ID']}-{os.environ['GITHUB_RUN_ATTEMPT']}")
        output({"candidate": candidate, "aliases": " ".join(aliases)})


if __name__ == "__main__":
    main()
