#!/usr/bin/env python3
"""Fail closed if promotion would discard another platform."""

import json
import subprocess
import sys


def validate(manifest, config=None):
    if "manifests" not in manifest:
        if not config:
            raise ValueError("single manifest requires inspected image configuration")
        platforms = {f"{config['Os']}/{config['Architecture']}"}
    else:
        platforms = {f"{m['platform']['os']}/{m['platform']['architecture']}" for m in manifest["manifests"]}
    platforms.discard("unknown/unknown")  # BuildKit provenance descriptors.
    if platforms != {"linux/amd64"}:
        raise ValueError(f"refusing to replace existing platforms: {sorted(platforms)}")


if __name__ == "__main__":
    image = sys.argv[1]
    manifest = json.loads(subprocess.check_output(["skopeo", "inspect", "--raw", image]))
    config = None
    if "manifests" not in manifest:
        config = json.loads(subprocess.check_output(["skopeo", "inspect", image]))
    validate(manifest, config)
