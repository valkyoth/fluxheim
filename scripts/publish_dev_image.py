#!/usr/bin/env python3
"""Trigger the Quay-only development Wolfi image build on GitHub Actions."""

from __future__ import annotations

import argparse
import subprocess
import sys


WORKFLOW = "images.yml"
REF = "main"


def run(command: list[str]) -> None:
    print("+ " + " ".join(command), flush=True)
    subprocess.run(command, check=True)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Publish quay.io/<namespace>/<repo>:dev-wolfi from latest main."
    )
    parser.add_argument(
        "--watch",
        action="store_true",
        help="Wait for the triggered GitHub Actions run to finish.",
    )
    args = parser.parse_args()

    try:
        run(
            [
                "gh",
                "workflow",
                "run",
                WORKFLOW,
                "--ref",
                REF,
                "-f",
                "publish_dev_wolfi=true",
                "-f",
                "platforms=linux/amd64",
            ]
        )
        if args.watch:
            run(["gh", "run", "watch"])
    except FileNotFoundError:
        print("error: GitHub CLI `gh` is required", file=sys.stderr)
        return 127
    except subprocess.CalledProcessError as error:
        return error.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
