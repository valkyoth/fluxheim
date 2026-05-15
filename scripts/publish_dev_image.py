#!/usr/bin/env python3
"""Trigger the Quay-only development Wolfi image build on GitHub Actions."""

from __future__ import annotations

import argparse
import re
import subprocess
import sys


WORKFLOW = "images.yml"
REF = "main"


def run(command: list[str]) -> None:
    print("+ " + " ".join(command), flush=True)
    subprocess.run(command, check=True)


def run_capture(command: list[str]) -> str:
    print("+ " + " ".join(command), flush=True)
    completed = subprocess.run(command, check=True, text=True, capture_output=True)
    if completed.stdout:
        print(completed.stdout, end="")
    if completed.stderr:
        print(completed.stderr, end="", file=sys.stderr)
    return completed.stdout + completed.stderr


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
        output = run_capture(
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
            match = re.search(r"/actions/runs/([0-9]+)", output)
            if not match:
                print("error: could not find workflow run id in gh output", file=sys.stderr)
                return 1
            run(["gh", "run", "watch", match.group(1), "--exit-status"])
    except FileNotFoundError:
        print("error: GitHub CLI `gh` is required", file=sys.stderr)
        return 127
    except subprocess.CalledProcessError as error:
        return error.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
