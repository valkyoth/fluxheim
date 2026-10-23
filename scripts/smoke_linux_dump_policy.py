#!/usr/bin/env python3
"""Prove real Linux entrypoints harden themselves and fail closed on prctl failure."""

import argparse
from pathlib import Path
import re
import subprocess
import sys
import tempfile


def check(binary, injection):
    with tempfile.TemporaryDirectory(prefix="fluxheim-dump-policy-") as temporary:
        trace = Path(temporary) / "trace.log"
        command = ["strace", "-qq", "-e", "trace=prctl", "-o", str(trace)]
        if injection:
            command += ["-e", f"inject=prctl:{injection}"]
        result = subprocess.run([*command, "--", str(binary), "--version"],
                                capture_output=True, text=True, timeout=15, check=False)
        calls = trace.read_text()
        if injection:
            assert result.returncode == 1, (binary, injection, result, calls)
            assert "unable to disable memory dumps:" in result.stderr, (result, calls)
            assert not result.stdout, result
            assert "(INJECTED)" in calls, calls
        else:
            assert result.returncode == 0, (result, calls)
            assert result.stdout.startswith("fluxheim "), result
            assert re.search(r"prctl\(PR_SET_DUMPABLE, SUID_DUMP_DISABLE\)\s+= 0", calls), calls
            assert re.search(r"prctl\(PR_GET_DUMPABLE\)\s+= 0", calls), calls
        print(f"{binary.name}: {injection or 'non-dumpable startup'} passed")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bin-dir", type=Path, required=True)
    args = parser.parse_args()
    if sys.platform != "linux":
        parser.error("this regression requires native Linux and strace fault injection")
    for name in ("fluxheim", "fluxheim-acme", "fluxheim-config-tester"):
        binary = (args.bin_dir / name).resolve(strict=True)
        # Verify both syscall errors and an unexpected readback result. --version
        # exits in clap: failure must precede even CLI parsing, not just serving.
        for injection in (None, "error=EPERM:when=1", "error=EPERM:when=2", "retval=1:when=2"):
            check(binary, injection)


if __name__ == "__main__":
    main()
