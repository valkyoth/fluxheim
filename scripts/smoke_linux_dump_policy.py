#!/usr/bin/env python3
"""Prove real Linux entrypoints harden themselves and fail closed on prctl failure."""

import argparse
from contextlib import contextmanager
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile


@contextmanager
def full_stderr_pipe():
    reader, writer = os.pipe()
    try:
        os.set_blocking(writer, False)
        filled = 0
        while True:
            try:
                filled += os.write(writer, b"x" * 4096)
            except BlockingIOError:
                break
        # Fill any remaining space and prove even a one-byte write would block.
        while True:
            try:
                filled += os.write(writer, b"x")
            except BlockingIOError:
                break
        assert filled > 0
        os.set_blocking(writer, True)
        yield reader, writer, filled
    finally:
        os.close(writer)
        os.close(reader)


def run_with_full_stderr(command):
    with full_stderr_pipe() as (reader, writer, filled):
        with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=writer,
                              start_new_session=True, text=True) as process:
            try:
                stdout, _ = process.communicate(timeout=5)
            except subprocess.TimeoutExpired as error:
                # Reap both tracer and tracee without draining stderr to unblock
                # the old implementation. Only this test's process group dies.
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.communicate()
                raise AssertionError("startup did not exit with full stderr within five seconds") from error
            assert os.read(reader, filled) == b"x" * filled
            return subprocess.CompletedProcess(command, process.returncode, stdout, "")


def check(binary, injection, full_stderr=False):
    with tempfile.TemporaryDirectory(prefix="fluxheim-dump-policy-") as temporary:
        trace = Path(temporary) / "trace.log"
        command = ["strace", "-qq", "-e", "trace=prctl", "-o", str(trace)]
        if injection:
            command += ["-e", f"inject=prctl:{injection}"]
        command += ["--", str(binary), "--version"]
        if full_stderr:
            result = run_with_full_stderr(command)
        else:
            result = subprocess.run(command, capture_output=True, text=True, timeout=15, check=False)
        calls = trace.read_text()
        if injection:
            assert result.returncode == 1, (binary, injection, result, calls)
            assert not result.stderr, (result, calls)
            assert not result.stdout, result
            assert "(INJECTED)" in calls, calls
        else:
            assert result.returncode == 0, (result, calls)
            assert result.stdout.startswith("fluxheim "), result
            assert re.search(r"prctl\(PR_SET_DUMPABLE, SUID_DUMP_DISABLE\)\s+= 0", calls), calls
            assert re.search(r"prctl\(PR_GET_DUMPABLE\)\s+= 0", calls), calls
        print(f"{binary.name}: {injection or 'non-dumpable startup'}"
              f"{' with full stderr' if full_stderr else ''} passed")


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
            if injection:
                check(binary, injection, full_stderr=True)


if __name__ == "__main__":
    main()
