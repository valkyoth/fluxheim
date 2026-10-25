#!/usr/bin/env python3
"""Prepare and boot the dedicated local Fluxheim Windows VM (Linux/KVM only)."""
import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
import uuid

ROOT = Path(__file__).resolve().parent.parent / "release-reports/windows11-fluxheim-vm"
PORTS = {2223: 22, 13390: 3389, 18080: 80, 18443: 443}
GIB = 1024 ** 3
CPU = "host,hv-relaxed=on,hv-vapic=on,hv-spinlocks=0x1fff,hv-time=on"
VM_DISK_BYTES_PER_SECOND = 64 * 1024 ** 2
QEMU = Path('/usr/bin/qemu-system-x86_64')
SWTPM = Path('/usr/bin/swtpm')
SANDBOX = 'on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny'


def background_priority():
    os.nice(10)
    subprocess.run(["ionice", "-c", "3", "-p", str(os.getpid())], check=True)


def qemu_path(path):
    value = str(path)
    if not path.is_absolute() or any(char in value for char in (",", "\n", "\r", "\x00")):
        raise ValueError("QEMU paths must be absolute without commas or control characters")
    return value


def validate_identity(identity):
    if set(identity) != {"uuid", "mac", "system_serial", "board_serial", "chassis_serial", "disk_serial"}:
        raise ValueError("invalid VM identity fields")
    if str(uuid.UUID(identity["uuid"], version=4)) != identity["uuid"]:
        raise ValueError("invalid VM UUID")
    mac = identity["mac"].split(":")
    if len(mac) != 6 or mac[0] != "02" or any(
        len(part) != 2 or any(char not in "0123456789abcdef" for char in part) for part in mac
    ):
        raise ValueError("invalid VM MAC")
    for name in ("system_serial", "board_serial", "chassis_serial", "disk_serial"):
        value = identity[name]
        if not value.startswith("FH-") or len(value) != 19 or any(char not in "0123456789abcdef" for char in value[3:]):
            raise ValueError("invalid VM serial")
    return identity


def new_identity():
    identity = {"uuid": str(uuid.uuid4()), "mac": "02:" + ":".join(f"{b:02x}" for b in secrets.token_bytes(5))}
    identity.update({name: "FH-" + secrets.token_hex(8) for name in
                     ("system_serial", "board_serial", "chassis_serial", "disk_serial")})
    return validate_identity(identity)


def check_resources(root, cpus, memory, minimum_free):
    if not 2 <= cpus <= min(os.cpu_count() or 1, 32):
        raise RuntimeError("vCPU count exceeds the host or supported range (2-32)")
    if not 8 <= memory <= 64:
        raise RuntimeError("memory must be between 8 and 64 GiB")
    available = next(int(line.split()[1]) * 1024 for line in
                     Path("/proc/meminfo").read_text().splitlines() if line.startswith("MemAvailable:"))
    if available < (memory + 8) * GIB:
        raise RuntimeError("not enough available RAM; leave at least 8 GiB for the host")
    if shutil.disk_usage(root).free < minimum_free * GIB:
        raise RuntimeError(f"at least {minimum_free} GiB of free host disk space is required")


def preflight():
    for tool in (QEMU, SWTPM):
        if not tool.is_file() or not os.access(tool, os.X_OK):
            raise RuntimeError(f"missing system executable: {tool}")
    for tool in ("qemu-img", "remote-viewer", "ionice"):
        if not shutil.which(tool):
            raise RuntimeError(f"missing executable: {tool}")
    if not os.access("/dev/kvm", os.R_OK | os.W_OK):
        raise RuntimeError("KVM unavailable; software emulation is not permitted")


@contextmanager
def vm_lock(root):
    if root.is_symlink() or root.stat().st_uid != os.getuid() or root.stat().st_mode & 0o077:
        raise RuntimeError("VM state must be a private, owned directory")
    with (root / "vm.lock").open("a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise RuntimeError("Fluxheim VM is already running; do not remove its lock") from None
        yield


def check_ports():
    with context_ports():
        pass


@contextmanager
def context_ports():
    sockets = []
    try:
        for port in PORTS:
            listener = socket.socket()
            sockets.append(listener)
            listener.bind(("127.0.0.1", port))
        yield
    finally:
        for listener in sockets:
            listener.close()


def initialize(root, firmware_code, firmware_vars, cpus, memory, disk):
    preflight()
    if not 80 <= disk <= 256:
        raise ValueError("disk capacity must be between 80 and 256 GiB")
    for path in (firmware_code, firmware_vars):
        qemu_path(path)
        if not path.is_file():
            raise RuntimeError(f"missing firmware: {path}")
    root.parent.mkdir(parents=True, exist_ok=True)
    check_resources(root.parent, cpus, memory, disk + 32)
    # Exclusive creation: no implicit reset, repair or borrowing another VM's state.
    root.mkdir(mode=0o700)
    with vm_lock(root):
        identity = new_identity()
        (root / "identity.json").write_text(json.dumps(identity, indent=2) + "\n")
        (root / "settings.json").write_text(json.dumps({"cpus": cpus, "memory_gib": memory, "disk_gib": disk}, indent=2) + "\n")
        shutil.copyfile(firmware_code, root / "uefi-code.bin")
        shutil.copyfile(firmware_vars, root / "uefi-vars.bin")
        (root / "uefi-code.bin").chmod(0o400)
        (root / "tpm").mkdir(mode=0o700)
        subprocess.run(["qemu-img", "create", "-f", "qcow2", qemu_path(root / "windows.qcow2"), f"{disk}G"], check=True)
        firmware = {name: hashlib.sha256((root / name).read_bytes()).hexdigest()
                    for name in ("uefi-code.bin", "uefi-vars.bin")}
        (root / "initial-firmware-sha256.json").write_text(json.dumps(firmware, indent=2) + "\n")
    print(f"Fresh blank VM prepared at {root}; no installation or activation performed.")


def command(root, runtime, identity, cpus, memory, iso=None, unthrottled_io=False):
    identity = validate_identity(identity)
    for path in (root, runtime):
        qemu_path(path)
    args = [str(QEMU), "-no-user-config", "-nodefaults", "-sandbox", SANDBOX,
            "-name", "fluxheim-windows11", "-uuid", identity["uuid"],
            "-smbios", "type=1,manufacturer=Fluxheim Local Lab,product=Windows Builder,version=1,serial=" + identity["system_serial"],
            "-smbios", "type=2,manufacturer=Fluxheim Local Lab,product=Virtual Mainboard,version=1,serial=" + identity["board_serial"],
            "-smbios", "type=3,manufacturer=Fluxheim Local Lab,version=1,serial=" + identity["chassis_serial"],
            "-machine", "q35,accel=kvm,smm=on,dump-guest-core=off,mem-merge=off",
            "-cpu", CPU, "-smp", f"{cpus},sockets=1,cores={cpus},threads=1", "-m", f"{memory}G",
            "-global", "driver=cfi.pflash01,property=secure,value=on",
            "-drive", f"if=pflash,format=raw,readonly=on,file={root / 'uefi-code.bin'}",
            "-drive", f"if=pflash,format=raw,file={root / 'uefi-vars.bin'}",
            "-drive", f"if=none,id=osdisk,format=qcow2,file={root / 'windows.qcow2'}" +
            ("" if unthrottled_io else f",throttling.bps-total={VM_DISK_BYTES_PER_SECOND}"),
            "-device", "nvme,drive=osdisk,serial=" + identity["disk_serial"] + ",bootindex=1",
            "-chardev", f"socket,id=chrtpm,path={runtime / 'tpm.sock'}",
            "-tpmdev", "emulator,id=tpm0,chardev=chrtpm", "-device", "tpm-tis,tpmdev=tpm0",
            "-netdev", "user,id=net0," + ",".join(f"hostfwd=tcp:127.0.0.1:{host}-:{guest}" for host, guest in PORTS.items()),
            "-device", "e1000e,netdev=net0,mac=" + identity["mac"],
            "-device", "qemu-xhci", "-device", "usb-tablet", "-vga", "std",
            "-display", "none", "-monitor", "none", "-serial", "none",
            "-qmp", f"unix:{runtime / 'qmp.sock'},server=on,wait=off",
            "-spice", f"unix=on,addr={runtime / 'spice.sock'},disable-ticketing=on,disable-copy-paste=on,disable-agent-file-xfer=on",
            "-rtc", "base=localtime,clock=host", "-boot", "menu=on" + (",once=d" if iso else "")]
    if iso:
        args += ["-drive", f"file={qemu_path(iso)},media=cdrom,readonly=on,format=raw,if=ide"]
    return args


def wait_socket(path, process):
    for _ in range(200):
        if process.poll() is not None:
            raise RuntimeError(f"VM component exited with status {process.returncode}")
        if path.exists():
            return
        time.sleep(0.05)
    raise RuntimeError(f"timed out waiting for {path.name}")


def start(root, iso, unthrottled_io=False):
    preflight()
    if iso and not iso.is_file():
        raise RuntimeError("installation ISO does not exist")
    with vm_lock(root):
        settings = json.loads((root / "settings.json").read_text())
        identity = validate_identity(json.loads((root / "identity.json").read_text()))
        for name in ("windows.qcow2", "uefi-code.bin", "uefi-vars.bin", "tpm"):
            path = root / name
            if path.is_symlink() or not path.exists():
                raise RuntimeError(f"missing or linked state: {name}; never recreate TPM or firmware automatically")
        check_resources(root, settings["cpus"], settings["memory_gib"], 32)
        check_ports()
        with tempfile.TemporaryDirectory(prefix="fluxheim-qemu-") as directory:
            runtime = Path(directory)
            args = command(root, runtime, identity, settings["cpus"], settings["memory_gib"], iso, unthrottled_io)
            (root / "last-command.json").write_text(json.dumps(args, indent=2) + "\n")
            with (root / "tpm.log").open("ab") as tpm_log, (root / "qemu.log").open("ab") as qemu_log:
                tpm = subprocess.Popen([str(SWTPM), "socket", "--tpm2", "--tpmstate", f"dir={root / 'tpm'}",
                                        "--ctrl", f"type=unixio,path={runtime / 'tpm.sock'}",
                                        "--flags", "not-need-init,startup-clear"], stdout=tpm_log, stderr=tpm_log)
                guest = None
                try:
                    wait_socket(runtime / "tpm.sock", tpm)
                    guest = subprocess.Popen(args, stdout=qemu_log, stderr=qemu_log)
                    wait_socket(runtime / "spice.sock", guest)
                    uri = "spice+unix://" + str(runtime / "spice.sock")
                    (root / "console-uri.txt").write_text(uri + "\n")
                    print(f"Console: remote-viewer {uri}", flush=True)
                    print("Shut down Windows normally. Closing the viewer does not stop the VM.", flush=True)
                    # A viewer can be reopened independently; the launcher owns the VM lifetime.
                    viewer = subprocess.Popen(["remote-viewer", uri])
                    result = guest.wait()
                    if viewer.poll() is None:
                        viewer.terminate()
                    viewer.wait(timeout=10)
                    if result:
                        raise RuntimeError(f"QEMU failed with status {result}; inspect {root / 'qemu.log'}")
                finally:
                    # Never tear down the TPM of a live guest after a launcher error.
                    if guest is not None and guest.poll() is None:
                        print("Launcher error: keeping TPM alive until Windows exits normally.", flush=True)
                        guest.wait()
                    tpm.terminate()
                    tpm.wait(timeout=10)


def qmp_call(stream, execute):
    stream.write((json.dumps({"execute": execute, "id": execute}) + "\n").encode())
    stream.flush()
    for _ in range(100):
        response = stream.readline(65537)
        if not response or len(response) > 65536:
            raise RuntimeError("invalid or closed QMP response")
        data = json.loads(response)
        if data.get("id") == execute:
            if "error" in data:
                raise RuntimeError(f"QMP {execute} failed")
            return data["return"]
    raise RuntimeError("QMP response limit exceeded")


def shutdown(root):
    identity = validate_identity(json.loads((root / "identity.json").read_text()))
    uri = (root / "console-uri.txt").read_text().strip()
    match = re.fullmatch(r"spice\+unix://(/tmp/fluxheim-qemu-[a-zA-Z0-9_-]+)/spice.sock", uri)
    if not match:
        raise RuntimeError("unexpected Fluxheim console path")
    with socket.socket(socket.AF_UNIX) as client:
        client.settimeout(10)
        client.connect(str(Path(match[1]) / "qmp.sock"))
        with client.makefile("rwb") as stream:
            qmp_call(stream, "qmp_capabilities")
            if qmp_call(stream, "query-name").get("name") != "fluxheim-windows11":
                raise RuntimeError("refusing shutdown of a different VM")
            if qmp_call(stream, "query-uuid").get("UUID") != identity["uuid"]:
                raise RuntimeError("VM identity mismatch; no shutdown requested")
            qmp_call(stream, "system_powerdown")
    print("Normal ACPI shutdown requested; wait for Windows and the launcher to exit.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    init = sub.add_parser("init", help="create blank state; refuses any existing VM directory")
    init.add_argument("--firmware-code", type=Path, required=True)
    init.add_argument("--firmware-vars", type=Path, required=True)
    init.add_argument("--cpus", type=int, default=8)
    init.add_argument("--memory-gib", type=int, default=16)
    init.add_argument("--disk-gib", type=int, default=192)
    boot = sub.add_parser("start", help="boot existing state without resetting it")
    boot.add_argument("--iso", type=Path, help="attach official Windows installation ISO and boot it once")
    boot.add_argument("--unthrottled-io", action="store_true",
                      help="disable the guest disk bandwidth limit for this boot only")
    sub.add_parser("shutdown", help="request normal ACPI shutdown of this exact VM; never force power-off")
    args = parser.parse_args()
    os.umask(0o077)
    background_priority()
    if args.action == "init":
        initialize(ROOT, args.firmware_code.resolve(strict=True), args.firmware_vars.resolve(strict=True),
                   args.cpus, args.memory_gib, args.disk_gib)
    elif args.action == "start":
        start(ROOT, args.iso.resolve(strict=True) if args.iso else None, args.unthrottled_io)
    else:
        shutdown(ROOT)


if __name__ == "__main__":
    main()
