#!/usr/bin/env python3
"""Host-only QEMU setup regressions; never starts a VM or edits existing state."""
import json
from pathlib import Path
import socket
import tempfile
import unittest
from unittest.mock import patch

import windows_qemu as vm


class VMTests(unittest.TestCase):
    def test_unique_valid_persistent_identity(self):
        one, two = vm.new_identity(), vm.new_identity()
        self.assertTrue(all(one[key] != two[key] for key in one))
        self.assertEqual(vm.validate_identity(json.loads(json.dumps(one))), one)
        for field in one:
            with self.subTest(field=field), self.assertRaises(ValueError):
                vm.validate_identity(dict(one, **{field: "invalid,option"}))

    def test_command_is_kvm_host_cpu_private_and_separate(self):
        identity = vm.new_identity()
        command = vm.command(Path("/private/state"), Path("/tmp/fh"), identity, 12, 32, Path("/media/Windows 11.iso"))
        self.assertIn("q35,accel=kvm,smm=on,dump-guest-core=off,mem-merge=off", command)
        self.assertTrue(command[command.index("-cpu") + 1].startswith("host,"))
        self.assertIn("12,sockets=1,cores=12,threads=1", command)
        self.assertIn("32G", command)
        self.assertIn(f"throttling.bps-total={64 * 1024 ** 2}", ' '.join(command))
        for field in ("system_serial", "board_serial", "chassis_serial", "disk_serial"):
            self.assertIn(identity[field], " ".join(command))
        self.assertIn("file=/media/Windows 11.iso,media=cdrom,readonly=on,format=raw,if=ide", command)
        network = command[command.index("-netdev") + 1]
        for port in vm.PORTS:
            self.assertIn(f"hostfwd=tcp:127.0.0.1:{port}-:", network)
        self.assertNotIn(2222, vm.PORTS)
        self.assertNotIn("-virtfs", command)
        self.assertNotIn("-fsdev", command)
        self.assertIn("disable-copy-paste=on", command[command.index("-spice") + 1])

    def test_normal_boot_has_no_installer(self):
        command = vm.command(Path("/state"), Path("/tmp/fh"), vm.new_identity(), 8, 16)
        self.assertNotIn("media=cdrom", " ".join(command))
        self.assertEqual(command[command.index("-boot") + 1], "menu=on")

    def test_unthrottled_boot_only_changes_disk_bandwidth(self):
        args = (Path('/state'), Path('/tmp/fh'), vm.new_identity(), 8, 16)
        normal = vm.command(*args)
        unlimited = vm.command(*args, unthrottled_io=True)
        self.assertEqual(unlimited, [part.replace(
            f',throttling.bps-total={vm.VM_DISK_BYTES_PER_SECOND}', '') for part in normal])

    def test_path_option_injection_rejected(self):
        for path in (Path("relative"), Path("/tmp/a,b"), Path("/tmp/a\nb")):
            with self.subTest(path=path), self.assertRaises(ValueError):
                vm.qemu_path(path)

    def test_lock_conflict_and_private_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with vm.vm_lock(root):
                with self.assertRaisesRegex(RuntimeError, "already running"):
                    with vm.vm_lock(root):
                        self.fail("second lock acquired")
            root.chmod(0o755)
            with self.assertRaisesRegex(RuntimeError, "private"):
                with vm.vm_lock(root):
                    self.fail("public VM accepted")

    def test_port_conflict(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            with patch.object(vm, "PORTS", {listener.getsockname()[1]: 22}):
                with self.assertRaises(OSError):
                    vm.check_ports()

    def test_kvm_missing_fails_closed(self):
        with patch.object(Path, 'is_file', return_value=True), \
                patch.object(vm.shutil, "which", return_value="/usr/bin/tool"), \
                patch.object(vm.os, "access", side_effect=lambda path, mode: str(path) != '/dev/kvm'):
            with self.assertRaisesRegex(RuntimeError, "KVM unavailable"):
                vm.preflight()

    def test_qemu_sandbox_and_explicit_devices_are_mandatory(self):
        for iso in (None, Path('/media/windows.iso')):
            with self.subTest(iso=iso):
                command = vm.command(Path('/state'), Path('/tmp/fh'), vm.new_identity(), 8, 16, iso)
                self.assertEqual(command[0], '/usr/bin/qemu-system-x86_64')
                self.assertIn('-no-user-config', command)
                self.assertIn('-nodefaults', command)
                self.assertEqual(command[command.index('-sandbox') + 1],
                                 'on,obsolete=deny,elevateprivileges=deny,spawn=deny,resourcecontrol=deny')
                self.assertEqual(command[command.index('-vga') + 1], 'std')
                self.assertIn('usb-tablet', command)
                self.assertTrue(any(value.startswith('e1000e,') for value in command))

    def test_missing_system_binary_never_falls_back_to_path(self):
        for missing in (vm.QEMU, vm.SWTPM):
            with self.subTest(missing=missing), \
                    patch.object(Path, 'is_file', autospec=True, side_effect=lambda path: path != missing), \
                    patch.object(vm.os, 'access', return_value=True), \
                    patch.object(vm.shutil, 'which') as which:
                with self.assertRaisesRegex(RuntimeError, 'missing system executable'):
                    vm.preflight()
                which.assert_not_called()

    def test_background_priority_is_process_local(self):
        with patch.object(vm.os, 'nice') as nice, patch.object(vm.os, 'getpid', return_value=123), \
                patch.object(vm.subprocess, 'run') as run:
            vm.background_priority()
            nice.assert_called_once_with(10)
            run.assert_called_once_with(['ionice', '-c', '3', '-p', '123'], check=True)

    def test_resource_limits(self):
        with patch.object(vm.os, "cpu_count", return_value=32), patch.object(Path, "read_text", return_value="MemAvailable: 104857600 kB\n"), patch.object(vm.shutil, "disk_usage") as disk:
            disk.return_value.free = 300 * vm.GIB
            vm.check_resources(Path("/unused"), 12, 32, 224)
            for cpus, memory in ((0, 32), (33, 32), (12, 4), (12, 65)):
                with self.assertRaises(RuntimeError):
                    vm.check_resources(Path("/unused"), cpus, memory, 224)
            disk.return_value.free = 20 * vm.GIB
            with self.assertRaisesRegex(RuntimeError, "disk space"):
                vm.check_resources(Path("/unused"), 12, 32, 224)
        with patch.object(Path, "read_text", return_value="MemAvailable: 8388608 kB\n"):
            with self.assertRaisesRegex(RuntimeError, "RAM"):
                vm.check_resources(Path("/unused"), 2, 32, 32)

    def test_existing_state_never_overwritten(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            code, variables = root / "code", root / "vars"
            code.write_bytes(b"code")
            variables.write_bytes(b"vars")
            state = root / "state"
            state.mkdir()
            marker = state / "identity.json"
            marker.write_text("preserve me")
            with patch.object(vm, "preflight"), patch.object(vm, "check_resources"), patch.object(vm.subprocess, "run") as run:
                with self.assertRaises(FileExistsError):
                    vm.initialize(state, code, variables, 12, 32, 192)
                run.assert_not_called()
            self.assertEqual(marker.read_text(), "preserve me")

    def test_shutdown_checks_vm_name_and_identity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            identity = vm.new_identity()
            (root / "identity.json").write_text(json.dumps(identity))
            (root / "console-uri.txt").write_text("spice+unix:///tmp/fluxheim-qemu-test/spice.sock\n")
            with patch.object(vm.socket, "socket"), patch.object(vm, "qmp_call") as call:
                call.side_effect = [{}, {"name": "other-project"}]
                with self.assertRaisesRegex(RuntimeError, "different VM"):
                    vm.shutdown(root)
                self.assertNotIn("system_powerdown", [args.args[1] for args in call.call_args_list])
                call.reset_mock()
                call.side_effect = [{}, {"name": "fluxheim-windows11"}, {"UUID": "wrong"}]
                with self.assertRaisesRegex(RuntimeError, "identity mismatch"):
                    vm.shutdown(root)
                self.assertNotIn("system_powerdown", [args.args[1] for args in call.call_args_list])
                call.reset_mock()
                call.side_effect = [{}, {"name": "fluxheim-windows11"}, {"UUID": identity["uuid"]}, {}]
                vm.shutdown(root)
                self.assertEqual(call.call_args.args[1], "system_powerdown")


if __name__ == "__main__":
    unittest.main()
