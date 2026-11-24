from __future__ import annotations

import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lowkey"))

import godmode


class Tier0SandboxTests(unittest.TestCase):
    def test_seccomp_filter_is_architecture_checked_and_nonempty(self):
        program, denied = godmode._sandbox_seccomp_filter()
        self.assertGreater(len(program), 0)
        self.assertIn("ptrace", denied)
        self.assertIn("mount", denied)
        self.assertIn("bpf", denied)

    def test_sandbox_runs_without_network_and_applies_seccomp_and_readonly_mounts(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            (root / "foundry.toml").write_text("[profile.default]\n", encoding="utf-8")
            (root / "src").mkdir()

            completed = Mock()
            completed.pid = 445566
            completed.returncode = 0
            completed.communicate.return_value = ("sandbox ok\n", "")
            with patch.object(godmode.shutil, "which", side_effect=lambda name: "/usr/bin/" + name if name in {"bwrap", "systemd-run"} else None), patch.object(godmode.subprocess, "Popen", return_value=completed) as popen_mock:
                code = godmode.sandbox([
                    "--root", str(root), "--timeout", "10", "--memory-mb", "256",
                    "--processes", "64", "--readonly-workspace",
                    "--", "python3", "-c", "print('sandbox ok')",
                ])

            self.assertEqual(code, 0)
            argv = popen_mock.call_args.args[0]
            self.assertEqual(argv[0], "systemd-run")
            self.assertIn("--user", argv)
            self.assertIn("--unshare-net", argv)
            self.assertIn("--seccomp", argv)
            self.assertIn("--ro-bind", argv)
            self.assertIn("--property=MemoryMax=268435456", argv)
            self.assertIn("--property=TasksMax=64", argv)
            self.assertIn("--property=LimitCPU=300s", argv)
            self.assertIn("--property=RuntimeMaxSec=10s", argv)
            self.assertIn("pass_fds", popen_mock.call_args.kwargs)
            self.assertIsNone(popen_mock.call_args.kwargs.get("preexec_fn"))
            self.assertTrue(popen_mock.call_args.kwargs["start_new_session"])
            self.assertIn('exec 3< "$1"', " ".join(argv))

    def test_sandbox_refuses_weaker_resource_limits_without_systemd(self):
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(godmode.shutil, "which", side_effect=lambda name: "/usr/bin/bwrap" if name == "bwrap" else None):
                with self.assertRaisesRegex(RuntimeError, "systemd-run cgroup controls"):
                    godmode.sandbox(["--root", temporary, "--", "true"])

    def test_sandbox_refuses_unsandboxed_execution_when_bwrap_is_missing(self):
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(godmode.shutil, "which", return_value=None):
                with self.assertRaisesRegex(RuntimeError, "bubblewrap is unavailable"):
                    godmode.sandbox(["--root", temporary, "--", "true"])

    def test_sandbox_allowlist_refuses_when_systemd_is_unavailable(self):
        with tempfile.TemporaryDirectory() as temporary:
            with patch.object(godmode.shutil, "which", side_effect=lambda name: "/usr/bin/bwrap" if name == "bwrap" else "/usr/bin/sudo" if name == "sudo" else None):
                with self.assertRaisesRegex(RuntimeError, "systemd-run cgroup controls"):
                    godmode.sandbox([
                        "--root", temporary, "--network", "allowlist",
                        "--allow-host", "rpc.example.test", "--", "true",
                    ])

    def test_sandbox_allowlist_builds_systemd_ip_deny_and_allow_policy(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            (root / "src").mkdir()
            real_is_file = pathlib.Path.is_file
            with patch.object(godmode.shutil, "which", side_effect=lambda name: "/usr/bin/" + name if name in {"bwrap", "sudo", "systemd-run"} else None), patch.object(pathlib.Path, "is_file", autospec=True, side_effect=lambda path: True if str(path) == "/sys/fs/cgroup/cgroup.controllers" else real_is_file(path)):
                with patch.object(godmode.socket, "getaddrinfo", return_value=[(None, None, None, None, ("203.0.113.5", 0))]):
                    completed = Mock()
                    completed.pid = 445567
                    completed.returncode = 0
                    completed.communicate.return_value = ("", "")
                    with patch.object(godmode.subprocess, "Popen", return_value=completed) as run_mock:
                        code = godmode.sandbox([
                            "--root", str(root), "--network", "allowlist",
                            "--allow-host", "rpc.example.test", "--timeout", "10",
                            "--memory-mb", "256", "--cpu-seconds", "10",
                            "--", "python3", "-c", "pass",
                        ])
            self.assertEqual(code, 0)
            argv = run_mock.call_args.args[0]
            self.assertIn("--system", argv)
            self.assertIn("--property=IPAddressDeny=any", argv)
            self.assertIn("--property=IPAddressAllow=203.0.113.5", argv)
            self.assertIn("--property=TasksMax=512", argv)
            self.assertIn("--property=MemoryMax=268435456", argv)
            self.assertIn("--property=LimitCPU=10s", argv)
            self.assertTrue(any(value.startswith("--property=RuntimeMaxSec=") for value in argv))


    def test_sandbox_timeout_terminates_the_entire_process_group(self):
        with tempfile.TemporaryDirectory() as temporary:
            completed = Mock()
            completed.pid = 445568
            completed.returncode = -15
            completed.communicate.side_effect = [
                subprocess.TimeoutExpired(["bwrap"], 1),
                ("partial output\n", "terminated\n"),
            ]
            with patch.object(godmode.shutil, "which", side_effect=lambda name: "/usr/bin/" + name if name in {"bwrap", "systemd-run"} else None), patch.object(godmode.subprocess, "Popen", return_value=completed), patch.object(godmode.os, "killpg") as killpg:
                code = godmode.sandbox([
                    "--root", temporary, "--timeout", "1", "--", "python3", "-c", "pass",
                ])
            self.assertEqual(code, 124)
            killpg.assert_called_once_with(completed.pid, godmode.signal.SIGTERM)

