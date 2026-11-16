import pathlib
import sys
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lowkey"))

import command_wrapper


class CommandWrapperTests(unittest.TestCase):
    def test_specialized_command_publishes_only_sanitized_completion_metadata(self):
        command = ["python3", "godmode.py", "--rpc-url", "https://user:secret@example.invalid/private"]
        fake_result = type("Result", (), {"returncode": 0})()
        with (
            patch.object(command_wrapper.subprocess, "run", return_value=fake_result),
            patch.object(command_wrapper.audit_context, "foundry_project_root", return_value=pathlib.Path("/tmp/project")),
            patch.object(command_wrapper.audit_context, "emit") as emit,
        ):
            result = command_wrapper.run_command("godmode", command)
        self.assertEqual(result, 0)
        emit.assert_called_once()
        args, kwargs = emit.call_args
        self.assertEqual(args[0], "command-completed")
        self.assertEqual(kwargs["tool"], "cli")
        self.assertEqual(kwargs["status"], "completed")
        self.assertEqual(kwargs["data"], {"command": "godmode", "exit_code": 0})
        self.assertNotIn("secret", repr(emit.call_args))
        self.assertNotIn("private", repr(emit.call_args))

    def test_failed_command_records_failure_and_preserves_exit_code(self):
        fake_result = type("Result", (), {"returncode": 5})()
        with (
            patch.object(command_wrapper.subprocess, "run", return_value=fake_result),
            patch.object(command_wrapper.audit_context, "foundry_project_root", return_value=pathlib.Path("/tmp/project")),
            patch.object(command_wrapper.audit_context, "emit") as emit,
        ):
            result = command_wrapper.run_command("proxy-resolve", ["python3", "godmode.py"])
        self.assertEqual(result, 5)
        self.assertEqual(emit.call_args.kwargs["status"], "failed")
        self.assertEqual(emit.call_args.kwargs["data"], {"command": "proxy-resolve", "exit_code": 5})

    def test_help_and_shell_probe_statuses_are_not_recorded(self):
        help_result = type("Result", (), {"returncode": 0})()
        probe_result = type("Result", (), {"returncode": 3})()
        with (
            patch.object(
                command_wrapper.subprocess,
                "run",
                side_effect=[help_result, probe_result],
            ),
            patch.object(command_wrapper.audit_context, "foundry_project_root", return_value=pathlib.Path("/tmp/project")),
            patch.object(command_wrapper.audit_context, "emit") as emit,
        ):
            command_wrapper.run_command("godmode", ["python3", "godmode.py", "--help"])
            status = command_wrapper.run_command(
                "project",
                ["python3", "workspace_tools.py", "project"],
                skip_exit_codes={3},
            )
        self.assertEqual(status, 3)
        emit.assert_not_called()

    def test_negative_signal_exit_codes_are_normalized_and_recorded(self):
        fake_result = type("Result", (), {"returncode": -2})()
        with (
            patch.object(command_wrapper.subprocess, "run", return_value=fake_result),
            patch.object(command_wrapper.audit_context, "foundry_project_root", return_value=pathlib.Path("/tmp/project")),
            patch.object(command_wrapper.audit_context, "emit") as emit,
        ):
            status = command_wrapper.run_command("forge", ["forge", "debug"])
        self.assertEqual(status, 130)
        self.assertEqual(emit.call_args.kwargs["status"], "failed")
        self.assertEqual(emit.call_args.kwargs["data"], {"command": "forge", "exit_code": 130})

    def test_project_rpc_overrides_global_environment_for_rpc_aware_routes(self):
        project_rpc = "http://127.0.0.1:9545"
        state = {"project": {"root": "/tmp/project"}, "rpc": project_rpc}
        fake_result = type("Result", (), {"returncode": 0})()
        with (
            patch.dict(command_wrapper.os.environ, {"FOUNDRY_ETH_RPC_URL": "http://global-rpc"}, clear=True),
            patch.object(command_wrapper.audit_context, "foundry_project_root", return_value=pathlib.Path("/tmp/project")),
            patch.object(command_wrapper.audit_context, "load", return_value=state),
            patch.object(command_wrapper, "_load_global_config", return_value={}),
            patch.object(command_wrapper.shared_context, "resolve_runtime_context", return_value={"rpc": project_rpc}),
            patch.object(command_wrapper.subprocess, "run", return_value=fake_result) as run,
            patch.object(command_wrapper.audit_context, "emit"),
        ):
            status = command_wrapper.run_command("godmode", ["python3", "godmode.py"])

            self.assertEqual(status, 0)
            child_env = run.call_args.kwargs["env"]
            self.assertEqual(child_env["FOUNDRY_ETH_RPC_URL"], project_rpc)
            self.assertEqual(child_env["ETH_RPC_URL"], project_rpc)
            self.assertEqual(child_env["LOWKEY_RPC_URL"], project_rpc)
            self.assertEqual(command_wrapper.os.environ["FOUNDRY_ETH_RPC_URL"], "http://global-rpc")

    def test_explicit_rpc_and_explicit_project_root_are_respected(self):
        explicit_rpc = "http://127.0.0.1:8547"
        fake_result = type("Result", (), {"returncode": 0})()
        with (
            patch.dict(command_wrapper.os.environ, {"FOUNDRY_ETH_RPC_URL": "http://global-rpc"}, clear=True),
            patch.object(command_wrapper.audit_context, "foundry_project_root") as root,
            patch.object(command_wrapper.shared_context, "resolve_runtime_context") as resolver,
            patch.object(command_wrapper.subprocess, "run", return_value=fake_result) as run,
            patch.object(command_wrapper.audit_context, "emit"),
        ):
            status = command_wrapper.run_command(
                "godmode",
                ["python3", "godmode.py", "--root", "/tmp/Token", "--rpc-url", explicit_rpc],
            )

        self.assertEqual(status, 0)
        root.assert_not_called()
        resolver.assert_not_called()
        self.assertNotIn("env", run.call_args.kwargs)


if __name__ == "__main__":
    unittest.main()
