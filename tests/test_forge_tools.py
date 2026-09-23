import importlib.util
import pathlib
import sys
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE = ROOT / "lowkey" / "forge_tools.py"
spec = importlib.util.spec_from_file_location("forge_tools", MODULE)
forge_tools = importlib.util.module_from_spec(spec)
sys.modules[spec.name] = forge_tools
spec.loader.exec_module(forge_tools)

class LowkeyForgeTests(unittest.TestCase):
    def test_native_commands(self):
        for command in ("build", "test", "inspect", "debug", "script", "coverage", "snapshot", "lint", "geiger"):
            self.assertIn(command, forge_tools.NATIVE_COMMANDS)

    @patch("forge_tools.forge_path", return_value="/usr/bin/forge")
    @patch("forge_tools.subprocess.run")
    def test_passthrough(self, run, _path):
        run.return_value.returncode = 0
        self.assertEqual(forge_tools.run_forge(["test", "-vvvv"]), 0)
        run.assert_called_once_with(["/usr/bin/forge", "test", "-vvvv"])

    @patch("forge_tools.forge_path", return_value=None)
    def test_missing_forge(self, _path):
        self.assertEqual(forge_tools.run_forge(["test"]), 2)

    @patch("forge_tools.run_forge", return_value=0)
    def test_test_audit_adds_trace(self, run):
        self.assertEqual(forge_tools.run_test_audit(["--match-test", "testFoo"]), 0)
        run.assert_called_once_with(["test", "-vvvv", "--match-test", "testFoo"])

    @patch("forge_tools.run_forge", return_value=0)
    def test_audit_sequence(self, run):
        self.assertEqual(forge_tools.run_audit([]), 0)
        self.assertEqual([call.args[0] for call in run.call_args_list],
                         [["build"], ["test", "-vvv"], ["coverage"]])

    @patch("forge_tools.run_forge", return_value=0)
    def test_inspect_audit_sequence(self, run):
        self.assertEqual(forge_tools.run_inspect_audit(["Vault"]), 0)
        self.assertEqual([call.args[0] for call in run.call_args_list],
                         [["build"], ["inspect", "Vault", "abi"],
                          ["inspect", "Vault", "methods"],
                          ["inspect", "Vault", "errors"],
                          ["inspect", "Vault", "events"],
                          ["inspect", "Vault", "storage-layout"]])

if __name__ == "__main__":
    unittest.main()
