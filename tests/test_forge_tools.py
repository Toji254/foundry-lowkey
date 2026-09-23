import importlib.util
import io
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
        for command in ("build", "test", "inspect", "script", "coverage", "snapshot", "lint", "geiger", "clone", "fuzz", "lsp"):
            self.assertIn(command, forge_tools.NATIVE_COMMANDS)
        self.assertNotIn("debug", forge_tools.NATIVE_COMMANDS)

    def test_unsupported_debug_is_rejected(self):
        with patch("forge_tools.forge_path", return_value="/usr/bin/forge"):
            with patch("forge_tools.subprocess.run") as run:
                run.return_value.returncode = 0
                self.assertEqual(forge_tools.main(["debug"]), 2)
                run.assert_not_called()

    @patch("forge_tools.forge_path", return_value="/usr/bin/forge")
    @patch("forge_tools.subprocess.run")
    def test_passthrough(self, run, _path):
        run.return_value.returncode = 0
        self.assertEqual(forge_tools.run_forge(["test", "-vvvv"]), 0)
        run.assert_called_once_with(["/usr/bin/forge", "test", "-vvvv"])

    @patch("forge_tools.forge_path", return_value="/usr/bin/forge")
    @patch("forge_tools.subprocess.run")
    def test_run_forge_quiet_suppresses_success_output(self, run, _path):
        run.return_value = type("Result", (), {"returncode": 0, "stdout": "noisy forge", "stderr": ""})()
        output = io.StringIO()
        with patch("sys.stdout", output):
            self.assertEqual(forge_tools.run_forge(["build"], quiet=True), 0)
        self.assertEqual(output.getvalue(), "")

    @patch("forge_tools.run_forge", return_value=0)
    @patch("forge_tools.run_coverage_audit", return_value=0)
    @patch("forge_tools._coverage_compatibility_flags", return_value=[])
    @patch("forge_tools._supports_option", return_value=True)
    def test_run_audit_is_quiet_by_default(self, _supports, _compat, coverage, run):
        output = io.StringIO()
        with patch("sys.stdout", output):
            self.assertEqual(forge_tools.run_audit([]), 0)
        rendered = output.getvalue()
        self.assertIn("Mode    : quiet", rendered)
        self.assertNotIn("=== LOWKEY FORGE", rendered)
        self.assertTrue(all(call.kwargs.get("quiet") is True for call in run.call_args_list))
        self.assertTrue(coverage.call_args.kwargs.get("quiet") is True)
    @patch("forge_tools.forge_path", return_value=None)
    def test_missing_forge(self, _path):
        self.assertEqual(forge_tools.run_forge(["test"]), 2)

    @patch("forge_tools.run_forge", return_value=0)
    def test_test_audit_adds_trace(self, run):
        self.assertEqual(forge_tools.run_test_audit(["--match-test", "testFoo"]), 0)
        run.assert_called_once_with(["test", "-vvvv", "--match-test", "testFoo"])

    @patch("forge_tools.run_forge", return_value=0)
    @patch("forge_tools.run_coverage_audit", return_value=0)
    @patch("forge_tools._coverage_compatibility_flags", return_value=[])
    @patch("forge_tools._supports_option", return_value=True)
    def test_audit_sequence(self, _supports, _compat, coverage, run):
        self.assertEqual(forge_tools.run_audit([]), 0)
        self.assertEqual([call.args[0] for call in run.call_args_list],
                         [["build", "--skip", "test", "--skip", "script"],
                          ["test", "-vvv", "--no-match-path", "test/Lowkey_*"]])
        self.assertEqual(
            coverage.call_args.args[0],
            ["coverage", "--no-match-path", "**/Lowkey_*"],
        )

    @patch("forge_tools.run_forge", return_value=0)
    @patch("forge_tools.run_coverage_audit", return_value=0)
    @patch("forge_tools.run_slither_preflight", return_value=0)
    @patch("forge_tools.command_available", return_value=False)
    @patch("forge_tools._coverage_compatibility_flags", return_value=[])
    @patch("forge_tools._supports_option", return_value=True)
    def test_audit_checks_runs_slither_preflight(self, supports, compat, available, slither, coverage, run):
        self.assertEqual(forge_tools.run_audit(["--checks"]), 0)
        slither.assert_called_once()
        self.assertEqual(run.call_args_list[0].args[0], ["build", "--skip", "test", "--skip", "script"])
        self.assertEqual(run.call_args_list[1].args[0], ["test", "-vvv", "--no-match-path", "test/Lowkey_*"])
        self.assertEqual(
            coverage.call_args.args[0],
            ["coverage", "--no-match-path", "**/Lowkey_*"],
        )
        self.assertEqual(run.call_count, 2)
        self.assertEqual(available.call_count, 2)

    def test_filter_generated_diagnostics(self):
        output = """note[custom-errors]: use custom errors
  ╭▸ src/Escrow.sol:10:5
  ╰ help: https://example.invalid

note[low-level-calls]: generated helper
  ╭▸ test/Lowkey_probe_release_abcd.t.sol:20:9
  ╰ help: https://example.invalid
"""
        visible, filtered = forge_tools._filter_generated_diagnostics(output)
        self.assertIn("src/Escrow.sol:10:5", visible)
        self.assertNotIn("test/Lowkey_probe_release_abcd.t.sol", visible)
        self.assertEqual(filtered, 1)

    @patch("forge_tools.run_forge", return_value=0)
    def test_inspect_audit_sequence(self, run):
        self.assertEqual(forge_tools.run_inspect_audit(["Vault"]), 0)
        self.assertEqual([call.args[0] for call in run.call_args_list],
                         [["build"], ["inspect", "Vault", "abi"],
                          ["inspect", "Vault", "methods"],
                          ["inspect", "Vault", "errors"],
                          ["inspect", "Vault", "events"],
                          ["inspect", "Vault", "storage-layout"]])

    @patch("forge_tools.run_forge", side_effect=[0, 0, 1, 0, 2, 0])
    def test_inspect_audit_aggregates_failures(self, run):
        self.assertEqual(forge_tools.run_inspect_audit(["Vault"]), 1)
        self.assertEqual(run.call_count, 6)


    def test_coverage_table_is_parsed_and_summarised(self):
        output = """╭--------------------------------------------+------------------+------------------+------------------+-----------------╮
| File                                       | % Lines          | % Statements     | % Branches       | % Funcs         |
+=======================================================================================================================+
| src/ConfidencePool.sol                     | 96.89% (312/322) | 97.01% (422/435) | 94.23% (98/104)  | 96.88% (31/32)  |
| src/ConfidencePoolFactory.sol              | 92.16% (47/51)   | 92.98% (53/57)   | 100.00% (13/13) | 100.00% (12/12) |
| src/mocks/MockERC20.sol                    | 100.00% (3/3)    | 100.00% (1/1)    | N/A (0/0)        | 100.00% (2/2)   |
| Total                                      | 87.60% (431/492) | 89.83% (530/590) | 92.62% (113/122)| 85.00% (68/80) |
╰--------------------------------------------+------------------+------------------+------------------+-----------------╯
"""
        rows = forge_tools._parse_coverage_table(output)
        self.assertEqual(len(rows), 4)
        self.assertEqual(rows[0]["file"], "src/ConfidencePool.sol")
        self.assertEqual(rows[0]["branches"], ("94.23", 98, 104))
        self.assertEqual(rows[2]["branches"], None)

        report = forge_tools._format_coverage_report(output)
        self.assertIn("COVERAGE TABLE", report)
        self.assertIn("src/ConfidencePool.sol", report)
        self.assertIn("312/322 (96.89%)", report)
        self.assertIn("10 / 13 / 6 / 1", report)
        self.assertIn("src/mocks/MockERC20.sol", report)
        self.assertIn("All reported files", report)

    def test_raw_coverage_table_is_stripped_before_display(self):
        output = """before
╭----------+
| File     | % Lines | % Statements | % Branches | % Funcs |
+----------+
| src/A.sol | 50.00% (1/2) | 50.00% (1/2) | 50.00% (1/2) | 100.00% (1/1) |
╰----------+
after
"""
        visible = forge_tools._strip_coverage_table(output)
        self.assertIn("before", visible)
        self.assertIn("after", visible)
        self.assertNotIn("| src/A.sol |", visible)
        self.assertNotIn("╭----------+", visible)


    @patch("forge_tools.audit_context.record_tool")
    @patch("forge_tools.audit_context.emit")
    @patch("forge_tools.forge_path", return_value="/usr/bin/forge")
    @patch("forge_tools.subprocess.run")
    def test_coverage_renders_table_from_stderr(self, run, _path, _emit, _record):
        result = type("Result", (), {
            "returncode": 0,
            "stdout": "",
            "stderr": """╭--------------------------------------------+------------------+------------------+------------------+-----------------╮
| File                                       | % Lines          | % Statements     | % Branches       | % Funcs         |
+=======================================================================================================================+
| src/ConfidencePool.sol                     | 96.89% (312/322) | 97.01% (422/435) | 94.23% (98/104)  | 96.88% (31/32)  |
╰--------------------------------------------+------------------+------------------+------------------+-----------------╯
"""
        })()
        run.return_value = result

        with patch("builtins.print") as printed:
            self.assertEqual(
                forge_tools.run_coverage_audit(["coverage"], pathlib.Path("/project")),
                0,
            )

        output = "\n".join(str(call.args[0]) for call in printed.call_args_list if call.args)
        self.assertIn("COVERAGE TABLE", output)
        self.assertIn("312/322 (96.89%)", output)
        self.assertNotIn("| src/ConfidencePool.sol", output)

    @patch("forge_tools._supports_option", return_value=True)
    @patch("forge_tools._coverage_needs_ir", return_value=True)
    def test_coverage_compatibility_flags_detect_via_ir(self, needs_ir, supports):
        flags = forge_tools._coverage_compatibility_flags(pathlib.Path("/project"), [])
        self.assertEqual(flags, ["--ir-minimum"])
        needs_ir.assert_called_once()
        supports.assert_called_once_with("coverage", "--ir-minimum")

    @patch("forge_tools._coverage_needs_ir", return_value=True)
    def test_coverage_compatibility_flags_respects_existing_ir_flag(self, needs_ir):
        self.assertEqual(
            forge_tools._coverage_compatibility_flags(pathlib.Path("/project"), ["--ir-minimum"]),
            [],
        )
        needs_ir.assert_not_called()

    @patch("forge_tools._supports_option", return_value=True)
    @patch("forge_tools.audit_context.record_tool")
    @patch("forge_tools.audit_context.emit")
    @patch("forge_tools.forge_path", return_value="/usr/bin/forge")
    @patch("forge_tools.subprocess.run")
    def test_coverage_retries_stack_too_deep_with_ir_minimum(
        self, run, _path, _emit, _record, _supports
    ):
        first = type("Result", (), {
            "returncode": 1,
            "stdout": "",
            "stderr": "Error: Compiler error: Stack too deep.",
        })()
        second = type("Result", (), {
            "returncode": 0,
            "stdout": "coverage ok\n",
            "stderr": "",
        })()
        run.side_effect = [first, second]

        self.assertEqual(
            forge_tools.run_coverage_audit(
                ["coverage", "--no-match-path", "test/Lowkey_*"],
                pathlib.Path("/project"),
            ),
            0,
        )
        self.assertEqual(run.call_count, 2)
        self.assertEqual(
            run.call_args_list[1].args[0],
            ["/usr/bin/forge", "coverage", "--no-match-path", "test/Lowkey_*", "--ir-minimum"],
        )
        _record.assert_called_once()
        self.assertEqual(_record.call_args.kwargs["status"], "completed")
        self.assertEqual(_record.call_args.kwargs["data"]["attempts"], 2)

    @patch("forge_tools._supports_option", return_value=True)
    @patch("forge_tools.audit_context.record_tool")
    @patch("forge_tools.audit_context.emit")
    @patch("forge_tools.forge_path", return_value="/usr/bin/forge")
    @patch("forge_tools.subprocess.run")
    def test_coverage_does_not_retry_unrelated_failure(
        self, run, _path, _emit, _record, _supports
    ):
        result = type("Result", (), {
            "returncode": 1,
            "stdout": "",
            "stderr": "Error: test fixture failed.",
        })()
        run.return_value = result

        self.assertEqual(
            forge_tools.run_coverage_audit(["coverage"], pathlib.Path("/project")),
            1,
        )
        run.assert_called_once()
        _record.assert_called_once()
        self.assertEqual(_record.call_args.kwargs["data"]["attempts"], 1)

    @patch("forge_tools.run_forge", return_value=0)
    @patch("forge_tools.run_coverage_audit", return_value=0)
    @patch("forge_tools._coverage_compatibility_flags", return_value=[])
    @patch("forge_tools._supports_option", return_value=True)
    def test_audit_keeps_default_verbosity_with_unrelated_v_flag_prefix(self, _supports, _compat, coverage, run):
        self.assertEqual(forge_tools.run_audit(["--via-ir"]), 0)
        self.assertEqual(
            run.call_args_list[1].args[0],
            ["test", "-vvv", "--via-ir", "--no-match-path", "test/Lowkey_*"],
        )
        self.assertEqual(
            coverage.call_args.args[0],
            ["coverage", "--via-ir", "--no-match-path", "**/Lowkey_*"],
        )

    @patch("forge_tools.run_forge", return_value=0)
    @patch("forge_tools.run_coverage_audit", return_value=0)
    @patch("forge_tools._coverage_compatibility_flags", return_value=[])
    @patch("forge_tools._supports_option", return_value=True)
    def test_audit_respects_explicit_verbosity(self, _supports, _compat, coverage, run):
        self.assertEqual(forge_tools.run_audit(["--verbosity", "4"]), 0)
        self.assertEqual(
            run.call_args_list[1].args[0],
            ["test", "--verbosity", "4", "--no-match-path", "test/Lowkey_*"],
        )
        self.assertEqual(
            coverage.call_args.args[0],
            ["coverage", "--verbosity", "4", "--no-match-path", "**/Lowkey_*"],
        )

if __name__ == "__main__":
    unittest.main()
