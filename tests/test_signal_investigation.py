import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lowkey import audit_context, signal_investigation


class SignalInvestigationTests(unittest.TestCase):
    SOURCE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Vault {
    address public owner;
    uint256 public balance;
    constructor() { owner = msg.sender; }
    modifier onlyOwner() { require(msg.sender == owner, "owner"); _; }
    function setBalance(uint256 nextValue) external onlyOwner { balance = nextValue; }
}
"""

    def _project(self, root: Path, source: str | None = None) -> Path:
        (root / "foundry.toml").write_text(
            '[profile.default]\n'
            'src = "src"\n'
            'test = "test"\n',
            encoding="utf-8",
        )
        (root / "src").mkdir()
        (root / "src" / "Vault.sol").write_text(source or self.SOURCE, encoding="utf-8")
        return root

    def _signal(self, root: Path, *, check="access-control", title="Access control review", function="setBalance(uint256)"):
        return audit_context.add_signal({
            "tool": "slither",
            "category": "static-analysis",
            "check": check,
            "title": title,
            "impact": "High",
            "confidence": "Medium",
            "file": "src/Vault.sol",
            "line": 7,
            "function": function,
        }, root)

    def _fake_generator(self, root: Path, *, validation_status="passed", exit_code=0, native_output="[PASS] test_nonOwnerCannotCall_setBalance()"):
        def fake_run(_config, args, *, project_root):
            project = Path(project_root)
            relative = Path(args[args.index("--output-dir") + 1])
            generated_root = project / relative / "Vault"
            generated_root.mkdir(parents=True, exist_ok=True)
            test_path = generated_root / "LowkeyGeneratedUnit_Vault.t.sol"
            test_path.write_text(
                "contract LowkeyGeneratedUnit_Vault { "
                "function test_nonOwnerCannotCall_setBalance() public {} }\\n",
                encoding="utf-8",
            )
            report = {
                "generated": [test_path.relative_to(project).as_posix()],
                "skipped": [],
                "generation_assessment": {"unit": {"level": "executable-candidate"}},
                "validation": {
                    "status": validation_status,
                    "detail": "native Forge validation fixture",
                    "baseline_exit_code": 0,
                    "exit_code": exit_code,
                    "test_executions": [{
                        "path": "test/lowkey-generated/LowkeyValidation_deadbeef_LowkeyGeneratedUnit_Vault.t.sol",
                        "exit_code": exit_code,
                        "stdout_tail": native_output,
                        "stderr_tail": "",
                    }],
                },
            }
            (generated_root / "report.json").write_text(json.dumps(report), encoding="utf-8")
            return 0 if validation_status == "passed" else 1
        return fake_run


    def test_source_only_plan_is_read_only_and_never_calls_generator(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(Path(tmp))
            signal = self._signal(root)
            with patch("lowkey.test_generation.run_test_gen", side_effect=AssertionError("must not generate")):
                report = signal_investigation.plan_signal_investigation(
                    signal["id"], project_root=root, audit_context=audit_context,
                )
            self.assertEqual(report["status"], "plan-only")
            self.assertEqual(report["recommended_next_command"], f"lk ai test-plan --finding {signal['id']}")
            self.assertFalse(report["effects"]["writes"])
            self.assertFalse(report["effects"]["tests_run"])
            self.assertFalse((root / ".audit" / "investigations").exists())

    def test_inspected_test_executes_only_the_requested_path_and_function(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(Path(tmp))
            signal = self._signal(root)
            test_dir = root / "test"
            test_dir.mkdir()
            test_file = test_dir / "Vault.t.sol"
            test_file.write_text(
                "contract VaultTest { function test_guard() public {} function test_other() public {} }",
                encoding="utf-8",
            )
            with patch("lowkey.signal_investigation.shutil.which", return_value="/usr/bin/forge"), \
                 patch("lowkey.signal_investigation.subprocess.run") as run:
                run.return_value.returncode = 0
                run.return_value.stdout = "[PASS] test_guard()"
                run.return_value.stderr = ""
                result = signal_investigation.execute_inspected_test(
                    signal["id"], "test/Vault.t.sol", "test_guard",
                    project_root=root, audit_context=audit_context,
                )
            self.assertEqual(result["status"], "passed")
            command = run.call_args.args[0]
            self.assertEqual(command[1:3], ["test", "--match-path"])
            self.assertIn("--match-test", command)
            self.assertEqual(command[-1], r"^test_guard(?:\(\))?$")
            self.assertIn("-vv", command)
            self.assertFalse(result["security_finding_confirmed"])
            self.assertTrue(result["evidence_attached"])

    def test_forge_failure_with_reason_is_recognized_as_an_executed_test(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(Path(tmp))
            signal = self._signal(root)
            test_dir = root / "test"
            test_dir.mkdir()
            (test_dir / "Vault.t.sol").write_text(
                "contract VaultTest { function test_guard() public {} }",
                encoding="utf-8",
            )
            with patch("lowkey.signal_investigation.shutil.which", return_value="/usr/bin/forge"), \
                 patch("lowkey.signal_investigation.subprocess.run") as run:
                run.return_value.returncode = 1
                run.return_value.stdout = "[FAIL: next call did not revert] test_guard() (gas: 1234)"
                run.return_value.stderr = ""
                result = signal_investigation.execute_inspected_test(
                    signal["id"], "test/Vault.t.sol", "test_guard",
                    project_root=root, audit_context=audit_context,
                )
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["exit_code"], 1)
            self.assertTrue(result["evidence_attached"])
            self.assertIn("did not revert", result["stdout"])
    def test_forge_zero_exit_without_exact_test_result_is_not_a_pass(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(Path(tmp))
            signal = self._signal(root)
            test_dir = root / "test"
            test_dir.mkdir()
            (test_dir / "Vault.t.sol").write_text(
                "contract VaultTest { function test_guard() public {} }",
                encoding="utf-8",
            )
            with patch("lowkey.signal_investigation.shutil.which", return_value="/usr/bin/forge"), \
                 patch("lowkey.signal_investigation.subprocess.run") as run:
                run.return_value.returncode = 0
                run.return_value.stdout = "Warning: no tests match the provided pattern"
                run.return_value.stderr = ""
                result = signal_investigation.execute_inspected_test(
                    signal["id"], "test/Vault.t.sol", "test_guard",
                    project_root=root, audit_context=audit_context,
                )
            self.assertEqual(result["status"], "not_run")
            self.assertEqual(result["exit_code"], 0)
            self.assertTrue(result["evidence_attached"])
            command = run.call_args.args[0]
            self.assertEqual(command[command.index("--match-path") + 1], "^test/Vault\\.t\\.sol$")

    def test_inspected_test_rejects_outside_test_directory_before_forge(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(Path(tmp))
            signal = self._signal(root)
            outside = root / "src" / "Oops.t.sol"
            outside.write_text("contract T { function test_bad() public {} }", encoding="utf-8")
            with patch("lowkey.signal_investigation.shutil.which") as which:
                with self.assertRaisesRegex(ValueError, "outside the active Foundry test directory"):
                    signal_investigation.execute_inspected_test(
                        signal["id"], "src/Oops.t.sol", "test_bad",
                        project_root=root, audit_context=audit_context,
                    )
                which.assert_not_called()

    def test_legacy_investigate_api_is_plan_only_and_never_generates(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(Path(tmp))
            signal = self._signal(root)
            with patch("lowkey.test_generation.run_test_gen", side_effect=AssertionError("legacy API must not generate")) as generator:
                report = signal_investigation.investigate_signal(
                    signal["id"], project_root=root, audit_context=audit_context,
                )
            generator.assert_not_called()
            self.assertEqual(report["status"], "plan-only")
            self.assertFalse(report["effects"]["writes"])
            self.assertFalse(report["effects"]["tests_run"])
            self.assertFalse(report["human_disposition_changed"])
            self.assertFalse((root / ".audit" / "investigations").exists())
            self.assertFalse(list((root / "test").glob("**/*.t.sol")) if (root / "test").exists() else [])

    def test_role_finding_plan_does_not_generate_or_execute_a_role_test(self):
        source = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract RoleVault {
    bytes32 public constant OPERATOR_ROLE = keccak256("OPERATOR_ROLE");
    mapping(bytes32 => mapping(address => bool)) private roleMembers;
    uint256 public limit;
    constructor() { roleMembers[OPERATOR_ROLE][msg.sender] = true; }
    modifier onlyRole(bytes32 role) {
        require(roleMembers[role][msg.sender], "missing role");
        _;
    }
    function setLimit(uint256 nextValue) external onlyRole(OPERATOR_ROLE) { limit = nextValue; }
}
"""
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(Path(tmp), source)
            signal = self._signal(root, function="setLimit(uint256)")
            with patch("lowkey.test_generation.run_test_gen", side_effect=AssertionError("must not generate")) as generator:
                report = signal_investigation.investigate_signal(
                    signal["id"], project_root=root, audit_context=audit_context,
                )
            generator.assert_not_called()
            self.assertEqual(report["status"], "plan-only")
            self.assertEqual(report["signal"]["function"], "setLimit")
            self.assertFalse(report["effects"]["tests_run"])
            self.assertIn("lk ai test-plan", report["recommended_next_command"])

    def test_unclassified_finding_plan_remains_read_only(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(Path(tmp))
            signal = self._signal(root, check="gas", title="Gas cost review")
            with patch("lowkey.test_generation.run_test_gen", side_effect=AssertionError("must not generate")) as generator:
                report = signal_investigation.investigate_signal(
                    signal["id"], project_root=root, audit_context=audit_context,
                )
            generator.assert_not_called()
            self.assertEqual(report["status"], "plan-only")
            self.assertFalse(report["effects"]["writes"])
            self.assertFalse(report["effects"]["tests_run"])
            self.assertIn("protocol-specific", report["property_hypothesis"])

    def test_constructor_arguments_are_not_implicit_execution_authorization(self):
        source = self.SOURCE.replace(
            "constructor() { owner = msg.sender; }",
            "constructor(address initialOwner) { owner = initialOwner; }",
        )
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(Path(tmp), source)
            signal = self._signal(root)
            with patch("lowkey.test_generation.run_test_gen", side_effect=AssertionError("must not generate")) as generator:
                report = signal_investigation.investigate_signal(
                    signal["id"], project_root=root, audit_context=audit_context,
                    constructor_args=["address(0x1234)"],
                )
            generator.assert_not_called()
            self.assertEqual(report["status"], "plan-only")
            self.assertIn("constructor_args are not execution authorization", report["compatibility_note"])
            self.assertFalse(report["effects"]["tests_run"])

    def test_legacy_investigate_api_does_not_auto_attach_or_confirm_native_test_results(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(Path(tmp))
            signal = self._signal(root)
            with patch("lowkey.test_generation.run_test_gen", side_effect=AssertionError("must not run")):
                report = signal_investigation.investigate_signal(
                    signal["id"], project_root=root, audit_context=audit_context,
                )
            self.assertEqual(report["status"], "plan-only")
            self.assertFalse(report["human_disposition_changed"])
            stored = next(item for item in audit_context.signals(root) if item["id"] == signal["id"])
            self.assertFalse(any(
                item.get("kind") in {"targeted-test-investigation", "inspected-native-test-execution"}
                for item in stored.get("evidence", [])
            ))

    def test_signal_from_outside_project_is_rejected_without_running_generator(self):
        with tempfile.TemporaryDirectory() as tmp, tempfile.TemporaryDirectory() as outside:
            root = self._project(Path(tmp))
            external = Path(outside) / "External.sol"
            external.write_text(self.SOURCE, encoding="utf-8")
            signal = audit_context.add_signal({
                "tool": "slither", "check": "access-control", "title": "Access control review",
                "file": str(external), "line": 1, "function": "setBalance(uint256)",
            }, root)
            with patch("lowkey.test_generation.run_test_gen") as generator:
                result = signal_investigation.investigate_signal(
                    signal["id"], project_root=root, audit_context=audit_context,
                )
            generator.assert_not_called()
            self.assertEqual(result["status"], "blocked")
            self.assertIn("outside", result["reason"])


if __name__ == "__main__":
    unittest.main()
