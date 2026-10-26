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
        (root / "foundry.toml").write_text('[profile.default]\\nsrc = "src"\\ntest = "test"\\n', encoding="utf-8")
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

    def test_supported_signal_generates_runs_and_attaches_repeat_safe_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(Path(tmp))
            signal = self._signal(root)
            with patch("lowkey.test_generation.run_test_gen", side_effect=self._fake_generator(root)):
                result = signal_investigation.investigate_signal(
                    signal["id"], project_root=root, audit_context=audit_context,
                )
            self.assertEqual(result["status"], "passed")
            self.assertTrue(result["evidence_attached"])
            self.assertTrue(Path(root, result["targeted_test"]).is_file())
            self.assertEqual(result["target_test_name"], "test_nonOwnerCannotCall_setBalance")
            stored = next(item for item in audit_context.signals(root) if item["id"] == signal["id"])
            evidence = [item for item in stored.get("evidence", []) if item.get("kind") == "targeted-test-investigation"]
            self.assertEqual(len(evidence), 1)
            self.assertFalse(evidence[0]["security_finding_confirmed"])
            report = json.loads((root / result["report_path"]).read_text(encoding="utf-8"))
            self.assertEqual(report["status"], "passed")

            with patch("lowkey.test_generation.run_test_gen", side_effect=self._fake_generator(root)):
                second = signal_investigation.investigate_signal(
                    signal["id"], project_root=root, audit_context=audit_context,
                )
            stored = next(item for item in audit_context.signals(root) if item["id"] == signal["id"])
            evidence = [item for item in stored.get("evidence", []) if item.get("kind") == "targeted-test-investigation"]
            self.assertEqual(second["evidence_id"], result["evidence_id"])
            self.assertEqual(len(evidence), 1)

    def test_only_role_signal_selects_role_holder_test(self):
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
            def fake_role_generator(_config, args, *, project_root):
                project = Path(project_root)
                relative = Path(args[args.index("--output-dir") + 1])
                generated_root = project / relative / "RoleVault"
                generated_root.mkdir(parents=True, exist_ok=True)
                test_name = "test_nonRoleHolderCannotCall_setLimit"
                test_path = generated_root / "LowkeyGeneratedUnit_RoleVault.t.sol"
                test_path.write_text(
                    "contract LowkeyGeneratedUnit_RoleVault { "
                    f"function {test_name}() public {{}} }}\n",
                    encoding="utf-8",
                )
                report = {
                    "generated": [test_path.relative_to(project).as_posix()],
                    "skipped": [],
                    "generation_assessment": {"unit": {"level": "executable-candidate"}},
                    "validation": {
                        "status": "passed", "detail": "role fixture validated",
                        "baseline_exit_code": 0, "exit_code": 0,
                        "test_executions": [{
                            "path": "test/lowkey-generated/LowkeyValidation_deadbeef_LowkeyGeneratedUnit_RoleVault.t.sol",
                            "exit_code": 0,
                            "stdout_tail": f"[PASS] {test_name}() (gas: 1234)",
                            "stderr_tail": "",
                        }],
                    },
                }
                (generated_root / "report.json").write_text(json.dumps(report), encoding="utf-8")
                return 0
            with patch("lowkey.test_generation.run_test_gen", side_effect=fake_role_generator):
                result = signal_investigation.investigate_signal(
                    signal["id"], project_root=root, audit_context=audit_context,
                )
            self.assertEqual(result["status"], "passed")
            self.assertEqual(result["target_test_name"], "test_nonRoleHolderCannotCall_setLimit")
            self.assertIn("onlyRole", result["property"])
            self.assertTrue(result["evidence_attached"])

    def test_unsupported_finding_writes_reason_without_generating_a_test(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(Path(tmp))
            signal = self._signal(root, check="reentrancy-eth", title="Potential reentrancy")
            with patch("lowkey.test_generation.run_test_gen") as generator:
                result = signal_investigation.investigate_signal(
                    signal["id"], project_root=root, audit_context=audit_context,
                )
            generator.assert_not_called()
            self.assertEqual(result["status"], "unsupported")
            self.assertFalse(result["generated_artifacts"])
            self.assertTrue(result["evidence_attached"])
            self.assertIn("will not infer", result["reason"])

    def test_constructor_arguments_are_required_before_generation(self):
        source = self.SOURCE.replace("constructor() { owner = msg.sender; }",
                                     "constructor(address initialOwner) { owner = initialOwner; }")
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(Path(tmp), source)
            signal = self._signal(root)
            with patch("lowkey.test_generation.run_test_gen") as generator:
                result = signal_investigation.investigate_signal(
                    signal["id"], project_root=root, audit_context=audit_context,
                )
            generator.assert_not_called()
            self.assertEqual(result["status"], "needs-setup")
            self.assertIn("constructor argument", result["reason"])

    def test_identified_target_test_failure_is_attached_as_review_lead(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = self._project(Path(tmp))
            signal = self._signal(root)
            output = "[FAIL: next call did not revert] test_nonOwnerCannotCall_setBalance()"
            with patch("lowkey.test_generation.run_test_gen",
                       side_effect=self._fake_generator(root, validation_status="failed",
                                                        exit_code=1, native_output=output)):
                result = signal_investigation.investigate_signal(
                    signal["id"], project_root=root, audit_context=audit_context,
                )
            self.assertEqual(result["status"], "test-failed-needs-review")
            self.assertTrue(result["evidence_attached"])
            self.assertFalse(result["native_evidence"].get("security_finding_confirmed", False))
            self.assertIn("may reproduce", result["interpretation"])

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
            self.assertEqual(result["status"], "unsupported")
            self.assertIn("outside", result["reason"])


if __name__ == "__main__":
    unittest.main()
