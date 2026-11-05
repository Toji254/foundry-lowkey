import json
import pathlib
import tempfile
import unittest

from lowkey.proof_evidence import (
    classify_proof, evaluate_economic_policy, freeze_control_manifest,
    validate_control_freeze,
)


class ProofEvidenceTests(unittest.TestCase):
    def test_fixture_profit_never_becomes_deployment_profit(self):
        result = classify_proof("fixture", "real_funded", "profitable")
        self.assertEqual(result["status"], "SIMULATED_BREAK")
        self.assertEqual(result["status_axes"]["target_authenticity"], "fixture")

    def test_forked_deployment_needs_independent_authenticity_verification(self):
        unverified = classify_proof("forked_deployment", "real_funded", "profitable")
        verified = classify_proof("forked_deployment", "real_funded", "profitable",
                                   authenticity_verified=True)
        self.assertEqual(unverified["status"], "OBSERVED")
        self.assertEqual(verified["status"], "PROFITABLE")

    def test_simulated_caller_caps_fork_result(self):
        result = classify_proof("forked_deployment", "simulated_caller", "profitable",
                                authenticity_verified=True)
        self.assertEqual(result["status"], "FORK_OBSERVED")

    def test_human_confirmation_is_never_inferred(self):
        self.assertEqual(classify_proof("forked_deployment", "real_funded", "profitable",
                                        authenticity_verified=True)["status"], "PROFITABLE")
        self.assertEqual(classify_proof("forked_deployment", "real_funded", "profitable",
                                        authenticity_verified=True, human_confirmed=True)["status"],
                         "HUMAN_CONFIRMED")

    def test_non_economic_requires_semantic_invariant_and_caps_status(self):
        denied = evaluate_economic_policy("dos", -100, semantic_invariant_verified=False)
        accepted = evaluate_economic_policy("dos", -100, semantic_invariant_verified=True)
        self.assertFalse(denied["accepted"])
        self.assertTrue(accepted["accepted"])
        self.assertEqual(accepted["promotion_cap"], "SIMULATED_BREAK")
        self.assertFalse(accepted["economic"])

    def test_economic_family_still_requires_positive_net_profit(self):
        self.assertFalse(evaluate_economic_policy("reentrancy", 0)["accepted"])
        self.assertTrue(evaluate_economic_policy("reentrancy", 1)["accepted"])

    def test_freeze_binds_manifest_and_referenced_command_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "attack.py").write_text("print('attack')", encoding="utf-8")
            (root / "control.json").write_text("{}", encoding="utf-8")
            spec = {
                "same_calls_id": "withdraw-v1", "family": "reentrancy",
                "target_address": "0x" + "1" * 40,
                "trace_expectations": [{"address": "0x" + "1" * 40,
                    "control_min_calls": 1, "control_max_calls": 1,
                    "attack_min_calls": 2, "attack_max_calls": 2}],
                "control": {"argv": ["python", "attack.py"]},
                "attack": {"argv": ["python", "attack.py"]},
            }
            freeze_control_manifest(root, root / "control.json", spec)
            check = validate_control_freeze(root, root / "control.json", spec, required=True)
            self.assertTrue(check["verified"])
            (root / "attack.py").write_text("print('changed')", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Frozen expectations"):
                validate_control_freeze(root, root / "control.json", spec, required=True)


if __name__ == "__main__":
    unittest.main()
