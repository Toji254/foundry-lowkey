import json
import pathlib
import tempfile
import unittest

from lowkey.proof_evidence import (
    classify_proof, evaluate_economic_policy, freeze_control_manifest,
    validate_control_freeze, validate_frozen_control, trace_evidence_capabilities,
    evaluate_evidence_requirements,
)


class ProofEvidenceTests(unittest.TestCase):
    def test_fixture_profit_never_becomes_deployment_profit(self):
        result = classify_proof("fixture", "real_funded", "profitable")
        self.assertEqual(result["status"], "LOCAL_PROFITABLE")
        self.assertEqual(result["status_axes"]["target_authenticity"], "fixture")
        simulated = classify_proof("fixture", "synthetic_state", "profitable")
        self.assertEqual(simulated["status"], "SIMULATED_BREAK")

    def test_forked_deployment_needs_independent_authenticity_verification(self):
        unverified = classify_proof("forked_deployment", "real_funded", "profitable")
        verified = classify_proof("forked_deployment", "real_funded", "profitable",
                                   authenticity_verified=True)
        self.assertEqual(unverified["status"], "OBSERVED")
        self.assertEqual(verified["status"], "FORK_PROFITABLE")

    def test_simulated_caller_caps_fork_result(self):
        result = classify_proof("forked_deployment", "simulated_caller", "profitable",
                                authenticity_verified=True)
        self.assertEqual(result["status"], "FORK_OBSERVED")

    def test_assumed_fuzz_inputs_are_not_real_funded_profit(self):
        result = classify_proof(
            "forked_deployment", "constrained_inputs", "profitable",
            authenticity_verified=True,
        )
        self.assertEqual(result["status"], "FORK_OBSERVED")

    def test_human_confirmation_is_never_inferred(self):
        self.assertEqual(classify_proof("forked_deployment", "real_funded", "profitable",
                                        authenticity_verified=True)["status"], "PROFITABLE")
        self.assertEqual(classify_proof("forked_deployment", "real_funded", "profitable",
                                        authenticity_verified=True, human_confirmed=True)["status"],
                         "HUMAN_CONFIRMED")
        self.assertEqual(classify_proof("fixture", "real_funded", "profitable",
                                        human_confirmed=True)["status"], "LOCAL_PROFITABLE")

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

    def test_replay_signature_and_access_control_remain_economic_by_default(self):
        for family in ("replay", "signature_replay", "access_control", "authorization_bypass"):
            with self.subTest(family=family):
                result = evaluate_economic_policy(family, -1)
                self.assertTrue(result["economic"])
                self.assertFalse(result["accepted"])
                self.assertEqual(result["promotion_cap"], "OBSERVED")

    def test_only_availability_families_default_to_non_economic(self):
        for family in ("dos", "denial_of_service", "griefing", "liveness"):
            with self.subTest(family=family):
                denied = evaluate_economic_policy(family, -1, semantic_invariant_verified=False)
                accepted = evaluate_economic_policy(family, -1, semantic_invariant_verified=True)
                self.assertFalse(denied["accepted"])
                self.assertTrue(accepted["accepted"])
                self.assertEqual(accepted["promotion_cap"], "SIMULATED_BREAK")

    def test_freeze_binds_declared_generator_hash(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "generator.py").write_text("print('v1')", encoding="utf-8")
            (root / "control.json").write_text("{}", encoding="utf-8")
            spec = {"family": "reentrancy", "generator_files": ["generator.py"]}
            frozen, _ = freeze_control_manifest(root, root / "control.json", spec)
            self.assertEqual(frozen["schema_version"], 2)
            self.assertTrue(frozen["generator_hashes"])
            default_paths = {item["path"] for item in frozen["generator_hashes"]}
            self.assertTrue(
                any(path.endswith("/generator.py") for path in default_paths),
                default_paths,
            )
            self.assertTrue(
                any(path.endswith("/break_engine.py") for path in default_paths),
                default_paths,
            )
            self.assertTrue(validate_control_freeze(
                root, root / "control.json", spec, required=True
            )["verified"])
            (root / "generator.py").write_text("print('v2')", encoding="utf-8")
            status = validate_control_freeze(root, root / "control.json", spec, required=True)
            self.assertFalse(status["verified"])
            self.assertTrue(status["requires_refreeze"])
            self.assertEqual(status["reason_code"], "generator_drift")
            self.assertIn("generator.py", status["changed_generators"])

    def test_freeze_does_not_bind_generated_state_diff_output_bytes(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "control.json").write_text("{}", encoding="utf-8")
            control_artifact = ".audit/godmode/control-state-diff.json"
            attack_artifact = ".audit/godmode/attack-state-diff.json"
            spec = {
                "family": "reentrancy",
                "control": {"harness": "test/Control.t.sol", "state_diff_file": control_artifact},
                "attack": {"harness": "test/Attack.t.sol", "state_diff_file": attack_artifact},
            }
            (root / "test").mkdir()
            (root / "test/Control.t.sol").write_text("contract Control {}", encoding="utf-8")
            (root / "test/Attack.t.sol").write_text("contract Attack {}", encoding="utf-8")
            freeze_control_manifest(root, root / "control.json", spec)
            (root / control_artifact).parent.mkdir(parents=True, exist_ok=True)
            (root / control_artifact).write_text('{"run":1}', encoding="utf-8")
            (root / attack_artifact).write_text('{"run":1}', encoding="utf-8")
            self.assertTrue(validate_control_freeze(
                root, root / "control.json", spec, required=True
            )["verified"])

    def test_freeze_rejects_tampered_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "control.json").write_text("{}", encoding="utf-8")
            _, freeze_path = freeze_control_manifest(
                root, root / "control.json", {"family": "reentrancy"}
            )
            frozen = json.loads(freeze_path.read_text(encoding="utf-8"))
            frozen["freeze_sha256"] = "0" * 64
            freeze_path.write_text(json.dumps(frozen), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "Frozen expectations"):
                validate_control_freeze(
                    root, root / "control.json", {"family": "reentrancy"}, required=True
                )

    def test_freeze_rejects_legacy_schema_one(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            manifest_path = root / "control.json"
            manifest_path.write_text("{}", encoding="utf-8")
            _, freeze_path = freeze_control_manifest(
                root, manifest_path, {"family": "reentrancy"}
            )
            frozen = json.loads(freeze_path.read_text(encoding="utf-8"))
            frozen["schema_version"] = 1
            freeze_path.write_text(json.dumps(frozen), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "older schema"):
                validate_control_freeze(root, manifest_path, {"family": "reentrancy"}, required=True)


    def test_validate_only_reads_frozen_manifest_and_rejects_tampered_digest(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            manifest = root / "control.json"
            manifest.write_text("{}", encoding="utf-8")
            _, freeze_path = freeze_control_manifest(root, manifest, {"family": "reentrancy"})
            valid = validate_frozen_control(root)
            self.assertTrue(valid["verified"], valid)
            self.assertEqual(valid["status"], "PROPOSED")
            self.assertFalse(valid["execution_attempted"])
            frozen = json.loads(freeze_path.read_text(encoding="utf-8"))
            frozen["freeze_sha256"] = "0" * 64
            freeze_path.write_text(json.dumps(frozen), encoding="utf-8")
            tampered = validate_frozen_control(root)
            self.assertFalse(tampered["verified"])
            self.assertEqual(tampered["status"], "REJECTED")
            self.assertEqual(tampered["reason_code"], "digest_mismatch")
            self.assertFalse(tampered["execution_attempted"])

    def test_fixture_without_real_funded_execution_cannot_be_local_profitable(self):
        for fidelity in ("synthetic_state", "simulated_caller", "simulated_dependencies"):
            with self.subTest(fidelity=fidelity):
                result = classify_proof("fixture", fidelity, "profitable")
                self.assertEqual(result["status"], "SIMULATED_BREAK")

    def test_trace_capabilities_preserve_anvil_dimensions_and_forge_storage_strength(self):
        anvil_without_tracer = trace_evidence_capabilities(
            "anvil-calltracer", storage_trace_supported=False
        )
        anvil_with_tracer = trace_evidence_capabilities(
            "anvil-calltracer", storage_trace_supported=True, storage_observations=1
        )
        forge = trace_evidence_capabilities(
            "forge-state-diff", storage_observations=1
        )

        self.assertEqual(anvil_without_tracer["call_tree"], "exact")
        self.assertEqual(anvil_without_tracer["calldata"], "exact")
        self.assertEqual(anvil_without_tracer["storage"], "declared_only")
        self.assertEqual(anvil_with_tracer["storage"], "partial")
        self.assertEqual(forge["storage"], "derived_per_access")
        self.assertTrue(evaluate_evidence_requirements(
            "reentrancy", anvil_with_tracer
        )["accepted"])
        self.assertFalse(evaluate_evidence_requirements(
            "reentrancy", anvil_without_tracer
        )["accepted"])
        self.assertFalse(evaluate_evidence_requirements(
            "storage_corruption", anvil_with_tracer,
            {"storage": "per_access"}
        )["accepted"])
        self.assertTrue(evaluate_evidence_requirements(
            "storage_corruption", anvil_with_tracer,
            {"storage": "declared_only"}, require_trace_storage=True
        )["accepted"])
        no_observation = trace_evidence_capabilities(
            "anvil-calltracer", storage_trace_supported=True, storage_observations=0
        )
        self.assertFalse(evaluate_evidence_requirements(
            "reentrancy", no_observation
        )["accepted"])
        self.assertTrue(evaluate_evidence_requirements(
            "storage_corruption", forge, {"storage": "per_access"}
        )["accepted"])

    def test_generator_drift_warns_and_requires_refreeze_without_rejecting_experiment(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "control.json").write_text("{}", encoding="utf-8")
            (root / "generator.py").write_text("print('generator v1')", encoding="utf-8")
            (root / "test").mkdir()
            harness = root / "test/Attack.t.sol"
            harness.write_text("contract Attack {}", encoding="utf-8")
            spec = {
                "family": "reentrancy",
                "generator_files": ["generator.py"],
                "control": {"harness": "test/Attack.t.sol", "argv": ["forge", "test"]},
                "attack": {"harness": "test/Attack.t.sol", "argv": ["forge", "test"]},
            }
            frozen, _ = freeze_control_manifest(root, root / "control.json", spec)
            original_inputs = frozen["inputs"]
            original_harness = next(
                item["sha256"] for item in original_inputs
                if item["path"] == "test/Attack.t.sol"
            )
            (root / "generator.py").write_text("print('generator v2')", encoding="utf-8")
            status = validate_control_freeze(
                root, root / "control.json", spec, required=True
            )
            self.assertFalse(status["verified"])
            self.assertTrue(status["requires_refreeze"])
            self.assertEqual(status["reason_code"], "generator_drift")
            self.assertIn("generator.py", status["changed_generators"])
            self.assertEqual(status["manifest_sha256"], frozen["manifest_sha256"])
            self.assertEqual(status["inputs"], original_inputs)
            self.assertEqual(
                next(item["sha256"] for item in status["inputs"]
                     if item["path"] == "test/Attack.t.sol"),
                original_harness,
            )
            self.assertNotIn("rejected", status["reason"].lower())

        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "control.json").write_text("{}", encoding="utf-8")
            freeze_path = root / ".audit/godmode/control.freeze.json"
            freeze_path.parent.mkdir(parents=True)
            freeze_path.write_text(json.dumps({"schema_version": 1}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "older schema"):
                validate_control_freeze(root, root / "control.json", {}, required=True)

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
