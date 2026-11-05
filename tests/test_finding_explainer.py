from __future__ import annotations

import pathlib
import tempfile
import unittest
from unittest.mock import patch
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lowkey"))

import audit_context
import ai_harness
import finding_explainer


class FindingExplainerTests(unittest.TestCase):
    def write(self, root, relative, text):
        path = root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def fixture(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = pathlib.Path(temp.name)
        self.write(root, "foundry.toml", '[profile.default]\nsrc = "src"\ntest = "test"\n')
        self.write(
            root,
            "src/Vault.sol",
            """
            pragma solidity ^0.8.20;
            contract Vault {
                address public owner;
                function withdraw(address payable recipient) external {
                    require(msg.sender == owner);
                    (bool ok,) = recipient.call{value: 1}("");
                    require(ok);
                }
            }
            """,
        )
        self.write(
            root,
            "test/Vault.t.sol",
            """
            contract VaultTest {
                function testWithdrawOnlyOwner() external {
                    vm.prank(attacker);
                    vm.expectRevert();
                    vault.withdraw(payable(attacker));
                }
            }
            """,
        )
        signal = audit_context.add_signal({
            "id": "SIG-AUTH-VAULT-01",
            "tool": "slither",
            "check": "missing-access-control",
            "title": "Potential missing authorization",
            "description": "A sensitive withdrawal function may lack access control.",
            "file": "src/Vault.sol",
            "line": 5,
            "function": "withdraw(address)",
            "contract": "Vault",
            "severity": "high",
            "confidence": "medium",
            "observation": "The detector did not see a direct modifier.",
        }, root)
        return root, signal

    def test_preview_is_local_bounded_and_does_not_call_provider(self):
        root, signal = self.fixture()
        with patch.object(ai_harness, "request_structured", side_effect=AssertionError("provider must not be called")):
            preview = finding_explainer.explain_finding(root, signal["id"], preview=True, show_context=True)
        self.assertIn("Provider call: NO", preview)
        self.assertIn("src/Vault.sol", preview)
        self.assertIn("test/Vault.t.sol", preview)
        self.assertIn("require(msg.sender == owner)", preview)
        self.assertIn("No tests", preview) is False
        self.assertFalse((root / ".audit" / "ai-review").exists())

    def test_context_contains_whole_function_related_tests_and_local_commit_metadata(self):
        root, signal = self.fixture()
        context, source_records, test_records = finding_explainer._source_records(root, signal)
        self.assertEqual(context["affected_function"]["symbol"], "withdraw")
        self.assertTrue(any("recipient.call" in item["source_excerpt"] for item in source_records))
        self.assertTrue(any(item["path"] == "test/Vault.t.sol" for item in test_records))
        self.assertLessEqual(context["context_bytes"], finding_explainer.MAX_CONTEXT_BYTES)
        self.assertIn("local checkout", context["project"]["source_of_truth"])
        self.assertIn("untrusted", context["trust_boundary"])

    def test_explanation_validation_marks_exact_quotes_and_never_verifies(self):
        root, signal = self.fixture()
        context, _sources, _tests = finding_explainer._source_records(root, signal)
        report = finding_explainer.validate_explanation({
            "classification": "potential-vulnerability",
            "plain_english": "The function transfers value.",
            "detector_assumption": "The detector expected a direct modifier.",
            "contrary_source_evidence": [{
                "path": "src/Vault.sol",
                "symbol": "withdraw",
                "quote": "require(msg.sender == owner);",
                "why_it_matters": "This is a direct caller check.",
            }],
            "references": [{
                "path": "src/Vault.sol",
                "symbol": "withdraw",
                "quote": "require(msg.sender == owner);",
                "role": "production source",
            }],
            "reachability": {"attacker_entry_point": "withdraw", "caller_policy": "owner only"},
            "exploit_preconditions": [],
            "attack_sequence": [],
            "impact_hypothesis": "No exploit is established.",
            "existing_test_coverage": [{
                "path": "test/Vault.t.sol",
                "test_name": "testWithdrawOnlyOwner",
                "assertions": ["expectRevert"],
                "what_it_covers": "Rejects an unprivileged caller.",
            }],
            "test_proposal": {"path": "test/Vault.t.sol", "test_name": "testWithdrawOnlyOwner"},
        }, context)
        self.assertEqual(report["classification"], "potential-vulnerability")
        self.assertEqual(report["references"][0]["quote_status"], "matched")
        self.assertEqual(report["contrary_source_evidence"][0]["quote_status"], "matched")
        self.assertEqual(report["existing_test_coverage"][0]["path_status"], "included")
        self.assertFalse(report["verified"])
        self.assertFalse(report["human_disposition_changed"])

    def test_signal_path_traversal_is_rejected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            self.write(root, "foundry.toml", '[profile.default]\nsrc = "src"\n')
            self.write(root, "src/Vault.sol", "contract Vault { function withdraw() external {} }")
            signal = audit_context.add_signal({
                "id": "SIG-OUTSIDE",
                "tool": "slither",
                "file": "../../.env",
                "line": 1,
                "function": "withdraw()",
            }, root)
            with self.assertRaises(ValueError):
                finding_explainer._source_records(root, signal)


if __name__ == "__main__":
    unittest.main()
