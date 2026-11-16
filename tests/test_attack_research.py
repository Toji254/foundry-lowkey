import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lowkey import attack_research


SOURCE = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Vault {
    uint256 public credit;
    function withdraw() external {
        credit = 0;
    }
}
"""


def valid_candidate(source_hash):
    return {
        "family": "accounting",
        "title": "Withdrawal clears credit before entitlement is transferred",
        "hypothesis": "Check whether a state transition can reduce recorded credit without a corresponding asset movement.",
        "security_property": "credit-conservation",
        "source_refs": [{
            "path": "src/Vault.sol",
            "line_start": 5,
            "line_end": 5,
            "source_sha256": source_hash,
            "quote": "    function withdraw() external {",
        }],
        "preconditions": ["A funded credit exists."],
        "attack_steps": ["Create a credit.", "Invoke the withdrawal path under the suspected condition."],
        "control_steps": ["Repeat with the documented valid withdrawal conditions."],
        "test_plan": ["Compare user credit and asset balances before and after the action."],
        "mutation_ideas": ["Restore the expected accounting update and require the hypothesis to disappear."],
        "model_confidence": 0.7,
    }


class AttackResearchTests(unittest.TestCase):
    def test_research_saves_only_source_cited_candidates_and_never_executes(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = root / "src" / "Vault.sol"
            source.parent.mkdir()
            source.write_text(SOURCE, encoding="utf-8")
            digest = attack_research._sha256(SOURCE.encode("utf-8"))
            response = {"candidates": [valid_candidate(digest)]}
            fake_config = {"provider": "test-provider", "model": "test-model"}
            with (
                patch("lowkey.ai_harness.load_config", return_value=fake_config),
                patch("lowkey.ai_harness.request_structured", return_value=response) as request,
                patch.object(attack_research, "_graph_context", return_value={
                    "compiler_ast_status": "AST_UNAVAILABLE",
                    "runtime_call_graph_status": "RUNTIME_TRACE_UNAVAILABLE",
                }),
                patch.object(attack_research, "_git_revision", return_value="a" * 40),
            ):
                report = attack_research.research_attack_hypotheses(root)
            self.assertEqual(request.call_args.kwargs["purpose"], "invariant_hypotheses")
            self.assertEqual(report["status"], "CANDIDATES_ONLY")
            self.assertEqual(report["candidate_count"], 1)
            candidate = report["candidates"][0]
            self.assertEqual(candidate["source_refs"][0]["source_sha256"], digest)
            self.assertFalse(candidate["execution_authorized"])
            self.assertFalse(candidate["vulnerability_confirmed"])
            self.assertFalse(report["execution_performed"])
            self.assertFalse(report["transactions_signed_or_sent"])
            stored = json.loads((root / report["report_path"]).read_text(encoding="utf-8"))
            self.assertEqual(stored["candidate_count"], 1)
            self.assertEqual(stored["source_revision"], "a" * 40)

    def test_selected_contract_and_function_are_prioritized_in_bounded_context(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            (root / "src").mkdir()
            (root / "src/AFirst.sol").write_text(
                "pragma solidity ^0.8.20; contract AFirst { function alpha() external {} }",
                encoding="utf-8",
            )
            (root / "src/ZTarget.sol").write_text(
                "pragma solidity ^0.8.20; contract ZTarget { function withdraw() external {} }",
                encoding="utf-8",
            )
            selected = attack_research._collect_sources(
                root, contract_name="ZTarget", function_name="withdraw"
            )
            self.assertEqual(selected[0]["path"], "src/ZTarget.sol")

    def test_research_rejects_hallucinated_source_quotes(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = root / "src" / "Vault.sol"
            source.parent.mkdir()
            source.write_text(SOURCE, encoding="utf-8")
            digest = attack_research._sha256(SOURCE.encode("utf-8"))
            candidate = valid_candidate(digest)
            candidate["source_refs"][0]["quote"] = "function secretWithdrawAll() external"
            with (
                patch("lowkey.ai_harness.load_config", return_value={"provider": "test", "model": "test"}),
                patch("lowkey.ai_harness.request_structured", return_value={"candidates": [candidate]}),
                patch.object(attack_research, "_graph_context", return_value={}),
                patch.object(attack_research, "_git_revision", return_value=None),
            ):
                report = attack_research.research_attack_hypotheses(root)
            self.assertEqual(report["candidate_count"], 0)
            self.assertEqual(len(report["rejected_candidates"]), 1)
            self.assertIn("quote does not appear", report["rejected_candidates"][0]["reason"])

    def test_research_rejects_source_hash_mismatch(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = root / "src" / "Vault.sol"
            source.parent.mkdir()
            source.write_text(SOURCE, encoding="utf-8")
            candidate = valid_candidate("0" * 64)
            sources = {
                "src/Vault.sol": {
                    "source_sha256": attack_research._sha256(SOURCE.encode("utf-8")),
                    "_source": SOURCE,
                }
            }
            with self.assertRaisesRegex(attack_research.AttackResearchError, "stale source hash"):
                attack_research._validate_candidate(candidate, sources, 0)

    def test_research_rejects_paths_outside_the_current_source_set(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            source = root / "src" / "Vault.sol"
            source.parent.mkdir()
            source.write_text(SOURCE, encoding="utf-8")
            digest = attack_research._sha256(SOURCE.encode("utf-8"))
            candidate = valid_candidate(digest)
            candidate["source_refs"][0]["path"] = "../../README.md"
            sources = attack_research._collect_sources(root)
            mapping = {item["path"]: item for item in sources}
            with self.assertRaisesRegex(attack_research.AttackResearchError, "not provided"):
                attack_research._validate_candidate(candidate, mapping, 0)


if __name__ == "__main__":
    unittest.main()
