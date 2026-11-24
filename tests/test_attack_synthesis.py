import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lowkey import attack_synthesis


SOURCE = """pragma solidity ^0.8.20;
contract Vault {
    uint256 public total;
    function deposit(uint256 amount) external {
        total = amount;
    }
    function withdraw(uint256 amount) external {
        total = total - amount;
    }
}
"""


def _span(source, fragment):
    start = source.index(fragment)
    end = source.index("\n    }", start) + len("\n    }")
    return f"{len(source[:start].encode('utf-8'))}:{len(source[start:end].encode('utf-8'))}:0"


def _candidate(candidate_id, line, quote, source_hash, title):
    return {
        "candidate_id": candidate_id,
        "status": "CANDIDATE_ONLY",
        "family": "accounting",
        "title": title,
        "hypothesis": "A state transition may break an asset/accounting conservation property.",
        "security_property": "vault-accounting-conservation",
        "source_refs": [{
            "path": "src/Vault.sol",
            "line_start": line,
            "line_end": line,
            "source_sha256": source_hash,
            "quote": quote,
        }],
        "preconditions": ["The vault has measurable assets."],
        "attack_steps": ["Invoke the first protocol action.", "Invoke the dependent protocol action."],
        "control_steps": ["Repeat the same action sequence with valid accounting."],
        "test_plan": ["Compare total assets and liabilities at each stage."],
        "mutation_ideas": ["Restore the missing accounting update and require the chain to disappear."],
        "model_confidence_unverified": 0.6,
        "execution_authorized": False,
        "vulnerability_confirmed": False,
    }


def _graph():
    deposit_id = "src/Vault.sol:Vault::deposit(uint256)"
    withdraw_id = "src/Vault.sol:Vault::withdraw(uint256)"
    return {
        "compiler_ast": {
            "status": "AST_OBSERVED",
            "nodes": [
                {"id": deposit_id, "kind": "function", "name": "deposit", "source": "src/Vault.sol",
                 "source_span": _span(SOURCE, "function deposit"), "reads": [], "writes": ["state::total"]},
                {"id": withdraw_id, "kind": "function", "name": "withdraw", "source": "src/Vault.sol",
                 "source_span": _span(SOURCE, "function withdraw"), "reads": ["state::total"], "writes": ["state::total"]},
            ],
            "edges": [{
                "kind": "state_dependency_candidate",
                "source": deposit_id,
                "target": withdraw_id,
                "via": "state::total",
                "evidence": "compiler_ast_state_access",
                "certainty": "candidate_only",
            }],
        },
        "runtime_call_graph": {"status": "RUNTIME_TRACE_UNAVAILABLE", "edges": []},
    }


class AttackSynthesisTests(unittest.TestCase):
    def _fixture(self, root: Path):
        source_path = root / "src" / "Vault.sol"
        source_path.parent.mkdir(parents=True)
        source_path.write_text(SOURCE, encoding="utf-8")
        source_hash = hashlib.sha256(SOURCE.encode("utf-8")).hexdigest()
        candidates = [
            _candidate(
                "a" * 20, 4, "    function deposit(uint256 amount) external {",
                source_hash, "Deposit stage",
            ),
            _candidate(
                "b" * 20, 7, "    function withdraw(uint256 amount) external {",
                source_hash, "Withdraw stage",
            ),
        ]
        report = {
            "schema_version": 1,
            "status": "CANDIDATES_ONLY",
            "source_revision": None,
            "context_sha256": "c" * 64,
            "source_files": [{"path": "src/Vault.sol", "source_sha256": source_hash}],
            "candidates": candidates,
        }
        report_path = root / ".audit" / "lowkey" / "attack-research" / "latest.json"
        report_path.parent.mkdir(parents=True)
        report_path.write_text(json.dumps(report), encoding="utf-8")
        return report_path, report

    def test_synthesizes_only_graph_connected_stages_and_keeps_adapter_gate(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            report_path, _ = self._fixture(root)
            with (
                patch.object(attack_synthesis, "_git_revision", return_value=None),
                patch("lowkey.protocol_graph.build_full_protocol_graph", return_value=_graph()),
            ):
                result = attack_synthesis.synthesize_attack_chains(
                    root,
                    research_report=report_path.relative_to(root).as_posix(),
                )
            self.assertEqual(result["status"], "CANDIDATE_CHAINS_ONLY")
            self.assertEqual(result["chain_count"], 1)
            chain = result["chains"][0]
            self.assertEqual(chain["status"], "BLOCKED_ADAPTER_REQUIRED")
            self.assertEqual(
                [stage["candidate_id"] for stage in chain["stages"]],
                ["a" * 20, "b" * 20],
            )
            self.assertEqual(chain["transitions"][0]["kind"], "state_dependency_candidate")
            self.assertFalse(chain["execution_performed"])
            self.assertFalse(chain["transaction_signed_or_sent"])
            self.assertFalse(chain["vulnerability_confirmed"])
            self.assertTrue(chain["adapter_gaps"])
            saved = json.loads((root / result["report_path"]).read_text(encoding="utf-8"))
            self.assertEqual(saved["chain_count"], 1)

    def test_no_chain_is_generated_without_a_real_compiler_graph_edge(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            report_path, _ = self._fixture(root)
            graph = _graph()
            graph["compiler_ast"]["edges"] = []
            with (
                patch.object(attack_synthesis, "_git_revision", return_value=None),
                patch("lowkey.protocol_graph.build_full_protocol_graph", return_value=graph),
            ):
                result = attack_synthesis.synthesize_attack_chains(
                    root, research_report=report_path.relative_to(root).as_posix()
                )
            self.assertEqual(result["status"], "NO_SUPPORTED_CHAIN")
            self.assertEqual(result["chain_count"], 0)

    def test_synthesis_refuses_stale_source_hashes_and_quotes(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            report_path, report = self._fixture(root)
            source = root / "src" / "Vault.sol"
            source.write_text(SOURCE + "// changed\n", encoding="utf-8")
            with self.assertRaisesRegex(attack_synthesis.AttackSynthesisError, "hash changed"):
                attack_synthesis._validated_candidates(root, report)

    def test_synthesis_requires_compiler_ast_before_mapping_functions(self):
        with tempfile.TemporaryDirectory() as raw:
            root = Path(raw)
            report_path, _ = self._fixture(root)
            with (
                patch.object(attack_synthesis, "_git_revision", return_value=None),
                patch("lowkey.protocol_graph.build_full_protocol_graph", return_value={
                    "compiler_ast": {"status": "AST_UNAVAILABLE", "nodes": [], "edges": []},
                    "runtime_call_graph": {"status": "RUNTIME_TRACE_UNAVAILABLE", "edges": []},
                }),
            ):
                with self.assertRaisesRegex(attack_synthesis.AttackSynthesisError, "Compiler AST is unavailable"):
                    attack_synthesis.synthesize_attack_chains(
                        root, research_report=report_path.relative_to(root).as_posix()
                    )


if __name__ == "__main__":
    unittest.main()
