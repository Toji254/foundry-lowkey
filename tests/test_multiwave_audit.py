import tempfile
import unittest
from pathlib import Path

from lowkey import multiwave_audit as audit


VAULT = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Vault {
    address public owner;
    mapping(address => uint256) public balances;

    constructor() { owner = msg.sender; }

    function withdraw(uint256 amount) external {
        require(msg.sender == owner, "owner");
        require(balances[msg.sender] >= amount, "balance");
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "transfer");
        balances[msg.sender] -= amount;
    }

    function previewWithdraw(uint256 amount) external view returns (uint256) {
        return amount;
    }
}
"""

OVERLOADED = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Overloaded {
    function quote(uint256 amount) external pure returns (uint256) {
        return amount;
    }

    function quote(address account) external pure returns (address) {
        return account;
    }
}
"""

TOKEN = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract Token {
    mapping(address => uint256) public balanceOf;

    function transfer(address to, uint256 amount) external returns (bool) {
        require(balanceOf[msg.sender] >= amount, "balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        return true;
    }
}
"""


class MultiWaveAuditTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        (self.root / "src").mkdir()
        (self.root / "src" / "Vault.sol").write_text(VAULT, encoding="utf-8")
        (self.root / "src" / "Token.sol").write_text(TOKEN, encoding="utf-8")
        (self.root / "src" / "Overloaded.sol").write_text(OVERLOADED, encoding="utf-8")

    def context(self):
        return {
            "project_label": "multiwave-fixture",
            "source_files": [
                {"path": "src/Vault.sol", "source_excerpt": VAULT},
                {"path": "src/Token.sol", "source_excerpt": TOKEN},
                {"path": "src/Overloaded.sol", "source_excerpt": OVERLOADED},
            ],
        }

    def ai_status(self):
        return {
            "usable": True,
            "provider": "openai-compatible",
            "model": "fixture-model",
            "jev_free_tier_mode": False,
        }

    def test_coverage_ledger_is_deterministic_and_evm_specific(self):
        first = audit.build_coverage_ledger(self.context(), self.root, "standard")
        second = audit.build_coverage_ledger(self.context(), self.root, "standard")
        self.assertEqual(
            [row["coverage_id"] for row in first],
            [row["coverage_id"] for row in second],
        )
        families = {row["family"] for row in first}
        self.assertIn("access-control", families)
        self.assertIn("reentrancy", families)
        self.assertIn("accounting", families)
        self.assertIn("business-logic", families)
        self.assertTrue(all(row["coverage_id"].startswith("CU-") for row in first))

    def test_overloaded_public_functions_get_distinct_coverage_units(self):
        units = audit.build_coverage_ledger(self.context(), self.root, "standard")
        quote_units = [
            row for row in units
            if row["source_path"] == "src/Overloaded.sol" and row["symbol"] == "quote"
        ]
        signatures = {row["signature"] for row in quote_units}
        self.assertEqual(signatures, {"quote(uint256amount)", "quote(addressaccount)"})
        self.assertEqual(len({row["coverage_id"] for row in quote_units}), len(quote_units))

    def test_unchanged_reviewed_units_can_be_carried_but_changed_source_cannot(self):
        first = audit.build_coverage_ledger(self.context(), self.root, "standard")
        prior = {
            row["coverage_id"]: {
                "source_sha256": row["source_sha256"],
                "status": "reviewed",
                "run_id": "run-prior",
                "checks": [{"agent_id": "prior-hunter", "status": "reviewed"}],
                "reviewed_paths": [row["source_path"]],
            }
            for row in first
        }
        carried = audit.build_coverage_ledger(self.context(), self.root, "standard", prior)
        self.assertTrue(all(row["carried_forward"] for row in carried if row["family"] != "business-logic"))
        self.assertTrue(all(not row["carried_forward"] for row in carried if row["family"] == "business-logic"))
        self.assertTrue(all(row["status"] == "reviewed" for row in carried if row["family"] != "business-logic"))
        self.assertTrue(all(row["status"] == "planned" for row in carried if row["family"] == "business-logic"))

        changed = self.root / "src" / "Vault.sol"
        changed.write_text(VAULT + "\n// changed\n", encoding="utf-8")
        refreshed = audit.build_coverage_ledger(self.context(), self.root, "standard", prior)
        changed_rows = [row for row in refreshed if row["source_path"] == "src/Vault.sol"]
        token_rows = [row for row in refreshed if row["source_path"] == "src/Token.sol"]
        self.assertTrue(all(not row["carried_forward"] for row in changed_rows))
        self.assertTrue(all(row["carried_forward"] for row in token_rows if row["family"] != "business-logic"))
        self.assertTrue(all(not row["carried_forward"] for row in token_rows if row["family"] == "business-logic"))

    def test_critic_only_adds_real_source_backed_units(self):
        sources = {
            "src/Vault.sol": {
                "path": "src/Vault.sol",
                "source_text": VAULT,
                "source_excerpt": VAULT,
                "source_sha256": "a" * 64,
            }
        }
        result = {
            "clean": False,
            "gaps": ["withdraw lifecycle is not covered by a dedicated governance pass"],
            "new_coverage": [
                {
                    "source_path": "src/Vault.sol",
                    "symbol": "withdraw",
                    "family": "governance",
                    "reason": "Challenge the privileged withdrawal lifecycle.",
                    "evidence_quote": 'require(msg.sender == owner, "owner");',
                },
                {
                    "source_path": "src/NotARealFile.sol",
                    "symbol": "withdraw",
                    "family": "governance",
                    "reason": "Invented path must be ignored.",
                    "evidence_quote": 'require(msg.sender == owner, "owner");',
                },
                {
                    "source_path": "src/Vault.sol",
                    "symbol": "missingFunction",
                    "family": "governance",
                    "reason": "Invented symbol must be ignored.",
                    "evidence_quote": 'require(msg.sender == owner, "owner");',
                },
            ],
        }
        additions, gaps, clean = audit._accept_critic(result, sources, set(), 100)
        self.assertEqual(len(additions), 1)
        self.assertEqual(additions[0]["family"], "governance")
        self.assertEqual(gaps, result["gaps"])
        self.assertFalse(clean)

    def test_quick_run_uses_distinct_hunters_critic_and_fresh_verifier(self):
        calls = []

        def fake_request(*, purpose, task, context, required_fields):
            assignment = context.get("assignment", {})
            calls.append((task, assignment))
            if "Perform Solidity/EVM protocol reconnaissance" in task:
                return {
                    "summary": "Vault and token fixture reconnaissance.",
                    "contract_roles": [],
                    "invariants": [],
                    "open_questions": [],
                    "deployment_considerations": [],
                }
            if "independent Solidity/EVM vulnerability hunter" in task:
                agent_id = assignment["agent_id"]
                units = assignment["assigned_units"]
                checks = [
                    {
                        "coverage_id": row["coverage_id"],
                        "status": "reviewed",
                        "reviewed_paths": [row["source_path"]],
                        "note": "Inspected the assigned source function and attack family.",
                    }
                    for row in units
                ]
                candidates = []
                if any(
                    row["source_path"] == "src/Vault.sol" and row["family"] == "access-control"
                    for row in units
                ):
                    candidates.append({
                        "title": "Owner guard may restrict the wrong withdrawal principal",
                        "category": "access-control",
                        "severity": "medium",
                        "location": {"path": "src/Vault.sol", "symbol": "withdraw"},
                        "evidence_quote": 'require(msg.sender == owner, "owner");',
                        "reasoning": "The source requires owner identity at a user withdrawal entrypoint.",
                        "impact": "A reachable authorization mismatch could block intended users.",
                        "exploit_preconditions": "Depends on the intended withdrawal policy.",
                        "recommendation": "Confirm the intended principal and enforce the matching role.",
                        "confidence": "medium",
                    })
                return {
                    "agent_id": agent_id,
                    "assignment_summary": "Independent EVM hunting pass.",
                    "checks": checks,
                    "candidate_findings": candidates,
                    "uncovered_units": [],
                }
            if "fresh independent Solidity/EVM coverage critic" in task:
                return {"clean": True, "gaps": [], "new_coverage": []}
            if "independent source-level candidate verifier" in task:
                return {
                    "decision": "survives_challenge",
                    "reason": "The source-level hypothesis was not refuted, but intended policy and exploitability remain unproven.",
                    "contrary_evidence": "",
                    "next_native_check": "Write a Foundry test that checks the intended owner and user withdrawal paths.",
                }
            raise AssertionError("Unexpected agent task: " + task[:120])

        result = audit.run_multiwave_audit(
            self.root,
            profile="quick",
            max_agent_calls=8,
            request_fn=fake_request,
            status_fn=self.ai_status,
            context_factory=lambda _root: self.context(),
        )
        self.assertEqual(result["status"], "coverage_complete", result)
        self.assertEqual(result["waves_completed"], 1)
        self.assertGreaterEqual(result["candidate_findings"], 1)
        self.assertEqual(result["unverified_candidates"], 0)
        findings_path = self.root / result["findings"]
        findings = __import__("json").loads(findings_path.read_text(encoding="utf-8"))
        candidate = findings[0]
        self.assertEqual(candidate["review_state"], "survived_independent_review_candidate_only")
        self.assertEqual(candidate["proof_status"], "not_run")
        self.assertIsNone(candidate["human_disposition"])
        roles = [record["role"] for record in __import__("json").loads(
            (self.root / ".audit/godmode/multiwave" / ("run-" + result["run_id"]) / "agents.json").read_text()
        )]
        self.assertIn("reconnaissance", roles)
        self.assertIn("hunter", roles)
        self.assertIn("final_clean_critic", roles)
        self.assertIn("candidate_verifier", roles)
        self.assertGreaterEqual(len({item[1]["agent_id"] for item in calls if item[1].get("agent_id")}), 2)

    def test_critic_discovery_launches_an_additional_hunting_wave(self):
        hunter_waves = []
        critic_rounds = []

        def fake_request(*, purpose, task, context, required_fields):
            assignment = context.get("assignment", {})
            if "Perform Solidity/EVM protocol reconnaissance" in task:
                return {
                    "summary": "Reconnaissance complete.",
                    "contract_roles": [],
                    "invariants": [],
                    "open_questions": [],
                    "deployment_considerations": [],
                }
            if "independent Solidity/EVM vulnerability hunter" in task:
                hunter_waves.append(assignment["wave"])
                return {
                    "agent_id": assignment["agent_id"],
                    "assignment_summary": "Coverage reviewed.",
                    "checks": [
                        {"coverage_id": row["coverage_id"], "status": "reviewed",
                         "reviewed_paths": [row["source_path"]], "note": "Inspected."}
                        for row in assignment["assigned_units"]
                    ],
                    "candidate_findings": [],
                    "uncovered_units": [],
                }
            if "fresh independent Solidity/EVM coverage critic" in task:
                stage = assignment.get("stage")
                wave = assignment.get("wave")
                critic_rounds.append((stage, wave))
                if stage == "coverage_critic" and wave == 1:
                    return {
                        "clean": False,
                        "gaps": ["The withdrawal lifecycle needs a dedicated governance-oriented challenge."],
                        "new_coverage": [{
                            "source_path": "src/Vault.sol",
                            "symbol": "withdraw",
                            "family": "governance",
                            "reason": "Independent critic found an unassigned lifecycle angle.",
                            "evidence_quote": 'require(msg.sender == owner, "owner");',
                        }],
                    }
                return {"clean": True, "gaps": [], "new_coverage": []}
            raise AssertionError("Unexpected task: " + task[:120])

        result = audit.run_multiwave_audit(
            self.root, profile="standard", max_agent_calls=16,
            request_fn=fake_request, status_fn=self.ai_status,
            context_factory=lambda _root: self.context(),
        )
        self.assertEqual(result["status"], "coverage_complete", result)
        self.assertEqual(result["waves_completed"], 2)
        self.assertIn(2, hunter_waves)
        self.assertIn(("final_clean_review", None), critic_rounds)


    def test_unredacted_caller_excerpt_is_ignored(self):
        source_path = self.root / "src" / "Vault.sol"
        supplied_secret = "DO_NOT_SEND_THIS_UNREDACTED_EXCERPT"
        with patch(
            "lowkey.ai_harness._redact_sensitive_source",
            return_value="redacted source only",
        ):
            record = audit._safe_source(
                self.root,
                {"path": "src/Vault.sol", "source_excerpt": supplied_secret},
            )
        self.assertIsNotNone(record)
        self.assertEqual(record["source_text"], "redacted source only")
        self.assertEqual(record["source_excerpt"], "redacted source only")
        self.assertNotIn(supplied_secret, record["source_excerpt"])

    def test_prior_run_symlink_artifacts_are_ignored(self):
        with tempfile.TemporaryDirectory() as external_dir:
            external = Path(external_dir)
            ledger_source = external / "coverage-ledger.json"
            findings_source = external / "findings.json"
            ledger_source.write_text(
                __import__("json").dumps([{
                    "coverage_id": "outside",
                    "source_path": "src/Vault.sol",
                    "status": "reviewed",
                }]),
                encoding="utf-8",
            )
            findings_source.write_text(
                __import__("json").dumps([{"finding_id": "outside"}]),
                encoding="utf-8",
            )
            run_dir = self.root / ".audit" / "godmode" / "multiwave" / "run-symlink"
            run_dir.mkdir(parents=True)
            (run_dir / "coverage-ledger.json").symlink_to(ledger_source)
            (run_dir / "findings.json").symlink_to(findings_source)
            units, findings = audit._read_prior(self.root)
        self.assertEqual(units, {})
        self.assertEqual(findings, [])


if __name__ == "__main__":
    unittest.main()
