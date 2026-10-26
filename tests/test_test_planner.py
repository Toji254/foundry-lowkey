import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lowkey import evidence_ledger, test_planner


class TestPlannerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "foundry.toml").write_text(
            '[profile.default]\nsrc = "src"\ntest = "test"\n',
            encoding="utf-8",
        )
        (self.root / "src").mkdir()
        self.source = (
            "pragma solidity ^0.8.20;\n"
            "contract Vault {\n"
            "    mapping(address => uint256) public balances;\n"
            "    function withdraw(uint256 amount) external {\n"
            "        require(amount <= balances[msg.sender], \"too much\");\n"
            "        balances[msg.sender] -= amount;\n"
            "    }\n"
            "}\n"
        )
        (self.root / "src" / "Vault.sol").write_text(self.source, encoding="utf-8")

    def _response(self, quote=None):
        return {
            "summary": "Propose a focused withdrawal regression case.",
            "test_cases": [{
                "title": "Withdrawal cannot exceed caller balance",
                "kind": "regression",
                "priority": "high",
                "suggested_test_name": "testWithdrawRejectsExcessAmount",
                "source": {
                    "path": "src/Vault.sol",
                    "symbol": "Vault.withdraw",
                    "quote": quote if quote is not None else 'require(amount <= balances[msg.sender], "too much");',
                },
                "hypothesis": "A caller cannot withdraw more than its recorded balance.",
                "setup": "Deploy Vault and arrange a recorded balance for the test actor.",
                "steps": ["Call withdraw with an amount greater than the recorded balance."],
                "assertions": ["The call reverts.", "The recorded balance remains unchanged."],
                "vulnerability_signal": "The call succeeds or the balance changes despite a revert.",
                "existing_coverage_note": "Check current test files before adding a duplicate case.",
            }],
            "limitations": ["This is a proposal only; no test was generated or executed."],
        }

    def test_plan_is_source_cited_persisted_and_never_verified(self):
        with patch.object(test_planner.ai_harness, "request_structured", return_value=self._response()):
            report = test_planner.create_test_plan(self.root, "Vault")
        case = report["test_cases"][0]
        self.assertEqual(case["source_quote_status"], "matched")
        self.assertEqual(case["status"], "proposed")
        self.assertFalse(case["verified"])
        self.assertFalse(case["executed"])
        self.assertTrue(report["_lowkey_meta"]["plan_id"])
        saved = self.root / report["_lowkey_meta"]["report_path"]
        self.assertTrue(saved.is_file())
        events = evidence_ledger.read_events(self.root)
        self.assertTrue(any(
            event["event_type"] == "test_plan_created"
            and event["details"]["plan_id"] == report["_lowkey_meta"]["plan_id"]
            for event in events
        ))

    def test_bad_source_quote_is_unmatched_not_confirmed(self):
        with patch.object(test_planner.ai_harness, "request_structured",
                          return_value=self._response("owner = msg.sender;")):
            report = test_planner.create_test_plan(self.root)
        case = report["test_cases"][0]
        self.assertEqual(case["source_quote_status"], "unmatched")
        self.assertEqual(case["status"], "proposed")
        self.assertFalse(case["verified"])

    def test_malformed_test_name_is_rejected(self):
        response = self._response()
        response["test_cases"][0]["suggested_test_name"] = "withdrawExcess"
        with patch.object(test_planner.ai_harness, "request_structured", return_value=response):
            with self.assertRaisesRegex(test_planner.TestPlanError, "beginning with 'test'"):
                test_planner.create_test_plan(self.root)

    def test_test_plan_never_writes_solidity_test_source(self):
        before = sorted(str(path.relative_to(self.root)) for path in self.root.rglob("*.sol"))
        with patch.object(test_planner.ai_harness, "request_structured", return_value=self._response()):
            test_planner.create_test_plan(self.root)
        after = sorted(str(path.relative_to(self.root)) for path in self.root.rglob("*.sol"))
        self.assertEqual(after, before)

    def test_test_plan_default_rendering_uses_plain_language(self):
        case = test_planner.validate_test_plan(
            self._response(),
            {"source_files": [{"path": "src/Vault.sol", "source_excerpt": self.source}]},
        )["test_cases"][0]
        rendered = test_planner.render_test_plan({
            "summary": "Check that withdrawals cannot exceed the caller's balance.",
            "test_cases": [case],
            "limitations": ["External fork tests need a reachable RPC endpoint."],
            "_lowkey_meta": {"plan_id": "TP-example", "report_path": ".audit/ai-review/test-plans/TP-example.json"},
        })
        self.assertIn("LOWKEY TEST IDEAS", rendered)
        self.assertIn("this is a plan, not test code", rendered.lower())
        self.assertIn("Write order: Write first", rendered)
        self.assertIn("Prevent a bug from coming back", rendered)
        self.assertIn("Source check: Found in the cited file", rendered)
        self.assertNotIn("[HIGH / regression]", rendered)
        self.assertIn("Existing tests were not checked", rendered)


if __name__ == "__main__":
    unittest.main()
