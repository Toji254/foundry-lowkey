import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lowkey import security_review


class SecurityReviewTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "foundry.toml").write_text('[profile.default]\nsrc = "src"\ntest = "test"\n')
        (self.root / "src").mkdir()
        self.source = (
            "pragma solidity ^0.8.20;\n"
            "contract Vault {\n"
            "    function withdraw() external {\n"
            "        payable(msg.sender).call{value: address(this).balance}(\"\");\n"
            "    }\n"
            "}\n"
        )
        (self.root / "src" / "Vault.sol").write_text(self.source)

    def _response(self, quote=None):
        return {
            "summary": "The source contains a candidate authorization or accounting risk.",
            "candidate_findings": [{
                "title": "Unsafe withdrawal",
                "category": "reentrancy",
                "severity": "high",
                "location": {"path": "src/Vault.sol", "symbol": "Vault.withdraw"},
                "evidence_quote": quote if quote is not None else 'payable(msg.sender).call{value: address(this).balance}("");',
                "reasoning": "The external call occurs before a state update.",
                "impact": "A malicious recipient may recursively withdraw.",
                "exploit_preconditions": "The recipient is a contract and a state value can be reused.",
                "recommendation": "Update state before the call and test the property.",
                "confidence": "high",
            }],
            "limitations": ["No runtime test was executed by the model."],
        }

    def test_review_records_candidate_and_checks_exact_source_quote(self):
        with patch.object(security_review.ai_harness, "_protocol_review_context",
                          wraps=security_review.ai_harness._protocol_review_context):
            with patch.object(security_review.ai_harness, "request_structured", return_value=self._response()):
                review = security_review.review_project_security(self.root)
        finding = review["candidate_findings"][0]
        self.assertEqual(finding["source_quote_status"], "matched")
        self.assertEqual(finding["status"], "candidate")
        self.assertFalse(finding["verified"])
        self.assertTrue((self.root / ".audit/ai-review/ledger.jsonl").is_file())

    def test_wrong_source_quote_is_marked_unmatched_not_falsely_verified(self):
        with patch.object(security_review.ai_harness, "request_structured",
                          return_value=self._response("owner = msg.sender;")):
            review = security_review.review_project_security(self.root)
        finding = review["candidate_findings"][0]
        self.assertEqual(finding["source_quote_status"], "unmatched")
        self.assertEqual(finding["status"], "candidate")
        self.assertFalse(finding["verified"])

    def test_security_review_rejects_malformed_schema(self):
        response = {"summary": "Bad output", "candidate_findings": [{"title": "missing fields"}], "limitations": []}
        with patch.object(security_review.ai_harness, "request_structured", return_value=response):
            with self.assertRaises(security_review.SecurityReviewError):
                security_review.review_project_security(self.root)

    def test_source_quote_matching_ignores_whitespace_only(self):
        items = [{"path": "src/Vault.sol", "source_excerpt": "function f() {\n  return 1;\n}"}]
        self.assertTrue(security_review.source_quote_matches("src/Vault.sol", "function f() { return 1; }", items))
        self.assertFalse(security_review.source_quote_matches("test/Vault.t.sol", "function f()", items))


if __name__ == "__main__":
    unittest.main()
