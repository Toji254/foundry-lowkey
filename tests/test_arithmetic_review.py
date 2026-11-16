import pathlib
import sys
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
LOWKEY = ROOT / "lowkey"
if str(LOWKEY) not in sys.path:
    sys.path.insert(0, str(LOWKEY))

import arithmetic_review
import godmode


VULNERABLE_TOKEN = """
pragma solidity ^0.6.0;

contract Token {
    mapping(address => uint256) balances;

    function transfer(address _to, uint256 _value) public returns (bool) {
        require(balances[msg.sender] - _value >= 0);
        balances[msg.sender] -= _value;
        balances[_to] += _value;
        return true;
    }
}
"""


class ArithmeticReviewTests(unittest.TestCase):
    def test_finds_pre_08_unsigned_mapping_underflow_guard(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            findings = arithmetic_review.scan_source(VULNERABLE_TOKEN, "src/Token.sol", root)

        self.assertEqual(len(findings), 1)
        finding = findings[0]
        self.assertEqual(finding["kind"], "unsigned-subtraction-compared-to-zero")
        self.assertEqual(finding["status"], "WRAPAROUND_POSSIBLE")
        self.assertTrue(finding["likely_exploitable"])
        self.assertEqual(finding["function"], "transfer")
        self.assertIn("balances[msg.sender] - _value", finding["expression"])
        self.assertEqual(finding["evidence_level"], "static-source-candidate")
        self.assertEqual(finding["verification_status"], "UNVERIFIED")

    def test_solidity_08_checked_arithmetic_is_not_labelled_as_wraparound(self):
        source = VULNERABLE_TOKEN.replace("^0.6.0", "^0.8.20")
        with tempfile.TemporaryDirectory() as temporary:
            findings = arithmetic_review.scan_source(source, "Token.sol", pathlib.Path(temporary))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["status"], "CHECKED_ARITHMETIC_REVERTS_BEFORE_GUARD")
        self.assertFalse(findings[0]["likely_exploitable"])

    def test_unchecked_block_restores_wraparound_candidate_in_solidity_08(self):
        source = VULNERABLE_TOKEN.replace("^0.6.0", "^0.8.20").replace(
            "require(balances[msg.sender] - _value >= 0);",
            "unchecked { require(balances[msg.sender] - _value >= 0); }",
        )
        with tempfile.TemporaryDirectory() as temporary:
            findings = arithmetic_review.scan_source(source, "Token.sol", pathlib.Path(temporary))

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["status"], "WRAPAROUND_POSSIBLE")
        self.assertTrue(findings[0]["likely_exploitable"])

    def test_safe_check_before_subtraction_is_not_flagged(self):
        source = VULNERABLE_TOKEN.replace(
            "require(balances[msg.sender] - _value >= 0);",
            "require(balances[msg.sender] >= _value);",
        )
        with tempfile.TemporaryDirectory() as temporary:
            findings = arithmetic_review.scan_source(source, "Token.sol", pathlib.Path(temporary))
        self.assertEqual(findings, [])

    def test_signed_operands_are_not_misclassified_as_uint(self):
        source = """
        pragma solidity ^0.6.0;
        contract SignedExample {
            int256 balance;
            function spend(int256 amount) public {
                require(balance - amount >= 0);
            }
        }
        """
        with tempfile.TemporaryDirectory() as temporary:
            findings = arithmetic_review.scan_source(source, "Signed.sol", pathlib.Path(temporary))
        self.assertEqual(findings, [])

    def test_comments_and_strings_do_not_create_findings(self):
        source = """
        pragma solidity ^0.6.0;
        contract Example {
            mapping(address => uint256) balances;
            function safe(uint256 amount) public {
                // require(balances[msg.sender] - amount >= 0);
                string memory note = "require(balances[msg.sender] - amount >= 0)";
                require(balances[msg.sender] >= amount);
            }
        }
        """
        with tempfile.TemporaryDirectory() as temporary:
            findings = arithmetic_review.scan_source(source, "Example.sol", pathlib.Path(temporary))
        self.assertEqual(findings, [])

    def test_project_scan_is_wired_into_godmode_source_maps(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            (root / "Token.sol").write_text(VULNERABLE_TOKEN, encoding="utf-8")
            maps = godmode.source_maps(root)

        self.assertEqual(len(maps["arithmetic_review"]), 1)
        self.assertEqual(maps["arithmetic_review"][0]["status"], "WRAPAROUND_POSSIBLE")


    def test_source_only_scan_succeeds_without_claiming_a_complete_audit(self):
        from contextlib import redirect_stdout
        from unittest.mock import patch
        import io
        import json

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            (root / "Token.sol").write_text(VULNERABLE_TOKEN, encoding="utf-8")
            with patch.object(godmode, "rpc", side_effect=AssertionError("source-only scan must not call RPC")), \
                 redirect_stdout(io.StringIO()):
                result_code = godmode.godmode(["--root", str(root)])

            self.assertEqual(result_code, 0)
            report = json.loads(
                (root / ".audit" / "godmode" / "latest.json").read_text(encoding="utf-8")
            )
            self.assertEqual(report["overall_status"], "REVIEW_REQUIRED")
            self.assertTrue(any(
                stage["name"] == "onchain-recon" and stage["status"] == "skipped"
                for stage in report["stages"]
            ))
            self.assertEqual(len(report["signals"]["arithmetic_review"]), 1)

    def test_plan_only_does_not_touch_rpc_or_execute_optional_stages(self):
        from contextlib import redirect_stdout
        from unittest.mock import patch
        import io
        import json

        with tempfile.TemporaryDirectory() as temporary:
            root = pathlib.Path(temporary)
            (root / "Token.sol").write_text(VULNERABLE_TOKEN, encoding="utf-8")
            with patch.object(godmode, "rpc", side_effect=AssertionError("RPC must not run")), \
                 patch.object(godmode, "mutation", side_effect=AssertionError("mutation must not run")), \
                 patch.object(godmode, "coverage", side_effect=AssertionError("coverage must not run")), \
                 redirect_stdout(io.StringIO()):
                result_code = godmode.godmode([
                    "--root", str(root), "--plan-only",
                    "0x1111111111111111111111111111111111111111",
                    "--rpc-url", "http://127.0.0.1:8545",
                    "--mutation-manifest", "mutations.json",
                    "--coverage-source", "Token.sol",
                ])

            self.assertEqual(result_code, 0)
            report = json.loads(
                (root / ".audit" / "godmode" / "latest.json").read_text(encoding="utf-8")
            )
            statuses = {stage["name"]: stage["status"] for stage in report["stages"]}
            self.assertEqual(statuses["onchain-recon"], "skipped")
            self.assertEqual(statuses["attack"], "skipped")
            self.assertEqual(statuses["mutation"], "skipped")
            self.assertEqual(statuses["target-coverage"], "skipped")
            self.assertEqual(len(report["signals"]["arithmetic_review"]), 1)


if __name__ == "__main__":
    unittest.main()
