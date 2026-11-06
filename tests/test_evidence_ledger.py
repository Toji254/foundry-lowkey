import json
import tempfile
import unittest
from pathlib import Path

from lowkey import evidence_ledger as ledger


class EvidenceLedgerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        (self.root / "foundry.toml").write_text('[profile.default]\nsrc = "src"\ntest = "test"\n')
        (self.root / "src").mkdir()
        (self.root / "src" / "Vault.sol").write_text("contract Vault {}")

    def _review(self):
        report = {
            "summary": "A candidate was found.",
            "candidate_findings": [{
                "finding_id": "F-0123456789ab",
                "title": "Missing authorization",
                "category": "access-control",
                "severity": "high",
                "location": {"path": "src/Vault.sol", "symbol": "withdraw"},
                "evidence_quote": "function withdraw() external {}",
                "source_quote_status": "matched",
                "status": "candidate",
                "verified": False,
            }],
            "_lowkey_meta": {"context_sha256": "abc", "source_files_included": 1, "provider": "fixture", "model": "test"},
        }
        self.root.joinpath("src", "Vault.sol").write_text("contract Vault { function withdraw() external {} }")
        return ledger.record_review(self.root, report)

    def test_ai_review_is_persisted_as_unverified_candidate(self):
        result = self._review()
        value = ledger.summary(self.root)
        self.assertEqual(result["finding_count"], 1)
        item = value["findings"][0]
        self.assertEqual(item["status"], "candidate")
        self.assertFalse(item["verified"])
        self.assertTrue((self.root / result["report_path"]).is_file())
        events = ledger.read_events(self.root)
        self.assertEqual([event["event_type"] for event in events[:2]], ["review_created", "finding_candidate"])

    def test_confirmed_disposition_needs_native_test_evidence(self):
        self._review()
        with self.assertRaisesRegex(ledger.EvidenceLedgerError, "requires --evidence-id"):
            ledger.record_disposition(
                self.root, "F-0123456789ab", disposition="confirmed",
                reviewer="reviewer", reason="manual confirmation",
            )

    def test_human_confirmation_requires_passing_test_and_is_a_separate_event(self):
        self._review()
        run = ledger.record_native_test(self.root, {
            "finding_id": "F-0123456789ab", "status": "passed",
            "test_path": "test/unit/Vault.t.sol", "test_name": "testExploitReproduces",
            "test_sha256": "1" * 64, "command": ["forge", "test"], "exit_code": 0,
            "elapsed_ms": 18, "output_sha256": "2" * 64,
            "summary_lines": ["[PASS] testExploitReproduces()"],
        })
        result = ledger.record_disposition(
            self.root, "F-0123456789ab", disposition="confirmed",
            reviewer="human-reviewer", reason="Passing reproduction test demonstrates the impact.",
            evidence_id=run["event_id"],
        )
        item = ledger.summary(self.root)["findings"][0]
        self.assertEqual(item["status"], "human-confirmed")
        self.assertTrue(result["details"]["explicit_human_decision"])
        self.assertFalse(result["details"]["verified_by_model"])

    def test_model_candidate_never_becomes_confirmed_from_test_run_alone(self):
        self._review()
        ledger.record_native_test(self.root, {
            "finding_id": "F-0123456789ab", "status": "passed",
            "test_path": "test/unit/Vault.t.sol", "test_name": "testExploitReproduces",
            "test_sha256": "1" * 64, "command": ["forge", "test"], "exit_code": 0,
            "elapsed_ms": 18, "output_sha256": "2" * 64, "summary_lines": [],
        })
        self.assertEqual(ledger.summary(self.root)["findings"][0]["status"], "native-test-recorded")

    def test_disposition_evidence_must_belong_to_the_same_finding(self):
        self._review()
        other = dict(self._review())
        second_id = "F-aaaaaaaaaaaa"
        ledger.append_event(self.root, "finding_candidate", {"finding_id": second_id, "title": "Another"})
        run = ledger.record_native_test(self.root, {
            "finding_id": "F-0123456789ab", "status": "passed",
            "test_path": "test/unit/Vault.t.sol", "test_name": "testExploitReproduces",
            "test_sha256": "1" * 64, "command": ["forge", "test"], "exit_code": 0,
            "elapsed_ms": 18, "output_sha256": "2" * 64, "summary_lines": [],
        })
        with self.assertRaisesRegex(ledger.EvidenceLedgerError, "attached to this finding"):
            ledger.record_disposition(
                self.root, second_id, disposition="confirmed", reviewer="human",
                reason="wrong finding", evidence_id=run["event_id"],
            )

    def test_ledger_rejects_corrupt_json_instead_of_silently_skipping_it(self):
        ledger.ledger_path(self.root).parent.mkdir(parents=True, exist_ok=True)
        ledger.ledger_path(self.root).write_text("{broken\n")
        with self.assertRaisesRegex(ledger.EvidenceLedgerError, "corrupt"):
            ledger.read_events(self.root)


if __name__ == "__main__":
    unittest.main()
