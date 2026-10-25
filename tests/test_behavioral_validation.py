import json
import sys
import tempfile
import unittest
from pathlib import Path

from lowkey.behavioral_validation import validate_mutations, write_report


class BehavioralValidationTests(unittest.TestCase):
    def make_project(self, root: Path) -> None:
        (root / "tests").mkdir()
        (root / "counter.py").write_text(
            "def normalize(value):\n    return value + 1\n\n# stable label\n",
            encoding="utf-8",
        )
        (root / "tests" / "test_counter.py").write_text(
            "import unittest\nfrom counter import normalize\n\n"
            "class CounterTests(unittest.TestCase):\n"
            "    def test_normalize(self):\n"
            "        self.assertEqual(normalize(2), 3)\n",
            encoding="utf-8",
        )

    def test_mutation_campaign_kills_behavioral_fault_and_counts_survivor(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_project(root)
            report = validate_mutations(
                root,
                [sys.executable, "-m", "unittest", "discover", "-s", "tests"],
                [
                    {"id": "off-by-one", "file": "counter.py", "before": "return value + 1", "after": "return value"},
                    {"id": "comment-only", "file": "counter.py", "before": "# stable label", "after": "# changed label"},
                    {"id": "syntax-invalid", "file": "counter.py", "before": "return value + 1", "after": "return ("},
                ],
                timeout_seconds=10,
            )
            self.assertEqual(report["status"], "completed")
            self.assertEqual(report["baseline"]["status"], "passed")
            self.assertEqual(report["summary"]["killed"], 1)
            self.assertEqual(report["summary"]["survived"], 1)
            self.assertEqual(report["summary"]["invalid"], 1)
            self.assertEqual(report["mutation_score"], 0.5)
            path = write_report(report, root / ".audit" / "mutation-report.json")
            saved = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(saved["summary"]["killed"], 1)

    def test_baseline_failure_prevents_mutation_conclusions(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_project(root)
            report = validate_mutations(
                root, [sys.executable, "-c", "raise SystemExit(3)"],
                [{"id": "not-run", "file": "counter.py", "before": "value", "after": "x"}],
                timeout_seconds=5,
            )
        self.assertEqual(report["status"], "baseline_failed")
        self.assertIsNone(report["mutation_score"])
        self.assertEqual(report["mutants"], [])

    def test_mutant_path_escape_is_invalid(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_project(root)
            report = validate_mutations(
                root,
                [sys.executable, "-m", "unittest", "discover", "-s", "tests"],
                [{"id": "escape", "file": "../outside.py", "before": "x", "after": "y"}],
                timeout_seconds=10,
            )
        self.assertEqual(report["mutants"][0]["status"], "invalid")


if __name__ == "__main__":
    unittest.main()
