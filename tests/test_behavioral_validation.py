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

    def test_missing_and_duplicate_mutant_ids_are_invalid(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_project(root)
            report = validate_mutations(
                root,
                [sys.executable, "-m", "unittest", "discover", "-s", "tests"],
                [
                    {"id": "same-id", "file": "counter.py", "before": "# stable label", "after": "# changed label"},
                    {"id": "same-id", "file": "counter.py", "before": "return value + 1", "after": "return value + 2"},
                    {"file": "counter.py", "before": "return value + 1", "after": "return value"},
                ],
                timeout_seconds=10,
            )
        self.assertEqual(report["mutants"][0]["status"], "survived")
        self.assertEqual(report["mutants"][1]["status"], "invalid")
        self.assertEqual(report["mutants"][2]["status"], "invalid")
        self.assertEqual(report["summary"]["invalid"], 2)
        self.assertEqual(report["summary"]["survived"], 1)

    def test_unexplained_nonzero_exit_is_unscored_not_killed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_project(root)
            (root / "marker.txt").write_text("healthy", encoding="utf-8")
            command = [
                sys.executable, "-c",
                "from pathlib import Path; import sys; "
                "bad = Path('marker.txt').read_text() == 'broken'; "
                "print('unexpected tool failure' if bad else 'baseline ok'); sys.exit(7 if bad else 0)",
            ]
            report = validate_mutations(
                root, command,
                [{"id": "tool-failure", "file": "marker.txt", "before": "healthy", "after": "broken"}],
                timeout_seconds=5,
            )
        self.assertEqual(report["mutants"][0]["status"], "invalid")
        self.assertEqual(report["summary"]["killed"], 0)
        self.assertEqual(report["summary"]["invalid"], 1)
        self.assertIsNone(report["mutation_score"])

    def test_recognized_assertion_failure_counts_as_killed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_project(root)
            report = validate_mutations(
                root,
                [sys.executable, "-c", "raise AssertionError('behavioral invariant changed')"],
                [],
                timeout_seconds=5,
            )
            # A failing baseline must never produce mutation conclusions.
            self.assertEqual(report["status"], "baseline_failed")
        # Exercise the classifier with a passing baseline and a failing mutant
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_project(root)
            (root / "marker.txt").write_text("healthy", encoding="utf-8")
            command = [
                sys.executable, "-c",
                "from pathlib import Path; import sys; "
                "bad = Path('marker.txt').read_text() == 'broken'; "
                "raise AssertionError('behavioral invariant changed') if bad else SystemExit(0)",
            ]
            report = validate_mutations(
                root, command,
                [{"id": "behavior-failure", "file": "marker.txt", "before": "healthy", "after": "broken"}],
                timeout_seconds=5,
            )
        self.assertEqual(report["mutants"][0]["status"], "killed")
        self.assertEqual(report["summary"]["killed"], 1)

    def test_network_or_infrastructure_failure_is_not_counted_as_killed(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_project(root)
            (root / "marker.txt").write_text("healthy", encoding="utf-8")
            command = [
                sys.executable, "-c",
                "from pathlib import Path; import sys; "
                "bad = Path('marker.txt').read_text() == 'broken'; "
                "print('Connection refused' if bad else 'baseline ok'); sys.exit(1 if bad else 0)",
            ]
            report = validate_mutations(
                root, command,
                [{"id": "rpc-unavailable", "file": "marker.txt", "before": "healthy", "after": "broken"}],
                timeout_seconds=5,
            )
        self.assertEqual(report["mutants"][0]["status"], "invalid")
        self.assertEqual(report["summary"]["killed"], 0)
        self.assertEqual(report["summary"]["invalid"], 1)


if __name__ == "__main__":
    unittest.main()
