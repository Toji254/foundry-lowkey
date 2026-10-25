import json
import sys
import tempfile
import unittest
from pathlib import Path

from lowkey.verification_benchmark import run_benchmark, write_report


class VerificationBenchmarkTests(unittest.TestCase):
    def test_benchmark_records_reproducible_case_and_enforces_score_gate(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            project = workspace / "fixture"
            (project / "tests").mkdir(parents=True)
            (project / "counter.py").write_text("def value():\n    return 2\n", encoding="utf-8")
            (project / "tests" / "test_counter.py").write_text(
                "import unittest\nfrom counter import value\n"
                "class CounterTests(unittest.TestCase):\n"
                "    def test_value(self): self.assertEqual(value(), 2)\n",
                encoding="utf-8",
            )
            manifest_path = workspace / "benchmark.json"
            manifest_path.write_text(json.dumps({
                "name": "tiny-python-regression",
                "cases": [{
                    "id": "python-unit",
                    "project": "fixture",
                    "command": [sys.executable, "-m", "unittest", "discover", "-s", "tests"],
                    "timeout_seconds": 10,
                    "labels": {"language": "python", "build_system": "unittest"},
                    "mutants": [{
                        "id": "wrong-value", "file": "counter.py",
                        "before": "return 2", "after": "return 3",
                    }],
                }],
            }), encoding="utf-8")
            report = run_benchmark(manifest_path, workspace_root=workspace, min_mutation_score=1.0)
            self.assertEqual(report["gate"], "passed")
            self.assertEqual(report["mutation_score"], 1.0)
            self.assertEqual(report["completed_cases"], 1)
            self.assertTrue(report["manifest_sha256"])
            saved = write_report(report, workspace / ".audit" / "benchmark-report.json")
            self.assertEqual(json.loads(saved.read_text())["gate"], "passed")

    def test_benchmark_fails_gate_when_mutant_survives(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            project = workspace / "fixture"
            (project / "tests").mkdir(parents=True)
            (project / "counter.py").write_text("def value():\n    return 2\n", encoding="utf-8")
            (project / "tests" / "test_counter.py").write_text(
                "import unittest\nfrom counter import value\n"
                "class CounterTests(unittest.TestCase):\n"
                "    def test_value(self): self.assertEqual(value(), 2)\n",
                encoding="utf-8",
            )
            manifest_path = workspace / "benchmark.json"
            manifest_path.write_text(json.dumps({
                "cases": [{
                    "id": "survivor",
                    "project": "fixture",
                    "command": [sys.executable, "-m", "unittest", "discover", "-s", "tests"],
                    "mutants": [{
                        "id": "comment-only", "file": "counter.py",
                        "before": "return 2", "after": "return 2 # unchanged behavior",
                    }],
                }],
            }), encoding="utf-8")
            report = run_benchmark(manifest_path, workspace_root=workspace, min_mutation_score=1.0)
        self.assertEqual(report["mutation_score"], 0.0)
        self.assertEqual(report["gate"], "failed")

    def test_invalid_score_threshold_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory)
            manifest = workspace / "benchmark.json"
            manifest.write_text(json.dumps({"cases": []}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "between 0 and 1"):
                run_benchmark(manifest, workspace_root=workspace, min_mutation_score=2.0)


if __name__ == "__main__":
    unittest.main()
