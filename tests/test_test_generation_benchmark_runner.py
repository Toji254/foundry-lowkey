"""Tests for the generic ecosystem benchmark runner."""
import importlib.util
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "test-gen-ecosystem-benchmark.py"
SPEC = importlib.util.spec_from_file_location("test_gen_ecosystem_benchmark", SCRIPT)
BENCHMARK = importlib.util.module_from_spec(SPEC)
assert SPEC and SPEC.loader
SPEC.loader.exec_module(BENCHMARK)


class TestGenerationBenchmarkRunner(unittest.TestCase):
    def test_discovers_contracts_from_unfamiliar_nested_source_paths(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "contracts" / "nested").mkdir(parents=True)
            (root / "contracts" / "nested" / "Protocol.sol").write_text(
                "// contract FakeInComment {}\n"
                "pragma solidity ^0.8.20;\n"
                "abstract contract SharedBase {}\n"
                "contract UnfamiliarVault is SharedBase {\n"
                "  string public label = \"contract NotADeclaration {}\";\n"
                "}\n",
                encoding="utf-8",
            )
            found = BENCHMARK.find_contracts(root)
            self.assertIn("SharedBase", found)
            self.assertIn("UnfamiliarVault", found)
            self.assertNotIn("FakeInComment", found)
            self.assertNotIn("NotADeclaration", found)
            self.assertEqual(found["UnfamiliarVault"], "contracts/nested/Protocol.sol")

    def test_ignores_build_outputs_and_git_metadata(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            for folder in ("src", "out", ".git", "cache", "node_modules"):
                path = root / folder
                path.mkdir()
                (path / "Artifact.sol").write_text(
                    "contract " + folder.replace(".", "Hidden") + "Artifact {}",
                    encoding="utf-8",
                )
            found = BENCHMARK.find_contracts(root)
            self.assertEqual(set(found), {"srcArtifact"})

    def test_target_is_not_marked_passed_when_generator_command_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output_root = root / ".audit" / "benchmark"

            def fake_run(command, cwd=None, timeout=1800):
                output_dir = Path(command[command.index("--output-dir") + 1])
                output_dir.mkdir(parents=True, exist_ok=True)
                if command[command.index("--types") + 1] == "all":
                    (output_dir / "report.json").write_text(
                        json.dumps({"generation_assessment": {"unit": {"level": "executable-candidate"}}}),
                        encoding="utf-8",
                    )
                    return {"command": command, "exit_code": 1, "stdout_tail": "", "stderr_tail": "generation error"}
                (output_dir / "report.json").write_text(
                    json.dumps({"validation": {"status": "passed"}}), encoding="utf-8"
                )
                return {"command": command, "exit_code": 0, "stdout_tail": "", "stderr_tail": ""}

            with patch.object(BENCHMARK, "run", side_effect=fake_run):
                result = BENCHMARK.evaluate_target(root, "UnfamiliarContract", output_root)

            self.assertFalse(result["generation_succeeded"])
            self.assertTrue(result["validation_succeeded"])
            self.assertEqual(result["honest_result"], "generation-or-validation-failed")

    def test_target_pass_requires_reports_and_zero_exit_codes_for_both_commands(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output_root = root / ".audit" / "benchmark"

            def fake_run(command, cwd=None, timeout=1800):
                output_dir = Path(command[command.index("--output-dir") + 1])
                output_dir.mkdir(parents=True, exist_ok=True)
                if command[command.index("--types") + 1] == "all":
                    (output_dir / "report.json").write_text(
                        json.dumps({"generation_assessment": {"unit": {"level": "executable-candidate"}}}),
                        encoding="utf-8",
                    )
                else:
                    (output_dir / "report.json").write_text(
                        json.dumps({"validation": {"status": "passed"}}), encoding="utf-8"
                    )
                return {"command": command, "exit_code": 0, "stdout_tail": "", "stderr_tail": ""}

            with patch.object(BENCHMARK, "run", side_effect=fake_run):
                result = BENCHMARK.evaluate_target(root, "UnfamiliarContract", output_root)

            self.assertTrue(result["generation_succeeded"])
            self.assertTrue(result["validation_succeeded"])
            self.assertEqual(result["honest_result"], "generation-and-validation-passed")


if __name__ == "__main__":
    unittest.main()
