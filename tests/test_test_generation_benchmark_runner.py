"""Tests for the generic ecosystem benchmark runner."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

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


if __name__ == "__main__":
    unittest.main()
