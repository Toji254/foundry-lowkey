import tempfile
import unittest
from pathlib import Path

from lowkey.generation_plugins import (
    GenerationCapability,
    GenerationRegistry,
    SolidityFoundryGenerationAdapter,
)
from lowkey.verification_adapters import inspect_project


class GenerationPluginTests(unittest.TestCase):
    def test_registry_rejects_duplicate_generators(self):
        adapter = SolidityFoundryGenerationAdapter()
        registry = GenerationRegistry([adapter])
        with self.assertRaisesRegex(ValueError, "already registered"):
            registry.register(adapter)

    def test_generator_routes_only_to_supported_project(self):
        adapter = SolidityFoundryGenerationAdapter()
        self.assertFalse(adapter.supports({"language": "rust", "build_system": "cargo", "root": "/tmp"} )[0])

    def test_generation_run_preserves_property_and_report_provenance(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "foundry.toml").write_text('[profile.default]\\nsrc = "src"\\n', encoding="utf-8")
            (root / "src" / "Counter.sol").write_text(
                "pragma solidity ^0.8.20; contract Counter { uint256 public count; "
                "function setCount(uint256 value) external { count = value; } }",
                encoding="utf-8",
            )
            project = inspect_project(root)
            runs = GenerationRegistry([SolidityFoundryGenerationAdapter()]).generate(
                project,
                {"contract": "Counter", "types": ["unit", "fuzz", "formal"]},
            )
            self.assertEqual(len(runs), 1)
            run = runs[0]
            self.assertEqual(run.status, "drafted")
            self.assertTrue(Path(run.report_path).is_file())
            kinds = {artifact.kind for artifact in run.artifacts}
            self.assertEqual(kinds, {"unit", "fuzz", "formal"})
            fuzz = next(artifact for artifact in run.artifacts if artifact.kind == "fuzz")
            self.assertIn("count equals", fuzz.intended_property)
            self.assertTrue(fuzz.metadata["review_required"])
            formal = next(artifact for artifact in run.artifacts if artifact.kind == "formal")
            self.assertEqual(formal.status, "property-draft")


if __name__ == "__main__":
    unittest.main()
