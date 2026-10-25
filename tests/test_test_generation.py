import contextlib
import io
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "lowkey"))
import test_generation as generation


class TestGenerationTests(unittest.TestCase):
    def test_parse_types_defaults_to_all_supported_scaffolds(self):
        self.assertEqual(
            generation.parse_types(None),
            ["unit", "fuzz", "invariant", "integration", "fork", "poc"],
        )

    def test_parse_types_deduplicates_and_rejects_unknown_values(self):
        self.assertEqual(generation.parse_types("unit,fuzz,unit"), ["unit", "fuzz"])
        with self.assertRaisesRegex(ValueError, "Unknown test type"):
            generation.parse_types("unit,magic")

    def _project(self, root: Path, constructor: str = ""):
        (root / "src").mkdir()
        (root / "foundry.toml").write_text(
            '[profile.default]\nsrc = "src"\n', encoding="utf-8"
        )
        (root / "src" / "Counter.sol").write_text(
            "pragma solidity ^0.8.20;\n"
            "contract Counter {\n"
            f"{constructor}\n"
            "uint256 public value;\n"
            "function setValue(uint256 next) external { value = next; }\n"
            "}\n",
            encoding="utf-8",
        )

    def test_generates_all_drafts_outside_foundry_test_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._project(root)
            previous = Path.cwd()
            try:
                os.chdir(root)
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    code = generation.run_test_gen(
                        {"target_contract": "Counter", "target": "0x" + "1" * 40},
                        ["--types", "all"],
                    )
            finally:
                os.chdir(previous)

            self.assertEqual(code, 0)
            folder = root / ".audit" / "test-gen" / "Counter"
            names = {p.name for p in folder.glob("*.t.sol")}
            self.assertEqual(len(names), 6)
            self.assertFalse((root / "test").exists())
            report = json.loads((folder / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(len(report["generated"]), 6)
            self.assertIn("not protocol proofs", report["warning"])
            self.assertIn("generated", output.getvalue())

    def test_constructor_arguments_skip_local_deployment_types(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._project(root, "constructor(uint256 initial) { value = initial; }")
            previous = Path.cwd()
            try:
                os.chdir(root)
                with contextlib.redirect_stdout(io.StringIO()):
                    code = generation.run_test_gen(
                        {"target_contract": "Counter", "target": "0x" + "1" * 40},
                        ["--types", "unit,fuzz,invariant,integration,fork,poc"],
                    )
            finally:
                os.chdir(previous)

            self.assertEqual(code, 0)
            folder = root / ".audit" / "test-gen" / "Counter"
            names = {p.name for p in folder.glob("*.t.sol")}
            self.assertEqual(len(names), 2)
            report = json.loads((folder / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["constructor"], "arguments-required")
            skipped = {item["type"] for item in report["skipped"]}
            self.assertEqual(skipped, {"unit", "fuzz", "invariant", "integration"})

    def test_existing_draft_is_preserved_without_force(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._project(root)
            previous = Path.cwd()
            try:
                os.chdir(root)
                with contextlib.redirect_stdout(io.StringIO()):
                    generation.run_test_gen({"target_contract": "Counter"}, ["--types", "unit"])
                file = root / ".audit" / "test-gen" / "Counter" / "LowkeyGeneratedUnit_Counter.t.sol"
                file.write_text("user edit\n", encoding="utf-8")
                with contextlib.redirect_stdout(io.StringIO()):
                    generation.run_test_gen({"target_contract": "Counter"}, ["--types", "unit"])
                self.assertEqual(file.read_text(encoding="utf-8"), "user edit\n")
            finally:
                os.chdir(previous)


if __name__ == "__main__":
    unittest.main()
