import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from lowkey import test_generation


class TestGenerationTests(unittest.TestCase):
    def make_project(self, root: Path, source: str) -> None:
        (root / "src").mkdir()
        (root / "foundry.toml").write_text(
            '[profile.default]\nsrc = "src"\ntest = "test"\n',
            encoding="utf-8",
        )
        (root / "src" / "Counter.sol").write_text(source, encoding="utf-8")

    def test_type_parser_includes_all_required_artifact_classes(self):
        required = {"unit", "integration", "invariant", "exploit", "regression", "fuzz", "formal"}
        self.assertTrue(required.issubset(set(test_generation.parse_types("all"))))
        self.assertEqual(set(test_generation.parse_types(",".join(sorted(required)))), required)

    def test_unknown_types_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "Unknown test type"):
            test_generation.parse_types("unit,magic")

    def test_generates_property_aware_artifacts_and_report_for_simple_contract(self):
        source = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;
contract Counter {
    uint256 public count;
    function setCount(uint256 value) external {
        count = value;
    }
}
"""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_project(root, source)
            with patch("pathlib.Path.cwd", return_value=root):
                result = test_generation.run_test_gen(
                    {},
                    ["Counter", "--types", "unit,integration,invariant,exploit,regression,fuzz,formal"],
                )
            self.assertEqual(result, 0)
            output = root / ".audit" / "test-gen" / "Counter"
            report = json.loads((output / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(set(report["requested_types"]), {
                "unit", "integration", "invariant", "exploit", "regression", "fuzz", "formal"
            })
            self.assertEqual(len(report["generated"]), 7)
            self.assertEqual(report["fuzz_property"]["setter"], "setCount")
            fuzz = (output / "LowkeyGeneratedFuzz_Counter.t.sol").read_text(encoding="utf-8")
            self.assertIn("assertEq(target.count(), fuzzValue)", fuzz)
            invariant = (output / "LowkeyGeneratedInvariant_Counter.t.sol").read_text(encoding="utf-8")
            self.assertIn("invariant_count_matchesLastSuccessfulSetterCall", invariant)
            formal = (output / "LowkeyGeneratedFormal_Counter.spec").read_text(encoding="utf-8")
            self.assertIn("assert target.count() == fuzzValue", formal)
            exploit = (output / "LowkeyGeneratedExploit_Counter.t.sol").read_text(encoding="utf-8")
            self.assertIn("LOWKEY_RPC_URL", exploit)
            self.assertIn("TODO", exploit)

    def test_unsupported_constructor_is_reported_not_guessed(self):
        source = """pragma solidity ^0.8.20;
interface IERC20 {}
contract NeedsDependency {
    IERC20 public immutable dependency;
    constructor(IERC20 dependency_) { dependency = dependency_; }
}
"""
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            self.make_project(root, source)
            with patch("pathlib.Path.cwd", return_value=root):
                result = test_generation.run_test_gen(
                    {}, ["NeedsDependency", "--types", "unit,integration"]
                )
            self.assertEqual(result, 0)
            report = json.loads(
                (root / ".audit" / "test-gen" / "NeedsDependency" / "report.json").read_text(encoding="utf-8")
            )
            self.assertEqual(report["generated"], [])
            self.assertEqual(len(report["skipped"]), 2)
            self.assertTrue(all("unsupported" in item["reason"] for item in report["skipped"]))


if __name__ == "__main__":
    unittest.main()
