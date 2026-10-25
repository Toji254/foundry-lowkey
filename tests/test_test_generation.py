import contextlib
import io
import json
import os
import subprocess
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
            ["unit", "fuzz", "invariant", "integration", "fork", "poc", "regression", "formal"],
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
            self.assertEqual(len(names), 7)
            self.assertFalse((root / "test").exists())
            report = json.loads((folder / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(len(report["generated"]), 8)
            self.assertIn("not protocol proofs", report["warning"])
            self.assertIn("generated", output.getvalue())
            self.assertEqual(
                report["fuzz_property"],
                {"setter": "setValue", "parameter": "next", "type": "uint256", "state": "value"},
            )
            fuzz_draft = (
                folder / "LowkeyGeneratedFuzz_Counter.t.sol"
            ).read_text(encoding="utf-8")
            self.assertIn(
                "function testFuzz_setValue_preservesStoredValue(uint256 fuzzValue)",
                fuzz_draft,
            )
            self.assertIn("assertEq(target.value(), fuzzValue);", fuzz_draft)
            unit_draft = (folder / "LowkeyGeneratedUnit_Counter.t.sol").read_text(encoding="utf-8")
            self.assertIn("function test_setValue_updatesPublicState()", unit_draft)
            invariant_draft = (folder / "LowkeyGeneratedInvariant_Counter.t.sol").read_text(encoding="utf-8")
            self.assertIn("function invariant_value_matchesLastSuccessfulSetterCall()", invariant_draft)
            self.assertIn("targetContract(address(handler));", invariant_draft)
            fork_draft = (folder / "LowkeyGeneratedFork_Counter.t.sol").read_text(encoding="utf-8")
            self.assertIn("function testFork_value_publicGetterIsCallable()", fork_draft)
            self.assertIn('abi.encodeWithSignature("value()")', fork_draft)
            self.assertNotIn("target.setValue(expected)", fork_draft)
            self.assertIn("target = Counter(TARGET);", fork_draft)
            self.assertTrue((folder / "test-plan.md").is_file())
            self.assertIn("Test plan by family", (folder / "test-plan.md").read_text(encoding="utf-8"))
            self.assertIn("security_surfaces", report["analysis"])
            formal_spec = (folder / "LowkeyGeneratedFormal_Counter.spec").read_text(encoding="utf-8")
            self.assertIn("rule setValue_round_trip(uint256 fuzzValue)", formal_spec)
            self.assertIn("assert target.value() == fuzzValue;", formal_spec)

    def test_constructor_arguments_generate_local_drafts_with_safe_placeholders(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._project(root, "constructor(uint256 initial) { value = initial; }")
            previous = Path.cwd()
            try:
                os.chdir(root)
                with contextlib.redirect_stdout(io.StringIO()):
                    code = generation.run_test_gen(
                        {"target_contract": "Counter", "target": "0x" + "1" * 40},
                        ["--types", "unit,fuzz,invariant,integration,fork,poc,regression"],
                    )
            finally:
                os.chdir(previous)

            self.assertEqual(code, 0)
            folder = root / ".audit" / "test-gen" / "Counter"
            drafts = list(folder.glob("*.t.sol"))
            self.assertEqual(len(drafts), 7)
            report = json.loads((folder / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["constructor"], "arguments-required")
            self.assertEqual(report["constructor_parameters"], "uint256 initial")
            self.assertEqual(report["constructor_placeholders"], ["0"])
            self.assertEqual(len(report["generated"]), 7)
            self.assertEqual(report["skipped"], [])
            unit = (folder / "LowkeyGeneratedUnit_Counter.t.sol").read_text(encoding="utf-8")
            fuzz = (folder / "LowkeyGeneratedFuzz_Counter.t.sol").read_text(encoding="utf-8")
            self.assertIn("new Counter(0)", unit)
            self.assertIn("new Counter(0)", fuzz)
            self.assertIn("Review the compile-safe constructor placeholder values", unit)

    def test_unsupported_constructor_types_remain_skipped(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._project(root, "constructor(MyType initial) {}")
            previous = Path.cwd()
            try:
                os.chdir(root)
                with contextlib.redirect_stdout(io.StringIO()):
                    code = generation.run_test_gen(
                        {"target_contract": "Counter", "target": "0x" + "1" * 40},
                        ["--types", "unit,fuzz,fork,poc"],
                    )
            finally:
                os.chdir(previous)

            self.assertEqual(code, 0)
            folder = root / ".audit" / "test-gen" / "Counter"
            names = {p.name for p in folder.glob("*.t.sol")}
            self.assertEqual(names, {
                "LowkeyGeneratedFork_Counter.t.sol",
                "LowkeyGeneratedPoc_Counter.t.sol",
            })
            report = json.loads((folder / "report.json").read_text(encoding="utf-8"))
            self.assertEqual(report["constructor"], "unsupported-arguments")
            self.assertIsNone(report["constructor_placeholders"])
            self.assertEqual(
                {item["type"] for item in report["skipped"]},
                {"unit", "fuzz"},
            )


    def test_fuzz_remains_a_todo_when_no_direct_setter_property_is_recognized(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._project(root, "constructor(uint256 initial) { value = initial; }")
            source_path = root / "src" / "Counter.sol"
            source = source_path.read_text(encoding="utf-8")
            source = source.replace(
                "function setValue(uint256 next) external { value = next; }",
                "function increase(uint256 amount) external { value += amount; }",
            )
            source_path.write_text(source, encoding="utf-8")
            previous = Path.cwd()
            try:
                os.chdir(root)
                with contextlib.redirect_stdout(io.StringIO()):
                    code = generation.run_test_gen(
                        {"target_contract": "Counter"},
                        ["--types", "fuzz"],
                    )
            finally:
                os.chdir(previous)

            self.assertEqual(code, 0)
            folder = root / ".audit" / "test-gen" / "Counter"
            draft = (folder / "LowkeyGeneratedFuzz_Counter.t.sol").read_text(encoding="utf-8")
            report = json.loads((folder / "report.json").read_text(encoding="utf-8"))
            self.assertIsNone(report["fuzz_property"])
            self.assertNotRegex(draft, r"(?m)^\s*function testFuzz_")
            self.assertIn("No safe direct-setter/public-integer-getter property was recognized", draft)


    def test_custom_modifier_prevents_unsafe_setter_inference(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._project(root)
            source_path = root / "src" / "Counter.sol"
            source = source_path.read_text(encoding="utf-8")
            source = source.replace(
                "function setValue(uint256 next) external { value = next; }",
                "function setValue(uint256 next) external onlyOwner { value = next; }",
            )
            source_path.write_text(source, encoding="utf-8")
            previous = Path.cwd()
            try:
                os.chdir(root)
                with contextlib.redirect_stdout(io.StringIO()):
                    code = generation.run_test_gen({"target_contract": "Counter"}, ["--types", "fuzz,formal"])
            finally:
                os.chdir(previous)

            self.assertEqual(code, 0)
            folder = root / ".audit" / "test-gen" / "Counter"
            report = json.loads((folder / "report.json").read_text(encoding="utf-8"))
            self.assertIsNone(report["fuzz_property"])
            fuzz = (folder / "LowkeyGeneratedFuzz_Counter.t.sol").read_text(encoding="utf-8")
            self.assertNotRegex(fuzz, r"(?m)^\\s*function testFuzz_")
            formal = (folder / "LowkeyGeneratedFormal_Counter.md").read_text(encoding="utf-8")
            self.assertIn("not an executable CVL spec yet", formal)

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


    def test_installer_packages_generator_and_exposes_new_help(self):
        with tempfile.TemporaryDirectory() as home:
            env = os.environ.copy()
            env["HOME"] = home
            installed = subprocess.run(
                ["bash", str(ROOT / "install.sh")],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(
                installed.returncode,
                0,
                installed.stdout + "\\n" + installed.stderr,
            )

            runtime = Path(home) / ".lowkey"
            generator_module = runtime / "test_generation.py"
            self.assertTrue(generator_module.is_file())
            manifest = json.loads(
                (runtime / "install-manifest.json").read_text(encoding="utf-8")
            )
            self.assertIn(str(generator_module), manifest["files"])

            help_result = subprocess.run(
                [
                    str(Path(home) / ".foundry" / "bin" / "lk"),
                    "test-gen",
                    "--help",
                ],
                cwd=ROOT,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(
                help_result.returncode,
                0,
                help_result.stdout + "\\n" + help_result.stderr,
            )
            self.assertIn("Generate project-aware starter files", help_result.stdout)
            self.assertIn("--types", help_result.stdout)

            # Running the scaffold generator must not trigger the legacy
            # evidence-based PoC refresh workflow.
            project = Path(home) / "fixture"
            project.mkdir()
            self._project(project)
            generated = subprocess.run(
                [
                    str(Path(home) / ".foundry" / "bin" / "lk"),
                    "test-gen",
                    "Counter",
                    "--types",
                    "unit,fuzz",
                ],
                cwd=project,
                env=env,
                text=True,
                capture_output=True,
                check=False,
            )
            self.assertEqual(
                generated.returncode,
                0,
                generated.stdout + "\\n" + generated.stderr,
            )
            self.assertTrue(
                (project / ".audit" / "test-gen" / "Counter" / "report.json").is_file()
            )
            self.assertFalse((project / "script" / "LowkeyPoC_Counter.s.sol").exists())
            self.assertFalse(
                (project / ".audit" / "poc" / "LowkeyPoc_Counter.json").exists()
            )




    def test_generates_narrow_non_owner_test_for_unconditional_only_owner_mutator(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._project(root)
            source_path = root / "src" / "Counter.sol"
            source = source_path.read_text(encoding="utf-8").replace(
                "uint256 public value;",
                "uint256 public value;\n"
                "bool public paused;\n"
                "address public owner;\n"
                "constructor() { owner = msg.sender; }\n"
                "modifier onlyOwner() { require(msg.sender == owner); _; }\n"
                "function pause() external onlyOwner { paused = true; }",
            )
            source_path.write_text(source, encoding="utf-8")
            previous = Path.cwd()
            try:
                os.chdir(root)
                with contextlib.redirect_stdout(io.StringIO()):
                    code = generation.run_test_gen(
                        {"target_contract": "Counter"},
                        ["--types", "unit"],
                    )
            finally:
                os.chdir(previous)
            self.assertEqual(code, 0)
            unit = (root / ".audit" / "test-gen" / "Counter" / "LowkeyGeneratedUnit_Counter.t.sol").read_text(encoding="utf-8")
            self.assertIn("function test_nonOwnerCannotCall_pause()", unit)
            self.assertIn("vm.prank(address(0xBEEF));", unit)
            self.assertIn("vm.expectRevert();", unit)

    def test_analysis_masks_comments_and_quoted_strings_before_finding_security_cues(self):
        from test_generation_analysis import analyse_contract, mask_solidity
        sample = (
            'contract Demo {\n'
            '  // onlyOwner should not count when commented out\n'
            '  string public note = "delegatecall and onlyRole";\n'
            '  address public owner;\n'
            '  function changeOwner(address next) external onlyOwner { owner = next; }\n'
            '}\n'
        )
        clean = mask_solidity(sample)
        self.assertNotIn("onlyOwner should not count", clean)
        self.assertNotIn("delegatecall and onlyRole", clean)
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_path = root / "Demo.sol"
            source_path.write_text(sample, encoding="utf-8")
            result = analyse_contract(root, "Demo", source_path, sample)
            self.assertIn("access control", result["security_surfaces"])
            self.assertEqual(result["functions"][0]["name"], "changeOwner")

if __name__ == "__main__":
    unittest.main()
