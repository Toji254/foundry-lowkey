import contextlib
import io
import json
import os
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
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
            self.assertEqual(len(report["source_sha256"]), 64)
            self.assertEqual(report["generation_assessment"]["unit"]["level"], "executable-candidate")
            self.assertEqual(report["generation_assessment"]["fuzz"]["level"], "executable-candidate")
            self.assertEqual(report["generation_assessment"]["invariant"]["level"], "executable-candidate")
            self.assertEqual(report["generation_assessment"]["integration"]["level"], "scaffold")
            self.assertEqual(report["generation_assessment"]["poc"]["protocol_security_established"], False)
            self.assertIn("compile-only", output.getvalue())
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
            self.assertEqual(report["generation_assessment"]["unit"]["level"], "requires-setup-review")
            self.assertEqual(report["generation_assessment"]["fuzz"]["level"], "requires-setup-review")
            self.assertEqual(report["generation_assessment"]["invariant"]["level"], "requires-setup-review")
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
            self.assertEqual(report["generation_assessment"]["unit"]["level"], "not-generated")
            self.assertEqual(report["generation_assessment"]["fuzz"]["level"], "not-generated")
            self.assertIn("unsupported", report["generation_assessment"]["unit"]["note"])


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
            self.assertEqual(len(result["source_sha256"]), 64)


    def test_validate_compiles_temporary_drafts_without_running_them(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._project(root)
            previous = Path.cwd()
            try:
                os.chdir(root)
                completed = subprocess.CompletedProcess(["forge", "build"], 0, "compile ok", "")
                with patch("test_generation.shutil.which", return_value="/fake/forge"), patch(
                    "test_generation.subprocess.run", return_value=completed
                ) as run:
                    with contextlib.redirect_stdout(io.StringIO()):
                        code = generation.run_test_gen(
                            {"target_contract": "Counter"},
                            ["--types", "unit", "--validate"],
                        )
            finally:
                os.chdir(previous)
            self.assertEqual(code, 0)
            report = json.loads(
                (root / ".audit" / "test-gen" / "Counter" / "report.json").read_text(encoding="utf-8")
            )
            self.assertEqual(report["validation"]["status"], "passed")
            self.assertEqual(run.call_count, 2)
            self.assertEqual(run.call_args.args[0], ["/fake/forge", "build"])
            self.assertEqual(run.call_args.kwargs["cwd"], root)
            self.assertIn("test functions were not executed", report["validation"]["detail"])
            self.assertFalse((root / "test" / "lowkey-generated").exists())

    def test_generated_pragma_and_import_follow_foundry_project_configuration(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._project(root)
            (root / "foundry.toml").write_text(
                '[profile.default]\nsrc = "src"\ntest = "spec"\n'
                '[profile.ci]\nfuzz.runs = 1\n', encoding="utf-8"
            )
            source_path = root / "src" / "Counter.sol"
            source_path.write_text(
                source_path.read_text(encoding="utf-8").replace(
                    "pragma solidity ^0.8.20;", "pragma solidity ^0.8.24;"
                ),
                encoding="utf-8",
            )
            previous = Path.cwd()
            try:
                os.chdir(root)
                with patch.dict(os.environ, {"FOUNDRY_PROFILE": "ci"}), contextlib.redirect_stdout(io.StringIO()):
                    code = generation.run_test_gen({"target_contract": "Counter"}, ["--types", "unit"])
            finally:
                os.chdir(previous)
            self.assertEqual(code, 0)
            unit = (root / ".audit" / "test-gen" / "Counter" / "LowkeyGeneratedUnit_Counter.t.sol").read_text(encoding="utf-8")
            self.assertIn("pragma solidity ^0.8.24;", unit)
            self.assertIn('import { Counter } from "../../src/Counter.sol";', unit)


    def test_fork_draft_is_read_only_and_chain_pin_is_optional_but_real(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._project(root)
            previous = Path.cwd()
            try:
                os.chdir(root)
                with contextlib.redirect_stdout(io.StringIO()):
                    code = generation.run_test_gen(
                        {"target_contract": "Counter", "target": "0x1111111111111111111111111111111111111111"},
                        ["--types", "fork"],
                    )
            finally:
                os.chdir(previous)
            self.assertEqual(code, 0)
            fork = (
                root / ".audit" / "test-gen" / "Counter" /
                "LowkeyGeneratedFork_Counter.t.sol"
            ).read_text(encoding="utf-8")
            self.assertIn("LOWKEY_EXPECTED_CHAIN_ID", fork)
            self.assertIn("uint256(0)", fork)
            self.assertIn("if (expectedChainId != 0) assertEq", fork)
            self.assertIn("staticcall(", fork)
            self.assertNotIn("target.setValue(", fork)
            self.assertNotIn("target.setValue(fuzzValue)", fork)


    def test_validate_does_not_blame_drafts_when_baseline_build_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._project(root)
            previous = Path.cwd()
            try:
                os.chdir(root)
                failed = subprocess.CompletedProcess(["forge", "build"], 1, "", "existing compile error")
                with patch("test_generation.shutil.which", return_value="/fake/forge"), patch(
                    "test_generation.subprocess.run", return_value=failed
                ) as run:
                    with contextlib.redirect_stdout(io.StringIO()):
                        code = generation.run_test_gen(
                            {"target_contract": "Counter"},
                            ["--types", "unit", "--validate"],
                        )
            finally:
                os.chdir(previous)
            self.assertEqual(code, 1)
            self.assertEqual(run.call_count, 1)
            report = json.loads(
                (root / ".audit" / "test-gen" / "Counter" / "report.json").read_text(encoding="utf-8")
            )
            self.assertEqual(report["validation"]["status"], "baseline-failed")
            self.assertEqual(report["validation"]["baseline_exit_code"], 1)
            self.assertIn("fails to build before generated drafts", report["validation"]["detail"])

    def test_validate_reports_missing_forge_without_claiming_success(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._project(root)
            previous = Path.cwd()
            try:
                os.chdir(root)
                with patch("test_generation.shutil.which", return_value=None), patch(
                    "test_generation.subprocess.run"
                ) as run:
                    with contextlib.redirect_stdout(io.StringIO()):
                        code = generation.run_test_gen(
                            {"target_contract": "Counter"},
                            ["--types", "unit", "--validate"],
                        )
            finally:
                os.chdir(previous)
            self.assertEqual(code, 1)
            run.assert_not_called()
            report = json.loads(
                (root / ".audit" / "test-gen" / "Counter" / "report.json").read_text(encoding="utf-8")
            )
            self.assertEqual(report["validation"]["status"], "unavailable")
            self.assertIn("forge was not found", report["validation"]["detail"])


    def test_foundry_test_environment_override_controls_import_path(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._project(root)
            previous = Path.cwd()
            try:
                os.chdir(root)
                with patch.dict(os.environ, {"FOUNDRY_TEST": "nested/spec"}), contextlib.redirect_stdout(io.StringIO()):
                    code = generation.run_test_gen({"target_contract": "Counter"}, ["--types", "unit"])
            finally:
                os.chdir(previous)
            self.assertEqual(code, 0)
            unit = (
                root / ".audit" / "test-gen" / "Counter" /
                "LowkeyGeneratedUnit_Counter.t.sol"
            ).read_text(encoding="utf-8")
            self.assertIn('import { Counter } from "../../../src/Counter.sol";', unit)


    def test_dapptools_test_environment_override_is_respected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._project(root)
            previous = Path.cwd()
            try:
                os.chdir(root)
                with patch.dict(os.environ, {"FOUNDRY_TEST": "", "DAPP_TEST": "nested/spec"}), contextlib.redirect_stdout(io.StringIO()):
                    code = generation.run_test_gen({"target_contract": "Counter"}, ["--types", "unit"])
            finally:
                os.chdir(previous)
            self.assertEqual(code, 0)
            unit = (
                root / ".audit" / "test-gen" / "Counter" /
                "LowkeyGeneratedUnit_Counter.t.sol"
            ).read_text(encoding="utf-8")
            self.assertIn('import { Counter } from "../../../src/Counter.sol";', unit)

    def test_custom_foundry_config_and_profile_source_directory_are_respected(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._project(root)
            contracts = root / "contracts"
            contracts.mkdir()
            (contracts / "Counter.sol").write_text(
                "pragma solidity ^0.8.20; contract Counter { uint256 public value; function setValue(uint256 next) external { value = next; } }\n",
                encoding="utf-8",
            )
            config_path = root / "foundry.ci.toml"
            config_path.write_text(
                '[profile.default]\nsrc = "src"\ntest = "test"\n'
                '[profile.ci]\nsrc = "contracts"\ntest = "spec"\n',
                encoding="utf-8",
            )
            (root / "foundry.toml").unlink()
            spec = root / "spec"
            spec.mkdir()
            (spec / "Existing.t.sol").write_text(
                'pragma solidity ^0.8.20; contract ExistingTest { function testExisting() public {} }',
                encoding="utf-8",
            )
            inactive_tests = root / "tests"
            inactive_tests.mkdir()
            (inactive_tests / "Inactive.t.sol").write_text(
                'pragma solidity ^0.8.20; contract InactiveTest { function test_inactive() public {} }',
                encoding="utf-8",
            )
            previous = Path.cwd()
            try:
                os.chdir(root)
                with patch.dict(os.environ, {"FOUNDRY_CONFIG": "foundry.ci.toml", "FOUNDRY_PROFILE": "ci"}), contextlib.redirect_stdout(io.StringIO()):
                    code = generation.run_test_gen({"target_contract": "Counter"}, ["--types", "unit"])
            finally:
                os.chdir(previous)
            self.assertEqual(code, 0)
            output = root / ".audit" / "test-gen" / "Counter" / "LowkeyGeneratedUnit_Counter.t.sol"
            generated = output.read_text(encoding="utf-8")
            self.assertIn('import { Counter } from "../../contracts/Counter.sol";', generated)
            self.assertTrue(spec.exists())
            report = json.loads(
                (root / ".audit" / "test-gen" / "Counter" / "report.json").read_text(encoding="utf-8")
            )
            self.assertEqual(report["analysis"]["existing_tests"]["function_count"], 1)
            self.assertEqual(report["analysis"]["existing_tests"]["files"][0]["path"], "spec/Existing.t.sol")


    def test_formal_only_validation_ignores_unrelated_existing_solidity_drafts(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._project(root)
            output = root / ".audit" / "test-gen" / "Counter"
            output.mkdir(parents=True)
            (output / "LowkeyGeneratedUnit_Counter.t.sol").write_text(
                "pragma solidity ^0.8.20; contract OldDraft {}",
                encoding="utf-8",
            )
            previous = Path.cwd()
            try:
                os.chdir(root)
                completed = subprocess.CompletedProcess(["forge", "build"], 0, "ok", "")
                with patch("test_generation.shutil.which", return_value="/fake/forge"), patch(
                    "test_generation.subprocess.run", return_value=completed
                ) as run, contextlib.redirect_stdout(io.StringIO()):
                    code = generation.run_test_gen(
                        {"target_contract": "Counter"},
                        ["--types", "formal", "--validate"],
                    )
            finally:
                os.chdir(previous)
            self.assertEqual(code, 1)
            run.assert_not_called()
            report = json.loads(
                (root / ".audit" / "test-gen" / "Counter" / "report.json").read_text(encoding="utf-8")
            )
            self.assertEqual(report["validation"]["status"], "not-applicable")
            self.assertIn("Formal specs are not validated by Forge", report["validation"]["detail"])


    def test_test_plan_includes_protocol_specific_obligations_for_detected_profile(self):
        from test_generation_analysis import render_test_plan

        plan = render_test_plan(
            {
                "contract": "Token",
                "source": "src/Token.sol",
                "inheritance": [],
                "profiles": ["ERC-20-like token", "ERC-721-like NFT"],
                "security_surfaces": {},
                "existing_tests": {"file_count": 0, "function_count": 0, "files": []},
                "functions": [],
                "imports": [],
                "audit_evidence": {"files": [], "signals": [], "note": "No evidence"},
                "limitations": [],
            },
            ["unit", "invariant"],
        )
        self.assertIn("Profile-specific test obligations", plan)
        self.assertIn("Source SHA-256:", plan)
        self.assertIn("allowance consumption", plan)
        self.assertIn("safe-transfer callbacks", plan)
        self.assertIn("candidate checks suggested by source/interface cues", plan)


    def test_validation_ignores_stale_solidity_files_not_generated_this_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._project(root)
            stale_dir = root / ".audit" / "test-gen" / "Counter"
            stale_dir.mkdir(parents=True)
            (stale_dir / "OldDraft.t.sol").write_text(
                "pragma solidity ^0.8.20; contract OldDraftTest {}",
                encoding="utf-8",
            )
            previous = Path.cwd()
            try:
                os.chdir(root)
                with patch("test_generation.shutil.which", return_value="/fake/forge"), patch(
                    "test_generation.subprocess.run"
                ) as run, contextlib.redirect_stdout(io.StringIO()):
                    code = generation.run_test_gen(
                        {"target_contract": "Counter"},
                        ["--types", "formal", "--validate"],
                    )
            finally:
                os.chdir(previous)
            self.assertEqual(code, 1)
            run.assert_not_called()
            report = json.loads(
                (stale_dir / "report.json").read_text(encoding="utf-8")
            )
            self.assertEqual(report["validation"]["status"], "not-applicable")
            self.assertIn("No generated Solidity drafts", report["validation"]["detail"])

    def test_profiles_use_inherited_standard_evidence_and_include_niche_obligations(self):
        from test_generation_analysis import analyse_contract, render_test_plan

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_dir = root / "src"
            source_dir.mkdir()
            source_path = source_dir / "Vault.sol"
            source = "pragma solidity ^0.8.20; contract Vault is ERC4626, UUPSUpgradeable {}"
            source_path.write_text(source, encoding="utf-8")
            analysis = analyse_contract(root, "Vault", source_path, source)
            self.assertIn("ERC4626", analysis["inheritance"])
            self.assertIn("UUPSUpgradeable", analysis["inheritance"])
            self.assertIn("ERC-4626-like vault", analysis["profiles"])
            self.assertIn("proxy / upgradeable", analysis["profiles"])
            plan = render_test_plan(analysis, ["unit", "invariant"])
            self.assertIn("donation/inflation attacks", plan)
            self.assertIn("initializer front-running", plan)

            multi_source_path = source_dir / "MultiToken.sol"
            multi_source = "pragma solidity ^0.8.20; contract MultiToken is ERC1155 {}"
            multi_source_path.write_text(multi_source, encoding="utf-8")
            multi_analysis = analyse_contract(root, "MultiToken", multi_source_path, multi_source)
            self.assertIn("ERC-1155-like multi-token", multi_analysis["profiles"])
            multi_plan = render_test_plan(multi_analysis, ["unit"])
            self.assertIn("single and batch mint", multi_plan)

    def test_mixed_solidity_and_formal_validation_reports_partial_scope(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._project(root)
            previous = Path.cwd()
            try:
                os.chdir(root)
                completed = subprocess.CompletedProcess(["forge", "build"], 0, "compile ok", "")
                with patch("test_generation.shutil.which", return_value="/fake/forge"), patch(
                    "test_generation.subprocess.run", return_value=completed
                ) as run, contextlib.redirect_stdout(io.StringIO()):
                    code = generation.run_test_gen(
                        {"target_contract": "Counter"},
                        ["--types", "unit,formal", "--force", "--validate"],
                    )
            finally:
                os.chdir(previous)
            self.assertEqual(code, 1)
            self.assertEqual(run.call_count, 2)
            report = json.loads(
                (root / ".audit" / "test-gen" / "Counter" / "report.json").read_text(encoding="utf-8")
            )
            self.assertEqual(report["validation"]["status"], "partial")
            self.assertEqual(report["validation"]["unvalidated_types"], ["formal"])
            self.assertIn("formal specification was not checked by Forge", report["validation"]["detail"])

    def test_external_active_test_directory_is_inventoried_without_relative_path_error(self):
        from test_generation_analysis import analyse_contract

        with tempfile.TemporaryDirectory() as project_tmp, tempfile.TemporaryDirectory() as tests_tmp:
            root = Path(project_tmp)
            self._project(root)
            external = Path(tests_tmp)
            test_file = external / "External.t.sol"
            test_file.write_text(
                'pragma solidity ^0.8.20; contract ExternalTest { function test_external() public {} }',
                encoding="utf-8",
            )
            source_path = root / "src" / "Counter.sol"
            source = source_path.read_text(encoding="utf-8")
            analysis = analyse_contract(root, "Counter", source_path, source, external)
            self.assertEqual(analysis["existing_tests"]["file_count"], 1)
            self.assertEqual(analysis["existing_tests"]["files"][0]["path"], str(test_file))


    def test_test_plan_covers_defi_and_account_abstraction_edge_cases(self):
        from test_generation_analysis import render_test_plan

        plan = render_test_plan(
            {
                "contract": "Protocol",
                "source": "src/Protocol.sol",
                "inheritance": [],
                "profiles": ["AMM / DEX", "ERC-4337 account abstraction", "Merkle claims / airdrop"],
                "security_surfaces": {},
                "existing_tests": {"file_count": 0, "function_count": 0, "files": []},
                "functions": [],
                "imports": [],
                "audit_evidence": {"files": [], "signals": [], "note": "No evidence"},
                "limitations": [],
            },
            ["fuzz", "invariant"],
        )
        self.assertIn("price-impact manipulation", plan)
        self.assertIn("UserOperation hash domain separation", plan)
        self.assertIn("duplicate claims", plan)


    def test_source_cues_recognize_amm_account_abstraction_flashloan_and_claim_profiles(self):
        from test_generation_analysis import analyse_contract

        source = """pragma solidity ^0.8.20;
contract Protocol {
    address public entryPoint;
    bytes32 public merkleRoot;
    bool public claimed;
    function swap() external {}
    function getReserves() external {}
    function validateUserOp() external {}
    function flashLoan() external {}
    function onFlashLoan() external {}
    function claim(bytes32[] calldata proof) external {}
    function cancelListing() external {}
    function royalty() external {}
    function safeTransferFrom() external {}
}
"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source_path = root / "Protocol.sol"
            source_path.write_text(source, encoding="utf-8")
            analysis = analyse_contract(root, "Protocol", source_path, source)
        for profile in (
            "AMM / DEX",
            "ERC-4337 account abstraction",
            "flash-loan / callback",
            "Merkle claims / airdrop",
            "NFT marketplace",
        ):
            self.assertIn(profile, analysis["profiles"], profile)



    def test_generation_assessment_does_not_overstate_scaffolds(self):
        assessment = generation._generation_assessment(
            ["unit", "fuzz", "invariant", "integration", "fork", "poc", "regression", "formal"],
            local_deploy=True,
            is_abstract=False,
            fuzz_property=None,
            target=None,
        )
        self.assertEqual(assessment["unit"]["level"], "smoke-only")
        self.assertEqual(assessment["fuzz"]["level"], "scaffold")
        self.assertEqual(assessment["invariant"]["level"], "scaffold")
        self.assertEqual(assessment["integration"]["level"], "scaffold")
        self.assertEqual(assessment["fork"]["level"], "requires-target")
        self.assertEqual(assessment["poc"]["level"], "scaffold")
        self.assertEqual(assessment["regression"]["level"], "scaffold")
        self.assertEqual(assessment["formal"]["level"], "worksheet")
        self.assertTrue(all(item["protocol_security_established"] is False for item in assessment.values()))


    def test_poc_uses_matching_recorded_call_as_replay_not_security_proof(self):
        from types import SimpleNamespace

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._project(root)
            target = "0x1111111111111111111111111111111111111111"
            fake_generator = SimpleNamespace(
                _request_from_latest=lambda project_root, expected_target: SimpleNamespace(
                    target=target, function="transfer", value="0", calldata="0xa9059cbb"
                ),
                _template_test=lambda contract, address, function, value, calldata, **kwargs: (
                    'pragma solidity ^0.8.20;\\n'
                    'contract LowkeyTest_Counter {\\n'
                    'function setUp() public { vm.createSelectFork(rpcUrl); }\\n'
                    '}\\n'
                ),
            )
            previous = Path.cwd()
            try:
                os.chdir(root)
                with patch.dict("sys.modules", {"generator": fake_generator}), contextlib.redirect_stdout(io.StringIO()):
                    code = generation.run_test_gen(
                        {"target_contract": "Counter", "target": target},
                        ["--types", "poc"],
                    )
            finally:
                os.chdir(previous)
            self.assertEqual(code, 0)
            folder = root / ".audit" / "test-gen" / "Counter"
            poc = (folder / "LowkeyGeneratedPoc_Counter.t.sol").read_text(encoding="utf-8")
            report = json.loads((folder / "report.json").read_text(encoding="utf-8"))
            self.assertIn("LOWKEY_FORK_BLOCK", poc)
            self.assertIn("LOWKEY_EXPECTED_CHAIN_ID", poc)
            self.assertIn("replays recorded calldata", poc)
            self.assertEqual(report["poc_replay"]["mode"], "recorded-call-replay")
            self.assertFalse(report["poc_replay"]["security_impact_assertion"])
            self.assertEqual(report["generation_assessment"]["poc"]["level"], "recorded-call-replay")


    def test_strict_mode_fails_when_requested_types_are_only_scaffolds(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._project(root)
            previous = Path.cwd()
            try:
                os.chdir(root)
                with contextlib.redirect_stdout(io.StringIO()):
                    code = generation.run_test_gen(
                        {"target_contract": "Counter"},
                        ["--types", "all", "--strict"],
                    )
            finally:
                os.chdir(previous)
            self.assertEqual(code, 1)
            report = json.loads(
                (root / ".audit" / "test-gen" / "Counter" / "report.json").read_text(encoding="utf-8")
            )
            self.assertTrue(report["strict"])
            blocker_types = {item["type"] for item in report["strict_blockers"]}
            self.assertTrue({"integration", "poc", "regression", "formal", "fork"} <= blocker_types)
            self.assertEqual(report["generation_assessment"]["unit"]["level"], "executable-candidate")


    def test_strict_mode_requires_and_accepts_successful_compile_validation(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            self._project(root)
            previous = Path.cwd()
            try:
                os.chdir(root)
                with patch(
                    "test_generation._validate_generated",
                    return_value={"requested": True, "status": "passed", "detail": "compiled"},
                ), contextlib.redirect_stdout(io.StringIO()):
                    code = generation.run_test_gen(
                        {"target_contract": "Counter"},
                        ["--types", "unit,fuzz,invariant", "--strict", "--validate"],
                    )
            finally:
                os.chdir(previous)
            self.assertEqual(code, 0)
            report = json.loads(
                (root / ".audit" / "test-gen" / "Counter" / "report.json").read_text(encoding="utf-8")
            )
            self.assertEqual(report["strict_blockers"], [])
            self.assertEqual(report["validation"]["status"], "passed")


    def test_test_plan_covers_additional_defi_and_infrastructure_profiles(self):
        from test_generation_analysis import render_test_plan

        profiles = [
            "AMM / DEX",
            "ERC-4337 account abstraction",
            "flash-loan / callback",
            "Merkle claims / airdrop",
            "NFT marketplace",
            "proxy / upgradeable",
            "ERC-1155-like multi-token",
        ]
        plan = render_test_plan(
            {
                "contract": "Protocol",
                "source": "src/Protocol.sol",
                "inheritance": [],
                "profiles": profiles,
                "security_surfaces": {},
                "existing_tests": {"file_count": 0, "function_count": 0, "files": []},
                "functions": [],
                "imports": [],
                "audit_evidence": {"files": [], "signals": [], "note": "No evidence"},
                "limitations": [],
            },
            ["unit", "fuzz", "invariant", "integration", "fork", "poc", "regression", "formal"],
        )
        for obligation in (
            "price-impact manipulation",
            "UserOperation hash domain separation",
            "callback initiator",
            "leaf domain separation",
            "signed orders bind chain",
            "initializer and reinitializer",
            "duplicate token IDs",
        ):
            with self.subTest(obligation=obligation):
                self.assertIn(obligation, plan)

if __name__ == "__main__":
    unittest.main()
