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

    def test_lockfile_dependency_install_command_is_deterministic(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text(
                json.dumps({"packageManager": "yarn@4.0.2"}), encoding="utf-8"
            )
            (root / "yarn.lock").write_text("# yarn lockfile v1\n", encoding="utf-8")
            (root / ".yarn" / "releases").mkdir(parents=True)
            (root / ".yarn" / "releases" / "yarn-4.0.2.cjs").write_text("", encoding="utf-8")
            self.assertEqual(
                BENCHMARK._dependency_install_command(root),
                ["node", str(root / ".yarn" / "releases" / "yarn-4.0.2.cjs"),
                 "install", "--immutable", "--mode=skip-builds"],
            )

    def test_npm_lockfile_uses_clean_reproducible_dependency_install(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text("{}", encoding="utf-8")
            (root / "package-lock.json").write_text("{}", encoding="utf-8")
            self.assertEqual(
                BENCHMARK._dependency_install_command(root),
                ["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"],
            )

    def test_forge_std_detection_accepts_custom_project_remapping(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            custom = root / "test" / "utils" / "forge-std" / "src"
            custom.mkdir(parents=True)
            (custom / "Test.sol").write_text("contract Test {}", encoding="utf-8")
            config = root / "foundry.toml"
            config.write_text(
                '[profile.default]\nremappings = ["forge-std=test/utils/forge-std/"]\n',
                encoding="utf-8",
            )
            self.assertTrue(BENCHMARK._forge_std_available(root, config))

    def test_forge_std_detection_does_not_accept_missing_harness(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / "foundry.toml"
            config.write_text('[profile.default]\nlibs = ["lib"]\n', encoding="utf-8")
            self.assertFalse(BENCHMARK._forge_std_available(root, config))

    def test_foundry_node_modules_detection_reads_declared_library_roots(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            config = root / "foundry.toml"
            config.write_text(
                '[profile.default]\nlibs = ["lib", "node_modules"]\n',
                encoding="utf-8",
            )
            self.assertTrue(BENCHMARK._config_uses_node_modules(config))
            config.write_text('[profile.default]\nlibs = ["lib"]\n', encoding="utf-8")
            self.assertFalse(BENCHMARK._config_uses_node_modules(config))

    def test_nearest_foundry_root_resolves_nested_package_from_source(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            package = root / "packages" / "example" / "evm"
            (package / "contracts").mkdir(parents=True)
            (package / "foundry.toml").write_text("[profile.default]\nsrc = \"contracts\"\n", encoding="utf-8")
            source = package / "contracts" / "Target.sol"
            source.write_text("contract Target {}", encoding="utf-8")
            found = BENCHMARK._nearest_foundry_root(root, source.relative_to(root).as_posix())
            self.assertEqual(found, package)

    def test_synthetic_config_is_isolated_and_infers_nested_contract_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            source = root / "packages" / "legacy" / "contracts" / "Target.sol"
            source.parent.mkdir(parents=True)
            source.write_text("contract Target {}", encoding="utf-8")
            config, synthetic = BENCHMARK._synthetic_foundry_config(
                root, ["packages/legacy/contracts/Target.sol"]
            )
            self.assertTrue(synthetic)
            self.assertEqual(config, root / ".audit" / "lowkey-ecosystem-foundry.toml")
            content = config.read_text(encoding="utf-8")
            self.assertIn('src = "packages/legacy/contracts"', content)
            self.assertFalse((root / "foundry.toml").exists())

    def test_abstract_contract_detection_is_source_anchored(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "contracts").mkdir()
            (root / "contracts" / "Targets.sol").write_text(
                "abstract contract AbstractTarget {} contract ConcreteTarget {}",
                encoding="utf-8",
            )
            self.assertTrue(BENCHMARK._is_abstract_contract(root, "contracts/Targets.sol", "AbstractTarget"))
            self.assertFalse(BENCHMARK._is_abstract_contract(root, "contracts/Targets.sol", "ConcreteTarget"))

    def test_report_assessment_requires_a_reason_for_every_requested_type(self):
        report = {
            "requested_types": ["unit", "formal"],
            "generation_assessment": {
                "unit": {"level": "executable-candidate", "note": "A grounded getter/setter property."},
                "formal": {"level": "not-generated", "note": "No verifier specification."},
            },
            "generated": [],
        }
        self.assertTrue(BENCHMARK._report_accounts_for_every_type(report))
        report["generation_assessment"].pop("formal")
        self.assertFalse(BENCHMARK._report_accounts_for_every_type(report))

    def test_manifest_negative_control_is_recorded_as_expected_unsupported(self):
        outcome = BENCHMARK.expected_unsupported_outcome({
            "id": "non-protocol-fixture",
            "expected_outcome": "Classify this test framework as unsupported.",
        })
        self.assertEqual(
            outcome,
            {
                "status": "expected-unsupported",
                "reason": "Classify this test framework as unsupported.",
            },
        )
        self.assertIsNone(BENCHMARK.expected_unsupported_outcome({"id": "ordinary-project"}))

    def test_target_is_not_marked_passed_when_generator_command_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            output_root = root / ".audit" / "benchmark"

            def fake_run(command, cwd=None, timeout=1800, env=None):
                output_dir = Path(command[command.index("--output-dir") + 1])
                report_dir = output_dir / "UnfamiliarContract"
                report_dir.mkdir(parents=True, exist_ok=True)
                if command[command.index("--types") + 1] == "all":
                    (report_dir / "report.json").write_text(
                        json.dumps({"generation_assessment": {"unit": {"level": "executable-candidate"}}}),
                        encoding="utf-8",
                    )
                    return {"command": command, "exit_code": 1, "stdout_tail": "", "stderr_tail": "generation error"}
                (report_dir / "report.json").write_text(
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

            def fake_run(command, cwd=None, timeout=1800, env=None):
                output_dir = Path(command[command.index("--output-dir") + 1])
                report_dir = output_dir / "UnfamiliarContract"
                report_dir.mkdir(parents=True, exist_ok=True)
                if command[command.index("--types") + 1] == "all":
                    (report_dir / "report.json").write_text(
                        json.dumps({"generation_assessment": {"unit": {"level": "executable-candidate"}}}),
                        encoding="utf-8",
                    )
                else:
                    (report_dir / "report.json").write_text(
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
