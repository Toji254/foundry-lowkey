import tempfile
import io
import json
from contextlib import redirect_stdout
from unittest.mock import patch
import unittest
from pathlib import Path

from lowkey.generation_plugins import (
    GenerationRegistry,
    SolidityFoundryGenerationAdapter,
    VyperTitanoboaGenerationAdapter,
    run_generation_command,
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


    def test_generation_help_documents_language_routing_and_namespaced_vyper_outputs(self):
        output = io.StringIO()
        with redirect_stdout(output):
            code = run_generation_command({}, ["--help"])
        self.assertEqual(code, 0)
        rendered = output.getvalue()
        self.assertIn("--language solidity|vyper", rendered)
        self.assertIn("requested contract", rendered.lower())
        self.assertIn(".audit/test-gen/vyper/", rendered)

    def test_cli_generation_command_routes_through_registry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "foundry.toml").write_text('[profile.default]\\nsrc = "src"\\n', encoding="utf-8")
            (root / "src" / "Counter.sol").write_text(
                "pragma solidity ^0.8.20; contract Counter { uint256 public count; "
                "function setCount(uint256 value) external { count = value; } }",
                encoding="utf-8",
            )
            output = io.StringIO()
            with patch("lowkey.generation_plugins.project_root_from_config", return_value=str(root)), redirect_stdout(output):
                code = run_generation_command({}, ["Counter", "--types", "unit,fuzz"])
            self.assertEqual(code, 0)
            self.assertIn("Generation plugin: solidity-foundry", output.getvalue())
            self.assertIn("property: count equals", output.getvalue())

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
            self.assertEqual(run.status, "partial")
            self.assertTrue(Path(run.report_path).is_file())
            kinds = {artifact.kind for artifact in run.artifacts}
            self.assertEqual(kinds, {"unit", "fuzz"})
            fuzz = next(artifact for artifact in run.artifacts if artifact.kind == "fuzz")
            self.assertIn("count equals", fuzz.intended_property)
            self.assertTrue(fuzz.metadata["review_required"])
            self.assertEqual(fuzz.status, "generated-unvalidated")
            self.assertIn("formal", {item["type"] for item in run.metadata["skipped"]})
            self.assertNotIn("formal", kinds)



    def test_generator_uses_fresh_latest_report_instead_of_stale_report_json(self):
        import sys
        import types

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "foundry.toml").write_text('[profile.default]\nsrc = "src"\n', encoding="utf-8")
            (root / "src" / "Counter.sol").write_text(
                "pragma solidity ^0.8.20; contract Counter { uint256 public count; "
                "function setCount(uint256 value) external { count = value; } }",
                encoding="utf-8",
            )
            output_root = root / ".audit" / "test-gen" / "Counter"
            output_root.mkdir(parents=True)
            (output_root / "report.json").write_text(json.dumps({
                "contract": "Counter",
                "source": "src/Counter.sol",
                "source_sha256": "old",
                "requested_types": ["unit", "formal"],
                "generated": ["test/OldUnit.t.sol"],
                "skipped": [{"type": "formal", "reason": "old run"}],
                "fuzz_property": {"state": "staleState", "setter": "staleSetter", "type": "uint256"},
                "validation": {"requested": False, "status": "not-requested"},
            }), encoding="utf-8")

            fake = types.ModuleType("test_generation")
            fake._solidity_name = lambda value: value
            fake._contract_source = lambda source_root, contract: (
                Path(source_root) / "src" / "Counter.sol",
                "pragma solidity ^0.8.20; contract Counter {}",
            )

            def write_fresh_report(config, args, *, project_root):
                latest = output_root / "report.latest.json"
                latest.write_text(json.dumps({
                    "contract": "Counter",
                    "source": "src/Counter.sol",
                    "source_sha256": "fresh",
                    "requested_types": ["unit"],
                    "generated": ["test/LowkeyGeneratedUnit_Counter.t.sol"],
                    "skipped": [],
                    "fuzz_property": {"state": "count", "setter": "setCount", "type": "uint256"},
                    "validation": {"requested": False, "status": "not-requested"},
                }), encoding="utf-8")
                return 0

            fake.run_test_gen = write_fresh_report
            project = inspect_project(root)
            with patch.dict(sys.modules, {"test_generation": fake}):
                runs = GenerationRegistry([SolidityFoundryGenerationAdapter()]).generate(
                    project,
                    {"contract": "Counter", "types": ["unit"]},
                )

            self.assertEqual(len(runs), 1)
            run = runs[0]
            self.assertEqual(Path(run.report_path).name, "report.latest.json")
            self.assertEqual(run.status, "generated")
            self.assertEqual(run.artifacts[0].provenance["source_sha256"], "fresh")
            self.assertEqual(len(run.artifacts), 1)
            self.assertIn("count equals", run.artifacts[0].intended_property)
            self.assertEqual(run.metadata["skipped"], [])


    def test_mixed_language_registry_runs_matching_backends_without_report_collision(self):
        import sys
        import types

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "contracts").mkdir()
            (root / "foundry.toml").write_text('[profile.default]\nsrc = "src"\n', encoding="utf-8")
            (root / "src" / "Counter.sol").write_text(
                "pragma solidity ^0.8.20; contract Counter { uint256 public count; "
                "function setCount(uint256 value) external { count = value; } }",
                encoding="utf-8",
            )
            (root / "contracts" / "Counter.vy").write_text(
                "# pragma version ^0.4.3\n"
                "count: public(uint256)\n"
                "@external\n"
                "def set_count(next_value: uint256):\n"
                "    self.count = next_value\n",
                encoding="utf-8",
            )
            project = {
                "root": str(root),
                "language": "solidity",
                "languages": ["solidity", "vyper"],
                "build_system": "foundry",
                "build_systems": ["foundry", "vyper"],
            }
            fake_modules = {
                "boa": types.ModuleType("boa"),
                "pytest": types.ModuleType("pytest"),
                "hypothesis": types.ModuleType("hypothesis"),
            }
            with patch.dict(sys.modules, fake_modules), patch(
                "lowkey.generation_plugins.shutil.which", return_value="/usr/bin/vyper"
            ):
                runs = GenerationRegistry([
                    SolidityFoundryGenerationAdapter(),
                    VyperTitanoboaGenerationAdapter(),
                ]).generate(project, {"contract": "Counter", "types": ["unit"]})

            self.assertEqual({run.generator for run in runs}, {"solidity-foundry", "vyper-titanoboa"})
            self.assertTrue(all(run.status == "generated" for run in runs), [
                (run.generator, run.status, run.stderr, run.metadata) for run in runs
            ])
            report_paths = {Path(run.report_path).resolve() for run in runs}
            self.assertEqual(len(report_paths), 2)
            self.assertTrue((root / ".audit" / "test-gen" / "Counter" / "report.json").is_file())
            self.assertTrue((root / ".audit" / "test-gen" / "vyper" / "Counter" / "report.json").is_file())
            artifact_paths = {Path(artifact.path).resolve() for run in runs for artifact in run.artifacts}
            self.assertEqual(len(artifact_paths), 2)
            self.assertEqual(
                {artifact.kind for run in runs for artifact in run.artifacts},
                {"unit"},
            )

    def test_mixed_language_registry_routes_to_source_that_matches_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "contracts").mkdir()
            (root / "foundry.toml").write_text('[profile.default]\nsrc = "src"\n', encoding="utf-8")
            (root / "src" / "Counter.sol").write_text(
                "pragma solidity ^0.8.20; contract Counter { uint256 public count; "
                "function setCount(uint256 value) external { count = value; } }",
                encoding="utf-8",
            )
            (root / "contracts" / "Other.vy").write_text(
                "other_count: public(uint256)\n"
                "@external\n"
                "def set_other_count(next_value: uint256):\n"
                "    self.other_count = next_value\n",
                encoding="utf-8",
            )
            project = {
                "root": str(root),
                "language": "solidity",
                "languages": ["solidity", "vyper"],
                "build_system": "foundry",
                "build_systems": ["foundry", "vyper"],
            }
            # No Vyper runtime is needed: source matching filters out the backend
            # whose source inventory does not contain Counter.
            runs = GenerationRegistry([
                SolidityFoundryGenerationAdapter(),
                VyperTitanoboaGenerationAdapter(),
            ]).generate(
                project,
                {"contract": "Counter", "types": ["unit"], "output_dir": ".audit/solidity-only"},
            )
            self.assertEqual([run.generator for run in runs], ["solidity-foundry"])
            self.assertEqual(runs[0].status, "generated")
    def test_vyper_adapter_generates_only_executable_property_tests(self):
        import sys
        import types

        adapter = VyperTitanoboaGenerationAdapter()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "contracts").mkdir()
            source = (
                "# pragma version ^0.4.3\n"
                "count: public(uint256)\n"
                "@external\n"
                "def set_count(next_value: uint256):\n"
                "    self.count = next_value\n"
            )
            (root / "contracts" / "Counter.vy").write_text(source, encoding="utf-8")
            project = {
                "root": str(root),
                "language": "vyper",
                "languages": ["vyper"],
                "build_system": "",
                "build_systems": [],
            }
            fake_modules = {
                "boa": types.ModuleType("boa"),
                "pytest": types.ModuleType("pytest"),
                "hypothesis": types.ModuleType("hypothesis"),
            }
            with patch.dict(sys.modules, fake_modules), patch(
                "lowkey.generation_plugins.shutil.which", return_value="/usr/bin/vyper"
            ):
                run = adapter.generate(
                    project,
                    {"contract": "Counter", "types": ["unit", "fuzz", "invariant"]},
                )

            self.assertEqual(run.status, "generated", run.stderr + repr(run.metadata))
            self.assertEqual(len(run.artifacts), 3)
            report = json.loads(Path(run.report_path).read_text(encoding="utf-8"))
            self.assertEqual(report["skipped"], [])
            self.assertFalse(report["protocol_security_established"])
            self.assertEqual({artifact.kind for artifact in run.artifacts}, {"unit", "fuzz", "invariant"})
            for artifact in run.artifacts:
                generated = Path(artifact.path).read_text(encoding="utf-8")
                self.assertIn("assert target.count() == ", generated)
                self.assertNotRegex(generated, r"(?i)\\bTODO\\b|\\bstarter\\b|\\bscaffold\\b")
                self.assertEqual(artifact.status, "generated-unvalidated")

    def test_vyper_adapter_refuses_categories_without_a_real_implementation(self):
        import sys
        import types

        adapter = VyperTitanoboaGenerationAdapter()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "Counter.vy").write_text(
                "count: public(uint256)\n@external\ndef set_count(next_value: uint256):\n    self.count = next_value\n",
                encoding="utf-8",
            )
            project = {"root": str(root), "language": "vyper", "languages": ["vyper"]}
            fake_modules = {
                "boa": types.ModuleType("boa"),
                "pytest": types.ModuleType("pytest"),
                "hypothesis": types.ModuleType("hypothesis"),
            }
            with patch.dict(sys.modules, fake_modules), patch(
                "lowkey.generation_plugins.shutil.which", return_value="/usr/bin/vyper"
            ):
                run = adapter.generate(project, {"contract": "Counter", "types": ["integration", "formal"]})

            self.assertEqual(run.status, "partial")
            self.assertEqual(run.artifacts, [])
            self.assertEqual(
                {item["type"] for item in run.metadata["skipped"]},
                {"integration", "formal"},
            )
            report = json.loads(Path(run.report_path).read_text(encoding="utf-8"))
            self.assertEqual(report["generated"], [])


if __name__ == "__main__":
    unittest.main()
