import unittest
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

from lowkey.verification_adapters import (
    CapabilityRegistry, EngineCapability, EngineResult, ExecutableAdapter,
    TEST_KINDS, default_registry, inspect_project,
)


class VerificationAdapterRegistryTests(unittest.TestCase):
    def test_all_seven_test_kinds_are_declared(self):
        self.assertEqual(
            set(TEST_KINDS),
            {"unit", "integration", "invariant", "exploit", "regression", "fuzz", "formal"},
        )

    def test_project_inspection_detects_foundry_and_solidity(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "foundry.toml").write_text('[profile.default]\\nsrc = "src"\\n', encoding="utf-8")
            (root / "src" / "Vault.sol").write_text("pragma solidity ^0.8.20; contract Vault {}", encoding="utf-8")
            project = inspect_project(root)
        self.assertIn("foundry.toml", project["markers"])
        self.assertIn("solidity", project["languages"])
        self.assertIn("foundry", project["build_systems"])

    def test_registry_selects_using_detected_project_descriptor(self):
        cap = EngineCapability(
            "python-test", sys.executable, ("unit",), ("solidity",), ("foundry",),
            ("foundry.toml",), memory_class="low",
        )
        registry = CapabilityRegistry([ExecutableAdapter(cap)])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "foundry.toml").write_text('[profile.default]\\nsrc = "src"\\n', encoding="utf-8")
            (root / "src" / "Vault.sol").write_text("pragma solidity ^0.8.20; contract Vault {}", encoding="utf-8")
            project = inspect_project(root)
            selected = registry.select(project, "unit", profile="light")
        self.assertEqual([item["engine"] for item in selected], ["python-test"])

    def test_registry_rejects_duplicate_names(self):
        cap = EngineCapability("forge", "forge", ("unit",))
        registry = CapabilityRegistry([ExecutableAdapter(cap)])
        with self.assertRaisesRegex(ValueError, "already registered"):
            registry.register(ExecutableAdapter(cap))

    def test_selection_uses_project_support_and_executable_presence(self):
        cap = EngineCapability("fake", "fake-engine", ("unit",), ("solidity",), ("foundry",), memory_class="low")
        adapter = ExecutableAdapter(cap)
        registry = CapabilityRegistry([adapter])
        with patch("lowkey.verification_adapters.shutil.which", return_value="/usr/bin/fake-engine"):
            selected = registry.select({"language": "solidity", "build_system": "foundry"}, "unit", profile="light")
            unsupported = registry.select({"language": "rust", "build_system": "cargo"}, "unit", profile="light")
        self.assertEqual([x["engine"] for x in selected], ["fake"])
        self.assertEqual(unsupported, [])

    def test_light_profile_excludes_high_memory_engines(self):
        registry = default_registry()
        with patch("lowkey.verification_adapters.shutil.which", return_value="/usr/bin/tool"):
            light = registry.select({"language": "solidity", "build_system": "foundry", "markers": ["foundry.toml"]}, "fuzz", profile="light")
            deep = registry.select({"language": "solidity", "build_system": "foundry", "markers": ["foundry.toml"]}, "formal", profile="deep")
        self.assertNotIn("halmos", {x["engine"] for x in light})
        self.assertIn("halmos", {x["engine"] for x in deep})

    def test_adapter_runs_argument_vector_and_preserves_output(self):
        cap = EngineCapability("python-test", sys.executable, ("unit",), memory_class="low")
        adapter = ExecutableAdapter(cap)
        with tempfile.TemporaryDirectory() as root:
            result = adapter.run(
                {"root": root},
                {"test_kind": "unit", "argv": ["-c", "print('native evidence')"]},
                budget={"timeout_seconds": 5},
            )
        self.assertEqual(result.status, "passed")
        self.assertIn("native evidence", result.raw_stdout)
        self.assertEqual(result.raw_evidence["cwd"], root)

    def test_adapter_reports_nonzero_exit_without_losing_stderr(self):
        cap = EngineCapability("python-test", sys.executable, ("unit",), memory_class="low")
        adapter = ExecutableAdapter(cap)
        with tempfile.TemporaryDirectory() as root:
            result = adapter.run(
                {"root": root},
                {"test_kind": "unit", "argv": ["-c", "import sys; print('failure evidence', file=sys.stderr); sys.exit(7)"]},
                budget={"timeout_seconds": 5},
            )
        self.assertEqual(result.status, "failed")
        self.assertEqual(result.exit_code, 7)
        self.assertIn("failure evidence", result.raw_stderr)

    def test_adapter_times_out_and_terminates_process(self):
        cap = EngineCapability("python-test", sys.executable, ("unit",), memory_class="low")
        adapter = ExecutableAdapter(cap)
        with tempfile.TemporaryDirectory() as root:
            result = adapter.run(
                {"root": root},
                {"test_kind": "unit", "argv": ["-c", "import time; time.sleep(5)"]},
                budget={"timeout_seconds": 1},
            )
        self.assertEqual(result.status, "timeout")
        self.assertEqual(result.exit_code, 124)

    def test_campaign_runs_selected_adapters_serially(self):
        cap = EngineCapability("python-test", sys.executable, ("unit",), memory_class="low")
        registry = CapabilityRegistry([ExecutableAdapter(cap)])
        with tempfile.TemporaryDirectory() as root:
            campaign = registry.run_campaign(
                {"root": root}, "unit",
                request={"argv_by_engine": {"python-test": ["-c", "print('campaign evidence')"]}},
                budget={"timeout_seconds": 5}, profile="light",
            )
        self.assertEqual(campaign["execution_mode"], "serial")
        self.assertEqual(campaign["selected_count"], 1)
        self.assertEqual(campaign["summary"]["passed"], 1)
        self.assertIn("campaign evidence", campaign["results"][0]["result"]["raw_stdout"])

    def test_campaign_scales_fuzz_depth_and_timeout_by_profile(self):
        class CaptureAdapter:
            capability = EngineCapability("forge", "forge", ("fuzz",), memory_class="low")
            def available(self):
                return True
            def supports(self, project, test_kind):
                return True, "fixture"
            def run(self, project, request, *, budget):
                self.request = request
                self.budget = budget
                return EngineResult("forge", "passed", 0, raw_evidence={"argv": request.get("argv")})

        for profile, expected_runs, expected_timeout in (("light", "32", 60), ("deep", "1024", 900)):
            adapter = CaptureAdapter()
            campaign = CapabilityRegistry([adapter]).run_campaign(
                {"root": "."}, "fuzz", profile=profile,
            )
            self.assertEqual(campaign["execution_mode"], "serial")
            self.assertIn(expected_runs, adapter.request["argv"])
            self.assertEqual(adapter.budget["timeout_seconds"], expected_timeout)

    def test_engine_result_keeps_native_evidence(self):
        result = EngineResult("forge", "failed", 1, raw_stdout="failed", raw_evidence={"trace": ["0xabc"]})
        serialized = result.to_dict()
        self.assertEqual(serialized["raw_evidence"], {"trace": ["0xabc"]})
        self.assertEqual(serialized["raw_stdout"], "failed")

    def test_unknown_test_kind_and_profile_fail_explicitly(self):
        registry = default_registry()
        with self.assertRaisesRegex(ValueError, "unknown test kind"):
            registry.select({}, "magic")
        with self.assertRaisesRegex(ValueError, "unknown resource profile"):
            registry.select({}, "unit", profile="unlimited")


if __name__ == "__main__":
    unittest.main()
