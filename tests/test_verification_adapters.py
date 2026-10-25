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

    def test_engine_capability_rejects_blank_name_or_command(self):
        for name, command, message in (
            ("   ", "forge", "name must not be empty"),
            ("forge", "  ", "command must not be empty"),
        ):
            with self.subTest(name=name, command=command):
                with self.assertRaisesRegex(ValueError, message):
                    EngineCapability(name, command, ("unit",))

    def test_engine_capability_rejects_non_string_metadata(self):
        with self.assertRaisesRegex(ValueError, "name must be a non-empty string"):
            EngineCapability(None, "forge", ("unit",))
        with self.assertRaisesRegex(ValueError, "command must be a non-empty string"):
            EngineCapability("forge", None, ("unit",))
        with self.assertRaisesRegex(ValueError, "test_kinds must be a tuple or list"):
            EngineCapability("forge", "forge", None)

    def test_engine_capability_rejects_unknown_memory_class(self):
        with self.assertRaisesRegex(ValueError, "memory_class must be one of"):
            EngineCapability("custom", "custom-tool", ("unit",), memory_class="unlimited")

    def test_engine_capability_rejects_unknown_test_kinds(self):
        with self.assertRaisesRegex(ValueError, "unknown or non-string kinds: 'mystery'"):
            EngineCapability("custom", "custom-tool", ("unit", "mystery"))
        with self.assertRaisesRegex(ValueError, "unknown or non-string kinds: 7"):
            EngineCapability("custom", "custom-tool", ("unit", 7))

    def test_engine_capability_accepts_supported_memory_classes(self):
        for memory_class in ("low", "medium", "high"):
            with self.subTest(memory_class=memory_class):
                self.assertEqual(
                    EngineCapability("custom", "custom-tool", ("unit",), memory_class=memory_class).memory_class,
                    memory_class,
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

    def test_plan_explains_profile_exclusions(self):
        registry = CapabilityRegistry([
            ExecutableAdapter(EngineCapability("light-tool", sys.executable, ("formal",), memory_class="low")),
            ExecutableAdapter(EngineCapability("heavy-tool", sys.executable, ("formal",), memory_class="high")),
        ])
        plan = registry.plan({}, "formal", profile="light")
        self.assertEqual([row["engine"] for row in plan["selected"]], ["light-tool"])
        excluded = next(row for row in plan["rejected"] if row["engine"] == "heavy-tool")
        self.assertEqual(excluded["status"], "profile_excluded")
        self.assertIn("light profile", excluded["reason"])

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
        self.assertIsNotNone(result.duration_seconds)
        self.assertGreaterEqual(result.duration_seconds, 0)
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

    def test_adapter_bounds_captured_output_and_records_truncation(self):
        cap = EngineCapability("python-test", sys.executable, ("unit",), memory_class="low")
        adapter = ExecutableAdapter(cap)
        with tempfile.TemporaryDirectory() as root:
            result = adapter.run(
                {"root": root},
                {
                    "test_kind": "unit",
                    "argv": ["-c", "import sys; print('x' * 10000); print('y' * 10000, file=sys.stderr)"],
                },
                budget={"timeout_seconds": 5, "max_output_bytes": 1024},
            )
        self.assertEqual(result.status, "passed")
        self.assertTrue(result.raw_evidence["stdout_truncated"])
        self.assertTrue(result.raw_evidence["stderr_truncated"])
        self.assertEqual(result.raw_evidence["output_limit_bytes"], 1024)
        self.assertIn("LOWKEY_OUTPUT_TRUNCATED", result.raw_stdout)
        self.assertIn("LOWKEY_OUTPUT_TRUNCATED", result.raw_stderr)
        self.assertLess(len(result.raw_stdout), 1200)
        self.assertLess(len(result.raw_stderr), 1200)

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
        self.assertIn("\nLOWKEY_TIMEOUT_SECONDS=1", result.raw_stderr)

    def test_adapter_cleans_up_descendant_holding_output_pipe(self):
        if sys.platform != "linux":
            self.skipTest("process-group descendant cleanup is POSIX-specific")
        cap = EngineCapability("python-test", sys.executable, ("unit",), memory_class="low")
        adapter = ExecutableAdapter(cap)
        with tempfile.TemporaryDirectory() as root:
            result = adapter.run(
                {"root": root},
                {
                    "test_kind": "unit",
                    "argv": [
                        "-c",
                        "import subprocess,sys; subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(30)']); print('parent done')",
                    ],
                },
                budget={"timeout_seconds": 5, "max_output_bytes": 1024},
            )
        self.assertEqual(result.status, "passed")
        self.assertIn("parent done", result.raw_stdout)
        self.assertTrue(result.raw_evidence["orphan_process_group_terminated"])
        self.assertFalse(result.raw_evidence["reader_threads_stuck_after_cleanup"])

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

    def test_campaign_rejects_non_forge_engine_without_native_configuration(self):
        cap = EngineCapability("echidna", sys.executable, ("fuzz",), memory_class="medium")
        registry = CapabilityRegistry([ExecutableAdapter(cap)])
        with tempfile.TemporaryDirectory() as root:
            campaign = registry.run_campaign(
                {"root": root}, "fuzz", request={}, profile="balanced",
            )
        self.assertEqual(campaign["selected_count"], 0)
        rejected = next(item for item in campaign["considered_engines"] if item["engine"] == "echidna")
        self.assertEqual(rejected["status"], "missing_configuration")
        self.assertEqual(campaign["results"], [])

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

    def test_public_support_matrix_reports_reasons(self):
        cap = EngineCapability("python-test", sys.executable, ("unit", "fuzz"), ("solidity",), ("foundry",), memory_class="low")
        registry = CapabilityRegistry([ExecutableAdapter(cap)])
        matrix = registry.support_matrix({"language": "solidity", "build_system": "foundry"})
        self.assertTrue(matrix["python-test"]["available"])
        self.assertTrue(matrix["python-test"]["test_kinds"]["unit"]["supported"])
        self.assertTrue(matrix["python-test"]["test_kinds"]["fuzz"]["supported"])

    def test_entry_point_plugins_register_through_documented_contract(self):
        adapter = ExecutableAdapter(EngineCapability("third-party", sys.executable, ("unit",), memory_class="low"))
        point = type("EntryPoint", (), {"name": "fixture-plugin", "load": lambda self: (lambda: adapter)})()
        with patch("lowkey.verification_adapters.entry_points") as discover:
            discover.return_value.select.return_value = [point]
            registry = default_registry(load_plugins=True)
        self.assertIn("third-party", {row["name"] for row in registry.inventory()})
        self.assertEqual(registry.plugin_errors, [])

    def test_campaign_preserves_later_results_when_adapter_raises(self):
        class BrokenAdapter(ExecutableAdapter):
            def run(self, project, request, *, budget):
                raise RuntimeError("adapter fixture failure")

        broken = BrokenAdapter(EngineCapability("broken", sys.executable, ("unit",), memory_class="low"))
        healthy = ExecutableAdapter(EngineCapability("healthy", sys.executable, ("unit",), memory_class="low"))
        registry = CapabilityRegistry([broken, healthy])
        with tempfile.TemporaryDirectory() as root:
            report = registry.run_campaign(
                {"root": root}, "unit", profile="light",
                request={"argv": ["-c", "print(42)"]},
                budget={"timeout_seconds": 5},
            )
        self.assertEqual(report["summary"]["error"], 1)
        self.assertEqual(report["summary"]["passed"], 1)
        self.assertEqual(report["results"][0]["result"]["status"], "error")
        self.assertIn("adapter fixture failure", report["results"][0]["result"]["summary"])
        self.assertGreaterEqual(report["results"][0]["result"]["duration_seconds"], 0)
        self.assertIn("42", report["results"][1]["result"]["raw_stdout"])

    def test_unknown_test_kind_and_profile_fail_explicitly(self):
        registry = default_registry()
        with self.assertRaisesRegex(ValueError, "unknown test kind"):
            registry.select({}, "magic")
        with self.assertRaisesRegex(ValueError, "unknown resource profile"):
            registry.select({}, "unit", profile="unlimited")


if __name__ == "__main__":
    unittest.main()
