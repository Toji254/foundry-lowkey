import unittest
import sys
import tempfile
from pathlib import Path
from unittest.mock import patch

from lowkey.verification_adapters import (
    CapabilityRegistry, CertoraAdapter, EchidnaAdapter, EngineCapability,
    EngineResult, ExecutableAdapter, HalmosAdapter, MedusaAdapter,
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
            ("   ", "forge", "name must be a non-empty string"),
            ("forge", "  ", "command must be a non-empty string"),
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

    def test_engine_capability_rejects_non_string_memory_class(self):
        for memory_class in (None, [], {}):
            with self.subTest(memory_class=memory_class):
                with self.assertRaisesRegex(ValueError, "memory_class must be one of"):
                    EngineCapability("custom", "custom-tool", ("unit",), memory_class=memory_class)

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
            (root / "foundry.toml").write_text('[profile.default]', encoding="utf-8")
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

    def test_broken_plugin_capability_check_does_not_abort_campaign(self):
        class BrokenAdapter:
            capability = EngineCapability("broken-plugin", "broken", ("unit",), memory_class="low")
            def available(self):
                return True
            def supports(self, project, test_kind):
                raise RuntimeError("plugin metadata unavailable")
            def run(self, project, request, *, budget):
                raise AssertionError("unsupported plugin must not run")

        class HealthyAdapter:
            capability = EngineCapability("healthy-plugin", sys.executable, ("unit",), memory_class="low")
            def available(self):
                return True
            def supports(self, project, test_kind):
                return True, "fixture supports this test"
            def run(self, project, request, *, budget):
                return EngineResult("healthy-plugin", "passed", 0, raw_stdout="healthy evidence")

        registry = CapabilityRegistry([BrokenAdapter(), HealthyAdapter()])
        with tempfile.TemporaryDirectory() as root:
            campaign = registry.run_campaign(
                {"root": root}, "unit", request={"argv": []}, profile="light",
            )
        self.assertEqual(campaign["summary"]["passed"], 1)
        broken = next(row for row in campaign["considered_engines"] if row["engine"] == "broken-plugin")
        self.assertEqual(broken["status"], "adapter_error")
        self.assertTrue(any("supports() raised RuntimeError" in row["error"] for row in campaign["plugin_errors"]))
        self.assertEqual(campaign["results"][0]["result"]["raw_stdout"], "healthy evidence")

    def test_native_engine_builders_require_real_project_configuration(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "src" / "Harness.sol").write_text("contract Harness {}", encoding="utf-8")
            (root / "echidna.yaml").write_text("testMode: property\n", encoding="utf-8")
            (root / "medusa.json").write_text("{}\n", encoding="utf-8")
            (root / "bad-medusa.json").write_text("{not-json}\n", encoding="utf-8")
            (root / "rules.conf").write_text('{"files": ["src/Harness.sol"]}\n', encoding="utf-8")
            project = {"root": str(root)}

            echidna = EchidnaAdapter(EngineCapability("echidna", "echidna", ("fuzz",)))
            argv, reason = echidna.request_configuration(
                project, {"target": "src/Harness.sol", "contract": "Harness", "config": "echidna.yaml"}
            )
            self.assertEqual(argv, ["src/Harness.sol", "--contract", "Harness", "--config", "echidna.yaml", "--format", "json"])
            self.assertIn("validated", reason)
            self.assertIsNone(echidna.request_configuration(project, {"target": "../outside.sol"})[0])

            medusa = MedusaAdapter(EngineCapability("medusa", "medusa", ("fuzz",)))
            argv, _ = medusa.request_configuration(project, {"target_contracts": ["Vault", "Token"]})
            self.assertEqual(argv, ["fuzz", "--config", "medusa.json", "--workers", "1", "--target-contracts", "Vault, Token"])

            self.assertIsNone(medusa.request_configuration(project, {"workers": 0})[0])
            self.assertIsNone(medusa.request_configuration(project, {"workers": 100})[0])
            self.assertIsNone(medusa.request_configuration(project, {"config": "bad-medusa.json"})[0])

            halmos = HalmosAdapter(EngineCapability("halmos", "halmos", ("formal",)))
            self.assertEqual(halmos.request_configuration(project, {})[0], ["--function", "test"])

            certora = CertoraAdapter(EngineCapability("certora", "certoraRun", ("formal",)))
            self.assertEqual(certora.request_configuration(project, {"config": "rules.conf"})[0], ["rules.conf"])
            self.assertIsNone(certora.request_configuration(project, {"config": "../rules.conf"})[0])

    def test_medusa_native_exit_codes_distinguish_failure_from_tool_error(self):
        adapter = MedusaAdapter(EngineCapability(
            "medusa", sys.executable, ("fuzz",), memory_class="medium"
        ))
        with tempfile.TemporaryDirectory() as root:
            def run(exit_code):
                return adapter.run(
                    {"root": root},
                    {"test_kind": "fuzz", "argv": [
                        "-c", f"raise SystemExit({exit_code})"
                    ]},
                    budget={"timeout_seconds": 5},
                )
            failed = run(7)
            general_error = run(1)
            handled_error = run(6)
            passed = run(0)
        self.assertEqual(failed.status, "failed")
        self.assertEqual(failed.metadata["result_semantics"], "medusa_native_test_failure_exit_7")
        self.assertIn("failing fuzz test", failed.summary)
        self.assertEqual(general_error.status, "error")
        self.assertEqual(handled_error.status, "error")
        self.assertEqual(general_error.metadata["result_semantics"], "medusa_native_execution_error")
        self.assertEqual(passed.status, "passed")
        self.assertEqual(passed.metadata["result_semantics"], "medusa_exit_success")

    def test_default_registry_plans_medusa_only_with_valid_config(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "src").mkdir()
            (root / "foundry.toml").write_text('[profile.default]\\nsrc = "src"\\n', encoding="utf-8")
            (root / "src" / "Vault.sol").write_text("contract Vault {}", encoding="utf-8")
            (root / "medusa.json").write_text("{}", encoding="utf-8")
            (root / "echidna.yaml").write_text("testMode: property", encoding="utf-8")
            project = inspect_project(root)
            registry = default_registry(load_plugins=False)
            with patch("lowkey.verification_adapters.shutil.which", return_value="/usr/bin/tool"):
                valid = registry.plan(
                    project, "fuzz", profile="balanced",
                    request={"engine_config_by_engine": {
                        "echidna": {"target": "src/Vault.sol", "config": "echidna.yaml"},
                        "medusa": {"config": "medusa.json", "target_contracts": ["Vault"]},
                    }},
                )
                missing = registry.plan(project, "fuzz", profile="balanced", request={"config": "missing.json"})
        selected = {row["engine"] for row in valid["selected"]}
        self.assertIn("medusa", selected)
        self.assertIn("echidna", selected)
        rejected = next(row for row in missing["rejected"] if row["engine"] == "medusa")
        self.assertEqual(rejected["status"], "missing_configuration")
        self.assertIn("does not exist", rejected["reason"])

    def test_echidna_requires_and_interprets_json_campaign_result(self):
        adapter = EchidnaAdapter(EngineCapability("echidna", sys.executable, ("fuzz",), memory_class="medium"))
        with tempfile.TemporaryDirectory() as root:
            project = {"root": root}
            def run(code, exit_code=0):
                script = f"print({code!r}); raise SystemExit({exit_code})"
                return adapter.run(
                    project,
                    {"test_kind": "fuzz", "argv": ["-c", script]},
                    budget={"timeout_seconds": 5},
                )
            passed = run('{"success": true, "tests": [{"name": "echidna_supply", "status": "passed"}]}')
            failed = run('{"success": false, "tests": [{"name": "echidna_supply", "status": "solved"}]}', exit_code=1)
            error = run('{"success": true, "error": "compiler failed", "tests": []}')
            unclear = run("not-json")
        self.assertEqual(passed.status, "passed")
        self.assertEqual(passed.metadata["result_semantics"], "echidna_json_campaign_success")
        self.assertEqual(failed.status, "failed")
        self.assertEqual(error.status, "error")
        self.assertEqual(unclear.status, "inconclusive")
        self.assertIn("native_result", passed.raw_evidence)

    def test_halmos_requires_recognized_symbolic_result_markers(self):
        adapter = HalmosAdapter(EngineCapability("halmos", sys.executable, ("formal",), memory_class="high"))
        with tempfile.TemporaryDirectory() as root:
            failed = adapter.run(
                {"root": root},
                {"test_kind": "formal", "argv": ["-c", "print('[FAIL] check_supply')"]},
                budget={"timeout_seconds": 5},
            )
            passed = adapter.run(
                {"root": root},
                {"test_kind": "formal", "argv": ["-c", "print('[PASS] check_supply')"]},
                budget={"timeout_seconds": 5},
            )
            unclear = adapter.run(
                {"root": root},
                {"test_kind": "formal", "argv": ["-c", "print('finished')"]},
                budget={"timeout_seconds": 5},
            )
        self.assertEqual(failed.status, "failed")
        self.assertEqual(passed.status, "passed")
        self.assertEqual(unclear.status, "inconclusive")

    def test_certora_cli_success_is_not_reported_as_proof_success(self):
        adapter = CertoraAdapter(EngineCapability("certora", sys.executable, ("formal",), memory_class="high"))
        with tempfile.TemporaryDirectory() as root:
            result = adapter.run(
                {"root": root},
                {"test_kind": "formal", "argv": ["-c", "print('job submitted')"]},
                budget={"timeout_seconds": 5},
            )
        self.assertEqual(result.status, "submitted")
        self.assertEqual(result.metadata["result_semantics"], "cli_success_is_not_proof_success")

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

    def test_adapter_enforces_optional_linux_process_group_memory_budget(self):
        if sys.platform != "linux":
            self.skipTest("live RSS budget uses Linux /proc accounting")
        cap = EngineCapability("python-test", sys.executable, ("unit",), memory_class="low")
        adapter = ExecutableAdapter(cap)
        with tempfile.TemporaryDirectory() as root:
            result = adapter.run(
                {"root": root},
                {
                    "test_kind": "unit",
                    "argv": [
                        "-c",
                        "import time; data=bytearray(96*1024*1024); print('allocated', flush=True); time.sleep(10)",
                    ],
                },
                budget={"timeout_seconds": 5, "max_memory_mb": 48},
            )
        self.assertEqual(result.status, "resource_limit")
        self.assertEqual(result.exit_code, 137)
        self.assertTrue(result.raw_evidence["resource_limit_exceeded"])
        self.assertGreater(result.raw_evidence["peak_process_group_rss_bytes"], 48 * 1024 * 1024)
        self.assertIn("LOWKEY_RESOURCE_LIMIT_MB=48", result.raw_stderr)
        self.assertIn("exceeded the 48 MiB", result.summary)

    def test_adapter_rejects_invalid_memory_budget_before_launch(self):
        cap = EngineCapability("python-test", sys.executable, ("unit",), memory_class="low")
        adapter = ExecutableAdapter(cap)
        with tempfile.TemporaryDirectory() as root:
            result = adapter.run(
                {"root": root},
                {"test_kind": "unit", "argv": ["-c", "print('must not launch')"]},
                budget={"max_memory_mb": 0},
            )
        self.assertEqual(result.status, "unsupported")
        self.assertIn("positive integer", result.summary)

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
        self.assertEqual(campaign["selection_summary"]["selected"], 1)
        self.assertEqual(campaign["selection_summary"]["missing_configuration"], 0)
        self.assertEqual(campaign["budget"]["timeout_seconds"], 5)
        self.assertEqual(campaign["profile_limits"]["timeout_seconds"], 60)
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
        self.assertEqual(campaign["selection_summary"]["selected"], 0)
        self.assertEqual(campaign["selection_summary"]["missing_configuration"], 1)
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
